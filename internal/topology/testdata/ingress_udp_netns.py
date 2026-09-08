"""Synthetic packets only. Every network mutation is in a NEW anonymous netns.

The script itself calls unshare before creating anything; it cannot modify the
network namespace from which it was invoked. Explicit cleanup is supplementary
to kernel teardown when both namespace-owning processes exit. No host files,
services, external network destinations or existing namespaces are modified.
"""
import ctypes
import json
import os
import subprocess
import sys

test_input = json.load(sys.stdin)
rules = test_input['rules']
before_namespace = os.readlink('/proc/self/ns/net')
libc = ctypes.CDLL(None, use_errno=True)
if libc.unshare(0x40000000) != 0:  # CLONE_NEWNET: fresh, anonymous, unconnected
    raise OSError(ctypes.get_errno(), 'isolated network namespace unavailable')
if os.readlink('/proc/self/ns/net') == before_namespace:
    raise RuntimeError('Refusing any network mutations without isolation')


def run(*args, text=None):
    result = subprocess.run(args, input=text, text=True, capture_output=True, timeout=5)
    if result.returncode:
        raise RuntimeError(' '.join(args[:4]) + ': ' + result.stderr.strip())
    return result.stdout


# A fresh namespace has only loopback. Abort if that invariant is not true.
if set(os.listdir('/sys/class/net')) != {'lo'}:
    # /sys can reflect its original mount namespace, so use netlink as authority.
    if {item['ifname'] for item in json.loads(run('ip', '-j', 'link'))} != {'lo'}:
        raise RuntimeError('Refusing to use a namespace containing existing interfaces')

client_code = r'''
import json, socket, sys
print('READY', flush=True)
for line in sys.stdin:
    command = json.loads(line)
    if command['action'] == 'quit':
        break
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('10.77.0.2', 4443 if command['action'] == 'receive' else 0))
    s.settimeout(1)
    if command['action'] == 'receive':
        print('LISTENING', flush=True)
    else:
        s.sendto(b'guardex-synthetic-request', ('10.77.0.1', command['port']))
    try:
        data, source = s.recvfrom(128)
        result = {'received': True, 'source_port': source[1]}
    except socket.timeout:
        result = {'received': False}
    finally:
        s.close()
    print(json.dumps(result), flush=True)
'''
server_code = r'''
import json, os, socket, sys
os.setgroups([])
os.setgid(65532)
os.setuid(65532)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 18443))
s.settimeout(5)
print('READY', flush=True)
for line in sys.stdin:
    action = line.strip()
    if action == 'quit':
        break
    outgoing = s
    if action == 'reply':
        _, target = s.recvfrom(128)
    elif action == 'egress_bound':
        target = ('10.77.0.2', 4443)
    else:
        outgoing = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        outgoing.bind(('10.77.0.1', 0))
        target = ('10.77.0.2', 4443)
    try:
        outgoing.sendto(b'guardex-synthetic-reply', target)
        result = {'uid': os.getuid(), 'send_errno': None}
    except OSError as exc:
        result = {'uid': os.getuid(), 'send_errno': exc.errno}
    finally:
        if outgoing is not s:
            outgoing.close()
    print(json.dumps(result), flush=True)
'''

client = None
server = None
try:
    client = subprocess.Popen(
        ['unshare', '--net', '--', 'python3', '-u', '-c', client_code],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if client.stdout.readline().strip() != 'READY':
        raise RuntimeError('Isolated peer failed to start')
    if os.readlink(f'/proc/{client.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
        raise RuntimeError('Peer is not isolated')
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'srv0', 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', str(client.pid))
    run('ip', 'address', 'add', '10.77.0.1/24', 'dev', 'srv0')
    run('ip', 'link', 'set', 'srv0', 'up')
    for args in [
        ['link', 'set', 'lo', 'up'],
        ['address', 'add', '10.77.0.2/24', 'dev', 'peer0'],
        ['link', 'set', 'peer0', 'up'],
    ]:
        run('nsenter', '-t', str(client.pid), '-n', 'ip', *args)
    run('ip', 'link', 'add', 'gxwg0', 'type', 'dummy')
    run('ip', 'address', 'add', '10.91.0.1/30', 'dev', 'gxwg0')
    run('ip', 'link', 'set', 'gxwg0', 'up')
    run('ip', 'route', 'add', 'default', 'dev', 'gxwg0', 'table', '51820')
    run('ip', 'rule', 'add', 'priority', '80', 'fwmark', '0x4758', 'lookup', 'main')
    run('ip', 'rule', 'add', 'priority', '100', 'uidrange', '65532-65532', 'lookup', '51820')

    def install_policy(policy, replace=False):
        prefix = 'delete table inet guardex_transport\n' if replace else ''
        # Counter instrumentation does not change the production verdicts.
        policy = policy.replace(' accept\n', ' counter accept\n')
        policy = policy.replace('meta skuid 65532 reject', 'meta skuid 65532 counter reject')
        policy = policy.replace('ct mark 0x4758 meta mark', 'ct mark 0x4758 counter meta mark')
        run('nft', '-f', '-', text=prefix + policy)

    reply_lines = [line for line in rules.splitlines() if 'ct direction reply' in line]
    assert len(reply_lines) == 1
    install_policy(rules.replace(reply_lines[0] + '\n', ''))
    run('nft', '-f', '-', text='''
table inet guardex_test_nat {
 chain prerouting { type nat hook prerouting priority dstnat; policy accept;
  udp dport { 443, 444, 445 } redirect to :18443
 }
}
''')
    server = subprocess.Popen(
        ['python3', '-u', '-c', server_code], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if server.stdout.readline().strip() != 'READY':
        raise RuntimeError('Unprivileged test listener failed to start')

    def command(process, text):
        process.stdin.write(text + '\n')
        process.stdin.flush()

    def probe(name, port, expected):
        command(server, 'reply')
        command(client, json.dumps({'action': 'probe', 'port': port}))
        received = json.loads(client.stdout.readline())
        sent = json.loads(server.stdout.readline())
        print(json.dumps({'case': name, 'client': received, 'endpoint': sent}), flush=True)
        if received['received'] is not expected:
            print(run('nft', 'list', 'table', 'inet', 'guardex_transport'), flush=True)
            print(run('ip', 'route', 'get', '10.77.0.2', 'from', '10.77.0.1', 'uid', '65532'), flush=True)
        assert received['received'] is expected, (name, received, sent)
        if expected:
            assert received['source_port'] == 443, (name, received)

    # Bind wildcard exactly like TT; the backbone has its own address too.
    # Without the source selector Linux chooses that address for the response,
    # which then no longer matches the public request's conntrack entry.
    probe('old_policy_wildcard_listener_reply_lost', 443, False)
    install_policy(rules, replace=True)
    run('ip', *test_input['source_policy_args'])
    probe('fixed_wildcard_listener_reply_uses_public_443', 443, True)
    # Route negatives to the synthetic public interface, so the kill switch is
    # actually exercised instead of packets simply disappearing in the dummy.
    run('ip', 'rule', 'add', 'priority', '90', 'to', '10.77.0.2/32', 'lookup', 'main')
    run('nft', 'add', 'rule', 'inet', 'guardex_transport', 'ingress_mark',
        'udp', 'dport', '444', 'ct', 'mark', 'set', '0x4758')
    probe('marked_reply_wrong_original_port_stays_blocked', 444, False)
    probe('unmarked_reply_stays_blocked', 445, False)

    for action, mark_original in [('egress', False), ('egress_bound', False), ('egress_bound', True)]:
        if mark_original:
            run('nft', 'add', 'rule', 'inet', 'guardex_transport', 'reply_route',
                'meta', 'skuid', '65532', 'udp', 'dport', '4443',
                'ct', 'mark', 'set', '0x4758', 'meta', 'mark', 'set', '0x4758')
        command(client, json.dumps({'action': 'receive'}))
        assert client.stdout.readline().strip() == 'LISTENING'
        command(server, action)
        sent = json.loads(server.stdout.readline())
        received = json.loads(client.stdout.readline())
        assert received['received'] is False, (mark_original, received, sent)
        print(json.dumps({'case': ('marked_' if mark_original else '') + action + '_blocked',
                          'client': received, 'endpoint': sent}), flush=True)
finally:
    # All names below were created only after this process successfully unshared.
    # Clean up explicitly as well as relying on anonymous namespace destruction.
    for process in (server, client):
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    for args in [
        ['nft', 'delete', 'table', 'inet', 'guardex_test_nat'],
        ['nft', 'delete', 'table', 'inet', 'guardex_transport'],
        ['ip', 'rule', 'del', 'priority', '80'],
        ['ip', 'rule', 'del', 'priority', '90'],
        ['ip', 'rule', 'del', 'priority', '95'],
        ['ip', 'rule', 'del', 'priority', '100'],
        ['ip', 'link', 'del', 'srv0'],
        ['ip', 'link', 'del', 'gxwg0'],
    ]:
        subprocess.run(args, capture_output=True, timeout=2)
