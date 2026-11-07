"""Guarded NL/ID API SNI routing with reviewed persistence and explicit backout.

Only new API-destination flows from the two existing backbone peers are
selected. Original bridges, TLS and all conntrack entries stay intact.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

BASE = Path('/var/lib/guardex-sni-netns-qualification')
SCOPE = BASE / 'live-nl-id-cohort-20261107a'
STATE = SCOPE / 'state.json'
SELF = SCOPE / 'controller.py'
BUNDLE = BASE / 'haproxy-bundle-20261105b/image-root'
BINARY = BUNDLE / 'usr/sbin/haproxy'
LOADER = BUNDLE / 'lib/ld-musl-x86_64.so.1'
LIBRARIES = BUNDLE / 'usr/lib'
UNIT = 'guardex-api-sni-nl-id'
TIMER = UNIT + '-rollback'
TABLE = 'gx_sni_nlid_20261107a'
CHAIN = 'GX_SNINLID_1107A'
TAG = 'guardex-api-sni-nl-id'
CLIENT, LOCAL, PRIMARY, SECONDARY, PUBLIC = (
    '10.77.2.1', '10.77.0.18', '193.247.73.15', '82.208.22.95', '94.249.195.63')
SPORT, PORT = 51489, 19445
HAPROXY_SHA = '6e9c23d293b6c2a14fc81ac27e647e41b75b9b91b8b0f2d7cb35a7dce255ed35'
LOADER_SHA = '99eab0629ed5e6bc258bea735a128d1de30c5a8b52f39eed4919452d03c6c4ee'


def run(argv, data=None, check=True):
    result = subprocess.run(argv, input=data, capture_output=True, text=True, timeout=6)
    if check and result.returncode:
        raise RuntimeError('owned_command_failed:' + argv[0] + ':' + result.stderr[-350:])
    return result


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def private(path, directory=False):
    info = path.lstat()
    assert (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
    assert info.st_uid == 0 and not info.st_mode & 0o077, 'unsafe_owned_path'


def save(value):
    temporary = STATE.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.chmod(0o600)
    temporary.replace(STATE)


def owner():
    private(BASE, True); private(SCOPE, True); private(STATE); private(SELF)
    value = json.loads(STATE.read_text())
    assert value['controller_sha256'] == sha(SELF)
    assert value['scope'] == str(SCOPE) and value['tag'] == TAG
    assert Path('/proc/self/ns/net').stat().st_ino == Path('/proc/1/ns/net').stat().st_ino
    assert sha(BINARY) == HAPROXY_SHA and sha(LOADER) == LOADER_SHA
    assert sha(SCOPE / 'haproxy.cfg') == value['configuration_sha256']
    assert sha(SCOPE / 'policy-templates.json') == value['templates_sha256']
    return value


POLICY_SHA = "62ae0bc81b512f390f81d453578d58248be8a84573e97f07dfffa32d1f6432cb"
UNIT_FILE = Path("/etc/systemd/system/" + UNIT + ".service")

def policy_module():
    import importlib.util
    path = SCOPE / "policy.py"
    private(path)
    assert sha(path) == POLICY_SHA
    spec = importlib.util.spec_from_file_location("owned_cohort_policy", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    assert module.CLIENTS == ("10.77.2.1", "10.77.0.13")
    return module

def jump(): return policy_module().input_jump()
def allowances(): return policy_module().allowances()
def nat_config(): return policy_module().nat_config()
def config(): return policy_module().haproxy_config()

def unit_source():
    return f"""[Unit]
Description={TAG}
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
ExecStartPre=/usr/bin/python3 {SELF} prepare-filter
ExecStart={LOADER} --library-path {LIBRARIES} {BINARY} -db -f {SCOPE}/haproxy.cfg
ExecStartPost=/usr/bin/python3 {SELF} select
ExecStopPost=/usr/bin/python3 {SELF} stop-select
Restart=on-failure
RestartSec=2s
TimeoutStartSec=20s
TimeoutStopSec=10s
MemoryMax=128M
LimitNOFILE=8192
NoNewPrivileges=yes
[Install]
WantedBy=multi-user.target
"""


def check_unit_link():
    assert UNIT_FILE.is_symlink() and UNIT_FILE.lstat().st_uid == 0
    assert UNIT_FILE.resolve() == SCOPE / (UNIT + ".service")
    assert sha(UNIT_FILE.resolve()) == hashlib.sha256(unit_source().encode()).hexdigest()


def table_present():
    rows = json.loads(run(['nft', '-j', 'list', 'tables']).stdout)['nftables']
    return any(row.get('table', {}).get('family') == 'ip'
               and row.get('table', {}).get('name') == TABLE for row in rows)


def unit_fields(name):
    result = run(['systemctl', 'show', name, '-p', 'ActiveState', '-p', 'Description', '-p', 'MainPID'], check=False)
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def arm():
    assert not STATE.exists() and not UNIT_FILE.exists() and not UNIT_FILE.is_symlink()
    assert not table_present()
    assert run(['iptables', '-w', '2', '-S', CHAIN], check=False).returncode != 0
    assert not run(['ss', '-Hln', 'sport = :' + str(PORT)]).stdout.strip()
    assert unit_fields(UNIT + '.service').get('ActiveState') not in ('active', 'activating')
    assert unit_fields(TIMER + '.timer').get('ActiveState') not in ('active', 'activating')
    policy_module()
    assert sha(BINARY) == HAPROXY_SHA and sha(LOADER) == LOADER_SHA
    path = SCOPE / 'haproxy.cfg'; path.write_text(config()); path.chmod(0o600)
    unit = SCOPE / (UNIT + '.service'); unit.write_text(unit_source()); unit.chmod(0o600)
    run([str(LOADER), '--library-path', str(LIBRARIES), str(BINARY), '-c', '-f', str(path)])
    private(SCOPE / 'policy-templates.json')
    templates = json.loads((SCOPE / 'policy-templates.json').read_text())
    assert templates['controller_sha256'] == sha(SELF) and templates['isolated_only'] is True
    assert len(templates['chain_snapshots']) == 4
    value = {'status': 'armed', 'scope': str(SCOPE), 'tag': TAG,
             'network_namespace': Path('/proc/self/ns/net').stat().st_ino,
             'controller_sha256': sha(SELF), 'configuration_sha256': sha(path),
             'templates_sha256': sha(SCOPE / 'policy-templates.json'),
             'deadline_epoch': time.time() + 900, 'mutation_intent': False,
             'nat_sha256': templates['nat_sha256'], 'listener_pid': None}
    save(value)
    run(['systemd-run', '--quiet', '--unit', TIMER, '--on-active=900s',
         '--timer-property=AccuracySec=1s', '/usr/bin/python3', str(SELF), 'rollback'])
    assert unit_fields(TIMER + '.timer').get('ActiveState') == 'active'
    return value


def validate_backbone():
    rows = json.loads(run(['ip', '-j', 'address', 'show', 'dev', 'gxwg0']).stdout)
    assert len(rows) == 1 and LOCAL in [row['local'] for row in rows[0].get('addr_info', [])]
    peers = run(['wg', 'show', 'gxwg0', 'allowed-ips']).stdout.splitlines()
    allowed = {token.strip(',') for row in peers for token in row.split()[1:]}
    assert {'10.77.2.1/32', '10.77.0.13/32'} <= allowed


def prepare_filter():
    value = owner(); runtime_authorized(value); check_unit_link(); validate_backbone()
    assert value['status'] in ('starting', 'applied', 'retained')
    templates = json.loads((SCOPE / 'policy-templates.json').read_text())
    present = run(['iptables', '-w', '2', '-S', CHAIN], check=False)
    if present.returncode != 0:
        run(['iptables', '-w', '2', '-N', CHAIN])
        present = run(['iptables', '-w', '2', '-S', CHAIN])
    assert present.stdout in templates['chain_snapshots'], 'foreign_or_changed_filter'
    count = templates['chain_snapshots'].index(present.stdout)
    rules = [*allowances(), policy_module().deny_other_listener_inputs()]
    for args in rules[count:]:
        run(['iptables', '-w', '2', '-A', CHAIN, *args])
    assert run(['iptables', '-w', '2', '-S', CHAIN]).stdout == templates['chain_snapshots'][-1]
    if run(['iptables', '-w', '2', '-C', 'INPUT', *jump()], check=False).returncode != 0:
        run(['iptables', '-w', '2', '-I', 'INPUT', '1', *jump()])
    return value


def select():
    value = owner(); runtime_authorized(value); check_unit_link(); validate_backbone()
    assert value['status'] in ('starting', 'applied', 'retained')
    fields = unit_fields(UNIT + '.service')
    assert fields.get('Description') == TAG and int(fields.get('MainPID', '0')) > 1
    for unused in range(20):
        if LOCAL + ':' + str(PORT) in run(['ss', '-Hlnt', 'sport = :' + str(PORT)]).stdout: break
        time.sleep(.05)
    else: raise RuntimeError('owned_listener_not_ready')
    if not table_present(): run(['nft', '-f', '-'], data=nat_config())
    actual = hashlib.sha256(run(['nft', '-s', 'list', 'table', 'ip', TABLE]).stdout.encode()).hexdigest()
    assert actual == value['nat_sha256'], 'changed_owned_nat'
    # A hook must never replace lifecycle state read before a concurrent retain.
    # Its independent receipt records current service identity without changing
    # the parent's armed/applied/retained decision.
    receipt = {'listener_pid': int(fields['MainPID']), 'last_selected_epoch': time.time(),
               'controller_sha256': value['controller_sha256']}
    temporary = SCOPE / 'selection.tmp'
    temporary.write_text(json.dumps(receipt)); temporary.chmod(0o600)
    temporary.replace(SCOPE / 'selection.json')
    return value


def runtime_authorized(value):
    if value['status'] == 'retained': return
    assert value['status'] in ('starting', 'applied')
    assert value['deadline_epoch'] - time.time() > 15, 'expired_unretained_scope'
    assert unit_fields(TIMER + '.timer').get('ActiveState') == 'active', 'inactive_unretained_guard'


def deselect(value):
    if table_present():
        actual = hashlib.sha256(run(['nft', '-s', 'list', 'table', 'ip', TABLE]).stdout.encode()).hexdigest()
        assert actual == value['nat_sha256'], 'changed_owned_nat_refusal'
        run(['nft', 'delete', 'table', 'ip', TABLE])
    assert not table_present()


def apply():
    value = owner()
    assert value['status'] == 'armed' and value['deadline_epoch'] - time.time() > 780
    assert unit_fields(TIMER + '.timer').get('ActiveState') == 'active'
    assert not UNIT_FILE.exists() and not UNIT_FILE.is_symlink()
    assert not table_present() and not run(['ss', '-Hln', 'sport = :' + str(PORT)]).stdout.strip()
    value['mutation_intent'] = True; value['status'] = 'starting'; save(value)
    UNIT_FILE.symlink_to(SCOPE / (UNIT + '.service'))
    run(['systemctl', 'daemon-reload'])
    # Unit callbacks deliberately do not acquire this parent's lifecycle lock.
    # They validate stable source/config/link identity and the current backbone.
    run(['systemctl', 'start', UNIT + '.service'])
    value = owner()
    assert unit_fields(UNIT + '.service').get('ActiveState') == 'active'
    value['status'] = 'applied'; save(value)
    return value


def retain():
    import uuid
    value = owner(); check_unit_link()
    assert value['status'] == 'applied' and value['deadline_epoch'] - time.time() > 45
    assert unit_fields(UNIT + '.service').get('ActiveState') == 'active'
    evidence = SCOPE / 'acceptance.json'; private(evidence)
    data = json.loads(evidence.read_text())
    assert data['scope'] == str(SCOPE)
    assert data['test_type'] == 'server_transport_acceptance'
    for country in ('NL', 'ID'):
        row = data['routes'][country]
        assert row['fresh_connections'] >= 20 and row['failed'] == 0
        assert row['verified_bytes_min'] >= 262144 and row['strict_TLS'] is True
        assert len(row['request_ids']) >= 20
        assert all(len(x) == 32 and all(c in '0123456789abcdef' for c in x) for x in row['request_ids'])
    assert data['preserved_existing_cohorts'] is True
    assert data['api_request_join_failures'] == 0
    run(['systemctl', 'enable', UNIT + '.service'])
    value['status'] = 'retained'; value['retained_epoch'] = time.time()
    value['acceptance_sha256'] = sha(evidence); save(value)
    run(['systemctl', 'stop', TIMER + '.timer'])
    return value


def rollback(*, explicit_retained=False):
    value = owner()
    if value['status'] == 'retained' and not explicit_retained:
        return value | {'automatic_rollback_ignored': 'retained_scope'}
    if value['status'] == 'rolled_back': return value
    if explicit_retained: assert value['status'] == 'retained'
    if value['mutation_intent']:
        deselect(value)
        value['status'] = 'rolling_back'; save(value)
        if UNIT_FILE.exists() or UNIT_FILE.is_symlink():
            check_unit_link()
            run(['systemctl', 'stop', UNIT + '.service'])
        present = run(['iptables', '-w', '2', '-S', CHAIN], check=False)
        if present.returncode == 0:
            templates = json.loads((SCOPE / 'policy-templates.json').read_text())
            assert present.stdout in templates['chain_snapshots'], 'changed_owned_chain_refusal'
            if run(['iptables', '-w', '2', '-C', 'INPUT', *jump()], check=False).returncode == 0:
                run(['iptables', '-w', '2', '-D', 'INPUT', *jump()])
            run(['iptables', '-w', '2', '-F', CHAIN]); run(['iptables', '-w', '2', '-X', CHAIN])
        wanted = Path('/etc/systemd/system/multi-user.target.wants') / (UNIT + '.service')
        if wanted.exists() or wanted.is_symlink():
            assert wanted.is_symlink() and wanted.resolve() == SCOPE / (UNIT + '.service')
            wanted.unlink()
        if UNIT_FILE.exists() or UNIT_FILE.is_symlink():
            check_unit_link(); UNIT_FILE.unlink()
            run(['systemctl', 'daemon-reload'])
    value['status'] = 'rolled_back'; value['rolled_back_epoch'] = time.time(); save(value)
    run(['systemctl', 'stop', TIMER + '.timer'], check=False)
    return value


def main():
    os.umask(0o077)
    assert os.geteuid() == 0
    private(BASE, True); private(SCOPE, True); private(SELF)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['arm', 'apply', 'inspect', 'rollback', 'retain',
        'backout-retained', 'prepare-filter', 'select', 'stop-select'])
    args = parser.parse_args()
    if args.action in ('prepare-filter', 'select', 'stop-select'):
        if args.action == 'prepare-filter': value = prepare_filter()
        elif args.action == 'select': value = select()
        else: value = owner(); check_unit_link(); deselect(value)
    else:
        with (SCOPE / 'control.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if args.action == 'arm': value = arm()
            elif args.action == 'apply': value = apply()
            elif args.action == 'retain': value = retain()
            elif args.action == 'rollback': value = rollback()
            elif args.action == 'backout-retained': value = rollback(explicit_retained=True)
            else: value = owner()
    print(json.dumps(value))


if __name__ == '__main__': main()


