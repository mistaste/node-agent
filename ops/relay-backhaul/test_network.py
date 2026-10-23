"""Linux/root integration: real OUTPUT DNAT, peer source guard and return path."""
import importlib.util
import os
import pathlib
import subprocess
import sys
import unittest

spec = importlib.util.spec_from_file_location('watchdog', pathlib.Path(__file__).with_name('watchdog.py'))
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)


@unittest.skipUnless(sys.platform == 'linux' and os.geteuid() == 0, 'requires disposable Linux network namespaces')
class NetworkTest(unittest.TestCase):
    def test_source_guard_and_bidirectional_transfer(self):
        relay, peer = f'gxrelaytest-{os.getpid()}', f'gxpeertest-{os.getpid()}'
        left, right = f'gxv{os.getpid()}r', f'gxv{os.getpid()}p'
        server = None

        def run(args, data=None, check=True):
            result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=5)
            if check and result.returncode:
                self.fail(result.stderr)
            return result

        def ns(name, args, data=None, check=True):
            return run(['ip', 'netns', 'exec', name, *args], data, check)

        try:
            run(['ip', 'netns', 'add', relay])
            run(['ip', 'netns', 'add', peer])
            run(['ip', 'link', 'add', left, 'type', 'veth', 'peer', 'name', right])
            run(['ip', 'link', 'set', left, 'netns', relay])
            run(['ip', 'link', 'set', right, 'netns', peer])
            for name, link, address in [(relay, left, '10.79.240.1'), (peer, right, '10.79.240.2')]:
                ns(name, ['ip', 'link', 'set', link, 'name', 'gxrelay0'])
                ns(name, ['ip', 'address', 'add', address+'/28', 'dev', 'gxrelay0'])
                ns(name, ['ip', 'link', 'set', 'gxrelay0', 'up'])
                ns(name, ['ip', 'link', 'set', 'lo', 'up'])
            ns(relay, ['ip', 'address', 'add', '138.16.163.18/32', 'dev', 'lo'])
            ns(relay, ['ip', 'route', 'add', 'default', 'via', '10.79.240.2'])
            # The private receiver, like a WireGuard peer with AllowedIPs /32,
            # must reject an encapsulated socket's unchanged public source.
            ns(peer, ['nft', '-f', '-'], '''table ip guard {
 chain input { type filter hook input priority filter; policy accept;
 tcp dport 443 ip saddr != 10.79.240.1 drop
 }
}
''')
            ns(relay, ['nft', '-f', '-'], watchdog.nft_initial())
            ns(relay, ['nft', '-f', '-'], watchdog.nft_update(
                [{'public_ip':'5.255.124.73','private_ip':'10.79.240.2'}], {'5.255.124.73'}))
            server_code = '''import socket
s=socket.socket();s.bind(('10.79.240.2',443));s.listen(1);s.settimeout(5)
print('READY',flush=True)
c,_=s.accept();c.settimeout(2);c.sendall(b'G'*2097152);c.close();s.close()
'''
            server = subprocess.Popen(['ip','netns','exec',peer,'python3','-c',server_code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertEqual(server.stdout.readline().strip(), 'READY')
            client_code = '''import socket
s=socket.socket();s.settimeout(.5);s.bind(('138.16.163.18',0))
try:
 s.connect(('5.255.124.73',443));s.settimeout(2);data=bytearray()
 while len(data)<2097152:
  part=s.recv(65536)
  if not part:break
  data.extend(part)
 assert data==b'G'*2097152
finally:s.close()
'''
            # Negative control: omitting source NAT reproduces the failed
            # public-socket/private-peer handshake, independent of app code.
            ns(relay, ['nft','delete','chain','ip',watchdog.TABLE,'postrouting'])
            self.assertNotEqual(ns(relay, ['python3','-c',client_code], check=False).returncode, 0)
            ns(relay, ['nft','delete','table','ip',watchdog.TABLE])
            ns(relay, ['nft','-f','-'], watchdog.nft_initial())
            ns(relay, ['nft','-f','-'], watchdog.nft_update(
                [{'public_ip':'5.255.124.73','private_ip':'10.79.240.2'}], {'5.255.124.73'}))
            result = ns(relay, ['python3','-c',client_code], check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(server.wait(timeout=3), 0)
        finally:
            if server is not None:
                if server.poll() is None: server.kill()
                server.communicate(timeout=3)
            run(['ip','netns','delete',relay], check=False)
            run(['ip','netns','delete',peer], check=False)
            run(['ip','link','delete',left], check=False)
