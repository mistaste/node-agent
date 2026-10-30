"""Mock DNS and netfilter; never mutate the test host firewall."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ManagementFirewallTest(unittest.TestCase):
    def run_rules(self, **overrides):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            log = path / "calls"
            for command in ("iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "getent"):
                mock = path / command
                mock.write_text('''#!/bin/sh
name="${0##*/}"
printf '%s %s\\n' "$name" "$*" >> "$RULE_LOG"
case "$name" in
 getent) [ "${DNS_FAIL:-0}" = 0 ] || exit 2; printf '%s\\n' "$DNS_REPLY";;
 *-restore) cat >> "$RULE_LOG"; [ "${RESTORE_FAIL:-0}" = 0 ] || exit 1;;
 *) case " $* " in *" -S "*|*" -C "*) [ "${CHAIN_EXISTS:-1}" = 1 ] || exit 1;; esac;;
esac
''')
                mock.chmod(0o755)
            env = {k: v for k, v in os.environ.items()
                   if k not in ("CONTROLLER_ORIGIN_IP", "CONTROLLER_HOST", "AGENT_PORT")}
            env.update(PATH=f"{path}:{env['PATH']}", RULE_LOG=str(log),
                       GUARDEX_FIREWALL_LOCK=str(path / "lock"),
                       DNS_REPLY="192.0.2.15 STREAM api.guardex-vpn.com")
            env.update(overrides)
            result = subprocess.run(["sh", str(ROOT / "ops/firewall/guardex-agent-firewall.sh")],
                                    env=env, capture_output=True, text=True, timeout=15)
            return result, log.read_text() if log.exists() else ""

    def test_resolves_domain_and_installs_only_exact_source(self):
        result, calls = self.run_rules()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('getent ahostsv4 api.guardex-vpn.com', calls)
        self.assertIn('-s 192.0.2.15 --dport 8099 -j ACCEPT', calls)
        self.assertIn('iptables-restore --wait 5 --noflush', calls)
        self.assertIn('ip6tables-restore --wait 5 --noflush', calls)
        self.assertIn('-p tcp --dport 8099 -j DROP', calls)
        self.assertNotIn('-s 0.0.0.0/0', calls)

    def test_dns_rotation_and_duplicates(self):
        result, calls = self.run_rules(CONTROLLER_HOST='control.example.test', AGENT_PORT='8100',
                                      DNS_REPLY='198.51.100.10 STREAM control.example.test\n198.51.100.10 DGRAM x\n198.51.100.20 STREAM x')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('getent ahostsv4 control.example.test', calls)
        self.assertEqual(calls.count('-s 198.51.100.10 --dport 8100 -j ACCEPT'), 1)
        self.assertIn('-s 198.51.100.20 --dport 8100 -j ACCEPT', calls)
        self.assertNotIn('192.0.2.15', calls)

    def test_dns_failure_preserves_existing_rules(self):
        for override in ({'DNS_FAIL': '1'}, {'DNS_REPLY': ''}, {'DNS_REPLY': '0.0.0.0 STREAM x'}, {'DNS_REPLY': '127.0.0.1 STREAM x'}, {'DNS_REPLY': '::1 STREAM x'}):
            result, calls = self.run_rules(**override)
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn('-restore', calls)
            self.assertNotIn('-F ', calls)
            self.assertNotIn(' ACCEPT', calls)

    def test_missing_rules_fail_closed_when_dns_is_down(self):
        result, calls = self.run_rules(DNS_FAIL='1', CHAIN_EXISTS='0')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls.count('-p tcp --dport 8099 -j DROP'), 2)
        self.assertNotIn(' ACCEPT', calls)
        self.assertIn('-I INPUT 1 -j GUARDEX_AGENT', calls)

    def test_invalid_configuration_and_legacy_ip_make_no_changes(self):
        for override in ({'CONTROLLER_HOST': '192.0.2.15'}, {'CONTROLLER_HOST': 'https://api.guardex-vpn.com'},
                         {'CONTROLLER_HOST': 'bad;name.example'}, {'CONTROLLER_ORIGIN_IP': '80.241.216.139'},
                         {'AGENT_PORT': '0'}, {'AGENT_PORT': '65536'}):
            result, calls = self.run_rules(**override)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls, '')

    def test_restore_failure_does_not_flush_individual_rules(self):
        result, calls = self.run_rules(RESTORE_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('iptables -w 5 -F', calls)
        self.assertNotIn('iptables-restore', calls.replace('ip6tables-restore', ''))

    def test_install_and_compose_have_no_endpoint_ip_pins(self):
        install = (ROOT / 'install.sh').read_text()
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertIn('CONTROLLER_HOST="${CONTROLLER_HOST:-api.guardex-vpn.com}"', install)
        self.assertIn('guardex-agent-firewall.timer', install)
        self.assertNotIn('extra_hosts:', compose)
        self.assertNotIn('CONTROLLER_ORIGIN_IP', compose)
        for file in ('install.sh', 'ops/firewall/guardex-agent-firewall.sh'):
            text = (ROOT / file).read_text()
            for address in ('80.241.216.139', '193.247.73.15', '82.208.22.95'):
                self.assertNotIn(address, text)
        unit = (ROOT / 'ops/systemd/guardex-agent-firewall.service').read_text()
        self.assertIn('After=network-online.target', unit)
        self.assertNotIn('RemainAfterExit=yes', unit)
        self.assertIn('OnUnitInactiveSec=5min', (ROOT / 'ops/systemd/guardex-agent-firewall.timer').read_text())

if __name__ == '__main__':
    unittest.main()
