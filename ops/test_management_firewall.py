"""Exercise management rules without touching the host firewall."""
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
            for command in ("iptables", "ip6tables"):
                mock = path / command
                mock.write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$RULE_LOG"\n')
                mock.chmod(0o755)
            env = {k: v for k, v in os.environ.items()
                   if k not in ("CONTROLLER_ORIGIN_IP", "AGENT_PORT")}
            env.update(PATH=f"{path}:{env['PATH']}", RULE_LOG=str(log))
            env.update(overrides)
            result = subprocess.run(
                ["sh", str(ROOT / "ops/firewall/guardex-agent-firewall.sh")],
                env=env, capture_output=True, text=True)
            return result, log.read_text() if log.exists() else ""

    def test_default_allows_backend_not_public_proxy(self):
        result, calls = self.run_rules()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-s 193.247.73.15 --dport 8099 -j ACCEPT', calls)
        self.assertNotIn('80.241.216.139', calls)
        self.assertIn('iptables -w 5 -A GUARDEX_AGENT -p tcp --dport 8099 -j DROP', calls)
        self.assertIn('ip6tables -w 5 -A GUARDEX_AGENT -p tcp --dport 8099 -j DROP', calls)
        self.assertNotIn('ip6tables -w 5 -A GUARDEX_AGENT -j ACCEPT', calls)

    def test_explicit_controller_and_port(self):
        result, calls = self.run_rules(CONTROLLER_ORIGIN_IP='192.0.2.15', AGENT_PORT='8100')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-s 192.0.2.15 --dport 8100 -j ACCEPT', calls)
        self.assertNotIn('193.247.73.15', calls)

    def test_invalid_config_changes_no_rules(self):
        for override in ({'CONTROLLER_ORIGIN_IP': '0.0.0.0/0'},
                         {'CONTROLLER_ORIGIN_IP': '999.1.1.1'},
                         {'AGENT_PORT': '0'}, {'AGENT_PORT': '65536'}):
            with self.subTest(override=override):
                result, calls = self.run_rules(**override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(calls, '')

    def test_installer_default_matches_firewall(self):
        expected = 'CONTROLLER_ORIGIN_IP="${CONTROLLER_ORIGIN_IP:-193.247.73.15}"'
        for name in ('install.sh', 'ops/firewall/guardex-agent-firewall.sh'):
            self.assertIn(expected, (ROOT / name).read_text())


if __name__ == '__main__':
    unittest.main()
