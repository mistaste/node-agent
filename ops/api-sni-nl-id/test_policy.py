import unittest
import importlib.util
from pathlib import Path
_spec=importlib.util.spec_from_file_location('policy',Path(__file__).with_name('policy.py'))
policy=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(policy)


class CohortBoundaryTests(unittest.TestCase):
    def test_selection_has_only_two_explicit_sources(self):
        self.assertEqual(('10.77.2.1', '10.77.0.13'), policy.CLIENTS)
        value = policy.nat_config()
        self.assertIn('ip saddr { 10.77.2.1, 10.77.0.13 }', value)
        for broad in ['10.77.0.0/16', '0.0.0.0/0', 'ip6', 'flush', 'delete']:
            self.assertNotIn(broad, value)

    def test_only_original_443_new_syn_is_selected(self):
        value = policy.nat_config()
        for match in ['iifname "gxwg0"', 'ip daddr 193.247.73.15', 'tcp dport 443',
                      'tcp flags & (fin|syn|rst|ack) == syn', 'priority -175',
                      'dnat to 10.77.0.18:19445']:
            self.assertIn(match, value)
        self.assertEqual(1, value.count('dnat to'))
        self.assertNotIn('tcp sport', value)  # Actual ordinary app uses dynamic ports.

    def test_listener_allow_requires_original_dnat_destination(self):
        rules = policy.allowances()
        self.assertEqual(2, len(rules))
        for source, rule in zip(policy.CLIENTS, rules):
            for flag, value in [('-i', 'gxwg0'), ('-s', source), ('-d', '10.77.0.18'),
                                ('--dport', '19445'), ('--ctorigdst', '193.247.73.15'),
                                ('--ctorigdstport', '443'), ('--ctstate', 'NEW,ESTABLISHED')]:
                self.assertEqual(value, rule[rule.index(flag)+1])
        self.assertEqual('DROP', policy.deny_other_listener_inputs()[-1])

    def test_unknown_sni_keeps_original_origin(self):
        config = policy.haproxy_config()
        self.assertIn('req.ssl_sni -i api.guardex-vpn.com api.guardex-vpn.ru', config)
        self.assertIn('default_backend original_origin', config)
        self.assertIn('server primary193 193.247.73.15:443', config)
        self.assertEqual(1, config.count('server qualified82 82.208.22.95:443'))

    def test_tls_is_passed_through_without_proxy_header_injection(self):
        config = policy.haproxy_config()
        for alteration in ['send-proxy', ' ssl ', ' crt ', 'verify none', 'ssl-default']:
            self.assertNotIn(alteration, config)
        self.assertEqual(2, config.count('source 94.249.195.63'))

    def test_proof_only_capacity_is_not_retained(self):
        config = policy.haproxy_config()
        self.assertIn('maxconn 1024', config)
        self.assertIn('timeout connect 4s', config)
        self.assertIn('timeout client 75s', config)
        self.assertIn('timeout server 75s', config)
        self.assertNotIn('timeout client 15s', config)


if __name__ == '__main__':
    unittest.main()
