import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('policy', Path(__file__).with_name('policy.py'))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)

class PolicyTests(unittest.TestCase):
    def test_edge_round_trip_preserves_existing_and_unrelated_changes(self):
        before = 'stream {\n    map $ssl_preread_server_name $guardex_tls_target {\n        default 127.0.0.1:8443;\n    }\n}\n\n'
        after = p.render_edge(before)
        self.assertEqual(p.restore_edge(after), before)
        self.assertEqual(p.restore_edge(after.replace('stream {', 'stream { # unrelated')), before.replace('stream {', 'stream { # unrelated'))
        with self.assertRaises(AssertionError): p.render_edge(after)
        with self.assertRaises(AssertionError): p.restore_edge(after.replace('proxy_protocol off;', 'proxy_protocol on;'))

    def test_only_exact_api_sni_uses_bridge(self):
        config = p.haproxy_config()
        self.assertIn('req.ssl_sni -i gateway.guardex-vpn.com }', config)
        self.assertIn('server original 0.0.0.0:0', config)
        self.assertIn('retries 0', config)
        self.assertNotIn(' ssl ', config)
        self.assertNotIn('send-proxy', config)
        self.assertNotIn('http-request', config)

    def test_selection_is_new_qualified_wg_tcp_only(self):
        config = p.nat_config(['37.230.168.172'])
        self.assertIn('iifname "gxwg0"', config)
        self.assertIn('tcp dport 443 tcp flags & (fin|syn|rst|ack) == syn', config)
        self.assertNotIn('hook output', config)
        self.assertEqual(len(p.rules()), 6)
        self.assertTrue(all('--ctorigdstport' in row for row in p.rules()[:-1]))

    def test_dns_cannot_expand_to_private_or_recursive_targets(self):
        for value in ['127.0.0.1', '10.77.0.18', '82.208.22.95', '94.249.195.63', '193.247.73.15', '::1']:
            with self.assertRaises((AssertionError, ValueError)): p.addresses([value])
        with self.assertRaises(AssertionError): p.addresses([])

if __name__ == '__main__': unittest.main()
