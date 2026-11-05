import importlib.util
import pathlib
import unittest

path = pathlib.Path(__file__).with_name('audit-udp443-redirect.py')
spec = importlib.util.spec_from_file_location('udp_audit', path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class NativeRedirectAuditTest(unittest.TestCase):
    line = '[0:0] -A PREROUTING -p udp -m comment --comment guardex-tt-h3-mux -j REDIRECT --to-ports 18443'

    @staticmethod
    def rule(handle, match):
        return {'rule': {'handle': handle, 'expr': [match, {'xt': None}, {'counter': {'packets': 0, 'bytes': 0}}, {'xt': None}]}}

    def test_real_mixed_projection_identifies_only_actual_broad_rule(self):
        broad = {'match': {'op': '==', 'left': {'meta': {'key': 'l4proto'}}, 'right': 'udp'}}
        scoped = {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 443}}
        native = {'nftables': [self.rule(7, broad), self.rule(15, scoped)]}
        rows = audit.inspect(native, self.line + '\n' + self.line)
        self.assertEqual([(r['handle'], r['status']) for r in rows],
                         [(7, 'UNSAFE_CATCH_ALL_UDP'), (15, 'SCOPED_TO_UDP443')])

    def test_native_scoped_rule_is_safe_despite_missing_projected_port(self):
        match = {'match': {'op': '==', 'left': {'payload': {'protocol': 'udp', 'field': 'dport'}}, 'right': 443}}
        rows = audit.inspect({'nftables': [self.rule(15, match)]}, self.line)
        self.assertEqual(rows[0]['status'], 'SCOPED_TO_UDP443')

    def test_mismatched_observations_fail_closed(self):
        with self.assertRaisesRegex(ValueError, 'count mismatch'):
            audit.inspect({'nftables': []}, self.line)

    def test_unknown_native_predicate_is_not_safe(self):
        with self.assertRaisesRegex(ValueError, 'UNKNOWN'):
            audit.inspect({'nftables': [self.rule(15, {'xt': None})]}, self.line)


if __name__ == '__main__':
    unittest.main()
