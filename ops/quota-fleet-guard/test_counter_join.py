"""Accounting checks reject missing sources, resets and cross-source conflation."""
import hashlib
import unittest

import counter_join as join

SERVER = '578f0ad0-ac34-4c1c-987a-c6e4bf7554b5'
CLIENT = 'c6b20bec-4106-40c9-b66b-89d9680b2fdf'


def sample(up=5, down=7):
    return dict(username=CLIENT, inbound=up, outbound=down, sessions=0)


def row(source='', up=5, down=7, server=SERVER):
    return dict(server_id=server, client_key_sha256=hashlib.sha256((source + CLIENT).encode()).hexdigest(),
                last_uplink=up, last_downlink=down)


class CounterJoinTests(unittest.TestCase):
    def test_both_sources_join_independently_without_mutation_authority(self):
        result = join.verify(dict(trusttunnel=[sample()], naive=[sample(11, 13)]),
                             SERVER, [row(), row('naive:', 11, 13)])
        self.assertTrue(result['all_source_counters_reconciled'])
        self.assertEqual(2, result['positive_rows'])
        self.assertFalse(result['rollback_authorized'])
        self.assertFalse(result['attribution_and_ledger_reconciled'])

    def test_missing_or_error_source_is_not_an_empty_array(self):
        for value in ({'trusttunnel': []}, {'trusttunnel': [], 'naive': {'status': 404}},
                      {'trusttunnel': [], 'naive': None}):
            with self.subTest(value=value), self.assertRaises(ValueError): join.native_rows(value)

    def test_lagging_greater_and_reset_counters_all_require_exact_reconciliation(self):
        for database in ([row(up=4)], [row(up=50)], [row(up=0, down=0)], []):
            result = join.verify(dict(trusttunnel=[sample()], naive=[]), SERVER, database)
            self.assertFalse(result['all_source_counters_reconciled'])

    def test_zero_reset_is_not_ignored_when_an_older_row_exists(self):
        snapshot = dict(trusttunnel=[sample(0, 0)], naive=[])
        self.assertFalse(join.verify(snapshot, SERVER, [row()])['all_source_counters_reconciled'])
        self.assertTrue(join.verify(snapshot, SERVER, [row(up=0, down=0)])['all_source_counters_reconciled'])
        self.assertTrue(join.verify(snapshot, SERVER, [])['all_source_counters_reconciled'])

    def test_same_client_on_another_server_cannot_satisfy_join(self):
        other = '8776c598-9d00-4691-9f09-00b11e48b8bd'
        result = join.verify(dict(trusttunnel=[sample()], naive=[]), SERVER, [row(server=other)])
        self.assertFalse(result['all_source_counters_reconciled'])

    def test_trusttunnel_aggregation_matches_collector_but_naive_duplicate_rejected(self):
        snapshot = dict(trusttunnel=[sample(), sample(11, 13)], naive=[])
        self.assertTrue(join.verify(snapshot, SERVER, [row(up=16, down=20)])['all_source_counters_reconciled'])
        with self.assertRaises(ValueError): join.native_rows(dict(trusttunnel=[], naive=[sample(), sample()]))

    def test_overflow_boolean_negative_and_ambiguous_source_names_rejected(self):
        for key, value in [('inbound', -1), ('inbound', True), ('outbound', 1 << 63),
                           ('sessions', None), ('username', 'naive:' + CLIENT)]:
            item = sample(); item[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                join.native_rows(dict(trusttunnel=[item], naive=[]))
        with self.assertRaises(ValueError):
            join.native_rows(dict(trusttunnel=[sample(join.MAX_INT64), sample(1)], naive=[]))

    def test_database_duplicate_or_invalid_counter_rejected(self):
        for rows in ([row(), row()], [dict(row(), last_uplink=True)], [dict(row(), client_key_sha256='wrong')]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                join.verify(dict(trusttunnel=[sample()], naive=[]), SERVER, rows)


if __name__ == '__main__': unittest.main()
