"""Consensus, replay and accounting-evidence failure regressions; no OS mutations."""
import copy
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import closure_gate as gate
import guard

SCOPE = 'ae41b7ca-5ebe-47e8-9e91-44da568651eb'
NOW = 1000
DOCUMENT = json.loads(Path(__file__).with_name('test_nft_fixture.json').read_text())


def fixture():
    config = dict(scope=SCOPE, image='sha256:' + 'e' * 64, guard_source_sha256='a' * 64,
                  created_epoch=900, deadline_epoch=1800, hosts={})
    tokens = {}
    for host in sorted(gate.HOSTS):
        token = hashlib.sha256(('own-fixture-token-' + host).encode()).hexdigest()
        tokens[host] = token
        ids = {service: hashlib.sha256((host + service).encode()).hexdigest() for service in guard.SERVICES}
        config['hosts'][host] = dict(bearer_sha256=hashlib.sha256(token.encode()).hexdigest(),
                                    manifest=dict(schema=1, scope=SCOPE, image=config['image'],
                                                  project='guardex-qf-' + SCOPE, deadline_epoch=1800,
                                                  ingress_ports=[443, 18443, 19080, 19443], containers=ids))
    return config, tokens


def report(config, host, sequence=1, observed=NOW):
    manifest = config['hosts'][host]['manifest']
    containers = []
    for service, cid in manifest['containers'].items():
        containers.append(dict(Id=cid, Image=config['image'], State=dict(Running=False, Pid=0),
                               Config=dict(Labels={'guardex.quota.rollout.scope': SCOPE,
                                                   'com.docker.compose.project': manifest['project'],
                                                   'com.docker.compose.service': service})))
    native = json.dumps(dict(trusttunnel=[], naive=[]))
    expiry = dict(scope=SCOPE, deadline_epoch=1800, barrier_closed_epoch=observed - 40,
                  ended_epoch=observed - 5, native_stable_30s=True, errors=[],
                  native_final_SHA256=hashlib.sha256(native.encode()).hexdigest(),
                  global_flags_changed=False, legacy_ingress_restored=False,
                  stopped=[dict(service=name, id=cid, PID=0) for name, cid in manifest['containers'].items()])
    return dict(scope=SCOPE, host=host, guard_source_sha256=config['guard_source_sha256'],
                sequence=sequence, observed_epoch=observed, nft_document=copy.deepcopy(DOCUMENT),
                containers=containers, native_final_file=native, expiry=expiry)


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.config, self.tokens = fixture()
        self.stored = []
        self.gate = gate.ClosureGate(self.config, lambda receipt, body: self.stored.append((receipt, body)))
        self.host = sorted(gate.HOSTS)[0]

    def submit(self, host=None, **kwargs):
        host = self.host if host is None else host
        body = kwargs.pop('body', report(self.config, host))
        return self.gate.submit(host, self.tokens[host], body, **kwargs)

    def all_closed(self):
        for host in gate.HOSTS:
            self.submit(host, now=NOW)

    def test_all_six_required_and_never_grants_flag_or_open_authority(self):
        for host in sorted(gate.HOSTS)[:-1]:
            self.submit(host, now=NOW)
        self.assertFalse(self.gate.status(NOW)['all_inventoried_hosts_closed'])
        self.submit(sorted(gate.HOSTS)[-1], now=NOW)
        status = self.gate.status(NOW)
        self.assertTrue(status['all_inventoried_hosts_closed'])
        self.assertTrue(status['all_native_snapshot_files_retained'])
        self.assertFalse(status['rollback_authorized'])
        self.assertFalse(status['ingress_open_authorized'])

    def test_replay_cannot_refresh_liveness(self):
        self.all_closed()
        result = self.submit(now=NOW + 31)
        self.assertTrue(result['duplicate'])
        self.assertFalse(self.gate.status(NOW + 31)['all_inventoried_hosts_closed'])
        self.assertEqual(6, len(self.stored))

    def test_new_running_engine_immediately_revokes_closed_consensus(self):
        self.all_closed()
        body = report(self.config, self.host, sequence=2, observed=NOW + 1)
        body['containers'][0]['State'] = dict(Running=True, Pid=4000)
        self.submit(body=body, now=NOW + 1)
        self.assertFalse(self.gate.status(NOW + 1)['all_inventoried_hosts_closed'])
        self.assertFalse(self.gate.status(NOW + 1)['all_native_snapshot_files_retained'])

    def test_unknown_host_wrong_host_bearer_and_unknown_scope_are_rejected(self):
        with self.assertRaises(gate.Rejected):
            self.gate.submit('203.0.113.44', self.tokens[self.host], report(self.config, self.host), NOW)
        other = sorted(gate.HOSTS)[-1]
        with self.assertRaises(gate.Rejected):
            self.gate.submit(self.host, self.tokens[other], report(self.config, self.host), NOW)
        body = report(self.config, self.host); body['scope'] = 'old-scope'
        with self.assertRaises(gate.Rejected): self.submit(body=body, now=NOW)
        self.assertEqual({}, self.gate.reports)

    def test_out_of_order_and_changed_same_sequence_rejected(self):
        self.submit(body=report(self.config, self.host, sequence=3), now=NOW)
        with self.assertRaises(gate.Rejected): self.submit(now=NOW)
        body = report(self.config, self.host, sequence=3, observed=NOW + 1)
        with self.assertRaises(gate.Rejected): self.submit(body=body, now=NOW + 1)

    def test_stale_future_and_nan_observations_rejected(self):
        for observed in (NOW - 31, NOW + 3, float('nan'), float('inf')):
            with self.subTest(observed=observed), self.assertRaises(gate.Rejected):
                self.submit(body=report(self.config, self.host, observed=observed), now=NOW)

    def test_old_scope_counter_or_changed_snapshot_never_qualifies_accounting(self):
        for change in ('scope', 'hash', 'deadline', 'dwell', 'ids'):
            with self.subTest(change=change):
                config, tokens = fixture()
                current = gate.ClosureGate(config, lambda *_: None)
                body = report(config, self.host)
                if change == 'scope': body['expiry']['scope'] = 'old-scope'
                elif change == 'hash': body['native_final_file'] = '{}'
                elif change == 'deadline': body['expiry']['deadline_epoch'] += 1
                elif change == 'dwell': body['expiry']['barrier_closed_epoch'] = NOW - 6
                else: body['expiry']['stopped'][0]['id'] = 'f' * 64
                current.submit(self.host, tokens[self.host], body, NOW)
                self.assertFalse(current.reports[self.host]['native_snapshot_retained'])

    def test_disk_failure_revokes_previous_positive_and_does_not_publish_new_one(self):
        self.all_closed()
        with patch.object(self.gate, 'persist', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.submit(body=report(self.config, self.host, sequence=2, observed=NOW + 1), now=NOW + 1)
        self.assertNotIn(self.host, self.gate.reports)
        self.assertFalse(self.gate.status(NOW + 1)['all_inventoried_hosts_closed'])

    def test_changed_or_duplicate_runtime_and_weakened_nft_never_count_closed(self):
        for change in ('image', 'PID', 'duplicate', 'nft'):
            with self.subTest(change=change):
                config, tokens = fixture(); current = gate.ClosureGate(config, lambda *_: None)
                body = report(config, self.host)
                if change == 'image': body['containers'][0]['Image'] = 'sha256:' + 'b' * 64
                elif change == 'PID': body['containers'][0]['State']['Pid'] = 99
                elif change == 'duplicate': body['containers'][0] = copy.deepcopy(body['containers'][1])
                else:
                    rule = next(x['rule'] for x in body['nft_document']['nftables'] if 'rule' in x)
                    rule['expr'][-1] = {'accept': None}
                current.submit(self.host, tokens[self.host], body, NOW)
                self.assertFalse(current.reports[self.host]['inventoried_ingress_closed'])

    def test_invalid_fleet_inventory_and_shared_tokens_rejected(self):
        for change in ('host', 'token', 'ids', 'deadline'):
            config, _ = fixture(); hosts = sorted(gate.HOSTS)
            if change == 'host': config['hosts'].pop(hosts[0])
            elif change == 'token': config['hosts'][hosts[0]]['bearer_sha256'] = config['hosts'][hosts[1]]['bearer_sha256']
            elif change == 'ids': config['hosts'][hosts[0]]['manifest']['containers'] = config['hosts'][hosts[1]]['manifest']['containers']
            else: config['deadline_epoch'] += 1
            with self.subTest(change=change), self.assertRaises(gate.Rejected):
                gate.ClosureGate(config, lambda *_: None)


if __name__ == '__main__':
    unittest.main()
