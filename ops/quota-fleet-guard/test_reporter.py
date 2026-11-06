"""Host evidence regressions: unknown reads, stale snapshots and TLS identity."""
import copy
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import reporter
from test_closure_gate import fixture, report


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        (self.root / 'guard.py').write_text('owned fixture guard')
        self.config, self.tokens = fixture()
        self.host = sorted(reporter.HOSTS)[0]
        self.manifest = self.config['hosts'][self.host]['manifest']
        self.body = report(self.config, self.host)
        self.settings = dict(host=self.host, bearer=self.tokens[self.host],
                             coordinator_url='https://api.guardex-vpn.com:44390')

    def execute(self, argv):
        if argv[0] == 'nft':
            value = self.body['nft_document']
        else:
            value = [copy.deepcopy(next(item for item in self.body['containers'] if item['Id'] == argv[2]))]
            value[0]['Config']['Env'] = ['SECRET=never-export']
            value[0]['Config']['Labels']['foreign-private-label'] = 'never-export'
        return types.SimpleNamespace(returncode=0, stdout=json.dumps(value))

    def expiry(self, name='expiry-old', epoch=100):
        root = self.root / name
        root.mkdir(mode=0o700)
        for name, value in [('expiry.json', json.dumps(self.body['expiry'])),
                            ('native-final-private.json', self.body['native_final_file'])]:
            path = root / name
            path.write_text(value)
            path.chmod(0o600)
        os.utime(root, (epoch, epoch))
        return root

    def test_observation_precedes_reads_and_private_environment_is_not_exported(self):
        self.expiry()
        with patch.object(reporter.time, 'time', side_effect=[1000, 1025]):
            body = reporter.collect(self.manifest, self.root, self.host, 1, self.execute)
        self.assertEqual((1000, 1025), (body['observed_epoch'], body['collected_epoch']))
        self.assertEqual(4, len(body['containers']))
        self.assertNotIn('never-export', json.dumps(body))
        self.assertEqual(self.body['native_final_file'], body['native_final_file'])

    def test_timeout_or_missing_binary_reports_unknown_and_continues_other_reads(self):
        for failure in (subprocess.TimeoutExpired('nft', 6), FileNotFoundError('docker')):
            calls = []
            def execute(argv):
                calls.append(argv)
                if len(calls) <= 2:
                    raise failure
                return self.execute(argv)
            body = reporter.collect(self.manifest, self.root, self.host, 1, execute)
            self.assertEqual(5, len(calls))
            self.assertIsNone(body['nft_document'])
            self.assertIsNone(body['containers'][0]['State']['Running'])
            self.assertEqual(3, sum(x['State']['Running'] is False for x in body['containers']))

    def test_new_unfinished_attempt_never_reuses_old_good_counters(self):
        self.expiry()
        root = self.root / 'expiry-new'
        root.mkdir(mode=0o700)
        os.utime(root, (200, 200))
        body = reporter.collect(self.manifest, self.root, self.host, 1, self.execute)
        self.assertEqual({}, body['expiry'])
        self.assertIsNone(body['native_final_file'])

    def test_nonprivate_attempt_does_not_resurrect_older_success(self):
        self.expiry()
        root = self.root / 'expiry-new'
        root.mkdir(mode=0o755)
        body = reporter.collect(self.manifest, self.root, self.host, 1, self.execute)
        self.assertEqual({}, body['expiry'])
        self.assertIsNone(body['native_final_file'])

    def test_malformed_expiry_and_runtime_are_unknown(self):
        root = self.expiry()
        (root / 'expiry.json').write_text('[]')
        def execute(argv):
            return types.SimpleNamespace(returncode=0, stdout='[null]') if argv[0] == 'docker' else self.execute(argv)
        body = reporter.collect(self.manifest, self.root, self.host, 1, execute)
        self.assertEqual({}, body['expiry'])
        self.assertTrue(all(x['State']['Running'] is None for x in body['containers']))

    def test_sequence_survives_restart_and_stranded_temporary_file(self):
        (self.root / 'report-sequence.tmp').write_text('old interrupted writer')
        self.assertEqual(1, reporter.next_sequence(self.root))
        self.assertEqual(2, reporter.next_sequence(self.root))
        self.assertEqual(0o600, (self.root / 'report-sequence.json').stat().st_mode & 0o777)
        self.assertEqual('old interrupted writer', (self.root / 'report-sequence.tmp').read_text())
        (self.root / 'report-sequence.json').write_text('{"sequence":true}')
        with self.assertRaises(ValueError): reporter.next_sequence(self.root)

    def test_nonexact_origins_and_foreign_hosts_are_rejected(self):
        urls = ['http://api.guardex-vpn.com:44390', 'https://example.com:44390',
                'https://api.guardex-vpn.com:443', 'https://api.guardex-vpn.com:44390/path',
                'https://api.guardex-vpn.com:44390?query', 'https://user@api.guardex-vpn.com:44390']
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                reporter.validate_settings(dict(self.settings, coordinator_url=url))
        for settings in (dict(self.settings, host='127.0.0.1'), dict(self.settings, bearer='short')):
            with self.assertRaises(ValueError): reporter.validate_settings(settings)

    def test_connection_pins_primary_and_keeps_certificate_hostname_verification(self):
        context = ssl.create_default_context()
        wrapped = Mock()
        with patch.object(context, 'wrap_socket', return_value=wrapped) as wrap:
            connection = reporter.PinnedHTTPSConnection(reporter.DOMAIN, 44390, timeout=3,
                          context=context, source_address=(self.host, 0))
            with patch.object(reporter.socket, 'create_connection') as connect:
                connection.connect()
                connect.assert_called_once_with((reporter.PRIMARY, 44390), 3, source_address=(self.host, 0))
                wrap.assert_called_once_with(connect.return_value, server_hostname=reporter.DOMAIN)
            self.assertIs(connection.sock, wrapped)
        insecure = ssl._create_unverified_context()
        connection = reporter.PinnedHTTPSConnection(reporter.DOMAIN, 44390, context=insecure)
        with patch.object(reporter.socket, 'create_connection') as connect:
            with self.assertRaises(ValueError): connection.connect()
            connect.assert_not_called()

    def test_send_requires_durable_acceptance_and_no_mutation_authority(self):
        for status, value in [(503, {}), (200, []), (200, {'status': []}),
                              (200, {'status': {'rollback_authorized': True, 'ingress_open_authorized': False}})]:
            connection = Mock()
            connection.getresponse.return_value.status = status
            connection.getresponse.return_value.read.return_value = json.dumps(value).encode()
            with patch.object(reporter, 'PinnedHTTPSConnection', return_value=connection):
                with self.assertRaises((OSError, ValueError)):
                    reporter.send(self.settings, self.body)
                connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
