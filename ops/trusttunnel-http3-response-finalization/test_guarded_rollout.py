import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rollout', ROOT/'guarded_rollout.py')
rollout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rollout)


class RuntimeFingerprintTest(unittest.TestCase):
    def setUp(self):
        self.namespace = {'REMOTE': '/tmp/guardex-test', 'OVERRIDE': '/opt/guardex-node/docker-compose.http3-rollout-fixture.yml',
                          'PIN': {'runtime': {'container': {'name': 'fixture'}}}}
        exec(rollout.PROGRAM.split('assert os.geteuid()==0')[0], self.namespace)
        self.context = {'default_hostname': True, 'hostname_sha256': '',
                        'compose_files': ['/base.yml'], 'old_overlay_marker': None}
        self.before = {
            'Id': 'a'*64,
            'Config': {'Hostname': 'a'*12, 'Image': 'old-tag', 'Env': ['FIXTURE=one'],
                       'Cmd': ['runner'], 'Entrypoint': ['/entry'], 'User': '65532',
                       'WorkingDir': '/work', 'Healthcheck': {'Test': ['CMD', 'health']},
                       'Labels': {'com.docker.compose.project.config_files': '/base.yml',
                                  'com.docker.compose.config-hash': 'old',
                                  'com.docker.compose.image': 'oldimage', 'owned': 'unchanged'}},
            'HostConfig': {'NetworkMode': 'host', 'Privileged': False,
                           'NanoCpus': 350000000, 'DnsOptions': None, 'DnsSearch': None,
                           'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '10m'}}},
            'Mounts': [{'Type': 'bind', 'Source': '/data', 'Destination': '/data',
                        'RW': True, 'Propagation': 'rprivate'}],
        }
        self.after = copy.deepcopy(self.before)
        self.after['Id'] = 'b'*64
        self.after['Config'].update(Hostname='b'*12, Image='reviewed-overlay')
        self.after['Config']['Labels'].update({
            'com.docker.compose.project.config_files': '/base.yml,'+'/opt/guardex-node/docker-compose.http3-rollout-fixture.yml',
            'com.docker.compose.config-hash': 'new', 'com.docker.compose.image': 'newimage',
            'org.guardex.http3-response-finalization': '1'})

    def fp(self, value, phase):
        return self.namespace['normalize'](value, self.context, phase)

    def test_exact_owned_image_hostname_compose_metadata_transition_allowed(self):
        self.assertEqual(self.fp(self.before, 'before'), self.fp(self.after, 'new'))

    def test_every_required_config_field_and_extra_labels_are_preserved(self):
        for key in ['Env', 'Cmd', 'Entrypoint', 'User', 'WorkingDir', 'Healthcheck']:
            changed = copy.deepcopy(self.after)
            changed['Config'][key] = ['FIXTURE=changed'] if key == 'Env' else {'unexpected': True}
            self.assertNotEqual(self.fp(self.before, 'before'), self.fp(changed, 'new'), key)
        changed = copy.deepcopy(self.after)
        changed['Config']['Labels']['owned'] = 'different'
        self.assertNotEqual(self.fp(self.before, 'before'), self.fp(changed, 'new'))

    def test_complete_hostconfig_and_mount_records_are_preserved(self):
        for key, value in [('Privileged', True), ('UnexpectedSetting', 'added'),
                           ('NanoCpus', 750000000), ('DnsOptions', []), ('DnsSearch', [])]:
            changed = copy.deepcopy(self.after)
            changed['HostConfig'][key] = value
            self.assertNotEqual(self.fp(self.before, 'before'), self.fp(changed, 'new'))
        changed = copy.deepcopy(self.after)
        changed['Mounts'][0]['Propagation'] = 'shared'
        self.assertNotEqual(self.fp(self.before, 'before'), self.fp(changed, 'new'))

    def test_other_compose_files_or_overlay_marker_rejected(self):
        changed = copy.deepcopy(self.after)
        changed['Config']['Labels']['com.docker.compose.project.config_files'] = '/other.yml,'+'/opt/guardex-node/docker-compose.http3-rollout-fixture.yml'
        with self.assertRaisesRegex(AssertionError, 'compose file list'):
            self.fp(changed, 'new')
        changed = copy.deepcopy(self.after)
        changed['Config']['Labels']['org.guardex.http3-response-finalization'] = 'unknown'
        with self.assertRaisesRegex(AssertionError, 'overlay label'):
            self.fp(changed, 'new')


class LosslessEnvTest(RuntimeFingerprintTest):
    def setUp(self):
        super().setUp()
        self.context['normalization_version'] = 2
        self.before['Config']['Env'] = ['A=one=two ', 'EMPTY=', 'SPACE= untouched ']
        self.after['Config']['Env'] = list(reversed(self.before['Config']['Env']))

    def test_permutation_matches_with_every_value_byte_preserved(self):
        self.assertEqual(self.fp(self.before, 'before'), self.fp(self.after, 'new'))
        result = self.namespace['canonical_env'](self.before['Config']['Env'])
        self.assertEqual(result, {'A': 'one=two ', 'EMPTY': '', 'SPACE': ' untouched '})

    def test_changed_missing_extra_values_or_keys_fail(self):
        for values in [['A=changed', 'EMPTY=', 'SPACE= untouched '],
                       ['A=one=two ', 'SPACE= untouched '],
                       ['A=one=two ', 'EMPTY=', 'SPACE= untouched ', 'EXTRA=value'],
                       ['OTHER=one=two ', 'EMPTY=', 'SPACE= untouched '],
                       ['A=one=two', 'EMPTY=', 'SPACE= untouched ']]:
            changed = copy.deepcopy(self.after)
            changed['Config']['Env'] = values
            self.assertNotEqual(self.fp(self.before, 'before'), self.fp(changed, 'new'))

    def test_duplicate_keys_and_malformed_entries_rejected(self):
        for values in [['A=one', 'A=one'], ['A=one', 'A=two'], ['NO_SEPARATOR'],
                       ['=empty_key'], [None], ['A=value\x00suffix']]:
            with self.assertRaises(AssertionError):
                self.namespace['canonical_env'](values)

    def test_v1_journal_keeps_ordered_representation(self):
        original_context = dict(self.context)
        del original_context['normalization_version']
        normalize = self.namespace['normalize']
        self.assertNotEqual(normalize(self.before, original_context, 'before'),
                            normalize(self.after, original_context, 'new'))


class ExactDnsInputTest(unittest.TestCase):
    def setUp(self):
        namespace = {'REMOTE': '/tmp/guardex-test', 'OVERRIDE': '/opt/guardex-node/docker-compose.http3-rollout-fixture.yml',
                     'PIN': {'runtime': {'container': {'name': 'fixture'}}}}
        exec(rollout.PROGRAM.split('assert os.geteuid()==0')[0], namespace)
        self.preserve = namespace['preserve_explicit_empty_dns']
        self.text = 'services:\n  trusttunnel-runner:\n    image: owned-pinned\n'

    def test_only_original_exact_empty_lists_get_explicit_owned_input(self):
        value = {'HostConfig': {'DnsOptions': [], 'DnsSearch': []}}
        self.assertEqual(self.preserve(value, self.text),
                         self.text + '    dns_opt: []\n    dns_search: []\n')
        self.assertEqual(value, {'HostConfig': {'DnsOptions': [], 'DnsSearch': []}})
        self.assertEqual(self.preserve({'HostConfig': {'DnsOptions': [], 'DnsSearch': None}}, self.text),
                         self.text + '    dns_opt: []\n')

    def test_null_and_nonempty_original_values_are_not_rewritten(self):
        for values in [(None, None), (['timeout:3'], ['guardex.invalid']),
                       (None, ['guardex.invalid']), (['attempts:2'], None)]:
            original = {'HostConfig': dict(zip(['DnsOptions', 'DnsSearch'], values))}
            snapshot = copy.deepcopy(original)
            self.assertEqual(self.preserve(original, self.text), self.text)
            self.assertEqual(original, snapshot)

    def test_missing_or_malformed_dns_fields_rejected(self):
        for value in [{'HostConfig': {'DnsOptions': []}},
                      {'HostConfig': {'DnsOptions': 'timeout:3', 'DnsSearch': []}},
                      {'HostConfig': {'DnsOptions': [None], 'DnsSearch': []}},
                      {'HostConfig': {'DnsOptions': [], 'DnsSearch': ['invalid\x00suffix']}}]:
            with self.assertRaises(AssertionError):
                self.preserve(value, self.text)


class ExactCpuInputTest(unittest.TestCase):
    def setUp(self):
        self.namespace = {'REMOTE': '/tmp/guardex-test',
                          'OVERRIDE': '/opt/guardex-node/docker-compose.http3-rollout-fixture.yml',
                          'PIN': {'runtime': {'container': {'name': 'fixture'}}}}
        exec(rollout.PROGRAM.split('assert os.geteuid()==0')[0], self.namespace)
        self.value = {'HostConfig': {'NanoCpus': 750000000, 'DnsOptions': None, 'DnsSearch': None}}
        self.text = 'services:\n  trusttunnel-runner:\n    image: owned-image\n'

    def test_exact_decimal_never_rounds_through_float(self):
        for value, expected in [(0, '0'), (350000000, '0.35'), (750000000, '0.75'),
                                (1000000001, '1.000000001')]:
            self.value['HostConfig']['NanoCpus'] = value
            self.assertEqual(self.namespace['exact_cpu'](self.value), expected)

    def test_owned_override_preserves_original_cpu_and_optional_deploy_limit(self):
        snapshot = copy.deepcopy(self.value)
        self.assertEqual(self.namespace['preserve_runtime_inputs'](self.value, self.text),
                         self.text + '    cpus: "0.75"\n')
        self.assertEqual(self.namespace['preserve_runtime_inputs'](self.value, self.text, True),
                         self.text + '    cpus: "0.75"\n' +
                         '    deploy:\n      resources:\n        limits:\n          cpus: "0.75"\n')
        self.assertEqual(self.value, snapshot)

    def test_dns_empty_fields_and_cpu_are_both_preserved(self):
        self.value['HostConfig'].update(DnsOptions=[], DnsSearch=[])
        self.assertEqual(self.namespace['preserve_runtime_inputs'](self.value, self.text),
                         self.text + '    dns_opt: []\n    dns_search: []\n    cpus: "0.75"\n')

    def test_malformed_cpu_constraint_is_rejected(self):
        for value in [-1, 0.75, None, '750000000', True]:
            self.value['HostConfig']['NanoCpus'] = value
            with self.assertRaises(AssertionError):
                self.namespace['preserve_runtime_inputs'](self.value, self.text)


class RolloutPlanCliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        binary = root / 'endpoint'
        binary.write_bytes(b'owned fixture')
        self.receipt = root / 'receipt.json'
        self.receipt.write_text(json.dumps({'build_exit': 0,
            'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}))
        self.pins = root / 'pins.json'
        self.pin = {'node': {'code': 'FIXTURE', 'host': '192.0.2.1'},
                    'runtime': {'container': {'name': 'guardex-node-trusttunnel-runner-1',
                                             'image_id': 'sha256:' + 'a' * 64},
                                'endpoint': {'file_sha256': 'b' * 64},
                                'compose_labels': {'com.docker.compose.project': 'guardex-node',
                                    'com.docker.compose.project.config_files': '/opt/guardex-node/base.yml'},
                                'compose_files': [{'path': '/opt/guardex-node/base.yml', 'sha256': 'c' * 64}],
                                'baseline_inputs': [{'matches_baseline': True, 'expected_sha256': 'd' * 64,
                                    'present_candidates': [{'path': '/opt/guardex-node/input-' + str(index)}]}
                                    for index in range(7)]},
                    'account_qos': {'endpoint_processes': [{'account_qos_socket_env': []}]}}
        self.pins.write_text(json.dumps({'nodes': {'FIXTURE': self.pin}}))
        self.args = [sys.executable, str(ROOT / 'guarded_rollout.py'), '--node', 'FIXTURE',
                     '--pins', str(self.pins), '--binary', str(binary),
                     '--receipt', str(self.receipt), '--operation', 'owned-fixture', '--mode', 'plan']

    def run_cli(self, extra=()):
        return subprocess.run(self.args + list(extra), text=True, capture_output=True, timeout=5)

    def test_plan_derives_only_the_owned_paths_without_remote_execution(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertFalse(plan['mutations'])
        self.assertEqual(plan['only_service'], 'trusttunnel-runner')
        self.assertEqual(plan['unique_override'],
                         '/opt/guardex-node/docker-compose.http3-rollout-owned-fixture.yml')

    def test_path_traversal_operation_and_reuse_outside_apply_are_rejected(self):
        for extra in [('--operation', '../../outside'), ('--reuse-uploaded',)]:
            self.assertNotEqual(self.run_cli(extra).returncode, 0)

    def test_bad_build_receipt_prevents_even_a_plan(self):
        self.receipt.write_text(json.dumps({'build_exit': 0, 'binary_sha256': 'tampered'}))
        self.assertNotEqual(self.run_cli().returncode, 0)

    def test_inventory_host_cannot_be_a_shell_expression(self):
        pins = json.loads(self.pins.read_text())
        pins['nodes']['FIXTURE']['node']['host'] = '192.0.2.1; unexpected'
        self.pins.write_text(json.dumps(pins))
        self.assertNotEqual(self.run_cli().returncode, 0)

    def test_missing_source_or_compose_pins_are_rejected_before_remote_work(self):
        for field in ['baseline_inputs', 'compose_files']:
            changed = copy.deepcopy(self.pin)
            changed['runtime'][field].pop()
            self.pins.write_text(json.dumps({'nodes': {'FIXTURE': changed}}))
            self.assertNotEqual(self.run_cli().returncode, 0)


if __name__ == '__main__':
    unittest.main()
