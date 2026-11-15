import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('rollout', Path(__file__).with_name('rollout.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RuntimePreservationTest(unittest.TestCase):
    def setUp(self):
        self.value = {'Id': 'a' * 64, 'Config': {'Hostname': 'a' * 12, 'Image': 'old',
                      'Env': ['A=1', 'B=2'], 'Cmd': ['trusttunnel-runner'],
                      'Labels': {'com.docker.compose.project.config_files': '/compose.yml',
                                 'com.docker.compose.image': 'old'}},
                      'HostConfig': {'NanoCpus': 500000000, 'Memory': 123,
                                     'CapDrop': ['ALL'], 'ReadonlyRootfs': True},
                      'Mounts': [{'Source': '/private', 'Destination': '/data', 'RW': True}]}
        self.fingerprint = module.fingerprint(self.value, ['/compose.yml'])

    def test_only_image_compose_metadata_and_env_order_may_change(self):
        changed = copy.deepcopy(self.value)
        changed['Id'] = 'b' * 64
        changed['Config'].update(Hostname='b' * 12, Image='new', Env=['B=2', 'A=1'])
        changed['Config']['Labels'].update({'com.docker.compose.project.config_files': '/compose.yml,/owned.yml',
                                          'com.docker.compose.image': 'new'})
        self.assertEqual(self.fingerprint, module.fingerprint(changed, ['/compose.yml']))

    def test_resources_security_environment_and_mount_changes_are_detected(self):
        for section, key, value in [('HostConfig', 'NanoCpus', 1000000000),
                                    ('HostConfig', 'Memory', 999),
                                    ('HostConfig', 'ReadonlyRootfs', False),
                                    ('Config', 'Env', ['A=other', 'B=2']),
                                    ('Config', 'Cmd', ['other'])]:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.value)
                changed[section][key] = value
                self.assertNotEqual(self.fingerprint, module.fingerprint(changed, ['/compose.yml']))
        changed = copy.deepcopy(self.value)
        changed['Mounts'][0]['RW'] = False
        self.assertNotEqual(self.fingerprint, module.fingerprint(changed, ['/compose.yml']))

    def test_duplicate_environment_and_unrelated_compose_are_rejected(self):
        for env, files in [(['A=1', 'A=2'], '/compose.yml'),
                           (['A=1'], '/other.yml')]:
            changed = copy.deepcopy(self.value)
            changed['Config']['Env'] = env
            changed['Config']['Labels']['com.docker.compose.project.config_files'] = files
            with self.assertRaises(AssertionError):
                module.fingerprint(changed, ['/compose.yml'])


if __name__ == '__main__':
    unittest.main()
