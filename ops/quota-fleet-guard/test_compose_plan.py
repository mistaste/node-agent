"""Inert plan regressions for retained service policy and scoped quota mounts."""
import copy
import unittest

import compose_plan as plan

SCOPE = 'ae41b7ca-5ebe-47e8-9e91-44da568651eb'
BASE = '/var/lib/guardex-quota-fleet/' + SCOPE
IMAGE = 'sha256:' + 'e' * 64


def fixture():
    effective, actual = {}, {}
    for name in plan.LEGACY_SERVICES:
        volumes = [dict(type='bind', source='/opt/guardex-node/data/' + name, target='/data/native')]
        if name == 'node-agent':
            volumes.append(dict(type='bind', source='/opt/guardex-node', target='/opt/guardex-node', read_only=True))
        effective[name] = dict(build='.', network_mode='host', read_only=True,
                               environment={'COMPOSE_FILE': 'current-rendered-value'}, volumes=volumes,
                               cap_drop=['ALL'], cap_add=['NET_BIND_SERVICE'],
                               security_opt=['no-new-privileges:true'],
                               tmpfs=['/tmp:size=16m,mode=1777'], cpus=.35)
        actual[name] = dict(Config=dict(Cmd=[name], Entrypoint=None, User='', WorkingDir='',
            Env=['COMPOSE_FILE=retained-live-value', 'CONTROLLER_URL=https://api.guardex-vpn.com',
                 'AGENT_SECRET=fixture-only-secret', 'INTERNAL_SERVICE_TOKEN=fixture-only-token'],
            Labels={'com.docker.compose.project': 'guardex-node', 'com.docker.compose.service': name}),
            HostConfig=dict(NetworkMode='host', ReadonlyRootfs=True, Privileged=False,
                            CapDrop=['ALL'], CapAdd=['NET_BIND_SERVICE']),
            Mounts=[dict(Type='bind', Source=v['source'], Destination=v['target'],
                         RW=not v.get('read_only', False)) for v in volumes])
    return effective, actual


class ComposePlanTests(unittest.TestCase):
    def render(self, effective=None, actual=None, **kwargs):
        a, b = fixture()
        return plan.render(SCOPE, IMAGE, 'a'*40, BASE+'/source', BASE+'/quota',
                           effective or a, actual or b, **kwargs)

    def test_retains_live_env_command_security_and_overrides(self):
        effective, actual = fixture()
        frozen = copy.deepcopy((effective, actual))
        result = self.render(effective, actual)
        self.assertEqual(frozen, (effective, actual))
        self.assertEqual(set(plan.LEGACY_SERVICES) | {'quota-broker'}, set(result['services']))
        for name in plan.LEGACY_SERVICES:
            item = result['services'][name]
            self.assertEqual('retained-live-value', item['environment']['COMPOSE_FILE'])
            self.assertEqual([name], item['command'])
            self.assertEqual([], item['entrypoint'])
            self.assertEqual(effective[name]['tmpfs'], item['tmpfs'])
            self.assertEqual(effective[name]['security_opt'], item['security_opt'])
            self.assertEqual(effective[name]['cap_add'], item['cap_add'])
            self.assertEqual(IMAGE, item['image'])
            self.assertEqual('no', item['restart'])
            self.assertNotIn('build', item)

    def test_pins_frozen_source_and_one_shared_owned_quota_directory(self):
        result = self.render()['services']
        agent = result['node-agent']
        self.assertEqual(BASE+'/source', next(v['source'] for v in agent['volumes'] if v['target']=='/opt/guardex-node'))
        self.assertEqual('a'*40, agent['environment']['AGENT_VERSION'])
        self.assertEqual('true', agent['environment']['GUARDEX_HARD_QUOTA_REQUIRED'])
        for name in ('trusttunnel-runner', 'transport-bundle-runner', 'quota-broker'):
            volume = next(v for v in result[name]['volumes'] if v['target']=='/run/guardex-quota')
            self.assertEqual(BASE+'/quota', volume['source'])
            self.assertFalse(volume['bind']['create_host_path'])
        self.assertEqual({'CONTROLLER_URL', 'AGENT_SECRET', 'INTERNAL_SERVICE_TOKEN', 'GUARDEX_HARD_QUOTA_SOCKET'},
                         set(result['quota-broker']['environment']))

    def test_rejects_foreign_runtime_mount_or_capability_drift(self):
        for change in ('project', 'service', 'mount', 'caps', 'readonly', 'network'):
            effective, actual = fixture(); item = actual['node-agent']
            if change == 'project': item['Config']['Labels']['com.docker.compose.project'] = 'foreign'
            elif change == 'service': item['Config']['Labels']['com.docker.compose.service'] = 'foreign'
            elif change == 'mount': item['Mounts'][0]['Source'] = '/foreign'
            elif change == 'caps': item['HostConfig']['CapAdd'].append('SYS_ADMIN')
            elif change == 'readonly': item['HostConfig']['ReadonlyRootfs'] = False
            else: item['HostConfig']['NetworkMode'] = 'bridge'
            with self.subTest(change=change), self.assertRaises(ValueError): self.render(effective, actual)

    def test_rejects_external_paths_floating_images_and_ambiguous_credentials(self):
        effective, actual = fixture()
        with self.assertRaises(ValueError):
            plan.render(SCOPE, IMAGE, 'a'*40, '/opt/foreign', BASE+'/quota', effective, actual)
        with self.assertRaises(ValueError):
            plan.render(SCOPE, 'latest', 'a'*40, BASE+'/source', BASE+'/quota', effective, actual)
        actual['node-agent']['Config']['Env'].append('AGENT_SECRET=duplicate')
        with self.assertRaises(ValueError): self.render(effective, actual)

    def test_literal_dollars_do_not_expand_host_variables_or_credentials(self):
        effective, actual = fixture()
        actual['node-agent']['Config']['Env'][0] = 'COMPOSE_FILE=literal$HOME/${PRIVATE_VALUE}'
        result = self.render(effective, actual)
        self.assertEqual('literal$$HOME/$${PRIVATE_VALUE}', result['services']['node-agent']['environment']['COMPOSE_FILE'])

    def test_bare_live_variable_remains_unset_in_sanitized_cli_environment(self):
        effective, actual = fixture()
        actual['node-agent']['Config']['Env'].append('UNSET_LIVE_VARIABLE')
        result = self.render(effective, actual)
        self.assertIsNone(result['services']['node-agent']['environment']['UNSET_LIVE_VARIABLE'])
        self.assertEqual({'PATH': '/fixture'}, plan.command_environment(result, {'PATH': '/fixture', 'UNSET_LIVE_VARIABLE': 'foreign'}))


if __name__ == '__main__': unittest.main()
