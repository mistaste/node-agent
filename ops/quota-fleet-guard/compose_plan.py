"""Render an inert private rollout Compose from each service's effective config.

No Docker invocation or host mutation. Live command/environment overrides are
preserved explicitly; all other effective service fields remain unchanged except
the listed rollout identities, pinned image, bounded restart policy and mounts.
The result must still be compared to actual Docker state by the installer.
"""
import copy
from pathlib import PurePosixPath
import re

import counter_join

LEGACY_SERVICES = ('node-agent', 'trusttunnel-runner', 'transport-bundle-runner')


def literal_compose(value):
    """Escape already-resolved values for Compose's single interpolation pass."""
    if isinstance(value, str):
        return value.replace('$', '$$')
    if isinstance(value, list):
        return [literal_compose(item) for item in value]
    if isinstance(value, dict):
        return {key: literal_compose(item) for key, item in value.items()}
    return value


def environment(container):
    result = {}
    for item in container['Config']['Env']:
        key, separator, value = item.partition('=')
        if not re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', key) or key in result:
            raise ValueError('unique valid live environment required')
        result[key] = value if separator else None
    return result


def command_environment(document, inherited):
    """Bare live entries stay unset instead of importing the CLI host's value."""
    unset = {key for service in document['services'].values()
             for key, value in service.get('environment', {}).items() if value is None}
    return {key: value for key, value in inherited.items() if key not in unset}


def owned_path(path, scope):
    value = PurePosixPath(path)
    base = PurePosixPath('/var/lib/guardex-quota-fleet') / scope
    if not value.is_absolute() or '..' in value.parts or str(value) != path or not value.is_relative_to(base):
        raise ValueError('canonical path inside exact rollout scope required')
    return path


def render(scope, image, source_revision, source_dir, quota_dir, effective, actual, mandatory=True):
    counter_join.canonical_uuid(scope)
    if not re.fullmatch('sha256:[a-f0-9]{64}', image) or not re.fullmatch('[a-f0-9]{40}', source_revision):
        raise ValueError('exact qualified image and source revision required')
    owned_path(source_dir, scope); owned_path(quota_dir, scope)
    if type(mandatory) is not bool or set(effective) != set(LEGACY_SERVICES) or set(actual) != set(LEGACY_SERVICES):
        raise ValueError('all three actual legacy services required')
    project = 'guardex-qf-' + scope
    services = {}
    for name in LEGACY_SERVICES:
        base, live = effective[name], actual[name]
        labels = live['Config'].get('Labels') or {}
        if (labels.get('com.docker.compose.project') != 'guardex-node'
                or labels.get('com.docker.compose.service') != name
                or live['HostConfig']['NetworkMode'] != 'host' or base.get('network_mode') != 'host'):
            raise ValueError('exact legacy service identity and host networking required')
        # Do not silently replace security policy that drifted from the source.
        for key, docker_key in [('read_only', 'ReadonlyRootfs'), ('privileged', 'Privileged')]:
            if base.get(key, False) != live['HostConfig'][docker_key]:
                raise ValueError('live security policy differs from effective Compose')
        if base.get('ports') or base.get('networks') or base.get('devices'):
            raise ValueError('unexpected additional ingress/device mapping requires review')
        expected_binds = sorted((v['source'], v['target'], v.get('read_only', False))
                                for v in base.get('volumes', []) if v['type'] == 'bind')
        actual_binds = sorted((v['Source'], v['Destination'], not v['RW'])
                              for v in live['Mounts'] if v['Type'] == 'bind')
        if expected_binds != actual_binds or any(v['Type'] != 'bind' for v in live['Mounts']):
            raise ValueError('actual mount ownership differs from effective Compose')
        for key, docker_key in [('cap_add', 'CapAdd'), ('cap_drop', 'CapDrop')]:
            normalize = lambda values: sorted(v.removeprefix('CAP_') for v in (values or []))
            if normalize(base.get(key)) != normalize(live['HostConfig'].get(docker_key)):
                raise ValueError('actual capabilities differ from effective Compose')
        item = copy.deepcopy(base)
        for key in ('build', 'pull_policy', 'depends_on', 'profiles', 'container_name', 'env_file'):
            item.pop(key, None)
        item.update(image=image, restart='no', command=copy.deepcopy(live['Config']['Cmd']),
                    entrypoint=copy.deepcopy(live['Config']['Entrypoint'] or []),
                    user=live['Config'].get('User') or '0',
                    working_dir=live['Config'].get('WorkingDir') or '/')
        item['environment'] = environment(live)
        item['labels'] = {key: value for key, value in (item.get('labels') or {}).items()
                          if not key.startswith('com.docker.compose.')}
        item['labels']['guardex.quota.rollout.scope'] = scope
        item['container_name'] = project + '-' + name
        volumes = item.setdefault('volumes', [])
        targets = [volume['target'] for volume in volumes]
        if len(set(targets)) != len(targets):
            raise ValueError('duplicate live mount targets')
        if '/run/guardex-quota' in targets:
            raise ValueError('legacy quota mount needs explicit ownership review')
        if name == 'node-agent':
            checkout = [volume for volume in volumes if volume['target'] == '/opt/guardex-node']
            if len(checkout) != 1 or checkout[0]['type'] != 'bind' or not checkout[0].get('read_only'):
                raise ValueError('one read-only legacy source mount required')
            checkout[0]['source'] = source_dir
            item['environment'].update(AGENT_REPO_DIR='/opt/guardex-node', AGENT_VERSION=source_revision,
                                       GUARDEX_HARD_QUOTA_REQUIRED=str(mandatory).lower(),
                                       GUARDEX_QUOTA_FLEET_MANAGED='true')
        else:
            volumes.append(dict(type='bind', source=quota_dir, target='/run/guardex-quota',
                                bind={'create_host_path': False}))
            item['environment']['GUARDEX_HARD_QUOTA_SOCKET'] = '/run/guardex-quota/broker.sock'
            if name == 'trusttunnel-runner':
                item['environment']['GUARDEX_HARD_QUOTA_REQUIRED'] = str(mandatory).lower()
        services[name] = item
    agent_env = services['node-agent']['environment']
    broker_env = {key: agent_env[key] for key in ('CONTROLLER_URL', 'AGENT_SECRET', 'INTERNAL_SERVICE_TOKEN')}
    if not all(isinstance(value, str) and value for value in broker_env.values()):
        raise ValueError('existing supported broker controller credentials required')
    broker_env['GUARDEX_HARD_QUOTA_SOCKET'] = '/run/guardex-quota/broker.sock'
    services['quota-broker'] = dict(image=image, command=['quota-broker'], restart='no', network_mode='host',
        container_name=project+'-quota-broker', environment=broker_env,
        labels={'guardex.quota.rollout.scope': scope}, read_only=True,
        cap_drop=['ALL'], cap_add=['CHOWN'], security_opt=['no-new-privileges:true'],
        pids_limit=64, mem_limit=134217728, cpus=.5,
        volumes=[dict(type='bind', source=quota_dir, target='/run/guardex-quota', bind={'create_host_path': False})],
        logging={'driver': 'json-file', 'options': {'max-size': '5m', 'max-file': '3'}})
    return literal_compose(dict(name=project, services=services))
