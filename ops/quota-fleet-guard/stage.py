"""Stage four exact STOPPED candidates. No start, firewall or systemd operation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

import compose_plan
import guard
from receipt_store import private, sync_directory
import source_archive


def read_private(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError('canonical private input path required')
    private(path.parent, True); private(path)
    with path.open('rb') as source:
        data = source.read((16 << 20) + 1)
    if len(data) > 16 << 20:
        raise ValueError('private staging input exceeds bound')
    return data


def write_new(path, value):
    data = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + '\n').encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        output.write(data); output.flush(); os.fsync(output.fileno())
    sync_directory(path.parent)


def run(argv, env=None, timeout=8):
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE, timeout=timeout, env=env)


def inspect(ids):
    return json.loads(run(['docker', 'inspect', *ids]))


def verify_host():
    if os.uname().sysname != 'Linux' or any(os.environ.get(key) for key in ('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY')):
        raise ValueError('actual Linux host and local Docker context required')
    if Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino:
        raise ValueError('actual host network namespace required')
    context = json.loads(run(['docker','context','inspect']))
    if len(context) != 1 or context[0].get('Endpoints',{}).get('docker',{}).get('Host') not in (
            'unix:///var/run/docker.sock','unix:///run/docker.sock'):
        raise ValueError('only the local host Docker socket may stage candidates')


def validate_plan(plan, value):
    scope = value['scope']; compose_plan.counter_join.canonical_uuid(scope)
    if plan['name'] != 'guardex-qf-' + scope or set(plan['services']) != guard.SERVICES:
        raise ValueError('exact four-service scoped plan required')
    if not re.fullmatch('[a-f0-9]{40}', value['source_revision']):
        raise ValueError('exact frozen source revision required')
    if not value['image'].startswith('sha256:') or not guard.HEX.fullmatch(value['image'][7:]):
        raise ValueError('exact cached image required')
    root = guard.BASE / scope
    quota = str(root / 'quota')
    for name, item in plan['services'].items():
        if (item['image'] != value['image'] or item.get('restart') != 'no'
                or item.get('network_mode') != 'host' or item.get('build') is not None
                or item.get('depends_on') or item.get('env_file') or item.get('ports') or item.get('networks')
                or item.get('labels', {}).get('guardex.quota.rollout.scope') != scope
                or item.get('container_name') != plan['name'] + '-' + name):
            raise ValueError('candidate cannot build, pull dependencies, restart or escape ownership')
        volumes = {v['target']: v for v in item.get('volumes', [])}
        if len(volumes) != len(item.get('volumes', [])):
            raise ValueError('unique candidate mount targets required')
        if name == 'node-agent':
            source = volumes.get('/opt/guardex-node', {})
            if source.get('source') != str(root/'source') or not source.get('read_only'):
                raise ValueError('exact frozen read-only source mount required')
            if item['environment'].get('AGENT_VERSION') != value['source_revision']:
                raise ValueError('candidate version disagrees with frozen image')
            if item['environment'].get('GUARDEX_HARD_QUOTA_REQUIRED') not in ('true', 'false'):
                raise ValueError('explicit candidate quota mode required')
            if item['environment'].get('GUARDEX_QUOTA_FLEET_MANAGED') != 'true':
                raise ValueError('metered fleet update boundary must survive optional mode')
        else:
            if volumes.get('/run/guardex-quota', {}).get('source') != quota:
                raise ValueError('one exact owned broker directory required')
    if (plan['services']['trusttunnel-runner']['environment'].get('GUARDEX_HARD_QUOTA_REQUIRED')
            != plan['services']['node-agent']['environment']['GUARDEX_HARD_QUOTA_REQUIRED']):
        raise ValueError('controller and native runner quota mode disagree')
    guard.barrier.normalize(scope, value['ingress_ports'])


def verify_candidate(item, service, plan, value, image_config):
    labels = item['Config'].get('Labels') or {}
    expected = plan['services'][service]
    if (item['Image'] != value['image'] or item['State']['Running'] or item['State']['Pid'] != 0
            or item['HostConfig']['RestartPolicy']['Name'] != 'no'
            or item['HostConfig']['NetworkMode'] != 'host'
            or labels.get('guardex.quota.rollout.scope') != value['scope']
            or labels.get('com.docker.compose.project') != plan['name']
            or labels.get('com.docker.compose.service') != service):
        raise ValueError('exact stopped candidate identity required')
    env = compose_plan.environment(item)
    for key, entry in expected['environment'].items():
        if env.get(key) != (entry.replace('$$', '$') if isinstance(entry, str) else entry):
            raise ValueError('candidate environment changed during Compose creation')
    wanted = sorted((v['source'], v['target'], not v.get('read_only', False))
                    for v in expected.get('volumes', []) if v['type'] == 'bind')
    actual = sorted((v['Source'], v['Destination'], v['RW']) for v in item['Mounts'] if v['Type'] == 'bind')
    if wanted != actual or item['Config']['Cmd'] != expected['command']:
        raise ValueError('candidate command or bind ownership differs')
    if (item['Config'].get('Entrypoint') or []) != (expected.get('entrypoint', image_config.get('Entrypoint')) or []):
        raise ValueError('candidate entrypoint differs')
    host = item['HostConfig']
    if (host['ReadonlyRootfs'] != expected.get('read_only', False)
            or host['Privileged'] != expected.get('privileged', False)
            or item['Config'].get('User') != expected.get('user', image_config.get('User', ''))
            or item['Config'].get('WorkingDir') != expected.get('working_dir', image_config.get('WorkingDir', ''))):
        raise ValueError('candidate security identity differs')
    for key, docker_key in [('cap_add', 'CapAdd'), ('cap_drop', 'CapDrop')]:
        normalize = lambda values: sorted(v.removeprefix('CAP_') for v in (values or []))
        if normalize(host.get(docker_key)) != normalize(expected.get(key)):
            raise ValueError('candidate capabilities differ')
    normalize_security = lambda values: sorted(entry.replace('no-new-privileges:true','no-new-privileges')
                                               .replace('no-new-privileges=true','no-new-privileges') for entry in (values or []))
    if normalize_security(host.get('SecurityOpt')) != normalize_security(expected.get('security_opt')):
        raise ValueError('candidate security options differ')
    for key, docker_key in [('mem_limit','Memory'),('pids_limit','PidsLimit')]:
        if key in expected:
            number = expected[key]
            if isinstance(number,str) and re.fullmatch('[0-9]+',number): number = int(number)
            if type(number) is not int or host.get(docker_key) != number:
                raise ValueError('candidate resource policy differs')
    if 'cpus' in expected and host.get('NanoCpus') != round(float(expected['cpus'])*1_000_000_000):
        raise ValueError('candidate CPU policy differs')


def runtime_identity(item):
    return dict(id=item['Id'], image=item['Image'], restart_count=item['RestartCount'],
                state={key: item['State'].get(key) for key in
                       ('Running', 'Pid', 'StartedAt', 'FinishedAt', 'ExitCode', 'Restarting', 'OOMKilled', 'Dead')})


def legacy_matches(previous, current, service):
    labels = current['Config'].get('Labels') or {}
    mounts = lambda item: sorted(json.dumps(entry, sort_keys=True) for entry in item['Mounts'])
    return (runtime_identity(previous) == runtime_identity(current)
            and current['State']['Running']
            and labels.get('com.docker.compose.project') == 'guardex-node'
            and labels.get('com.docker.compose.service') == service
            and all(current[key] == previous[key] for key in ('Image','Config','HostConfig'))
            and mounts(current) == mounts(previous))


def seal_stopped(root, value, plan, candidates, items):
    for name in ('guard.py','barrier.py'):
        private(root/name)
        if (root/name).read_bytes() != Path(__file__).with_name(name).read_bytes():
            raise ValueError('staged expiry helpers changed')
    manifest = dict(schema=1, scope=value['scope'], image=value['image'], project=plan['name'],
                    deadline_epoch=value['deadline_epoch'], ingress_ports=value['ingress_ports'], containers=candidates)
    guard.validate_manifest(manifest)
    write_new(root/'candidate-runtime-private.json', items)
    write_new(root/'manifest.json', manifest)
    seal = ''.join(hashlib.sha256((root/name).read_bytes()).hexdigest()+'  '+name+'\n'
                   for name in ('guard.py','barrier.py','manifest.json'))
    write_new(root/'source.sha256', seal.encode()); guard.verify_seal(root)
    for name, text in guard.unit_sources(manifest, root).items(): write_new(root/(name+'.rendered'), text.encode())


def finalize_stopped(root, expected_input_sha256):
    """Revalidate already-created stopped resources; preserve failed attempt.

    This phase cannot create/start/stop containers or install/arm a guard. The
    original input hash fences the deadline and plan against silent changes.
    """
    os.umask(0o077)
    if os.geteuid() != 0:
        raise ValueError('root required for exact stopped-resource finalization')
    verify_host(); root=Path(root)
    if root.resolve()!=root or root.parent!=guard.BASE:
        raise ValueError('canonical existing owned scope required')
    private(root,True)
    raw=read_private(root/'stage-input-private.json')
    if hashlib.sha256(raw).hexdigest()!=expected_input_sha256:
        raise ValueError('original fixed staging input changed')
    value=json.loads(raw)
    if value.get('schema')!=1 or root.name!=value['scope'] or time.time()+300>=value['deadline_epoch']:
        raise ValueError('same unexpired scope/deadline required')
    plan_raw=read_private(root/'candidate-compose-private.json')
    if hashlib.sha256(plan_raw).hexdigest()!=value['plan_sha256']:
        raise ValueError('qualified stopped plan changed')
    plan=json.loads(plan_raw); validate_plan(plan,value)
    for path in (root/'manifest.json',root/'source.sha256',root/'candidate-runtime-private.json'):
        if path.exists()or path.is_symlink():
            raise ValueError('scope already finalized or partial seal exists; inspect instead of overwrite')
    source_archive.verify_tree(root/'frozen-source.tar',root/'source',value['source_archive_sha256'],value['source_revision'])
    image=json.loads(run(['docker','image','inspect',value['image']]))[0]
    if image['Id']!=value['image']or(image['Config'].get('Labels')or{}).get('org.opencontainers.image.revision')!=value['source_revision']:
        raise ValueError('exact cached image provenance required')
    originals={name:json.loads(read_private(path))for name,path in value['legacy_snapshot_paths'].items()}
    before={item['Id']:item for item in inspect([item['Id']for item in originals.values()])}
    if any(not legacy_matches(previous,before[previous['Id']],name)for name,previous in originals.items()):
        raise ValueError('legacy identity changed; stopped finalization cannot authorize it')
    ids=run(['docker','ps','-aq','--filter','label=com.docker.compose.project='+plan['name']]).split()
    if len(ids)!=4:
        raise ValueError('exact four existing candidates required')
    items=inspect(ids);candidates={}
    for item in items:
        service=(item['Config'].get('Labels')or{}).get('com.docker.compose.service')
        if service not in guard.SERVICES or service in candidates:
            raise ValueError('foreign or duplicate stopped candidate')
        verify_candidate(item,service,plan,value,image['Config']);candidates[service]=item['Id']
    after={item['Id']:item for item in inspect(list(before))}
    if any(runtime_identity(after[cid])!=runtime_identity(item)for cid,item in before.items()):
        raise ValueError('legacy process changed during revalidation')
    seal_stopped(root,value,plan,candidates,items)
    receipt=dict(status='EXISTING_FOUR_STOPPED_CANDIDATES_REVALIDATED_SEALED_NOT_ARMED_OR_STARTED',
                 scope=value['scope'],image=value['image'],deadline_epoch=value['deadline_epoch'],
                 original_input_sha256=expected_input_sha256,containers=candidates,legacy_runtime_unchanged=True,
                 prior_stage_receipt_preserved=True,guard_installed=False,runtime_started=False,
                 global_flags_changed=False,validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    write_new(root/('stage-revalidation-'+uuid.uuid4().hex+'.json'),receipt)
    return receipt


def stage(input_path):
    os.umask(0o077)
    if os.geteuid() != 0:
        raise ValueError('root required for owned host staging')
    verify_host()
    value = json.loads(read_private(input_path))
    if value.get('schema') != 1:
        raise ValueError('exact staging input schema required')
    plan_raw = read_private(value['plan_path'])
    if hashlib.sha256(plan_raw).hexdigest() != value['plan_sha256']:
        raise ValueError('qualified plan changed')
    plan = json.loads(plan_raw); validate_plan(plan, value)
    if type(value['deadline_epoch']) is not int or not time.time()+300 < value['deadline_epoch'] <= time.time()+3600:
        raise ValueError('one fixed future guard deadline required; never extend an old operation')
    source_raw = read_private(value['source_archive_path'])
    archive, _ = source_archive.verified(source_raw, value['source_archive_sha256'], value['source_revision'])
    archive.close()
    originals = {name: json.loads(read_private(path)) for name, path in value['legacy_snapshot_paths'].items()}
    if set(originals) != set(compose_plan.LEGACY_SERVICES):
        raise ValueError('three exact live legacy snapshots required')
    current = {item['Id']: item for item in inspect([item['Id'] for item in originals.values()])}
    for name, previous in originals.items():
        now = current[previous['Id']]
        if not legacy_matches(previous, now, name):
            projection = dict(service=name, previous=runtime_identity(previous), current=runtime_identity(now),
                              different_fields=[key for key in ('Image','Config','HostConfig','Mounts') if now[key] != previous[key]],
                              current_field_sha256={key:hashlib.sha256(json.dumps(now[key],sort_keys=True).encode()).hexdigest()
                                                    for key in ('Config','HostConfig','Mounts')})
            write_new(Path(input_path).parent/('preflight-mismatch-'+uuid.uuid4().hex+'.json'), projection)
            raise ValueError('live legacy runtime changed; recapture before any staging')
    image = json.loads(run(['docker', 'image', 'inspect', value['image']]))[0]
    if (image['Id'] != value['image'] or (image['Config'].get('Labels') or {}).get('org.opencontainers.image.revision') != value['source_revision']):
        raise ValueError('qualified runtime image missing or source differs')
    if run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project='+plan['name']]).strip():
        raise ValueError('scope already has resources; inspect instead of reusing it')
    guard.BASE.mkdir(mode=0o700, exist_ok=True); private(guard.BASE, True)
    root = guard.BASE / value['scope']; root.mkdir(mode=0o700, exist_ok=False); sync_directory(guard.BASE)
    write_new(root/'stage-input-private.json', value)
    source_archive_path = root/'frozen-source.tar'; write_new(source_archive_path, source_raw)
    source_archive.extract(source_archive_path, root/'source', value['source_archive_sha256'], value['source_revision'])
    (root/'quota').mkdir(mode=0o700)
    plan_path = root/'candidate-compose-private.json'; write_new(plan_path, plan_raw)
    for name in ('guard.py', 'barrier.py'):
        write_new(root/name, Path(__file__).with_name(name).read_bytes())
    env = compose_plan.command_environment(plan, os.environ)
    receipt = dict(scope=value['scope'], image=value['image'], status='STAGING_NO_ARM_OR_START',
                   deadline_epoch=value['deadline_epoch'], guard_installed=False, runtime_started=False,
                   global_flags_changed=False)
    try:
        run(['docker', 'compose', '--project-directory', str(root), '-f', str(plan_path),
             'create', '--no-build', '--pull', 'never', *sorted(guard.SERVICES)], env=env, timeout=45)
        ids = run(['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project='+plan['name']]).split()
        items = inspect(ids); candidates = {}
        for item in items:
            service = (item['Config'].get('Labels') or {}).get('com.docker.compose.service')
            if service not in guard.SERVICES or service in candidates:
                raise ValueError('unexpected or duplicate candidate service')
            verify_candidate(item, service, plan, value, image['Config']); candidates[service] = item['Id']
        if set(candidates) != guard.SERVICES:
            raise ValueError('all four stopped candidates required')
        seal_stopped(root,value,plan,candidates,items)
        after = {item['Id']: item for item in inspect([item['Id'] for item in originals.values()])}
        if any(runtime_identity(after[cid]) != runtime_identity(item) for cid, item in current.items()):
            raise ValueError('legacy process state changed during staging')
        receipt.update(status='FOUR_CANDIDATES_STAGED_STOPPED_NOT_ARMED_OR_STARTED', containers=candidates,
                       legacy_runtime_unchanged=True, source_revision=value['source_revision'])
    except Exception as error:
        receipt.update(status='STAGING_FAILED_NO_ARM_OR_START', error_type=type(error).__name__)
        write_new(root/'stage-receipt.json', receipt)
        raise
    write_new(root/'stage-receipt.json', receipt)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--input', type=Path)
    action.add_argument('--finalize-stopped', type=Path)
    parser.add_argument('--expected-input-sha256')
    args = parser.parse_args()
    print(json.dumps(stage(args.input)if args.input else finalize_stopped(args.finalize_stopped,args.expected_input_sha256)))
