#!/usr/bin/env python3
"""One-node runner-only repair. Default preflight is read-only; apply rolls back on failure.

Run as root on the node with a tested static runner in --directory. The endpoint,
credentials, original Compose files and all other services remain unchanged.
Private Docker inspect backups stay on the host with mode 0600.
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

CONTAINER = 'guardex-node-trusttunnel-runner-1'
ENDPOINT = '/opt/trusttunnel/trusttunnel_endpoint'
RUNNER = '/usr/local/bin/trusttunnel-runner'


def call(args, **kwargs):
    return subprocess.check_output(args, text=True, timeout=90, **kwargs).strip()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def fingerprint(value, files):
    value = copy.deepcopy(value)
    cfg = value['Config']
    if cfg['Hostname'] == value['Id'][:12]:
        cfg['Hostname'] = '<default>'
    cfg.pop('Image')
    labels = cfg.get('Labels') or {}
    for key in ['com.docker.compose.config-hash', 'com.docker.compose.image']:
        labels.pop(key, None)
    actual = labels['com.docker.compose.project.config_files'].split(',')
    assert actual[:len(files)] == files and len(actual) in (len(files), len(files) + 1)
    labels['com.docker.compose.project.config_files'] = ','.join(files)
    # Environment ordering has no semantic effect; duplicate keys are unsafe.
    env = [entry.split('=', 1) for entry in cfg['Env']]
    assert len(dict(env)) == len(env)
    cfg['Env'] = dict(env)
    return digest(json.dumps({'Config': cfg, 'HostConfig': value['HostConfig'],
                              'Mounts': sorted(value['Mounts'], key=lambda m: m['Destination'])},
                             sort_keys=True).encode())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--runner-sha256', required=True)
    parser.add_argument('--expected-image', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    assert os.geteuid() == 0
    os.umask(0o077)
    root = args.directory
    assert root.is_absolute() and root.is_dir() and not root.is_symlink()
    assert root.stat().st_mode & 0o077 == 0
    lock = (root / 'operation.lock').open('a') if args.apply else None
    if lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    inspect = lambda: json.loads(call(['docker', 'inspect', CONTAINER]))[0]
    before = inspect()
    assert before['State']['Running'] and before['RestartCount'] == 0
    assert before['Image'] == args.expected_image
    labels = before['Config']['Labels']
    files = labels['com.docker.compose.project.config_files'].split(',')
    for name in files:
        assert Path(name).is_file() and not Path(name).is_symlink()
    file_hashes = {name: digest(Path(name).read_bytes()) for name in files}
    project = labels['com.docker.compose.project']
    compose = ['docker', 'compose', '--project-name', project]
    for name in files:
        compose += ['-f', name]
    override = root / 'compose.runner.yml'
    assert not override.exists()
    runner = root / 'trusttunnel-runner'
    assert runner.is_file() and not runner.is_symlink()
    assert digest(runner.read_bytes()) == args.runner_sha256
    expected_fp = fingerprint(before, files)
    endpoint_sha = call(['docker', 'exec', CONTAINER, 'sha256sum', ENDPOINT]).split()[0]
    def record(name, value):
        path = root / name
        with path.open('x') as stream:
            json.dump(value, stream, indent=2)
    def original_files_unchanged():
        assert all(digest(Path(name).read_bytes()) == sha for name, sha in file_hashes.items())
    summary = {'image': before['Image'], 'endpoint_sha256': endpoint_sha,
               'runtime_fingerprint': expected_fp, 'runner_sha256': args.runner_sha256}
    if not args.apply:
        print(json.dumps(summary))
        return
    assert not (root / 'before.json').exists()
    record('before.json', before)
    record('inputs.json', {**summary, 'compose_sha256': file_hashes})
    tag = 'guardex-credential-runner:' + args.runner_sha256[:16]
    base_tag = 'guardex-credential-runner-base:' + before['Image'].split(':')[1][:20]
    call(['docker', 'tag', before['Image'], base_tag])
    assert json.loads(call(['docker', 'image', 'inspect', base_tag]))[0]['Id'] == before['Image']
    dockerfile = ('FROM ' + base_tag + '\nCOPY --chmod=0755 trusttunnel-runner ' + RUNNER + '\n')
    context = root / 'context'
    context.mkdir(mode=0o700)
    (context / 'Dockerfile').write_text(dockerfile)
    (context / 'trusttunnel-runner').write_bytes(runner.read_bytes())
    # Private inspect/config backups are outside the build context.
    with (root / 'build.log').open('x') as stream:
        subprocess.run(['docker', 'build', '--pull=false', '-t', tag, str(context)],
                       stdout=stream, stderr=subprocess.STDOUT, timeout=90, check=True)
    candidate = json.loads(call(['docker', 'image', 'inspect', tag]))[0]['Id']
    model = json.loads(call(compose + ['config', '--format', 'json']))['services']['trusttunnel-runner']
    def overlay(image):
        from decimal import Decimal
        cpu = format(Decimal(before['HostConfig']['NanoCpus']) / Decimal(1000000000), 'f')
        text = 'services:\n  trusttunnel-runner:\n    image: ' + image + '\n    cpus: "' + cpu + '"\n'
        if 'cpus' in model.get('deploy', {}).get('resources', {}).get('limits', {}):
            text += '    deploy:\n      resources:\n        limits:\n          cpus: "' + cpu + '"\n'
        for field, key in [('DnsOptions', 'dns_opt'), ('DnsSearch', 'dns_search')]:
            if before['HostConfig'][field] == []:
                text += '    ' + key + ': []\n'
        return text
    def recreate(image):
        original_files_unchanged()
        temp = override.with_suffix('.new')
        temp.write_text(overlay(image))
        os.replace(temp, override)
        call(compose + ['-f', str(override), 'up', '-d', '--no-deps', '--no-build',
                        '--pull', 'never', 'trusttunnel-runner'])
    def verify(image, require_reload):
        deadline = time.monotonic() + 35
        while True:
            current = inspect()
            try:
                raw = call(['docker', 'exec', CONTAINER, 'cat', '/data/trusttunnel/runner-state.json'])
                state = json.loads(raw)
                ready = bool(state.get('revision')) and (not require_reload or state.get('credential_reload_version') == 1)
            except (subprocess.CalledProcessError, ValueError):
                ready = False
            if ready and current['State']['Running']:
                break
            assert time.monotonic() < deadline, 'runner acknowledgement deadline exceeded'
            time.sleep(1)
        assert current['Image'] == image and current['RestartCount'] == 0
        assert current['Config']['Labels']['com.docker.compose.project.config_files'].split(',') == files + [str(override)]
        assert fingerprint(current, files) == expected_fp, 'runtime configuration changed'
        assert call(['docker', 'exec', CONTAINER, 'sha256sum', ENDPOINT]).split()[0] == endpoint_sha
        processes = call(['docker', 'top', CONTAINER, '-eo', 'pid,args']).splitlines()[1:]
        endpoints = [int(line.split()[0]) for line in processes
                     if len(line.split()) > 1 and Path(line.split()[1]).name == 'trusttunnel_endpoint']
        assert endpoints and all(digest(Path('/proc', str(pid), 'exe').read_bytes()) == endpoint_sha for pid in endpoints)
        if require_reload:
            assert call(['docker', 'exec', CONTAINER, 'sha256sum', RUNNER]).split()[0] == args.runner_sha256
            credentials_sha = call(['docker', 'exec', CONTAINER, 'sha256sum', '/data/trusttunnel/credentials.toml']).split()[0]
            assert state.get('credentials_sha256') == credentials_sha, 'credentials not acknowledged'
        original_files_unchanged()
        return {'image': image, 'credential_reload_version': state.get('credential_reload_version'),
                'endpoint_unchanged': True, 'runtime_unchanged': True, 'restart_count': 0}
    try:
        assert inspect()['Id'] == before['Id'], 'another deployment changed the container'
        recreate(candidate)
        result = verify(candidate, True)
        time.sleep(5)
        result = verify(candidate, True)
    except BaseException:
        recreate(before['Image'])
        record('rollback.json', verify(before['Image'], False))
        raise
    record('deployed.json', result)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
