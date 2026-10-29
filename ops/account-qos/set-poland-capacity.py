#!/usr/bin/env python3
"""Apply a tested Poland-only budget without restarting VPN transports."""
import argparse
import fcntl
import json
import os
import pathlib
import re
import shutil
import subprocess
import time

ROOT = pathlib.Path('/opt/guardex-node')
SAVE = pathlib.Path('/var/lib/guardex-remediation/account-qos-capacity-20261029')
UNIT = pathlib.Path('/etc/systemd/system/guardex-account-qos.service')
BINARY = pathlib.Path('/usr/local/sbin/guardex-account-qos')
OVERLAY = ROOT / 'docker-compose.account-qos-capacity.yml'
SERVICES = ['trusttunnel-runner', 'transport-bundle-runner']


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def compose_overlay(enabled):
    env = ROOT / '.env'
    raw = env.read_text()
    match = re.search(r'^COMPOSE_FILE=(.*)$', raw, re.M)
    assert match, 'missing persistent compose configuration'
    parts = match.group(1).strip().strip('"').strip("'").split(':')
    parts = [part for part in parts if pathlib.Path(part).name != OVERLAY.name]
    if enabled:
        parts.append(str(OVERLAY))
    raw = re.sub(r'^COMPOSE_FILE=.*$', lambda _: 'COMPOSE_FILE=' + ':'.join(parts), raw, flags=re.M)
    temporary = env.with_name('.env.capacity-next')
    temporary.write_text(raw)
    temporary.chmod(0o600)
    temporary.replace(env)


def restart_with_binary(source):
    temporary = BINARY.with_name('guardex-account-qos.next')
    shutil.copy2(source, temporary)
    temporary.chmod(0o755)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'stop', 'guardex-account-qos')
    temporary.replace(BINARY)
    # Existing native clients fail open while the old socket is absent.
    time.sleep(0.05)
    run('systemctl', 'start', 'guardex-account-qos')
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if pathlib.Path('/run/guardex-account-qos/broker.sock').exists():
            assert run('systemctl', 'is-active', 'guardex-account-qos') == 'active'
            return
        time.sleep(0.05)
    raise RuntimeError('broker socket did not become available')


def rollback(state):
    UNIT.write_text(state['unit'])
    if state['overlay'] is None:
        OVERLAY.unlink(missing_ok=True)
    else:
        OVERLAY.write_text(state['overlay'])
    compose_overlay(state['overlay'] is not None)
    for service, record in state['containers'].items():
        run('docker', 'update', '--cpus', str(record['nano_cpus'] / 1e9), 'guardex-node-' + service + '-1')
    restart_with_binary(SAVE / 'account-qos.before')
    print('Previous Poland budget and CPU quotas restored')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rollback', action='store_true')
    parser.add_argument('--binary', default='/tmp/guardex-account-qos-anticipatory-final')
    parser.add_argument('--initial-mbps', type=int, default=256)
    parser.add_argument('--max-mbps', type=int, default=256)
    parser.add_argument('--endpoint-cpus', type=float, default=0.75)
    args = parser.parse_args()
    assert '212.127.91.131' in run('hostname', '-I').split(), 'Poland only'
    os.chdir(ROOT)
    SAVE.mkdir(mode=0o700, parents=True, exist_ok=True)
    SAVE.chmod(0o700)
    state_file = SAVE / 'before.json'
    if args.rollback:
        rollback(json.loads(state_file.read_text()))
        return
    assert 32 <= args.initial_mbps <= args.max_mbps <= 256
    assert 0.35 <= args.endpoint_cpus <= 0.75
    if not state_file.exists():
        containers = {}
        for service in SERVICES:
            obj = json.loads(run('docker', 'inspect', 'guardex-node-' + service + '-1'))[0]
            assert obj['State']['Running']
            containers[service] = {'image': obj['Image'], 'nano_cpus': obj['HostConfig']['NanoCpus'], 'started_at': obj['State']['StartedAt']}
        state = {'unit': UNIT.read_text(), 'overlay': OVERLAY.read_text() if OVERLAY.exists() else None, 'containers': containers}
        shutil.copy2(BINARY, SAVE / 'account-qos.before')
        state_file.write_text(json.dumps(state))
        state_file.chmod(0o600)
    state = json.loads(state_file.read_text())
    try:
        unit = re.sub(r'--initial-mbps=\S+', '--initial-mbps=' + str(args.initial_mbps), UNIT.read_text())
        unit = re.sub(r'--max-mbps=\S+', '--max-mbps=' + str(args.max_mbps), unit)
        if 'ExecStopPost=' not in unit:
            unit = unit.replace('Restart=on-failure', 'ExecStopPost=/usr/bin/rm -f /run/guardex-account-qos/broker.sock\nRestart=on-failure')
        UNIT.write_text(unit)
        OVERLAY.write_text('services:\n' + ''.join('  ' + service + ':\n    cpus: ' + str(args.endpoint_cpus) + '\n' for service in SERVICES))
        compose_overlay(True)
        run('docker', 'compose', 'config', '--quiet')
        for service in SERVICES:
            run('docker', 'update', '--cpus', str(args.endpoint_cpus), 'guardex-node-' + service + '-1')
        restart_with_binary(pathlib.Path(args.binary))
        for service in SERVICES:
            obj = json.loads(run('docker', 'inspect', 'guardex-node-' + service + '-1'))[0]
            assert obj['Image'] == state['containers'][service]['image'], 'transport image changed'
            assert obj['State']['StartedAt'] == state['containers'][service]['started_at'], 'transport restarted'
        print(json.dumps({'initial_mbps': args.initial_mbps, 'max_mbps': args.max_mbps, 'endpoint_cpus': args.endpoint_cpus, 'transport_restarts': False}))
    except BaseException:
        rollback(state)
        raise


if __name__ == '__main__':
    with open('/run/lock/guardex-qos-capacity.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        main()
