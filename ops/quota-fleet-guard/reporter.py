"""Read-only host evidence reporter. No firewall/container/account mutation."""
import argparse
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import uuid

import barrier
import guard
from closure_gate import HOSTS
from receipt_store import private, sync_directory

PRIMARY = '193.247.73.15'
DOMAIN = 'api.guardex-vpn.com'


def validate_settings(settings):
    parsed = urllib.parse.urlsplit(settings['coordinator_url'])
    if (parsed.scheme != 'https' or parsed.hostname != DOMAIN or parsed.username is not None
            or parsed.password is not None or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or parsed.port is None or not 44390 <= parsed.port <= 44999):
        raise ValueError('exact verified primary coordinator origin required')
    if settings['host'] not in HOSTS or re.fullmatch('[A-Za-z0-9_-]{43,128}', settings['bearer']) is None:
        raise ValueError('exact host identity and private per-host bearer required')
    return parsed.port


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        if self.host != DOMAIN or not self._context.check_hostname or self._context.verify_mode != ssl.CERT_REQUIRED:
            raise ValueError('normal certificate/hostname verification required')
        stream = socket.create_connection((PRIMARY, self.port), self.timeout, source_address=self.source_address)
        try:
            self.sock = self._context.wrap_socket(stream, server_hostname=DOMAIN)
        except Exception:
            stream.close()
            raise


def send(settings, report):
    port = validate_settings(settings)
    context = ssl.create_default_context()
    connection = PinnedHTTPSConnection(DOMAIN, port, timeout=3, context=context,
                                       source_address=(settings['host'], 0))
    payload = json.dumps(report, separators=(',', ':'), allow_nan=False).encode()
    if len(payload) > 12 << 20:
        raise ValueError('evidence payload exceeds coordinator bound')
    try:
        connection.request('POST', '/v1/receipt', body=payload,
                           headers={'Authorization': 'Bearer ' + settings['bearer'],
                                    'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read((1 << 20) + 1)
        if response.status != 200 or len(raw) > 1 << 20:
            raise OSError('closure collector did not accept durable evidence')
        value = json.loads(raw)
        if not isinstance(value, dict) or not isinstance(value.get('status'), dict):
            raise ValueError('malformed closure collector response')
        status = value.get('status') or {}
        if status.get('rollback_authorized') is not False or status.get('ingress_open_authorized') is not False:
            raise ValueError('unexpected mutation authority in collection protocol')
        return dict(accepted=True, duplicate=value.get('duplicate') is True)
    finally:
        connection.close()


def next_sequence(root):
    path = root / 'report-sequence.json'
    previous = 0
    if path.exists() or path.is_symlink():
        private(path)
        previous = json.loads(path.read_bytes())['sequence']
        if type(previous) is not int or previous < 1:
            raise ValueError('invalid retained report sequence')
    sequence = previous + 1
    temporary = root / ('report-sequence.tmp-' + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump({'sequence': sequence}, stream); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    temporary.replace(path); sync_directory(root)
    return sequence


def collect(manifest, root, host, sequence, execute=guard.run):
    table, _ = guard.validate_manifest(manifest)
    result = dict(scope=manifest['scope'], host=host, sequence=sequence,
                  observed_epoch=time.time(),
                  guard_source_sha256=hashlib.sha256((root / 'guard.py').read_bytes()).hexdigest(),
                  nft_document=None, containers=[], expiry={}, native_final_file=None)
    def read(argv):
        try:
            return execute(argv)
        except (OSError, subprocess.TimeoutExpired):
            return None
    response = read(['nft', '-j', 'list', 'table', 'inet', table])
    if response is not None and response.returncode == 0:
        try: result['nft_document'] = json.loads(response.stdout)
        except ValueError: pass
    for service, cid in manifest['containers'].items():
        response = read(['docker', 'inspect', cid])
        item = dict(Id=cid, Image=None, Config={'Labels': {}}, State={'Running': None, 'Pid': None})
        if response is not None and response.returncode == 0:
            try:
                raw = json.loads(response.stdout)[0]
                labels = raw.get('Config', {}).get('Labels') or {}
                item = dict(Id=raw['Id'], Image=raw['Image'],
                            Config={'Labels': {key: labels.get(key) for key in (
                                'guardex.quota.rollout.scope', 'com.docker.compose.project', 'com.docker.compose.service')}},
                            State={key: raw.get('State', {}).get(key) for key in ('Running', 'Pid')})
            except (ValueError, KeyError, IndexError, TypeError, AttributeError):
                pass
        result['containers'].append(item)
    attempts = []
    unknown_attempt = False
    # A newer unfinished attempt invalidates earlier successful evidence. Never
    # search backwards for a convenient complete native snapshot.
    for path in root.glob('expiry-*'):
        try:
            private(path, True)
            attempts.append(path)
        except OSError:
            unknown_attempt = True
    if attempts and not unknown_attempt:
        try:
            path = max(attempts, key=lambda entry: entry.stat().st_mtime_ns) / 'expiry.json'
            private(path)
            expiry = json.loads(path.read_bytes())
            if expiry.get('scope') != manifest['scope'] or expiry.get('deadline_epoch') != manifest['deadline_epoch']:
                raise ValueError('expiry receipt outside exact host operation')
            result['expiry'] = expiry
            native = path.parent / 'native-final-private.json'
            private(native)
            if native.stat().st_size <= 8 << 20:
                result['native_final_file'] = native.read_text()
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            pass
    result['collected_epoch'] = time.time()
    return result


def main(settings_path, once=False):
    os.umask(0o077)
    if os.geteuid() != 0 or settings_path.resolve() != settings_path:
        raise ValueError('canonical private root-owned settings required')
    guard.private(settings_path.parent, True); guard.private(settings_path)
    settings = json.loads(settings_path.read_bytes())
    validate_settings(settings)
    manifest_path = settings_path.parent / 'manifest.json'
    manifest = guard.load(manifest_path)
    if Path(__file__).resolve() != settings_path.parent / 'reporter.py':
        raise ValueError('only the staged reporter may operate this host scope')
    guard.private(Path(__file__))
    with (settings_path.parent / 'reporter.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        while time.time() <= manifest['deadline_epoch'] + 120:
            sequence = next_sequence(settings_path.parent)
            body = collect(manifest, settings_path.parent, settings['host'], sequence)
            try:
                outcome = send(settings, body)
                event = dict(kind='host_closure_report', sequence=sequence, **outcome)
            except (OSError, ValueError, ssl.SSLError, http.client.HTTPException) as error:
                event = dict(kind='host_closure_report_failed', sequence=sequence, error_type=type(error).__name__)
            event.update(scope=manifest['scope'], host=settings['host'], utc=datetime.datetime.now(datetime.timezone.utc).isoformat())
            print(json.dumps(event), flush=True)
            if once: break
            time.sleep(5)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--settings', type=Path, required=True)
    parser.add_argument('--once', action='store_true')
    args = parser.parse_args()
    main(args.settings, args.once)
