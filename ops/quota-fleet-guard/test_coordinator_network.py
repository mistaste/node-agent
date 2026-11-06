"""Actual TLS/HTTP acceptance in one disposable Linux network namespace.

Run: timeout 30s unshare --net -- python3 test_coordinator_network.py /private/evidence
Closure reports and credentials are synthetic; no production closure is asserted.
"""
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time
from unittest.mock import patch

from closure_gate import ClosureGate, HOSTS
from coordinator import Server, MAX_BODY
from receipt_store import ReceiptStore
from test_closure_gate import fixture, report
import reporter


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=5)


def main(root):
    os.umask(0o077)
    assert os.geteuid() == 0 and root.is_dir()
    assert Path('/proc/self/ns/net').stat().st_ino != Path('/proc/1/ns/net').stat().st_ino
    assert [x['ifname'] for x in json.loads(command('ip', '-j', 'link', 'show'))] == ['lo']
    command('ip', 'link', 'set', 'lo', 'up')
    for address in [*HOSTS, '198.18.0.7', reporter.PRIMARY]:
        command('ip', 'addr', 'add', address + '/32', 'dev', 'lo')
    cert, key = root / 'fixture-cert.pem', root / 'fixture-key-private.pem'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,DNS:api.guardex-vpn.com',
            '-keyout', str(key), '-out', str(cert))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    trusted = ssl.create_default_context(cafile=str(cert))
    assert trusted.check_hostname and trusted.verify_mode == ssl.CERT_REQUIRED
    config, tokens = fixture()
    now = int(time.time()); config.update(created_epoch=now - 100, deadline_epoch=now + 600)
    for record in config['hosts'].values(): record['manifest']['deadline_epoch'] = now + 600
    gate = ClosureGate(config, ReceiptStore(root))
    server = Server(('0.0.0.0', 44390), context, gate)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
    worker.start(); port = server.server_address[1]; checks = []
    first, other = sorted(HOSTS)[:2]

    def body(host, sequence=1):
        value = report(config, host, sequence=sequence, observed=time.time())
        value['expiry']['deadline_epoch'] = config['deadline_epoch']
        return value

    def request(host, method, path, value=None, token=None, headers=None, tls=trusted):
        connection = http.client.HTTPSConnection('localhost', port, timeout=2, context=tls, source_address=(host, 0))
        data = None if value is None else json.dumps(value).encode()
        fields = {'Authorization': 'Bearer ' + (tokens.get(host, '') if token is None else token), 'Content-Type': 'application/json'}
        fields.update(headers or {})
        try:
            connection.request(method, path, body=data, headers=fields)
            response = connection.getresponse(); raw = response.read(1 << 20)
            return response.status, json.loads(raw)
        finally:
            connection.close()

    try:
        status, result = request(first, 'GET', '/v1/status')
        assert status == 200 and not result['all_inventoried_hosts_closed']
        checks.append('initial_missing_hosts_fail_closed')
        for token in ('wrong-fixture-token', tokens[other]):
            assert request(first, 'POST', '/v1/receipt', body(first), token=token)[0] == 401
        checks.append('wrong_and_other_host_bearers_rejected')
        try:
            request('198.18.0.7', 'GET', '/v1/status', token=tokens[first])
            raise AssertionError('unknown source reached authenticated handler')
        except (OSError, ssl.SSLError, http.client.HTTPException):
            pass
        checks.append('unknown_source_rejected_before_TLS')
        try:
            request(first, 'GET', '/v1/status', tls=ssl.create_default_context())
            raise AssertionError('untrusted fixture certificate accepted')
        except ssl.SSLCertVerificationError:
            pass
        checks.append('untrusted_server_certificate_rejected')
        with socket.socket() as raw:
            raw.settimeout(2); raw.bind((first, 0)); raw.connect(('127.0.0.1', port))
            try:
                trusted.wrap_socket(raw, server_hostname='wrong.example.invalid')
                raise AssertionError('wrong TLS hostname accepted')
            except ssl.SSLCertVerificationError:
                pass
        checks.append('wrong_TLS_hostname_rejected')
        assert request(first, 'POST', '/v1/receipt', {}, headers={'Content-Length': str(MAX_BODY + 1)})[0] == 413
        assert request(first, 'POST', '/v1/receipt', {}, headers={'Transfer-Encoding': 'chunked'})[0] == 400
        checks.append('oversized_and_ambiguous_body_framing_rejected')
        assert request(first, 'POST', '/v1/open', {})[0] == 404
        checks.append('no_open_route')
        originals = {}
        for host in HOSTS:
            originals[host] = body(host)
            assert request(host, 'POST', '/v1/receipt', originals[host])[0] == 200
        status, result = request(first, 'GET', '/v1/status')
        assert status == 200 and result['all_inventoried_hosts_closed'] and result['all_native_snapshot_files_retained']
        assert not result['rollback_authorized'] and not result['ingress_open_authorized']
        checks.append('all_six_synthetic_receipts_retained_without_mutation_authority')
        assert request(first, 'POST', '/v1/receipt', originals[first])[1]['duplicate'] is True
        changed = body(first)
        assert request(first, 'POST', '/v1/receipt', changed)[0] == 409
        checks.append('idempotent_retry_and_changed_sequence_replay')
        with patch.object(gate, 'persist', side_effect=OSError('fixture disk failure')):
            assert request(first, 'POST', '/v1/receipt', body(first, sequence=2))[0] == 503
        assert not request(other, 'GET', '/v1/status')[1]['all_inventoried_hosts_closed']
        checks.append('wire_disk_failure_revokes_positive_consensus')
        settings = dict(host=first, bearer=tokens[first],
                        coordinator_url='https://api.guardex-vpn.com:44390')
        try:
            reporter.send(settings, body(first, sequence=2))
            raise AssertionError('host reporter trusted a fixture CA by default')
        except ssl.SSLCertVerificationError:
            pass
        checks.append('host_reporter_default_roots_reject_fixture_CA')
        # Test-only CA injection; the production sender always creates the OS
        # default context and still enforces hostname + CERT_REQUIRED.
        with patch.object(reporter.ssl, 'create_default_context', return_value=trusted):
            for host in HOSTS:
                settings.update(host=host, bearer=tokens[host])
                assert reporter.send(settings, body(host, sequence=2))['accepted']
        result = request(first, 'GET', '/v1/status')[1]
        assert result['all_inventoried_hosts_closed'] and not result['rollback_authorized']
        assert not result['ingress_open_authorized']
        checks.append('all_six_host_reporters_use_pinned_primary_verified_hostname_and_source_bind')
        result = dict(status='ISOLATED_TLS_CLOSURE_COLLECTOR_PASS', checks=checks,
                      host_network_namespace_untouched=True, actual_production_receipts=False,
                      account_flags_changed=False, ingress_opened=False,
                      retained_receipt_count=len(list((root / 'receipts').iterdir())))
        (root / 'TLS-result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps(result), flush=True)
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)
        assert not worker.is_alive()


if __name__ == '__main__':
    main(Path(sys.argv[1]))
