"""TLS closure-receipt collector. It cannot change quota flags or open ingress."""
import argparse
import datetime
import json
import os
from pathlib import Path
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from closure_gate import ClosureGate, HOSTS, Rejected
from receipt_store import ReceiptStore, private

MAX_BODY = 12 << 20


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def handle(self):
        timer = threading.Timer(8, self.expire_connection)
        timer.daemon = True
        timer.start()
        try:
            super().handle()
        finally:
            timer.cancel()

    def expire_connection(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def log_message(self, *args):
        # Never log a raw request line/header or bearer. Accepted evidence is
        # retained privately; only constrained status/peer metadata is logged.
        pass

    def reply(self, status, value):
        body = json.dumps(value, separators=(',', ':'), allow_nan=False).encode()
        self.close_connection = True
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        print(json.dumps(dict(kind='coordinator_http', status=status, peer=self.client_address[0],
                              utc=datetime.datetime.now(datetime.timezone.utc).isoformat())), flush=True)

    def bearer(self):
        values = self.headers.get_all('Authorization') or []
        if len(values) != 1 or not values[0].startswith('Bearer '):
            raise Rejected('unauthorized host')
        return values[0][7:]

    def do_GET(self):
        if self.path != '/v1/status':
            self.reply(404, {'error': 'unknown_route'})
            return
        try:
            with self.server.gate_lock:
                self.server.gate._authorized(self.client_address[0], self.bearer())
                status = self.server.gate.status()
            self.reply(200, status)
        except Rejected:
            self.reply(401, {'error': 'unauthorized_host'})

    def do_POST(self):
        if self.path != '/v1/receipt':
            self.reply(404, {'error': 'unknown_route'})
            return
        try:
            token = self.bearer()
            self.server.gate._authorized(self.client_address[0], token)
            lengths = self.headers.get_all('Content-Length') or []
            if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                    or self.headers.get('Transfer-Encoding') is not None):
                self.reply(400, {'error': 'one_content_length_required'})
                return
            length = int(lengths[0])
            if not 1 <= length <= MAX_BODY:
                self.reply(413, {'error': 'receipt_body_bound'})
                return
            if self.headers.get('Content-Type', '').split(';', 1)[0] != 'application/json':
                self.reply(415, {'error': 'json_required'})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('incomplete body')
            body = json.loads(raw)
            with self.server.gate_lock:
                outcome = self.server.gate.submit(self.client_address[0], token, body)
            self.reply(200, outcome)
        except Rejected as error:
            self.reply(401 if str(error).startswith('unauthorized') else 409, {'error': str(error)})
        except (ValueError, TypeError, KeyError, AttributeError):
            self.reply(422, {'error': 'invalid_receipt'})
        except OSError:
            self.reply(503, {'error': 'evidence_not_durable'})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, context, gate):
        self.context = context
        self.gate = gate
        self.gate_lock = threading.RLock()
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(address, Handler)

    def get_request(self):
        stream, address = super().get_request()
        if address[0] not in HOSTS:
            stream.close()
            raise OSError('peer not in sealed host inventory')
        stream.settimeout(3)
        try:
            return self.context.wrap_socket(stream, server_side=True), address
        except Exception:
            stream.close()
            raise

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        # Retain an error marker without printing request bodies/headers.
        print(json.dumps(dict(kind='coordinator_request_failed', peer=client_address[0],
                              utc=datetime.datetime.now(datetime.timezone.utc).isoformat())), flush=True)


def main(path):
    os.umask(0o077)
    if os.geteuid() != 0 or path.resolve() != path:
        raise ValueError('canonical root-owned coordinator configuration required')
    private(path.parent, True); private(path)
    config = json.loads(path.read_bytes())
    if (config['bind_ip'] != '193.247.73.15' or type(config['listen_port']) is not int
            or not 44390 <= config['listen_port'] <= 44999):
        raise ValueError('owned primary high-port listener required')
    key = Path(config['tls_key_file']).resolve()
    private(key)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(config['tls_cert_file'], str(key))
    gate = ClosureGate(config, ReceiptStore(path.parent))
    if not config['created_epoch'] <= time.time() <= config['deadline_epoch'] + 120:
        raise ValueError('coordinator outside its sealed operation window')
    server = Server((config['bind_ip'], config['listen_port']), context, gate)
    deadline = threading.Timer(max(0, config['deadline_epoch'] + 120 - time.time()), server.shutdown)
    deadline.daemon = True
    deadline.start()
    print(json.dumps(dict(kind='coordinator_ready', scope=config['scope'], PID=os.getpid(),
                          deadline_epoch=config['deadline_epoch'], mutation_authority=False)), flush=True)
    try:
        server.serve_forever(poll_interval=.25)
    finally:
        deadline.cancel()
        server.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    main(parser.parse_args().config)
