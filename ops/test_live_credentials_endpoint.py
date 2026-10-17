#!/usr/bin/env python3
"""Real runner + endpoint gate. Only owned loopback ports and fixture accounts.

Requires Linux, curl and openssl. No production configuration or credentials.
"""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time


def wait_for(predicate, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.025)
    raise AssertionError("bounded fixture condition not met")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--runner", required=True)
    args = parser.parse_args()
    endpoint = runner = None
    transfers = []
    payload_bytes = 8 * 1024 * 1024
    chunk = b"G" * (64 * 1024)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            size = payload_bytes if self.path == "/stream" else len(chunk)
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            try:
                for _ in range(size // len(chunk)):
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    if self.path == "/stream":
                        time.sleep(0.05)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix="guardex-credential-fixture-") as directory, \
            tempfile.TemporaryDirectory(prefix="guardex-endpoint-fixture-bin-") as binaries:
        root = Path(directory)
        # The dedicated endpoint identity must be able to execute this binary;
        # managed configuration remains group-readable, never world-readable.
        os.chmod(binaries, 0o755)
        binary = Path(binaries) / "trusttunnel_endpoint"
        shutil.copyfile(args.binary, binary)
        os.chmod(binary, 0o755)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        settings = (f'listen_address="127.0.0.1:{port}"\nipv6_available=false\n'
                    f'allow_private_network_connections=true\ncredentials_file="{root}/credentials.toml"\n'
                    'default_max_http2_conns_per_client=8\ndefault_max_http3_conns_per_client=8\n'
                    '[listen_protocols.http1]\n[listen_protocols.http2]\n[listen_protocols.quic]\n')
        hosts = f'[[main_hosts]]\nhostname="localhost"\ncert_chain_path="{cert}"\nprivate_key_path="{key}"\n'
        for name, raw in [("vpn.toml", settings), ("hosts.toml", hosts)]:
            (root / name).write_text(raw)
            os.chmod(root / name, 0o600)
        revision = 0

        def publish(users, malformed=False):
            nonlocal revision
            revision += 1
            credentials = "invalid [" if malformed else "\n".join(
                f'[[client]]\nusername="{user}"\npassword="fixture"\n' for user in users)
            temporary = root / "credentials.next"
            temporary.write_text(credentials)
            os.chmod(temporary, 0o600)
            temporary.replace(root / "credentials.toml")
            digest = hashlib.sha256(credentials.encode()).hexdigest()
            state = dict(version=1, inbound_id="fixture", revision=revision,
                         digest=hashlib.sha256((settings+"\0"+hosts+"\0"+credentials+"\0").encode()).hexdigest(),
                         client_set_sha256=hashlib.sha256("|".join(users).encode()).hexdigest(),
                         credentials_sha256=digest)
            temporary = root / "state.next"
            temporary.write_text(json.dumps(state))
            os.chmod(temporary, 0o600)
            temporary.replace(root / "state.json")
            return digest

        def acknowledged(digest):
            try:
                state = json.loads((root / "runner-state.json").read_text())
                return state.get("credentials_sha256") == digest and state.get("credential_reload_version") == 1
            except (OSError, ValueError):
                return False

        def download(user, name, stream=True):
            output = root / name
            process = subprocess.Popen([
                "curl", "--silent", "--show-error", "--fail", "--max-time", "20", "--noproxy", "",
                "--proxy", f"https://localhost:{port}", "--proxytunnel", "--proxy-cacert", str(cert),
                "--proxy-user", f"{user}:fixture", "--output", str(output),
                f"http://127.0.0.1:{server.server_port}/" + ("stream" if stream else "small")],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            transfers.append(process)
            return process, output

        digest = publish(["alice"])
        with (root / "runner.log").open("w") as log:
            runner = subprocess.Popen([args.runner], env={**os.environ, "TRUSTTUNNEL_ROOT": str(root),
                                        "TRUSTTUNNEL_BINARY": str(binary)}, stdout=log, stderr=log)
            try:
                wait_for(lambda: acknowledged(digest))
                def children_of_runner():
                    # Go may spawn from any runtime thread, not its main TID.
                    return sorted({pid for child_list in Path(f"/proc/{runner.pid}/task").glob("*/children")
                                   for pid in child_list.read_text().split()})
                children = children_of_runner()
                assert len(children) == 1, "exactly one endpoint process required"
                endpoint = children[0]
                alice, alice_file = download("alice", "alice.bin")
                wait_for(lambda: alice_file.exists() and alice_file.stat().st_size >= len(chunk))
                digest = publish(["alice", "bob"])
                wait_for(lambda: acknowledged(digest))
                assert alice.poll() is None, "existing client must remain active during addition"
                bob, bob_file = download("bob", "bob.bin")
                wait_for(lambda: bob_file.exists() and bob_file.stat().st_size >= len(chunk))
                # A malformed replacement cannot revoke valid credentials or be acknowledged.
                invalid = publish(["alice", "bob"], malformed=True)
                time.sleep(0.35)
                assert not acknowledged(invalid), "invalid credentials were acknowledged"
                assert alice.poll() is None and bob.poll() is None
                digest = publish(["alice"])
                wait_for(lambda: acknowledged(digest))
                assert bob.wait(timeout=2) != 0, "revoked user's existing flow remained usable"
                assert alice.poll() is None, "other user's flow was interrupted by revocation"
                rejected, _ = download("bob", "rejected.bin", stream=False)
                assert rejected.wait(timeout=3) != 0, "revoked credential could reconnect"
                assert alice.wait(timeout=15) == 0, alice.stderr.read().decode()
                assert alice_file.stat().st_size == payload_bytes
                assert hashlib.sha256(alice_file.read_bytes()).hexdigest() == hashlib.sha256(chunk * (payload_bytes // len(chunk))).hexdigest()
                assert children_of_runner() == [endpoint]
                assert (root / "runner.log").read_text().count("endpoint started") == 1
                print("PASS: real endpoint PID unchanged; 8 MiB verified across add, malformed update and revoke; only revoked flow closed")
            finally:
                for process in transfers:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                runner.terminate()
                try:
                    runner.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    runner.kill()
                    runner.wait()
                if runner.returncode != 0:
                    print((root / "runner.log").read_text()[-2500:])
    server.shutdown()


if __name__ == "__main__":
    main()
