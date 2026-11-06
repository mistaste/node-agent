"""Root Linux acceptance, exclusively in disposable network namespaces.

Run: timeout 45s unshare --net -- python3 test_network.py --isolated
No production address, namespace, listener or firewall is modified.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import barrier

SCOPE = "ae41b7ca-5ebe-47e8-9e91-44da568651eb"
PORTS = [443, 18443, 19080, 19443]


def command(*args, data=None):
    return subprocess.check_output(args, input=data, text=True, stderr=subprocess.PIPE, timeout=4)


def listeners():
    sockets = []
    for family, address in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        for port in (443, 18443, 1987):
            for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                sock = socket.socket(family, kind)
                if family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((address, port))
                sockets.append(sock)
                if kind == socket.SOCK_STREAM:
                    sock.listen(16)

                    def accept(listener=sock):
                        while True:
                            conn, _ = listener.accept()

                            def echo(stream=conn):
                                try:
                                    stream.settimeout(8)
                                    while stream.recv(1):
                                        stream.sendall(b"Y")
                                except OSError:
                                    pass
                                finally:
                                    stream.close()
                            threading.Thread(target=echo, daemon=True).start()
                    threading.Thread(target=accept, daemon=True).start()
                else:
                    def datagrams(listener=sock):
                        while True:
                            _, source = listener.recvfrom(32)
                            listener.sendto(b"Y", source)
                    threading.Thread(target=datagrams, daemon=True).start()
    return sockets


def probe(address, port, protocol):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    try:
        with socket.socket(family, kind) as sock:
            sock.settimeout(.35)
            sock.connect((address, port))
            sock.sendall(b"N")
            return sock.recv(1) == b"Y"
    except (OSError, TimeoutError):
        return False


def isolated():
    assert os.geteuid() == 0
    assert Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino
    command("ip", "link", "set", "lo", "up")
    servers = listeners()
    peer = subprocess.Popen(["unshare", "--net", "--", sys.executable, __file__, "--peer"],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    held = None
    try:
        assert peer.stdout.readline().strip() == "READY"
        assert Path(f"/proc/{peer.pid}/ns/net").stat().st_ino != Path("/proc/self/ns/net").stat().st_ino
        command("ip", "link", "add", "qf_server", "type", "veth", "peer", "name", "qf_client")
        command("ip", "link", "set", "qf_client", "netns", str(peer.pid))
        command("ip", "addr", "add", "198.18.0.1/30", "dev", "qf_server")
        command("ip", "-6", "addr", "add", "fd45:9ad1::1/64", "dev", "qf_server", "nodad")
        command("ip", "link", "set", "qf_server", "up")
        prefix = ["nsenter", "-t", str(peer.pid), "--net", "--"]
        command(*prefix, "ip", "addr", "add", "198.18.0.2/30", "dev", "qf_client")
        command(*prefix, "ip", "-6", "addr", "add", "fd45:9ad1::2/64", "dev", "qf_client", "nodad")
        command(*prefix, "ip", "link", "set", "qf_client", "up")

        def external(address, port, protocol):
            return json.loads(command(*prefix, sys.executable, __file__, "--probe", address, str(port), protocol))

        for address in ("198.18.0.1", "fd45:9ad1::1"):
            for protocol in ("tcp", "udp"):
                assert external(address, 443, protocol), "fixture initially unreachable"
        held = subprocess.Popen(prefix + [sys.executable, __file__, "--held", "198.18.0.1"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert held.stdout.readline().strip() == "CONNECTED_AND_ECHOED"
        command("nft", "-f", "-", data=barrier.render(SCOPE, PORTS))
        table, _ = barrier.normalize(SCOPE, PORTS)
        document = json.loads(command("nft", "-j", "list", "table", "inet", table))
        assert barrier.inspect(SCOPE, PORTS, document), json.dumps(document)
        held.stdin.write("CHECK\n"); held.stdin.flush()
        assert held.stdout.readline().strip() == "BLOCKED", "existing stream escaped ingress barrier"
        assert held.wait(timeout=2) == 0
        checks = 1
        for address in ("198.18.0.1", "fd45:9ad1::1"):
            for protocol in ("tcp", "udp"):
                for port in (443, 18443):
                    assert not external(address, port, protocol), "new native ingress escaped"
                    checks += 1
                assert external(address, 1987, protocol), "management/counter ingress blocked"
                checks += 1
        for address in ("127.0.0.1", "::1"):
            for protocol in ("tcp", "udp"):
                assert not probe(address, 443, protocol), "loopback data listener escaped"
                assert probe(address, 1987, protocol), "loopback management blocked"
                checks += 2
        for address in ("198.18.0.2", "fd45:9ad1::2"):
            for protocol in ("tcp", "udp"):
                assert probe(address, 443, protocol), "unrelated outbound traffic blocked"
                checks += 1
        command("nft", "delete", "table", "inet", table)
        assert external("198.18.0.1", 443, "tcp"), "exact owned removal did not restore fixture"
        checks += 1
        print(json.dumps({"status": "ISOLATED_BARRIER_ACCEPTANCE_PASS", "checks": checks,
                          "host_network_namespace_untouched": True,
                          "IPv4_IPv6_TCP_UDP": True, "existing_stream_blocked": True,
                          "management_and_nonlocal_egress_preserved": True}))
    finally:
        if held and held.poll() is None:
            held.terminate(); held.wait(timeout=2)
        peer.terminate(); peer.wait(timeout=2)
        for sock in servers:
            sock.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--isolated"]:
        isolated()
    elif sys.argv[1:] == ["--peer"]:
        assert Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino
        command("ip", "link", "set", "lo", "up")
        sockets = listeners()
        print("READY", flush=True)
        time.sleep(40)
    elif len(sys.argv) == 5 and sys.argv[1] == "--probe":
        assert Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino
        print(json.dumps(probe(sys.argv[2], int(sys.argv[3]), sys.argv[4])))
    elif len(sys.argv) == 3 and sys.argv[1] == "--held":
        assert Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino
        with socket.create_connection((sys.argv[2], 443), timeout=.35) as sock:
            sock.sendall(b"N"); assert sock.recv(1) == b"Y"
            print("CONNECTED_AND_ECHOED", flush=True)
            assert sys.stdin.readline().strip() == "CHECK"
            try:
                sock.sendall(b"N"); assert not sock.recv(1), "existing flow remains reachable"
            except TimeoutError:
                print("BLOCKED", flush=True)
    else:
        raise SystemExit("explicit isolated test mode required")
