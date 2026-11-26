#!/usr/bin/env python3
"""Capture a bounded transport window without overwriting its beginning."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import time


def capture_filter(peers, ports):
    normalized_peers = []
    for peer in peers:
        address = ipaddress.ip_address(peer)
        if getattr(address, "scope_id", None):
            raise ValueError("scoped IPv6 addresses are unsupported")
        normalized_peers.append(str(address))
    normalized_ports = sorted(set(ports))
    if any(port < 1 or port > 65535 for port in normalized_ports):
        raise ValueError("invalid port")
    if not normalized_ports:
        raise ValueError("at least one port is required")
    port_clause = " or ".join(f"port {port}" for port in normalized_ports)
    if not normalized_peers:
        return f"tcp and ({port_clause})"
    peer_clause = " or ".join(f"host {peer}" for peer in normalized_peers)
    return f"tcp and ({peer_clause}) and ({port_clause})"


def command(interface, output, peers, ports):
    if not interface or interface.startswith("-"):
        raise ValueError("invalid interface")
    return [
        "tcpdump",
        "-i",
        interface,
        "-n",
        "-s",
        "128",
        "-U",
        "-w",
        str(output),
        capture_filter(peers, ports),
    ]


def stop(process):
    process.send_signal(signal.SIGINT)
    try:
        return process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError("capture did not stop gracefully")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", action="append", default=[])
    parser.add_argument("--port", action="append", type=int, default=[])
    parser.add_argument("--interface", default="any")
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--max-bytes", type=int, default=512 * 1024 * 1024)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 7200:
        parser.error("capture duration must be 1..7200 seconds")
    if not 1024 * 1024 <= args.max_bytes <= 2 * 1024 * 1024 * 1024:
        parser.error("max bytes must be 1 MiB..2 GiB")
    ports = args.port or [443, 4443]
    try:
        argv = command(args.interface, args.output, args.peer, ports)
    except ValueError as error:
        parser.error(str(error))

    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    metadata = args.output.with_suffix(args.output.suffix + ".json")
    metadata_fd = os.open(metadata, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(metadata_fd)
    started = time.time()
    reason = "duration"
    status = None
    process = subprocess.Popen(argv, stdout=subprocess.DEVNULL)
    try:
        while True:
            status = process.poll()
            if status is not None:
                reason = "tcpdump_exit"
                break
            if args.output.stat().st_size >= args.max_bytes:
                reason = "size_limit"
                status = stop(process)
                break
            if time.time() - started >= args.seconds:
                status = stop(process)
                break
            time.sleep(0.25)
    finally:
        if process.poll() is None:
            stop(process)

    record = {
        "started_unix": started,
        "finished_unix": time.time(),
        "stop_reason": reason,
        "bytes": args.output.stat().st_size,
        "tcpdump_status": status,
        "filter": argv[-1],
    }
    with metadata.open("w", encoding="utf-8") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.write("\n")
    os.chmod(metadata, 0o600)
    if status not in (0, 130):
        raise RuntimeError("tcpdump failed; capture privileges may be required")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    main()
