#!/usr/bin/env python3
"""Bounded, peer-specific capture. Does not change routes, firewall or services."""
import argparse
import ipaddress
import os
from pathlib import Path
import signal
import subprocess
import sys

def command(peer, port, interface, output):
    address = ipaddress.ip_address(peer)
    if getattr(address, "scope_id", None):
        raise ValueError("scoped IPv6 addresses are unsupported")
    peer = str(address)
    if not 1 <= port <= 65535 or not interface or interface.startswith("-"):
        raise ValueError("invalid port/interface")
    return ["tcpdump", "-i", interface, "-n", "-s", "128", "-U", "-c", "2000", "-w", str(output), "host " + peer + " and tcp port " + str(port)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--interface", default="any")
    parser.add_argument("--seconds", type=int, default=30)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 60:
        parser.error("capture duration must be 1..60 seconds")
    try:
        argv = command(args.peer, args.port, args.interface, args.output)
        # Refuse overwriting files/symlinks. Capture metadata is private too.
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        process = subprocess.Popen(argv, stdout=subprocess.DEVNULL)
        try:
            status = process.wait(timeout=args.seconds)
        except subprocess.TimeoutExpired:
            process.send_signal(signal.SIGINT)
            try:
                status = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError("capture did not stop gracefully")
        if status not in (0, 130):
            raise RuntimeError("tcpdump failed; capture privileges may be required")
        print("Capture complete; private file retained locally. Compare synchronized client/server captures.")
    except (ValueError, OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
