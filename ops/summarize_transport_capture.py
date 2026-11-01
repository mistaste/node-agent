#!/usr/bin/env python3
"""Summarize private capture metadata without printing addresses or payloads."""
import argparse
from collections import Counter
import ipaddress
import json
import subprocess

def summarize(lines, peer):
    peer = str(ipaddress.ip_address(peer))
    counts = Counter()
    for line in lines:
        fields = line.rstrip("\n").split("\t")
        if len(fields) != 8:
            continue
        _, ipv4, ipv6, syn, fin, reset, retransmit, handshake = fields
        source = ipv4 or ipv6
        try:
            direction = "peer" if str(ipaddress.ip_address(source)) == peer else "local"
        except ValueError:
            continue
        counts["packets"] += 1
        for name, value in [("syn", syn), ("fin", fin), ("rst", reset)]:
            if value == "1": counts[direction + "_" + name] += 1
        if retransmit: counts[direction + "_retransmission"] += 1
        for code in handshake.split(","):
            if code == "1": counts[direction + "_tls_client_hello"] += 1
            if code == "2": counts[direction + "_tls_server_hello"] += 1
    return dict(counts)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture")
    parser.add_argument("--peer", required=True)
    args = parser.parse_args()
    ipaddress.ip_address(args.peer)
    fields = ["frame.time_epoch", "ip.src", "ipv6.src", "tcp.flags.syn", "tcp.flags.fin", "tcp.flags.reset", "tcp.analysis.retransmission", "tls.handshake.type"]
    command = ["tshark", "-n", "-r", args.capture, "-T", "fields"]
    for field in fields: command += ["-e", field]
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=15)
    print(json.dumps(summarize(result.stdout.splitlines(), args.peer), sort_keys=True))
