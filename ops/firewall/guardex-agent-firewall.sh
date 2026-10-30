#!/bin/sh
# DNS names are configuration; numeric source rules are generated at runtime.
exec python3 - <<'PYTHON'
import fcntl
import ipaddress
import os
import re
import shutil
import subprocess
import sys

host = os.environ.get("CONTROLLER_HOST", "api.guardex-vpn.com").rstrip(".")
port = os.environ.get("AGENT_PORT", "8099")
if os.environ.get("CONTROLLER_ORIGIN_IP"):
    sys.exit("Legacy CONTROLLER_ORIGIN_IP is unsupported; configure CONTROLLER_HOST")
if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9-]{0,62}", host):
    sys.exit("CONTROLLER_HOST must be a DNS name, never an IP or URL")
if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
    sys.exit("AGENT_PORT must be between 1 and 65535")
for command in ["iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "getent"]:
    if not shutil.which(command):
        sys.exit("Missing firewall prerequisite: " + command)

# Serialize timer, installer and operator refreshes without flushing other rules.
lock = open(os.environ.get("GUARDEX_FIREWALL_LOCK", "/run/lock/guardex-agent-firewall.lock"), "a")
fcntl.flock(lock, fcntl.LOCK_EX)
chain = "GUARDEX_AGENT"

def run(args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, timeout=10, **kwargs)

def apply(family, addresses):
    rules = ["*filter", ":" + chain + " - [0:0]", "-F " + chain]
    for address in addresses:
        rules.append(f"-A {chain} -p tcp -s {address} --dport {port} -j ACCEPT")
    rules += [f"-A {chain} -p tcp --dport {port} -j DROP", f"-A {chain} -j RETURN", "COMMIT", ""]
    result = run([family + "-restore", "--wait", "5", "--noflush"], input="\n".join(rules))
    if result.returncode:
        raise RuntimeError("Atomic " + family + " update failed")
    if run([family, "-w", "5", "-C", "INPUT", "-j", chain]).returncode:
        if run([family, "-w", "5", "-I", "INPUT", "1", "-j", chain]).returncode:
            raise RuntimeError("Cannot install " + family + " input guard")

try:
    reply = run(["getent", "ahostsv4", host])
    if reply.returncode:
        raise ValueError("DNS lookup failed")
    addresses = set()
    for line in reply.stdout.splitlines():
        if not line.strip():
            continue
        address = ipaddress.IPv4Address(line.split()[0])
        if address.is_unspecified or address.is_loopback or address.is_multicast or int(address) == 2**32 - 1:
            raise ValueError("Invalid controller unicast address")
        addresses.add(str(address))
    if not 1 <= len(addresses) <= 8:
        raise ValueError("DNS must return one to eight IPv4 addresses")
except (ValueError, subprocess.TimeoutExpired) as error:
    # DNS failure never erases an existing narrow allowlist. On first boot,
    # install deny-only chains rather than leaving the management port open.
    for family in ["ip6tables", "iptables"]:
        if run([family, "-w", "5", "-S", chain]).returncode:
            apply(family, [])
    sys.exit("Controller DNS unavailable; existing rules retained (or deny-only installed)")

# Management is IPv4-only; IPv6 must not bypass the controller allowlist.
apply("ip6tables", [])
apply("iptables", sorted(addresses))
print(f"Controller DNS ACL applied: {len(addresses)} IPv4 address(es), TCP {port}")
PYTHON
