#!/usr/bin/env python3
"""Apply only the blind relay's owned TCP segment policy, atomically."""

import re
import subprocess
import sys
from pathlib import Path

TABLE = "guardex_relay_tcp_mss"
POLICY = Path("/etc/guardex/relay-tcp-mss.nft")


def exists():
    return subprocess.run(
        ["nft", "list", "table", "inet", TABLE],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def transaction(policy):
    declarations = re.findall(r"\btable\s+\w+\s+(\w+)\s*\{", policy)
    if declarations != [TABLE] or re.search(r"\binclude\b", policy):
        raise ValueError("Policy must declare only the owned relay TCP table")
    prefix = f"delete table inet {TABLE}\n" if exists() else ""
    return prefix + policy


def apply(path=POLICY, check_only=False):
    rules = transaction(Path(path).read_text())
    # Validate the entire replacement before touching the live table. One
    # nft transaction then replaces it without a gap or a connection reset.
    subprocess.run(["nft", "-c", "-f", "-"], input=rules, text=True, check=True)
    if not check_only:
        subprocess.run(["nft", "-f", "-"], input=rules, text=True, check=True)


def remove():
    if exists():
        subprocess.run(["nft", "delete", "table", "inet", TABLE], check=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["apply"]:
        apply()
    elif sys.argv[1:] == ["remove"]:
        remove()
    elif len(sys.argv) == 3 and sys.argv[1] == "check":
        apply(sys.argv[2], check_only=True)
    else:
        raise SystemExit("Usage: guardex-relay-tcp-mss apply|remove|check FILE")
