#!/usr/bin/env python3
"""Upgrade gate: reviewed version and timeout policy must move together."""
from pathlib import Path
import re
import sys

def check(dockerfile, config):
    pins = re.findall(r"xcaddy build (v[0-9.]+)", dockerfile)
    if len(pins) != 1:
        raise ValueError("exactly one pinned Caddy version required")
    if pins[0] == "v2.11.6":
        raise ValueError("Caddy 2.11.6 idle-stream regressions are forbidden")
    if pins[0] != "v2.11.4":
        raise ValueError("Caddy upgrade requires reviewed timeout compatibility and real-binary idle acceptance")
    # These options do not exist in the currently pinned version. Do not copy
    # a newer Caddyfile into older nodes and break their config validation.
    if re.search(r"\b(read_body_idle|write_idle)\b", config):
        raise ValueError("new idle timeout directives require a compatible reviewed Caddy version")

if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    try:
        check((root / "Dockerfile").read_text(), (root / "internal/transportbundle/config.go").read_text())
    except ValueError as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)
    print("Caddy version/idle policy: PASS (2.11.4, no unsupported directives)")
