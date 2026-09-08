#!/usr/bin/env python3
"""Reload only the management listener whose mounted certificate was renewed."""
import json
import os
from pathlib import PurePosixPath
import subprocess

lineage = os.environ.get("RENEWED_LINEAGE", "")
if not lineage:
    raise SystemExit(0)
result = subprocess.run(["docker", "inspect", "guardex-node-node-agent-1"], capture_output=True, text=True)
if result.returncode:
    raise SystemExit(0)
container = json.loads(result.stdout)[0]
environment = dict(item.split("=", 1) for item in container["Config"]["Env"] if "=" in item)
certificate = environment.get("AGENT_TLS_CERT_FILE", "")
if "/live/" in certificate and PurePosixPath(certificate).parent.name == PurePosixPath(lineage).name:
    subprocess.run(["docker", "restart", "guardex-node-node-agent-1"], check=True, stdout=subprocess.DEVNULL)
