"""Independent host expiry: close owned ingress and stop owned new engines.

This helper cannot change account flags, open ingress, restore legacy engines,
or extend a deadline. Fleet accounting/rollback remains a separate coordinator
operation requiring actual receipts from every affected host.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.request
import uuid

import barrier

BASE = Path("/var/lib/guardex-quota-fleet")
SERVICES = {"node-agent", "trusttunnel-runner", "transport-bundle-runner", "quota-broker"}
HEX = re.compile(r"^[a-f0-9]{64}$")


def run(argv, data=None, timeout=6):
    return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=timeout)


def validate_manifest(value):
    table, ports = barrier.normalize(value["scope"], value["ingress_ports"])
    if value["schema"] != 1 or value["project"] != "guardex-qf-" + value["scope"]:
        raise ValueError("unexpected rollout identity")
    if type(value["deadline_epoch"]) is not int or value["deadline_epoch"] <= 0:
        raise ValueError("fixed deadline required")
    if not HEX.fullmatch(value["image"].removeprefix("sha256:")) or not value["image"].startswith("sha256:"):
        raise ValueError("exact runtime image required")
    containers = value["containers"]
    if set(containers) != SERVICES or any(not HEX.fullmatch(cid) for cid in containers.values()):
        raise ValueError("all exact new runtime IDs required")
    if len(set(containers.values())) != len(SERVICES):
        raise ValueError("duplicate runtime ID")
    return table, ports


def private(path, directory=False):
    info = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise ValueError("private root-owned regular path required")


def load(path):
    if os.geteuid() != 0 or path.resolve() != path:
        raise ValueError("root and canonical owned path required")
    private(BASE, True); private(path.parent, True); private(path)
    value = json.loads(path.read_bytes())
    validate_manifest(value)
    if path != BASE / value["scope"] / "manifest.json":
        raise ValueError("manifest path disagrees with scope")
    for name in ("guard.py", "barrier.py", "source.sha256"):
        private(path.parent / name)
    if Path(__file__).resolve() != path.parent / "guard.py" or Path(barrier.__file__).resolve() != path.parent / "barrier.py":
        raise ValueError("only the sealed staged helpers may operate this scope")
    verify_seal(path.parent)
    return value


def verify_seal(root):
    required = {"guard.py", "barrier.py", "manifest.json"}
    entries = {}
    for line in (root / "source.sha256").read_text().splitlines():
        match = re.fullmatch(r"([a-f0-9]{64})  (guard\.py|barrier\.py|manifest\.json)", line)
        if not match or match[2] in entries:
            raise ValueError("exact unique sealed file inventory required")
        entries[match[2]] = match[1]
    if set(entries) != required:
        raise ValueError("complete sealed helper/manifest inventory required")
    for name, expected in entries.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected:
            raise ValueError("sealed helper/manifest hash mismatch")


def save(root, name, value):
    temporary = root / (name + ".tmp")
    with temporary.open("w") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    temporary.replace(root / name)


def matching(container, value, service):
    labels = container.get("Config", {}).get("Labels") or {}
    return (container.get("Id") == value["containers"][service]
            and container.get("Image") == value["image"]
            and labels.get("guardex.quota.rollout.scope") == value["scope"]
            and labels.get("com.docker.compose.project") == value["project"]
            and labels.get("com.docker.compose.service") == service)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def native_snapshot():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    result = {}
    for source, url in [("trusttunnel", "http://127.0.0.1:1987/clients"),
                        ("naive", "http://127.0.0.1:2019/guardex/clients")]:
        with opener.open(url, timeout=2) as response:
            if response.status != 200:
                raise ValueError("native counter response failed")
            raw = response.read((4 << 20) + 1)
            if len(raw) > 4 << 20:
                raise ValueError("native counter response exceeds bound")
            result[source] = json.loads(raw)
    return result


def expire(value, root):
    table, _ = validate_manifest(value)
    receipt = {"scope": value["scope"], "started_epoch": time.time(),
               "deadline_epoch": value["deadline_epoch"], "errors": [],
               "barrier_verified": False, "stopped": [], "global_flags_changed": False,
               "legacy_ingress_restored": False, "native_stable_30s": False}
    def record():
        try:
            save(root, "expiry.json", receipt)
        except OSError as error:
            # Disk exhaustion must never prevent the remaining stop actions.
            receipt["errors"].append("evidence_write_failed:" + type(error).__name__)
    record()
    try:
        current = run(["nft", "-j", "list", "table", "inet", table])
        if current.returncode:
            applied = run(["nft", "-f", "-"], barrier.render(value["scope"], value["ingress_ports"]))
            if applied.returncode:
                raise ValueError("owned barrier application failed")
            current = run(["nft", "-j", "list", "table", "inet", table])
        if current.returncode or not barrier.inspect(value["scope"], value["ingress_ports"], json.loads(current.stdout)):
            raise ValueError("actual owned barrier differs")
        receipt["barrier_verified"] = True
        receipt["barrier_closed_epoch"] = time.time()
        record()
        first = native_snapshot(); save(root, "native-first-private.json", first)
        began = time.monotonic(); time.sleep(30)
        last = native_snapshot(); save(root, "native-final-private.json", last)
        receipt["native_stable_30s"] = first == last and time.monotonic() - began >= 30
        receipt["native_final_SHA256"] = hashlib.sha256((root / "native-final-private.json").read_bytes()).hexdigest()
        # Equality alone is not a durable DB accounting join. That remains a
        # separate prerequisite to any coordinator-authorized global rollback.
    except Exception as error:
        receipt["errors"].append(type(error).__name__ + ":" + str(error)[:160])
    finally:
        # A counter/validator failure must not skip stopping the exact owned
        # engines. No name-based, project-wide or global Docker stop is used.
        for service in ("trusttunnel-runner", "transport-bundle-runner", "quota-broker", "node-agent"):
            try:
                cid = value["containers"][service]
                inspected = run(["docker", "inspect", cid])
                if inspected.returncode:
                    raise ValueError("owned runtime inspect unavailable")
                item = json.loads(inspected.stdout)[0]
                if not matching(item, value, service):
                    raise ValueError("runtime ownership/image mismatch")
                if item["State"]["Running"]:
                    stopped = run(["docker", "stop", "--time", "3", cid], timeout=8)
                    if stopped.returncode:
                        raise ValueError("owned runtime stop failed")
                actual = run(["docker", "inspect", cid])
                item = json.loads(actual.stdout)[0]
                if actual.returncode or item["State"]["Running"] or item["State"]["Pid"] != 0:
                    raise ValueError("actual runtime closure unconfirmed")
                receipt["stopped"].append({"service": service, "id": cid, "PID": 0})
            except Exception as error:
                receipt["errors"].append(service + ":" + type(error).__name__ + ":" + str(error)[:120])
            record()
        receipt["ended_epoch"] = time.time()
        receipt["status"] = ("INGRESS_CLOSED_PINNED_RUNTIMES_STOPPED_COORDINATOR_REVIEW_REQUIRED"
                             if receipt["barrier_verified"] and len(receipt["stopped"]) == 4
                             else "CLOSURE_UNCONFIRMED_NO_ROLLBACK_AUTHORITY")
        record()
    return receipt


def unit_sources(value, root):
    validate_manifest(value)
    name = "guardex-qf-" + value["scope"]
    deadline = datetime.datetime.fromtimestamp(value["deadline_epoch"], datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    service = ("[Unit]\nDescription=Guardex owned quota rollout expiry\n"
               "After=network-online.target docker.service time-sync.target\n"
               "[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=180s\n"
               f"ExecStart=/usr/bin/python3 {root}/guard.py --if-due --expire {root}/manifest.json\n"
               "[Install]\nWantedBy=multi-user.target\n")
    timer = ("[Unit]\nDescription=Fixed Guardex quota rollout deadline\n[Timer]\n"
             f"OnCalendar={deadline}\nAccuracySec=1s\nRandomizedDelaySec=0\nPersistent=true\n"
             f"Unit={name}.service\n[Install]\nWantedBy=timers.target\n")
    return {name + ".service": service, name + ".timer": timer}


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--expire", type=Path)
    action.add_argument("--render-units", type=Path)
    parser.add_argument("--if-due", action="store_true")
    args = parser.parse_args()
    path = args.expire or args.render_units
    value = load(path)
    if args.render_units:
        print(json.dumps(unit_sources(value, path.parent)))
    else:
        if Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino:
            raise SystemExit("actual host namespace required for production expiry")
        if args.if_due and time.time() < value["deadline_epoch"]:
            print(json.dumps({"scope": value["scope"], "status": "BEFORE_UNCHANGED_FIXED_DEADLINE"}))
            raise SystemExit(0)
        with (path.parent / "guard.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            evidence = path.parent / ("expiry-" + str(uuid.uuid4()))
            evidence.mkdir(mode=0o700, exist_ok=False)
            result = expire(value, evidence)
        print(json.dumps({key: result[key] for key in ("scope", "status", "barrier_verified", "global_flags_changed")}))
