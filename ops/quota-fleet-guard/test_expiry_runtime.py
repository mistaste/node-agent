"""Actual Docker expiry acceptance, inside a disposable network namespace.

Only new labelled, network-none sleep fixtures are created/stopped/removed.
No production timer, account API, Docker project or host firewall is changed.
Run under a host-independent timeout: timeout 80s unshare --net -- python3 ...
"""
import datetime
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid

import guard

IMAGE = "sha256:50f1a8a0238af50e1ac885dc5efa7aeca8761d351672e11ad49c9947a947f54e"
RUN = str(uuid.uuid4())


def command(*args, timeout=6):
    return subprocess.check_output(args, text=True, stderr=subprocess.PIPE, timeout=timeout)


class CounterFixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        assert self.path in ("/clients", "/guardex/clients")
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers()
        self.wfile.write(b"[]")

    def log_message(self, *args):
        pass


def main(root):
    assert os.geteuid() == 0 and root.is_dir()
    assert Path("/proc/self/ns/net").stat().st_ino != Path("/proc/1/ns/net").stat().st_ino
    command("ip", "link", "set", "lo", "up")
    created = []; results = []; removed = []
    counters = [http.server.HTTPServer(("127.0.0.1", port), CounterFixture) for port in (1987, 2019)]
    for server in counters:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    def create(scope, service):
        cid = command("docker", "run", "--detach", "--network", "none", "--read-only",
                      "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
                      "--pids-limit", "16", "--memory", "16m", "--restart", "no",
                      "--label", "guardex.quota.test.run=" + RUN,
                      "--label", "guardex.quota.rollout.scope=" + scope,
                      "--label", "com.docker.compose.project=guardex-qf-" + scope,
                      "--label", "com.docker.compose.service=" + service,
                      "--entrypoint", "/bin/sleep", IMAGE, "120").strip()
        assert len(cid) == 64
        created.append(cid)
        return cid

    def manifest():
        scope = str(uuid.uuid4())
        value = {"schema": 1, "scope": scope, "ingress_ports": [443, 18443, 19080, 19443],
                 "project": "guardex-qf-" + scope, "image": IMAGE,
                 "deadline_epoch": int(time.time()) + 60, "containers": {}}
        for service in sorted(guard.SERVICES):
            value["containers"][service] = create(scope, service)
        return value

    try:
        value = manifest(); evidence = root / "normal"; evidence.mkdir(mode=0o700)
        (evidence / "fixture-manifest.json").write_text(json.dumps(value, indent=2))
        receipt = guard.expire(value, evidence)
        assert receipt["barrier_verified"] and len(receipt["stopped"]) == 4
        assert receipt["native_stable_30s"] and not receipt["errors"], receipt
        assert not receipt["global_flags_changed"] and not receipt["legacy_ingress_restored"]
        results.append({"case": "ACTUAL_DOCKER_FOUR_PINNED_IDS_STOPPED_30S_COUNTERS_RETAINED", "status": "PASS"})
        for server in counters:
            server.shutdown(); server.server_close()
        value = manifest()
        foreign = create(str(uuid.uuid4()), "trusttunnel-runner")
        value["containers"]["trusttunnel-runner"] = foreign
        evidence = root / "foreign"; evidence.mkdir(mode=0o700)
        (evidence / "fixture-manifest.json").write_text(json.dumps(value, indent=2))
        receipt = guard.expire(value, evidence)
        actual = json.loads(command("docker", "inspect", foreign))[0]
        assert actual["State"]["Running"] and len(receipt["stopped"]) == 3
        assert receipt["status"] == "CLOSURE_UNCONFIRMED_NO_ROLLBACK_AUTHORITY"
        assert not receipt["native_stable_30s"] and receipt["errors"]
        results.append({"case": "ACTUAL_FOREIGN_ID_PRESERVED_COUNTER_ERROR_OTHER_IDS_STOPPED", "status": "PASS"})
    finally:
        for cid in created:
            item = json.loads(command("docker", "inspect", cid))[0]
            assert item["Config"]["Labels"]["guardex.quota.test.run"] == RUN
            assert item["Image"] == IMAGE and item["HostConfig"]["NetworkMode"] == "none"
            assert item["Config"]["Entrypoint"] == ["/bin/sleep"] and item["Config"]["Cmd"] == ["120"]
            command("docker", "rm", "--force", cid)
            check = subprocess.run(["docker", "inspect", cid], capture_output=True, timeout=4)
            assert check.returncode != 0
            removed.append(cid)
        result = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "run": RUN,
                  "cases": results, "created_fixture_count": len(created), "removed_fixture_count": len(removed),
                  "actual_fixture_cleanup": set(created) == set(removed), "host_network_namespace_untouched": True,
                  "production_timers_installed": 0, "account_flags_changed": False}
        (root / "runtime-result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main(Path(sys.argv[1]))
