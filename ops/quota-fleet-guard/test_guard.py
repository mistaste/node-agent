"""Failure regressions for expiry; no host/network/Docker mutations."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import barrier
import guard

SCOPE = "ae41b7ca-5ebe-47e8-9e91-44da568651eb"
PORTS = [443, 18443, 19080, 19443]
# Actual nft1.0.2 output from the disposable Linux namespace acceptance.
DOCUMENT = json.loads(Path(__file__).with_name("test_nft_fixture.json").read_text())


def manifest():
    return {"schema": 1, "scope": SCOPE, "ingress_ports": PORTS,
            "project": "guardex-qf-" + SCOPE, "deadline_epoch": 1793923800,
            "image": "sha256:" + "a" * 64,
            "containers": {s: str(n) * 64 for n, s in enumerate(sorted(guard.SERVICES), 1)}}


class DockerFixture:
    def __init__(self, value):
        self.value = value
        self.items = {}
        self.calls = []
        self.barrier = False
        self.nft_failure = False
        self.stop_failure = set()
        for service, cid in value["containers"].items():
            self.items[cid] = {"Id": cid, "Image": value["image"],
                               "Config": {"Labels": {"guardex.quota.rollout.scope": SCOPE,
                                   "com.docker.compose.project": value["project"],
                                   "com.docker.compose.service": service}},
                               "State": {"Running": True, "Pid": 1234}}

    def run(self, args, data=None, timeout=6):
        self.calls.append(args)
        status, text = 0, ""
        if args[:3] == ["nft", "-j", "list"]:
            status, text = (0, json.dumps(DOCUMENT)) if self.barrier else (1, "")
        elif args[:2] == ["nft", "-f"]:
            if self.nft_failure:
                status = 1
            else:
                self.barrier = True
        elif args[:2] == ["docker", "inspect"]:
            text = json.dumps([self.items[args[2]]])
        elif args[:2] == ["docker", "stop"]:
            cid = args[-1]
            if cid in self.stop_failure:
                status = 1
            else:
                self.items[cid]["State"] = {"Running": False, "Pid": 0}
        else:
            raise AssertionError("unexpected privileged command: " + repr(args))
        return SimpleNamespace(returncode=status, stdout=text, stderr="")


class GuardTest(unittest.TestCase):
    def expiry(self, fixture):
        with tempfile.TemporaryDirectory() as root, patch.object(guard, "run", fixture.run), \
                patch.object(guard, "native_snapshot", side_effect=OSError("counter unavailable")):
            return guard.expire(fixture.value, Path(root))

    def test_missing_counters_still_stop_every_owned_runtime(self):
        fixture = DockerFixture(manifest())
        receipt = self.expiry(fixture)
        self.assertEqual(len(receipt["stopped"]), 4)
        self.assertTrue(receipt["barrier_verified"])
        self.assertFalse(receipt["native_stable_30s"])
        self.assertFalse(receipt["global_flags_changed"])
        self.assertFalse(receipt["legacy_ingress_restored"])
        self.assertIn("COORDINATOR_REVIEW_REQUIRED", receipt["status"])

    def test_barrier_failure_still_stops_all_engines_without_false_closure(self):
        fixture = DockerFixture(manifest()); fixture.nft_failure = True
        receipt = self.expiry(fixture)
        self.assertEqual(len(receipt["stopped"]), 4)
        self.assertFalse(receipt["barrier_verified"])
        self.assertEqual(receipt["status"], "CLOSURE_UNCONFIRMED_NO_ROLLBACK_AUTHORITY")

    def test_one_docker_failure_does_not_skip_other_stops(self):
        fixture = DockerFixture(manifest())
        fixture.stop_failure.add(fixture.value["containers"]["trusttunnel-runner"])
        receipt = self.expiry(fixture)
        self.assertEqual(len(receipt["stopped"]), 3)
        self.assertEqual(receipt["status"], "CLOSURE_UNCONFIRMED_NO_ROLLBACK_AUTHORITY")

    def test_foreign_or_changed_runtime_is_never_stopped(self):
        for change in ("scope", "image", "project", "service"):
            with self.subTest(change=change):
                fixture = DockerFixture(manifest())
                cid = fixture.value["containers"]["trusttunnel-runner"]
                item = fixture.items[cid]
                if change == "image":
                    item["Image"] = "sha256:" + "b" * 64
                else:
                    key = {"scope": "guardex.quota.rollout.scope", "project": "com.docker.compose.project",
                           "service": "com.docker.compose.service"}[change]
                    item["Config"]["Labels"][key] = "foreign"
                receipt = self.expiry(fixture)
                self.assertTrue(item["State"]["Running"])
                self.assertFalse(any(c[:2] == ["docker", "stop"] and c[-1] == cid for c in fixture.calls))
                self.assertEqual(len(receipt["stopped"]), 3)

    def test_disk_full_does_not_skip_barrier_or_any_stop(self):
        fixture = DockerFixture(manifest())
        with patch.object(guard, "save", side_effect=OSError("disk full")):
            receipt = self.expiry(fixture)
        self.assertTrue(receipt["barrier_verified"])
        self.assertEqual(len(receipt["stopped"]), 4)
        self.assertTrue(any(e.startswith("evidence_write_failed:") for e in receipt["errors"]))

    def test_stable_counters_are_retained_but_never_authorize_flags_or_ingress(self):
        fixture = DockerFixture(manifest())
        with tempfile.TemporaryDirectory() as root, patch.object(guard, "run", fixture.run), \
                patch.object(guard, "native_snapshot", return_value={"fixture": [17, 42]}), \
                patch.object(guard.time, "sleep"), patch.object(guard.time, "monotonic", side_effect=[1, 31.01]):
            receipt = guard.expire(fixture.value, Path(root))
            self.assertTrue(receipt["native_stable_30s"])
            self.assertTrue((Path(root) / "native-final-private.json").is_file())
        self.assertFalse(receipt["global_flags_changed"])
        self.assertFalse(receipt["legacy_ingress_restored"])
        self.assertTrue(all(c[0] in ("nft", "docker") for c in fixture.calls))

    def test_fixed_deadline_units_survive_reboot_and_cannot_slide(self):
        value = manifest(); root = guard.BASE / value["scope"]
        units = guard.unit_sources(value, root)
        timer = units["guardex-qf-" + SCOPE + ".timer"]
        self.assertIn("OnCalendar=2026-11-06 00:10:00 UTC", timer)
        self.assertIn("Persistent=true", timer)
        self.assertNotIn("OnActiveSec", timer)
        service = units["guardex-qf-" + SCOPE + ".service"]
        self.assertIn("--if-due --expire", service)
        self.assertIn("WantedBy=multi-user.target", service)
        self.assertEqual(units, guard.unit_sources(value, root))

    def test_manifest_rejects_control_ports_duplicate_ids_and_noncanonical_scope(self):
        for field, replacement in [("ingress_ports", [443, 22]), ("ingress_ports", [443, 1987]),
                                    ("ingress_ports", [443, 443]), ("scope", "../" + SCOPE),
                                    ("image", "latest"), ("deadline_epoch", True)]:
            value = manifest(); value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                guard.validate_manifest(value)
        value = manifest(); value["containers"]["node-agent"] = value["containers"]["quota-broker"]
        with self.assertRaises(ValueError):
            guard.validate_manifest(value)

    def test_kernel_fixture_accepts_counters_but_rejects_weakened_rules(self):
        self.assertTrue(barrier.inspect(SCOPE, PORTS, DOCUMENT))
        for edit in ("accept", "port", "hook", "extra"):
            document = copy.deepcopy(DOCUMENT)
            rule = next(x["rule"] for x in document["nftables"] if "rule" in x)
            if edit == "accept": rule["expr"][-1] = {"accept": None}
            elif edit == "port": rule["expr"][2]["match"]["right"]["set"] = [443]
            elif edit == "hook": next(x["chain"] for x in document["nftables"] if "chain" in x)["prio"] = 100
            else: document["nftables"].append({"rule": copy.deepcopy(rule)})
            with self.subTest(edit=edit):
                self.assertFalse(barrier.inspect(SCOPE, PORTS, document))

    def test_seal_rejects_missing_duplicate_external_paths_and_manifest_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("guard.py", "barrier.py", "manifest.json"):
                (root / name).write_text("fixture " + name)
            lines = [hashlib.sha256((root / name).read_bytes()).hexdigest() + "  " + name
                     for name in ("guard.py", "barrier.py", "manifest.json")]
            seal = root / "source.sha256"
            seal.write_text("\n".join(lines) + "\n")
            guard.verify_seal(root)
            for invalid in (lines[:2], lines + [lines[0]], lines + ["0" * 64 + "  ../outside"]):
                seal.write_text("\n".join(invalid) + "\n")
                with self.assertRaises(ValueError):
                    guard.verify_seal(root)
            seal.write_text("\n".join(lines) + "\n")
            (root / "manifest.json").write_text("changed deadline")
            with self.assertRaises(ValueError):
                guard.verify_seal(root)


if __name__ == "__main__":
    unittest.main()
