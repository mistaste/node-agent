import importlib.util
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("relay_mss", ROOT / "firewall/guardex-relay-tcp-mss.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
POLICY = ROOT / "firewall/guardex-relay-tcp-mss.nft"


class PolicyTests(unittest.TestCase):
    def test_validation_failure_cannot_mutate_live_policy(self):
        with patch.object(MODULE, "exists", return_value=True), patch.object(
            MODULE.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "nft")
        ) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                MODULE.apply(POLICY)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], ["nft", "-c", "-f", "-"])

    def test_reload_validates_then_replaces_only_owned_table_in_one_transaction(self):
        with patch.object(MODULE, "exists", return_value=True), patch.object(MODULE.subprocess, "run") as run:
            MODULE.apply(POLICY)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args_list[0].kwargs["input"], run.call_args_list[1].kwargs["input"])
        self.assertTrue(run.call_args.kwargs["input"].startswith("delete table inet guardex_relay_tcp_mss\n"))
        self.assertEqual(run.call_args.args[0], ["nft", "-f", "-"])

    def test_check_is_read_only_and_rejects_foreign_tables(self):
        with patch.object(MODULE, "exists", return_value=False), patch.object(MODULE.subprocess, "run") as run:
            MODULE.apply(POLICY, check_only=True)
        self.assertEqual(run.call_count, 1)
        with self.assertRaises(ValueError):
            MODULE.transaction("table inet guardex_transport { }")

    def test_rollback_cannot_flush_topology_or_other_firewall_tables(self):
        with patch.object(MODULE, "exists", return_value=True), patch.object(MODULE.subprocess, "run") as run:
            MODULE.remove()
        run.assert_called_once_with(["nft", "delete", "table", "inet", "guardex_relay_tcp_mss"], check=True)


if __name__ == "__main__":
    unittest.main()
