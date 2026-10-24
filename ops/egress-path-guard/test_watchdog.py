import base64
import json
import pathlib
import tempfile
import unittest
from unittest import mock

import watchdog

KEY = base64.b64encode(bytes(range(32))).decode()
CONFIG = {"interface": "gxwg0", "peer_public_key": KEY, "probe_ip": "10.77.0.14",
          "endpoints": ["94.249.195.63:443", "[2a14:7c0:1002:19c4::]:443"]}


class RecoveryTest(unittest.TestCase):
    def underlay_rule(self):
        def match(left, right):
            return {"match": {"op": "==", "left": left, "right": right}}
        return {"comment": "guardex_egress_ipv6_underlay", "expr": [
            match({"meta": {"key": "skuid"}}, 65532),
            match({"payload": {"protocol": "ip6", "field": "daddr"}}, "2a14:7c0:1002:19c4::"),
            match({"payload": {"protocol": "udp", "field": "sport"}}, 51821),
            match({"payload": {"protocol": "udp", "field": "dport"}}, 443), {"accept": None}]}

    def test_underlay_rule_requires_all_four_exact_restrictions(self):
        rule = self.underlay_rule()
        self.assertTrue(watchdog.valid_underlay_rule(rule, "2a14:7c0:1002:19c4::", 51821))
        for index in range(4):
            broad = {**rule, "expr": [x for i, x in enumerate(rule["expr"]) if i != index]}
            self.assertFalse(watchdog.valid_underlay_rule(broad, "2a14:7c0:1002:19c4::", 51821))
        self.assertFalse(watchdog.valid_underlay_rule(rule, "2606:4700:4700::1111", 51821))
        self.assertFalse(watchdog.valid_underlay_rule(rule, "2a14:7c0:1002:19c4::", 51824))

    def test_underlay_policy_is_restored_after_topology_recreates_chain(self):
        config = {**CONFIG, "ensure_underlay_policy": True, "listen_port": 51821}
        with mock.patch("watchdog.command", side_effect=[KEY, KEY+"\t"+CONFIG["endpoints"][0],
                                                       "51821", '{"nftables": []}', ""]) as command:
            watchdog.Runtime(config).ensure_underlay_policy()
            args = command.call_args.args
            self.assertIn("65532", args)
            self.assertIn("2a14:7c0:1002:19c4::", args)
            self.assertEqual(args[args.index("sport")+1], "51821")
            self.assertEqual(args[args.index("dport")+1], "443")

    def test_underlay_policy_refuses_changed_wg_source_port(self):
        config = {**CONFIG, "ensure_underlay_policy": True, "listen_port": 51821}
        with mock.patch("watchdog.command", side_effect=[KEY, KEY+"\t"+CONFIG["endpoints"][0], "51824"]) as command:
            with self.assertRaisesRegex(RuntimeError, "source port"):
                watchdog.Runtime(config).ensure_underlay_policy()
            self.assertFalse(any("nft" in c.args for c in command.call_args_list))

    def test_transient_loss_does_not_switch_and_success_resets_failure(self):
        health = watchdog.Health()
        self.assertFalse(health.observe(False, 0))
        self.assertFalse(health.observe(True, 5))
        self.assertFalse(health.observe(False, 10))
        self.assertTrue(health.observe(False, 15))

    def test_cooldown_prevents_flapping_when_both_paths_fail(self):
        health = watchdog.Health()
        health.observe(False, 0)
        self.assertTrue(health.observe(False, 5))
        health.switched(5)
        for now in (10, 15, 20, 30):
            self.assertFalse(health.observe(False, now))
        self.assertTrue(health.observe(False, 35))

    def test_healthy_secondary_does_not_trigger_disruptive_failback(self):
        health = watchdog.Health()
        health.switched(5)
        for now in range(10, 300, 5):
            self.assertFalse(health.observe(True, now))

    def test_config_rejects_foreign_interface_or_untrusted_paths(self):
        for field, value in [("interface", "gxrelay0"), ("probe_ip", "1.1.1.1"),
                             ("peer_public_key", "not-a-key"),
                             ("endpoints", ["94.249.195.63:443", "[::1]:443"]),
                             ("endpoints", ["94.249.195.63:51820", "[2a14:7c0:1002:19c4::]:443"])]:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory)/"config.json"
                path.write_text(json.dumps({**CONFIG, field: value}))
                with self.assertRaises(ValueError):
                    watchdog.load_config(path)

    def test_valid_config_preserves_exact_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory)/"config.json"
            path.write_text(json.dumps(CONFIG))
            self.assertEqual(watchdog.load_config(path), CONFIG)

    def test_switch_never_overwrites_foreign_or_shared_peer(self):
        for peers in ("foreign", KEY+"\nforeign", ""):
            with self.subTest(peers=peers), mock.patch("watchdog.command", return_value=peers) as command:
                with self.assertRaises(RuntimeError):
                    watchdog.Runtime(CONFIG).switch(CONFIG["endpoints"][1])
                self.assertTrue(all("set" not in call.args for call in command.call_args_list))

    def test_unknown_runtime_endpoint_is_preserved(self):
        with mock.patch("watchdog.command", side_effect=[KEY, KEY+"\t8.8.8.8:443"]) as command:
            with self.assertRaises(RuntimeError):
                watchdog.Runtime(CONFIG).switch(CONFIG["endpoints"][1])
            self.assertEqual(command.call_count, 2)

    def test_switch_only_mutates_endpoint_after_identity_validation(self):
        with mock.patch("watchdog.command", side_effect=[KEY, KEY+"\t"+CONFIG["endpoints"][0], ""]) as command:
            watchdog.Runtime(CONFIG).switch(CONFIG["endpoints"][1])
            self.assertEqual(command.call_args.args,
                             ("wg", "set", "gxwg0", "peer", KEY, "endpoint", CONFIG["endpoints"][1]))


if __name__ == "__main__":
    unittest.main()
