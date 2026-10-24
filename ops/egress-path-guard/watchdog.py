#!/usr/bin/env python3
"""Recover one authenticated WG egress peer through independent IPv4/IPv6 paths."""
import argparse
import base64
import ipaddress
import json
import subprocess
import time


def load_config(path):
    with open(path, encoding="utf-8") as source:
        config = json.load(source)
    if config.get("interface") != "gxwg0":
        raise ValueError("only the ingress egress interface is supported")
    key = config.get("peer_public_key", "")
    if len(base64.b64decode(key, validate=True)) != 32:
        raise ValueError("invalid public peer identity")
    probe = ipaddress.IPv4Address(config["probe_ip"])
    if probe not in ipaddress.ip_network("10.77.0.0/16"):
        raise ValueError("probe must address the authenticated private exit")
    endpoints = config.get("endpoints", [])
    if len(endpoints) != 2:
        raise ValueError("exactly one IPv4 and one IPv6 endpoint are required")
    for endpoint, family in zip(endpoints, (4, 6)):
        host, separator, port = endpoint.rpartition(":")
        address = ipaddress.ip_address(host.strip("[]"))
        if separator != ":" or port != "443" or address.version != family or not address.is_global:
            raise ValueError("expected public IPv4/IPv6 endpoints on the existing exit port")
        canonical = f"[{address}]:443" if family == 6 else f"{address}:443"
        if endpoint != canonical:
            raise ValueError("endpoint must use a canonical literal address")
    if type(config.get("ensure_underlay_policy", False)) is not bool:
        raise ValueError("underlay policy activation must be explicit")
    if config.get("ensure_underlay_policy") and (type(config.get("listen_port")) is not int
            or not 1024 <= config["listen_port"] <= 65535):
        raise ValueError("the existing WireGuard source port must be pinned")
    return config


def command(*args):
    return subprocess.check_output(args, text=True, timeout=8).strip()


class Runtime:
    def __init__(self, config):
        self.config = config

    def endpoint(self):
        peers = command("wg", "show", "gxwg0", "peers").splitlines()
        if peers != [self.config["peer_public_key"]]:
            raise RuntimeError("refusing to change a missing, foreign or shared peer")
        rows = command("wg", "show", "gxwg0", "endpoints").splitlines()
        if len(rows) != 1:
            raise RuntimeError("unexpected endpoint set")
        key, endpoint = rows[0].split()
        if key != peers[0] or endpoint not in self.config["endpoints"]:
            raise RuntimeError("refusing to overwrite an unconfigured endpoint")
        return endpoint

    def probe(self):
        # A recent handshake or open public TCP port does not prove the data path.
        result = subprocess.run(["ping", "-n", "-c", "1", "-W", "1", "-s", "1200",
                                 "-I", "gxwg0", self.config["probe_ip"]],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        return result.returncode == 0

    def switch(self, endpoint):
        # Revalidate the actual peer immediately before the only mutation.
        self.endpoint()
        if endpoint not in self.config["endpoints"]:
            raise ValueError("unconfigured destination")
        command("wg", "set", "gxwg0", "peer", self.config["peer_public_key"], "endpoint", endpoint)

    def ensure_underlay_policy(self, *, create=True):
        if not self.config.get("ensure_underlay_policy"):
            return
        self.endpoint()
        port = self.config["listen_port"]
        if int(command("wg", "show", "gxwg0", "listen-port")) != port:
            raise RuntimeError("refusing to authorize an unconfigured source port")
        address = self.config["endpoints"][1].rpartition(":")[0].strip("[]")
        marker = "guardex_egress_ipv6_underlay"
        data = json.loads(command("nft", "-j", "list", "chain", "inet", "guardex_transport", "output"))
        rules = [entry["rule"] for entry in data["nftables"] if entry.get("rule", {}).get("comment") == marker]
        if len(rules) > 1:
            raise RuntimeError("duplicate underlay policy requires operator review")
        if rules:
            if not valid_underlay_rule(rules[0], address, port):
                raise RuntimeError("refusing to overwrite a different underlay policy")
        elif create:
            # WG outer packets can retain the originating transport UID. Root
            # probes and cross-netns tests can miss this owner-policy failure.
            command("nft", "insert", "rule", "inet", "guardex_transport", "output",
                    "meta", "skuid", "65532", "ip6", "daddr", address,
                    "udp", "sport", str(port), "udp", "dport", "443", "counter", "accept",
                    "comment", '"'+marker+'"')


def valid_underlay_rule(rule, address, port):
    def condition(left, right):
        return json.dumps({"left": left, "right": right}, sort_keys=True)
    required = {condition({"meta": {"key": "skuid"}}, 65532),
                condition({"payload": {"protocol": "ip6", "field": "daddr"}}, address),
                condition({"payload": {"protocol": "udp", "field": "sport"}}, port),
                condition({"payload": {"protocol": "udp", "field": "dport"}}, 443)}
    allowed = required | {condition({"meta": {"key": "l4proto"}}, value) for value in ("udp", 17)}
    seen, accepts = set(), 0
    for expr in rule.get("expr", []):
        if "match" in expr:
            match = expr["match"]
            if match.get("op") != "==":
                return False
            seen.add(condition(match.get("left"), match.get("right")))
        elif expr == {"accept": None}:
            accepts += 1
        elif set(expr) != {"counter"}:
            return False
    return required <= seen <= allowed and accepts == 1


class Health:
    def __init__(self):
        self.failures = 0
        self.last_switch = None

    def observe(self, success, now):
        if success:
            self.failures = 0
            return False
        self.failures += 1
        return self.failures >= 2 and (self.last_switch is None or now - self.last_switch >= 30)

    def switched(self, now):
        self.last_switch = now
        self.failures = 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/guardex-egress-path/config.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = load_config(args.config)
    runtime = Runtime(config)
    current = runtime.endpoint()
    if args.check:
        runtime.ensure_underlay_policy(create=False)
        print("egress path configuration and peer identity valid")
        return
    health = Health()
    while True:
        started = time.monotonic()
        try:
            current = runtime.endpoint()
            runtime.ensure_underlay_policy()
            if health.observe(runtime.probe(), started):
                target = config["endpoints"][1 - config["endpoints"].index(current)]
                runtime.switch(target)
                health.switched(started)
                print(json.dumps({"event": "egress_endpoint_switched", "from": current,
                                  "to": target, "time": time.time()}), flush=True)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
            print(json.dumps({"event": "egress_path_check_failed", "error": str(error)}), flush=True)
        time.sleep(max(.1, 2 - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
