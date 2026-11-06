"""Render an owned local-ingress barrier. Importing this module has no effects."""
import uuid


# These are management/control ports, never VPN ingress. Reject a mistaken
# inventory instead of cutting off the operator or final counter collectors.
CONTROL_PORTS = frozenset((22, 1987, 2019, 8099))


def normalize(scope, ports):
    canonical = str(uuid.UUID(scope))
    if canonical != scope:
        raise ValueError("canonical scope UUID required")
    if not isinstance(ports, list) or not ports or len(ports) > 128:
        raise ValueError("actual ingress port inventory required")
    if any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
        raise ValueError("invalid ingress port")
    if len(set(ports)) != len(ports) or set(ports) & CONTROL_PORTS:
        raise ValueError("duplicate or protected control port in ingress inventory")
    return "gx_qf_" + uuid.UUID(scope).hex, sorted(ports)


def render(scope, ports):
    table, ordered = normalize(scope, ports)
    selected = ", ".join(map(str, ordered))
    # An inet table covers IPv4 and IPv6, including extension headers. The
    # pre-conntrack hook also drops established flows and runs before DNAT.
    # fib local limits this to the host's ingress, preserving transit traffic
    # and outbound API replies. Output covers local cached/loopback listeners.
    rule = ("fib daddr type local meta l4proto { tcp, udp } "
            "th dport { " + selected + " } counter drop")
    return (f"table inet {table} {{\n"
            " chain ingress {\n"
            "  type filter hook prerouting priority -310; policy accept;\n"
            f"  {rule}\n }}\n"
            " chain local_ingress {\n"
            "  type filter hook output priority -310; policy accept;\n"
            f"  {rule}\n }}\n}}\n")


def inspect(scope, ports, document):
    """Accept only our exact structural rules; counters/handles may advance."""
    table, ordered = normalize(scope, ports)
    objects = document.get("nftables", [])
    tables = [x["table"] for x in objects if "table" in x]
    chains = [x["chain"] for x in objects if "chain" in x]
    rules = [x["rule"] for x in objects if "rule" in x]
    if any(set(x) - {"metainfo", "table", "chain", "rule"} for x in objects):
        return False
    if len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != table:
        return False
    expected = {"ingress": "prerouting", "local_ingress": "output"}
    if len(chains) != 2 or {c.get("name") for c in chains} != set(expected):
        return False
    for chain in chains:
        if (chain.get("family"), chain.get("table"), chain.get("type"),
                chain.get("hook"), chain.get("prio"), chain.get("policy")) != (
                "inet", table, "filter", expected[chain["name"]], -310, "accept"):
            return False
    if len(rules) != 2 or {r.get("chain") for r in rules} != set(expected):
        return False
    # nft's JSON uses set elements in the input order; accept canonical set
    # ordering while rejecting extra accepts, jumps, expressions or rules.
    for rule in rules:
        if rule.get("family") != "inet" or rule.get("table") != table:
            return False
        expr = rule.get("expr")
        if not isinstance(expr, list) or len(expr) != 5:
            return False
        wanted = [
            {"match": {"op": "==", "left": {"fib": {"result": "type", "flags": ["daddr"]}}, "right": "local"}},
            {"match": {"op": "==", "left": {"meta": {"key": "l4proto"}}, "right": {"set": ["tcp", "udp"]}}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "th", "field": "dport"}}, "right": {"set": ordered}}},
        ]
        if expr[:3] != wanted or set(expr[3]) != {"counter"} or expr[4] != {"drop": None}:
            return False
    return True
