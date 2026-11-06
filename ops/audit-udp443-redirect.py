#!/usr/bin/env python3
"""Read-only audit of native UDP443 rule semantics, including nft/xt projections.

Some iptables-save versions omit a native nft UDP destination-port expression.
Never infer an all-port redirect from that text alone or repair by line number.
"""
import hashlib
import json
import shlex
import subprocess


def inspect(native, saved):
    rules = [item['rule'] for item in native['nftables'] if 'rule' in item]
    lines = [line for line in saved.splitlines()
             if ' -A PREROUTING ' in line or line.startswith('-A PREROUTING ')]
    if len(rules) != len(lines):
        raise ValueError('Native/projection rule count mismatch; semantics UNKNOWN')
    result = []
    for rule, line in zip(rules, lines):
        words = shlex.split(line)
        if '--comment' not in words:
            continue
        if words[words.index('--comment') + 1] != 'guardex-tt-h3-mux':
            continue
        if words[words.index('-j') + 1] != 'REDIRECT':
            raise ValueError('Unrecognized owned redirect target')
        if '--to-ports' not in words or words[words.index('--to-ports') + 1] != '18443':
            raise ValueError('Unrecognized owned destination port')
        udp = False
        ports = []
        for expr in rule['expr']:
            match = expr.get('match', {})
            left = match.get('left', {})
            if not isinstance(left, dict):
                continue
            if left.get('meta', {}).get('key') == 'l4proto':
                udp = match.get('op') == '==' and match.get('right') == 'udp'
            payload = left.get('payload', {})
            if payload.get('protocol') == 'udp' and payload.get('field') == 'dport':
                if match.get('op') != '==':
                    raise ValueError('Unrecognized native destination-port predicate')
                ports.append(match.get('right'))
        if ports == [443]:
            status = 'SCOPED_TO_UDP443'
        elif udp and not ports:
            status = 'UNSAFE_CATCH_ALL_UDP'
        else:
            raise ValueError('Owned native UDP semantics UNKNOWN')
        result.append({'handle': rule['handle'], 'status': status,
                       'actual_udp_destination_ports': ports})
    if not result:
        raise ValueError('Expected owned UDP443 redirect missing')
    return result


def main():
    native_raw = subprocess.check_output(
        ['nft', '-j', 'list', 'chain', 'ip', 'nat', 'PREROUTING'], timeout=5)
    saved = subprocess.check_output(['iptables-save', '-c', '-t', 'nat'], timeout=5)
    rows = inspect(json.loads(native_raw), saved.decode())
    safe = all(row['status'] == 'SCOPED_TO_UDP443' for row in rows)
    print(json.dumps({'read_only': True, 'safe_udp443_scope': safe, 'rules': rows,
                      'native_snapshot_sha256': hashlib.sha256(native_raw).hexdigest(),
                      'projection_sha256': hashlib.sha256(saved).hexdigest()}))
    raise SystemExit(0 if safe else 1)


if __name__ == '__main__':
    main()
