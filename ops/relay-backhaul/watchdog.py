#!/usr/bin/env python3
"""Select authenticated WireGuard backhauls, retaining the public TCP fallback."""
import argparse
import concurrent.futures
import ipaddress
import json
import subprocess
import time

TABLE = 'guardex_relay_backhaul'
INTERFACE = 'gxrelay0'
PREFIX = ipaddress.ip_network('10.79.240.0/28')


def load_config(path):
    with open(path, encoding='utf-8') as source:
        config = json.load(source)
    if config.get('interface') != INTERFACE:
        raise ValueError('unexpected backhaul interface')
    peers = config.get('peers', [])
    if not 1 <= len(peers) <= 12:
        raise ValueError('expected one to twelve peers')
    public, private = set(), set()
    for peer in peers:
        outer = ipaddress.IPv4Address(peer['public_ip'])
        inner = ipaddress.IPv4Address(peer['private_ip'])
        if not outer.is_global or inner not in PREFIX or int(inner) - int(PREFIX.network_address) not in range(2, 15):
            raise ValueError('invalid backhaul peer address')
        if str(outer) in public or str(inner) in private:
            raise ValueError('duplicate backhaul peer')
        public.add(str(outer))
        private.add(str(inner))
    return peers


def nft_initial():
    # No rule ever decrypts, forwards between hosts, or changes a client-facing
    # endpoint. An absent map entry follows the existing public/SSH path.
    return f'''table ip {TABLE} {{
 map healthy_peers {{ type ipv4_addr : ipv4_addr; }}
 chain output {{
  type nat hook output priority -102; policy accept;
  tcp dport 443 dnat to ip daddr map @healthy_peers
 }}
 chain postrouting {{
  type nat hook postrouting priority 100; policy accept;
  oifname "{INTERFACE}" ip daddr {PREFIX} tcp dport 443 snat to 10.79.240.1
 }}
}}
'''


def nft_update(peers, healthy):
    rows = [f'flush map ip {TABLE} healthy_peers']
    entries = [f"{p['public_ip']} : {p['private_ip']}" for p in peers if p['public_ip'] in healthy]
    if entries:
        rows.append(f"add element ip {TABLE} healthy_peers {{ {', '.join(entries)} }}")
    return '\n'.join(rows) + '\n'


class Health:
    def __init__(self):
        self.healthy = set()
        self.successes = {}
        self.failures = {}

    def observe(self, public_ip, success):
        if success:
            self.failures[public_ip] = 0
            self.successes[public_ip] = self.successes.get(public_ip, 0) + 1
            if self.successes[public_ip] >= 2:
                self.healthy.add(public_ip)
        else:
            self.successes[public_ip] = 0
            self.failures[public_ip] = self.failures.get(public_ip, 0) + 1
            if self.failures[public_ip] >= 2:
                self.healthy.discard(public_ip)


def probe(peer):
    try:
        result = subprocess.run(['/usr/bin/ping', '-n', '-c', '1', '-W', '1', '-I', INTERFACE, peer['private_ip']],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return peer['public_ip'], result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return peer['public_ip'], False


def nft(script):
    subprocess.run(['/usr/sbin/nft', '-f', '-'], input=script, text=True, check=True, timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', default='/etc/guardex-relay-backhaul/config.json')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    peers = load_config(args.config)
    if args.check:
        print('backhaul configuration valid')
        return
    nft(nft_initial())
    health = Health()
    installed = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(peers)) as pool:
        while True:
            started = time.monotonic()
            for address, success in pool.map(probe, peers):
                health.observe(address, success)
            if installed != health.healthy:
                nft(nft_update(peers, health.healthy))
                installed = set(health.healthy)
                print(json.dumps({'healthy_backhauls': sorted(installed)}), flush=True)
            time.sleep(max(.1, 5 - (time.monotonic() - started)))


if __name__ == '__main__':
    main()
