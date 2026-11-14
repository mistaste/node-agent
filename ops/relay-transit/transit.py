#!/usr/bin/env python3
"""Fixed, opaque Germany TLS transit over the existing authenticated backhaul."""
import argparse
import asyncio
import ipaddress
import json
import os
import signal
import socket
import ssl
import stat
import subprocess

TABLE = 'guardex_relay_transit_de'
COMMENT = 'guardex-transit-de-24443'
PREFIX = ipaddress.ip_network('10.79.240.0/28')


def validate(config):
    if set(config) != {'role', 'public_address', 'via_address', 'hostname'}:
        raise ValueError('unexpected configuration fields')
    if config['role'] not in ('forward', 'select'):
        raise ValueError('invalid role')
    public = ipaddress.IPv4Address(config['public_address'])
    via = ipaddress.IPv4Address(config['via_address'])
    # Deliberately scoped: this service is not an arbitrary destination proxy.
    if str(public) != '207.241.172.230' or str(via) != '10.79.240.2':
        raise ValueError('unexpected Germany transit destination')
    if config['hostname'] != 'frankfurt.de.guardex-vpn.com':
        raise ValueError('unexpected TLS identity')
    return config


def load(path):
    info = os.stat(path)
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError('configuration must be root-owned and not writable by others')
    with open(path, encoding='utf-8') as source:
        return validate(json.load(source))


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, timeout=5, **kwargs)


def firewall(action):
    state = json.loads(run(['nft', '-j', '-a', 'list', 'chain', 'inet',
        'guardex_relay_backhaul_guard', 'input']).stdout)
    handles = [item['rule']['handle'] for item in state['nftables']
        if 'rule' in item and item['rule'].get('comment') == COMMENT]
    if action == 'allow' and not handles:
        run(['nft', 'insert', 'rule', 'inet', 'guardex_relay_backhaul_guard',
            'input', 'iifname', 'gxrelay0', 'ip', 'saddr', '10.79.240.1',
            'ip', 'daddr', '10.79.240.2', 'tcp', 'dport', '24443',
            'accept', 'comment', '"' + COMMENT + '"'])
    elif action == 'remove':
        for handle in handles:
            run(['nft', 'delete', 'rule', 'inet', 'guardex_relay_backhaul_guard',
                'input', 'handle', str(handle)])


def nft_script(config):
    validate(config)
    return f'''table ip {TABLE} {{
 chain output {{
  type nat hook output priority -103; policy accept;
  ip daddr {config['public_address']} tcp dport 443 dnat to {config['via_address']}:24443
 }}
 chain postrouting {{
  type nat hook postrouting priority 99; policy accept;
  oifname "gxrelay0" ip daddr {config['via_address']} tcp dport 24443 snat to 10.79.240.1
 }}
}}
'''


def remove_route():
    subprocess.run(['nft', 'delete', 'table', 'ip', TABLE],
        capture_output=True, timeout=5, check=False)


class Health:
    def __init__(self):
        self.enabled = False
        self.successes = self.failures = 0

    def observe(self, success):
        if success:
            self.failures = 0
            self.successes += 1
            if self.successes >= 3:
                self.enabled = True
        else:
            self.successes = 0
            self.failures += 1
            if self.failures >= 2:
                self.enabled = False
        return self.enabled


async def tls_health(config):
    writer = None
    context = ssl.create_default_context()
    context.set_alpn_protocols(['h2'])
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(
            config['via_address'], 24443, ssl=context,
            server_hostname=config['hostname']), 4)
        return True
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return False
    finally:
        if writer:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, asyncio.TimeoutError):
                pass


class Forwarder:
    def __init__(self, target, source='10.79.240.1', limit=1024):
        self.target, self.source, self.limit = target, source, limit
        self.active = 0
        self.tasks = set()

    @staticmethod
    def keepalive(writer):
        connection = writer.get_extra_info('socket')
        if connection:
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            for name, value in [('TCP_KEEPIDLE', 60), ('TCP_KEEPINTVL', 15), ('TCP_KEEPCNT', 4)]:
                if hasattr(socket, name):
                    connection.setsockopt(socket.IPPROTO_TCP, getattr(socket, name), value)

    @staticmethod
    async def copy(reader, writer):
        while True:
            data = await reader.read(65536)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 45)

    async def handle(self, reader, writer):
        peer = writer.get_extra_info('peername')
        if not peer or peer[0] != self.source or self.active >= self.limit:
            writer.close()
            return
        self.active += 1
        task = asyncio.current_task()
        self.tasks.add(task)
        upstream = None
        copies = []
        try:
            remote, upstream = await asyncio.wait_for(
                asyncio.open_connection(*self.target), 5)
            self.keepalive(writer)
            self.keepalive(upstream)
            copies = [asyncio.create_task(self.copy(reader, upstream)),
                asyncio.create_task(self.copy(remote, writer))]
            await asyncio.gather(*copies)
        except (OSError, asyncio.TimeoutError):
            pass
        finally:
            for copy in copies:
                copy.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            for connection in [writer, upstream]:
                if connection:
                    connection.close()
            self.active -= 1
            self.tasks.discard(task)

    async def close(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def serve(config):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    if config['role'] == 'forward':
        forwarder = Forwarder((config['public_address'], 443))
        server = await asyncio.start_server(forwarder.handle,
            config['via_address'], 24443, limit=65536)
        try:
            async with server:
                await stop.wait()
        finally:
            await forwarder.close()
        return
    health = Health()
    installed = False
    remove_route()
    try:
        while not stop.is_set():
            selected = health.observe(await tls_health(config))
            if selected != installed:
                if selected:
                    run(['nft', '-f', '-'], input=nft_script(config), text=True)
                else:
                    remove_route()
                installed = selected
                print(json.dumps({'germany_transit_enabled': installed}), flush=True)
            try:
                await asyncio.wait_for(stop.wait(), 10)
            except asyncio.TimeoutError:
                pass
    finally:
        remove_route()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('run', 'check', 'allow', 'remove'))
    parser.add_argument('--config', default='/etc/guardex-relay-transit.json')
    args = parser.parse_args()
    config = load(args.config)
    if args.action in ('allow', 'remove'):
        if config['role'] != 'forward':
            raise ValueError('firewall action requires forward role')
        firewall(args.action)
    elif args.action == 'run':
        asyncio.run(serve(config))
    else:
        print('Germany transit configuration valid')


if __name__ == '__main__':
    main()
