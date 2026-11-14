import asyncio
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location('transit', pathlib.Path(__file__).with_name('transit.py'))
transit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transit)
CONFIG = dict(role='select', public_address='207.241.172.230',
    via_address='10.79.240.2', hostname='frankfurt.de.guardex-vpn.com')


class PolicyTest(unittest.TestCase):
    def test_scope_and_config_validation(self):
        self.assertEqual(transit.validate(CONFIG), CONFIG)
        for change in [dict(public_address='1.1.1.1'), dict(via_address='10.79.240.1'),
            dict(hostname='wrong.example'), dict(role='invalid'), dict(extra=True)]:
            with self.assertRaises(ValueError):
                transit.validate({**CONFIG, **change})

    def test_qualification_and_public_fallback_hysteresis(self):
        health = transit.Health()
        self.assertFalse(health.observe(True))
        self.assertFalse(health.observe(True))
        self.assertTrue(health.observe(True))
        self.assertTrue(health.observe(False))
        self.assertFalse(health.observe(False))
        self.assertFalse(health.observe(True))

    def test_only_germany_output_and_exact_private_source_are_changed(self):
        rules = transit.nft_script(CONFIG)
        self.assertIn('ip daddr 207.241.172.230 tcp dport 443 dnat to 10.79.240.2:24443', rules)
        self.assertIn('priority -103', rules)
        self.assertIn('tcp dport 24443 snat to 10.79.240.1', rules)
        self.assertNotIn('forward {', rules)


class ForwarderTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.forwarders = []

    async def asyncTearDown(self):
        for server in self.servers:
            server.close()
            await server.wait_closed()
        for forwarder in self.forwarders:
            await forwarder.close()

    async def make(self, handler, source='127.0.0.1', limit=1024):
        target = await asyncio.start_server(handler, '127.0.0.1', 0)
        self.servers.append(target)
        forwarder = transit.Forwarder(target.sockets[0].getsockname(), source, limit)
        self.forwarders.append(forwarder)
        relay = await asyncio.start_server(forwarder.handle, '127.0.0.1', 0)
        self.servers.append(relay)
        return forwarder, await asyncio.open_connection(*relay.sockets[0].getsockname())

    async def test_bidirectional_two_mib_and_half_close(self):
        async def target(reader, writer):
            received = await reader.read()
            self.assertEqual(received, b'U' * 2097152)
            writer.write(b'D' * 2097152)
            await writer.drain()
            writer.close()
        forwarder, (reader, writer) = await self.make(target)
        writer.write(b'U' * 2097152)
        await writer.drain()
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 5), b'D' * 2097152)
        writer.close()
        await writer.wait_closed()
        await forwarder.close()
        self.assertEqual(forwarder.active, 0)

    async def test_untrusted_peer_and_capacity_do_not_open_target(self):
        calls = 0
        async def target(reader, writer):
            nonlocal calls
            calls += 1
            writer.close()
        for source, limit in [('10.79.240.1', 10), ('127.0.0.1', 0)]:
            _, (reader, writer) = await self.make(target, source, limit)
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
            writer.close()
            await writer.wait_closed()
        self.assertEqual(calls, 0)

    async def test_shutdown_joins_active_flows(self):
        connected = asyncio.Event()
        async def target(reader, writer):
            connected.set()
            await reader.read()
            writer.close()
        forwarder, (reader, writer) = await self.make(target)
        await asyncio.wait_for(connected.wait(), 1)
        await forwarder.close()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b'')
        self.assertEqual(forwarder.active, 0)
        writer.close()
        await writer.wait_closed()


if __name__ == '__main__':
    unittest.main()
