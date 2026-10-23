import importlib.util
import json
import pathlib
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('watchdog', pathlib.Path(__file__).with_name('watchdog.py'))
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)
PEER = {'public_ip': '5.255.124.73', 'private_ip': '10.79.240.2'}


class WatchdogTest(unittest.TestCase):
    def test_hysteresis_recovers_and_falls_back_independently(self):
        state = watchdog.Health()
        for ip in ['5.255.124.73', '207.241.172.230']:
            state.observe(ip, True)
            self.assertNotIn(ip, state.healthy)
            state.observe(ip, True)
        state.observe('5.255.124.73', False)
        self.assertEqual(len(state.healthy), 2)
        state.observe('5.255.124.73', False)
        self.assertEqual(state.healthy, {'207.241.172.230'})
        state.observe('5.255.124.73', True)
        self.assertNotIn('5.255.124.73', state.healthy)
        state.observe('5.255.124.73', True)
        self.assertEqual(len(state.healthy), 2)

    def test_failed_probe_resets_recovery_evidence(self):
        state = watchdog.Health()
        for success in [True, False, True]:
            state.observe(PEER['public_ip'], success)
        self.assertFalse(state.healthy)

    def test_map_update_is_atomic_and_scoped_to_healthy_peers(self):
        self.assertEqual(watchdog.nft_update([PEER], set()), 'flush map ip guardex_relay_backhaul healthy_peers\n')
        script = watchdog.nft_update([PEER], {PEER['public_ip']})
        self.assertIn('5.255.124.73 : 10.79.240.2', script)
        self.assertIn('tcp dport 443', watchdog.nft_initial())
        self.assertNotIn('flush ruleset', script)

    def test_configuration_rejects_arbitrary_targets_and_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / 'config.json'
            for peer in [PEER, {'public_ip': '127.0.0.1', 'private_ip': '10.79.240.2'},
                         {'public_ip': '5.255.124.73', 'private_ip': '10.0.0.1'},
                         {'public_ip': '5.255.124.73; drop', 'private_ip': '10.79.240.2'}]:
                path.write_text(json.dumps({'interface': 'gxrelay0', 'peers': [peer]}))
                if peer == PEER:
                    self.assertEqual(watchdog.load_config(path), [PEER])
                else:
                    with self.assertRaises(ValueError): watchdog.load_config(path)
            path.write_text(json.dumps({'interface': 'gxrelay0', 'peers': [PEER, PEER]}))
            with self.assertRaises(ValueError): watchdog.load_config(path)


if __name__ == '__main__':
    unittest.main()
