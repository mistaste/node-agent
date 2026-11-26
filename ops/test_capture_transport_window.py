#!/usr/bin/env python3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import capture_transport_window as capture


class CaptureTransportWindowTest(unittest.TestCase):
    def test_filter_normalizes_and_deduplicates_ports(self):
        self.assertEqual(
            capture.capture_filter(["192.0.2.10", "2001:db8::1"], [4443, 443, 443]),
            "tcp and (host 192.0.2.10 or host 2001:db8::1) and (port 443 or port 4443)",
        )

    def test_filter_without_peers_is_port_bounded(self):
        self.assertEqual(
            capture.capture_filter([], [443, 4443]),
            "tcp and (port 443 or port 4443)",
        )

    def test_rejects_injection_and_invalid_values(self):
        for peer in ["1.2.3.4 or net 0/0", "$(whoami)", "; rm -rf /", "::1%lo0"]:
            with self.assertRaises(ValueError):
                capture.capture_filter([peer], [443])
        for ports in [[], [0], [65536]]:
            with self.assertRaises(ValueError):
                capture.capture_filter([], ports)
        with self.assertRaises(ValueError):
            capture.command("-any", Path("out.pcap"), [], [443])

    def test_stop_escalates_only_after_graceful_timeout(self):
        process = mock.Mock()
        process.wait.side_effect = [capture.subprocess.TimeoutExpired("tcpdump", 10), 0]
        with self.assertRaisesRegex(RuntimeError, "did not stop gracefully"):
            capture.stop(process)
        process.send_signal.assert_called_once_with(capture.signal.SIGINT)
        process.kill.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
