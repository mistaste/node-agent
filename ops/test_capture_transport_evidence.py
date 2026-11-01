import unittest
from capture_transport_evidence import command
class CaptureTests(unittest.TestCase):
    def test_fixed_bounds_and_one_peer(self):
        argv = command("2001:db8::1",443,"any","private.pcap")
        self.assertIn("2000",argv)
        self.assertIn("128",argv)
        self.assertEqual(argv[-1],"host 2001:db8::1 and tcp port 443")
    def test_no_shell_injection_or_arbitrary_filter(self):
        for peer in ["1.2.3.4 or net 0/0","$(whoami)","; rm -rf /","example.com", "::1%zone or net ::/0"]:
            with self.assertRaises(ValueError):command(peer,443,"any","out")
        for port in [0,65536]:
            with self.assertRaises(ValueError):command("127.0.0.1",port,"any","out")
if __name__ == "__main__":unittest.main()
