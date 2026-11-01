import unittest
from summarize_transport_capture import summarize
class SummaryTests(unittest.TestCase):
    def test_directions_and_no_addresses(self):
        rows = ["1\t192.0.2.1\t\t1\t0\t0\t\t", "2\t192.0.2.2\t\t0\t0\t0\t\t1", "3\t192.0.2.1\t\t0\t0\t1\t1\t"]
        result = summarize(rows,"192.0.2.1")
        self.assertEqual(result,{"packets":3,"peer_syn":1,"local_tls_client_hello":1,"peer_rst":1,"peer_retransmission":1})
        self.assertNotIn("192.0.2",str(result))
    def test_truncated_and_malformed_rows_do_not_claim_failure(self):
        self.assertEqual(summarize(["truncated","1\tnot-an-ip\t\t0\t0\t0\t\t"],"::1"),{})
if __name__ == "__main__":unittest.main()
