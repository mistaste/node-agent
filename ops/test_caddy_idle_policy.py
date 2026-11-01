import unittest
from check_caddy_idle_policy import check
class IdlePolicyTests(unittest.TestCase):
    def test_current_pin(self): check("xcaddy build v2.11.4", "servers {}")
    def test_regression_unknown_upgrade_and_unpinned_are_blocked(self):
        for version in ["v2.11.6", "v2.11.7", "latest", ""]:
            with self.subTest(version=version), self.assertRaises(ValueError): check("xcaddy build " + version, "")
    def test_new_directives_on_old_pin_are_blocked(self):
        for directive in ["read_body_idle", "write_idle"]:
            with self.assertRaises(ValueError): check("xcaddy build v2.11.4", directive + " -1s")
if __name__ == "__main__": unittest.main()
