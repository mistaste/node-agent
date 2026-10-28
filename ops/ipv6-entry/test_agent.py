import base64
import io
import json
import unittest
from unittest.mock import patch
import agent

class AgentValidationTest(unittest.TestCase):
    def invoke(self, request):
        stream = io.TextIOWrapper(io.BytesIO(json.dumps(request).encode()))
        with patch.object(agent.sys, "stdin", stream), patch("builtins.exec") as execute:
            agent.main()
            return execute

    def test_rejects_nonpublic_or_mapped_addresses(self):
        for address in ["::1", "fe80::1", "fd00::1", "::ffff:8.8.8.8", "8.8.8.8", "2001:db8::1"]:
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.invoke({"action": "probe", "address": address,
                  "hostname": "helsinki.fi.guardex-vpn.com", "pin": base64.b64encode(bytes(32)).decode()})

    def test_rejects_command_injection_and_invalid_install_type(self):
        for request in [{"action":"shell", "command":"id"},
                        {"action":"setup", "install":"true"},
                        {"action":"setup", "install":True,"command":"id"}]:
            with self.assertRaises(ValueError): self.invoke(request)

    def test_setup_has_only_constant_code_and_boolean(self):
        execute = self.invoke({"action":"setup", "install":False})
        execute.assert_called_once_with(agent.REMOTE_SETUP,
            {"PROBE":"2a01:96e0:0:545:1::641", "INSTALL":False})

if __name__ == "__main__": unittest.main()
