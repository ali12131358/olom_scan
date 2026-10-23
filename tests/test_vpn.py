import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import unittest
from unittest import mock

from backend import vpn_manager


class VpnProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmpfile = Path(self.enterContext(__import__("tempfile").TemporaryDirectory())) / "profiles.json"
        vpn_manager.PROFILE_FILE = self.tmpfile
        vpn_manager.PROFILES = {}

    def test_save_and_delete_profile(self):
        saved = vpn_manager.save_profile({"id": "branch1", "protocol": "openvpn", "host": "vpn.example.com", "routes": "10.10.0.0/24"})
        self.assertEqual(saved["routes"], ["10.10.0.0/24"])
        # Secrets must never be persisted to disk.
        text = vpn_manager.PROFILE_FILE.read_text()
        self.assertNotIn("password", text)
        self.assertNotIn("config_content", text)
        # DEFAULT_PROFILES injects built-in "olom" on every _load(); user profile is extra.
        ids = {p["id"] for p in vpn_manager.list_profiles()}
        self.assertIn("branch1", ids)
        self.assertIn("olom", ids)
        self.assertTrue(vpn_manager.delete_profile("branch1"))
        self.assertFalse(vpn_manager.delete_profile("branch1"))
        # Built-in default must not be removable.
        with self.assertRaises(ValueError):
            vpn_manager.delete_profile("olom")

    def test_invalid_profile_rejected(self):
        for bad in ({"id": "bad id!", "protocol": "openvpn"}, {"id": "x", "protocol": "ikev2"}):
            with self.assertRaises(ValueError):
                vpn_manager.save_profile(bad)

    def test_routes_validation(self):
        self.assertEqual(vpn_manager._routes("10.0.0.0/24, 192.168.5.0/24"), ["10.0.0.0/24", "192.168.5.0/24"])
        with self.assertRaises(ValueError):
            vpn_manager._routes("not-a-cidr")
        with self.assertRaises(ValueError):
            vpn_manager._routes("x" * 500)

    def test_status_when_idle(self):
        vpn_manager.ACTIVE = None
        st = vpn_manager.status()
        self.assertFalse(st["connected"])
        self.assertEqual(st["active"], None)
        self.assertIsInstance(st["interfaces"], list)

    def test_unknown_protocol_rejected(self):
        with self.assertRaises(ValueError):
            vpn_manager.connect({"protocol": "tor", "config_content": "x"})

    def test_config_file_written_restricted(self):
        vpn_manager.ACTIVE = None
        with mock.patch.object(vpn_manager.shutil, "which", return_value="/usr/bin/wg-quick"), \
             mock.patch.object(vpn_manager.subprocess, "run", return_value=mock.Mock(returncode=0, stdout="", stderr="")):
            vpn_manager.connect({"protocol": "wireguard", "config_content": "[Interface]\nPrivateKey = x"})
            cfg = Path(vpn_manager.ACTIVE["config"])
            self.assertTrue(cfg.exists())
            mode = cfg.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            vpn_manager.disconnect()
            self.assertFalse(cfg.exists())


if __name__ == "__main__":
    unittest.main()
