import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.fernet import Fernet
from backend import credential_crypto


class CredentialCryptoTests(unittest.TestCase):
    def setUp(self):
        self.key = Fernet.generate_key().decode()
        self.env = mock.patch.dict(os.environ, {"NETSCAN_CREDENTIALS_KEY": self.key})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_encrypt_decrypt_round_trip(self):
        plain = "VPN-secret-123!"
        encrypted = credential_crypto.encrypt_secret(plain)
        self.assertTrue(encrypted.startswith("fernet:v1:"))
        self.assertNotIn(plain, encrypted)
        self.assertEqual(credential_crypto.decrypt_secret(encrypted), plain)

    def test_profile_secret_fields_are_encrypted(self):
        profile = {"username": "vpn-user", "password": "pass-123", "host": "vpn.example"}
        stored = credential_crypto.protect_profile(profile, encrypt=True)
        self.assertNotIn("pass-123", str(stored))
        self.assertEqual(stored["username"], "vpn-user")
        self.assertEqual(credential_crypto.protect_profile(stored, encrypt=False)["password"], "pass-123")

    def test_missing_key_fails_closed(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "NETSCAN_CREDENTIALS_KEY"):
                credential_crypto.encrypt_secret("secret")

    def test_wrong_key_cannot_decrypt(self):
        encrypted = credential_crypto.encrypt_secret("secret")
        with mock.patch.dict(os.environ, {"NETSCAN_CREDENTIALS_KEY": Fernet.generate_key().decode()}):
            with self.assertRaisesRegex(RuntimeError, "Cannot decrypt"):
                credential_crypto.decrypt_secret(encrypted)

    def test_plaintext_legacy_value_remains_readable_for_migration(self):
        self.assertEqual(credential_crypto.decrypt_secret("legacy-plain"), "legacy-plain")


if __name__ == "__main__":
    unittest.main()