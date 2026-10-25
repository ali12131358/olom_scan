"""Encrypt credentials at rest with a key supplied outside the repository.

Set NETSCAN_CREDENTIALS_KEY to a Fernet key generated with:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Never commit that key or a populated .env file.
"""
from __future__ import annotations

import os
from cryptography.fernet import Fernet, InvalidToken
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
except ImportError:
    pass  # Environment variables may be injected by the service manager.

ENV_KEY = "NETSCAN_CREDENTIALS_KEY"
_PREFIX = "fernet:v1:"


def _fernet() -> Fernet:
    key = os.environ.get(ENV_KEY, "").strip()
    if not key:
        raise RuntimeError(
            f"{ENV_KEY} is required to encrypt/decrypt saved VPN credentials. "
            "Generate a Fernet key and configure it outside the repository."
        )
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError(f"{ENV_KEY} is not a valid Fernet key") from exc


def encrypt_secret(value: str | None) -> str | None:
    if value is None or value == "":
        return value
    if value.startswith(_PREFIX):
        # Validate existing ciphertext rather than accidentally double-encrypting.
        decrypt_secret(value)
        return value
    token = _fernet().encrypt(value.encode("utf-8")).decode("ascii")
    return _PREFIX + token


def decrypt_secret(value: str | None) -> str | None:
    if value is None or value == "" or not value.startswith(_PREFIX):
        return value
    try:
        return _fernet().decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise RuntimeError(
            "Cannot decrypt a saved credential: the key is wrong or the data is damaged."
        ) from exc


def protect_profile(profile: dict, *, encrypt: bool) -> dict:
    """Copy a VPN profile and transform only known secret fields."""
    result = dict(profile)
    for field in ("password", "private_key", "preshared_key"):
        value = result.get(field)
        if value is not None:
            result[field] = encrypt_secret(value) if encrypt else decrypt_secret(value)
    # WireGuard/OpenVPN config text can itself contain private keys/passwords.
    # Do not persist those in the JSON profile; users should store config files
    # securely outside the public repository.
    return result
