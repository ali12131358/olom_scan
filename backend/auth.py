"""Cookie-based admin authentication for the olom_scan UI.

Credentials are supplied through environment variables; no default password is
accepted. Session signing key is generated/persisted locally, never in Git.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT_DIR / ".env")
except ImportError:
    pass  # Environment variables may be injected by the service manager.
_SECRET_FILE = Path(
    os.environ.get("NETSCAN_AUTH_SECRET_FILE") or (ROOT_DIR / "databases" / ".auth_secret")
)
SESSION_DAYS = int(os.environ.get("NETSCAN_SESSION_DAYS", "7"))
ADMIN_USER = os.environ.get("NETSCAN_ADMIN_USER", "").strip()
ADMIN_PASSWORD = os.environ.get("NETSCAN_ADMIN_PASSWORD", "")
COOKIE_NAME = "net_scan_session"
COOKIE_MAX_AGE = SESSION_DAYS * 86400


def _secret() -> bytes:
    try:
        data = _SECRET_FILE.read_bytes().strip()
        if len(data) >= 32:
            return data
    except OSError:
        pass
    data = secrets.token_hex(32).encode()
    try:
        _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_FILE.write_bytes(data)
        try:
            os.chmod(_SECRET_FILE, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    return data


def _sign(payload: bytes) -> str:
    return hmac.new(_secret(), payload, hashlib.sha256).hexdigest()


def create_token(username: str) -> str:
    exp = int((datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).timestamp())
    payload = json.dumps({"u": username, "exp": exp}, separators=(",", ":")).encode()
    b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    return f"{b64}.{_sign(payload)}"


def verify_token(token: str | None) -> str | None:
    if not token or "." not in token:
        return None
    b64, sig = token.rsplit(".", 1)
    try:
        payload = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
    except Exception:
        return None
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    try:
        data = json.loads(payload)
        if int(data.get("exp", 0)) < time.time():
            return None
    except (ValueError, TypeError):
        return None
    return data.get("u") or None


def check_credentials(username: str, password: str) -> bool:
    """Fail closed until explicit admin credentials are configured."""
    if not ADMIN_USER or not ADMIN_PASSWORD:
        return False
    return hmac.compare_digest(str(username), ADMIN_USER) and hmac.compare_digest(
        str(password), ADMIN_PASSWORD
    )
