"""SMTP configuration and outbound mail for شبکه‌بان.

Two transport modes:
  - relay  : classic SMTP through a provider (Gmail, host mail, VPS, …)
  - direct : resolve recipient MX and deliver directly (no third-party SMTP)

Direct mode needs outbound TCP 25 (sometimes 587) allowed by the ISP/firewall.
"""
from __future__ import annotations

import json
import random
import smtplib
import socket
import ssl
import struct
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_CONFIG = _ROOT / "smtp_config.json"

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "mode": "direct",  # "direct" | "relay"
    "host": "smtp.gmail.com",
    "port": 587,
    "use_tls": True,
    "use_ssl": False,
    "username": "",
    "password": "",
    "from_email": "",
    "from_name": "شبکه‌بان",
    "to_email": "",
    "timeout": 30,
    "helo_host": "shabakeban.local",
}


def _load_raw() -> dict:
    try:
        data = json.loads(_CONFIG.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {}


def get_config(mask_password: bool = True) -> dict:
    cfg = {**DEFAULTS, **_load_raw()}
    try:
        cfg["port"] = int(cfg.get("port") or 587)
    except (TypeError, ValueError):
        cfg["port"] = 587
    try:
        cfg["timeout"] = float(cfg.get("timeout") or 30)
    except (TypeError, ValueError):
        cfg["timeout"] = 30.0
    cfg["enabled"] = bool(cfg.get("enabled"))
    cfg["use_tls"] = bool(cfg.get("use_tls", True))
    cfg["use_ssl"] = bool(cfg.get("use_ssl", False))
    mode = str(cfg.get("mode") or "direct").lower().strip()
    cfg["mode"] = mode if mode in ("direct", "relay") else "direct"
    for k in ("host", "username", "password", "from_email", "from_name", "to_email", "helo_host"):
        cfg[k] = str(cfg.get(k) or "")
    if mask_password and cfg.get("password"):
        cfg["password"] = "********"
        cfg["password_set"] = True
    else:
        cfg["password_set"] = bool(_load_raw().get("password"))
    return cfg


def save_config(body: dict) -> dict:
    current = {**DEFAULTS, **_load_raw()}
    for key in DEFAULTS:
        if key not in body:
            continue
        val = body[key]
        if key == "password":
            if val is None or str(val).strip() in ("", "********"):
                continue
            current["password"] = str(val)
            continue
        if key == "port":
            try:
                current[key] = int(val)
            except (TypeError, ValueError):
                raise ValueError("پورت نامعتبر است") from None
        elif key == "timeout":
            try:
                current[key] = float(val)
            except (TypeError, ValueError):
                raise ValueError("timeout نامعتبر است") from None
        elif key in ("enabled", "use_tls", "use_ssl"):
            current[key] = bool(val)
        elif key == "mode":
            m = str(val or "direct").lower().strip()
            if m not in ("direct", "relay"):
                raise ValueError("mode باید direct یا relay باشد")
            current[key] = m
        else:
            current[key] = str(val or "").strip()
    if not current.get("from_email") and current.get("username"):
        current["from_email"] = current["username"]
    _CONFIG.write_text(json.dumps(current, ensure_ascii=False, indent=2), encoding="utf-8")
    return get_config(mask_password=True)


def _plain_config() -> dict:
    return {**DEFAULTS, **_load_raw()}


def _looks_like_email(s: str) -> bool:
    s = (s or "").strip()
    return bool(s) and "@" in s and "." in s.split("@")[-1] and " " not in s


# ---------------------------------------------------------------------------
# Minimal DNS MX lookup (stdlib only, UDP/53)
# ---------------------------------------------------------------------------
def _dns_query_mx(domain: str, nameserver: str = "8.8.8.8", timeout: float = 5.0) -> list[tuple[int, str]]:
    """Return list of (preference, host) for MX records. Empty if none."""
    domain = domain.strip(".").lower()
    if not domain:
        return []
    labels = domain.split(".")
    qname = b"".join(bytes([len(l)]) + l.encode("ascii", "ignore") for l in labels) + b"\x00"
    tid = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = qname + struct.pack("!HH", 15, 1)  # MX IN
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return []
    rtid, flags, _qd, an, _, _ = struct.unpack("!HHHHHH", data[:12])
    if rtid != tid or (flags & 0x000F) != 0 or an == 0:
        return []

    def decode_name(buf: bytes, offset: int) -> tuple[str, int]:
        parts: list[str] = []
        jumped = False
        end = offset
        for _ in range(64):
            if offset >= len(buf):
                break
            length = buf[offset]
            if length == 0:
                if not jumped:
                    end = offset + 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 1 >= len(buf):
                    break
                pointer = ((length & 0x3F) << 8) | buf[offset + 1]
                if not jumped:
                    end = offset + 2
                offset = pointer
                jumped = True
                continue
            offset += 1
            parts.append(buf[offset : offset + length].decode("ascii", "ignore"))
            offset += length
            if not jumped:
                end = offset
        return ".".join(parts), end

    # skip question
    pos = 12
    _, pos = decode_name(data, pos)
    pos += 4  # qtype + qclass

    results: list[tuple[int, str]] = []
    for _ in range(an):
        _, pos = decode_name(data, pos)
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[pos : pos + 10])
        pos += 10
        if pos + rdlen > len(data):
            break
        if rtype == 15 and rdlen >= 3:
            pref = struct.unpack("!H", data[pos : pos + 2])[0]
            # MX exchange name is inside message; decode at absolute offset
            name, _ = decode_name(data, pos + 2)
            if name:
                results.append((pref, name.rstrip(".")))
        pos += rdlen
    results.sort(key=lambda x: x[0])
    return results


def resolve_mx(domain: str, timeout: float = 5.0) -> list[str]:
    """Resolve MX hosts for domain; fall back to domain itself as A last resort."""
    for ns in ("8.8.8.8", "1.1.1.1", "9.9.9.9"):
        try:
            mx = _dns_query_mx(domain, nameserver=ns, timeout=timeout)
            if mx:
                return [h for _, h in mx]
        except OSError:
            continue
    # last resort: try the domain as host
    return [domain]


def _build_message(
    subject: str,
    body: str,
    from_email: str,
    from_name: str,
    dest: str,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject or "شبکه‌بان"
    msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
    msg["To"] = dest
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=from_email.split("@")[-1] if "@" in from_email else "shabakeban.local")
    msg.set_content(body or "")
    for att in attachments or []:
        fname, data, mime = att[0], att[1], (att[2] if len(att) > 2 else "application/octet-stream")
        maintype, _, subtype = mime.partition("/")
        if not subtype:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=fname)
    return msg


def _smtp_send_once(host, port, username, password, msg, timeout, mode: str, helo: str = "shabakeban.local"):
    if mode == "ssl":
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(host, port, timeout=timeout, context=context) as server:
            if helo:
                try:
                    server.ehlo(helo)
                except Exception:
                    pass
            if username and password:
                server.login(username, password)
            server.send_message(msg)
    elif mode == "starttls":
        with smtplib.SMTP(host, port, timeout=timeout, local_hostname=helo or None) as server:
            server.ehlo(helo or None)
            context = ssl.create_default_context()
            server.starttls(context=context)
            server.ehlo(helo or None)
            if username and password:
                server.login(username, password)
            server.send_message(msg)
    else:  # plain (port 25 typical for MX)
        with smtplib.SMTP(host, port, timeout=timeout, local_hostname=helo or None) as server:
            server.ehlo(helo or None)
            if username and password:
                server.login(username, password)
            server.send_message(msg)


def send_direct(
    subject: str,
    body: str,
    from_email: str,
    from_name: str,
    dest: str,
    timeout: float = 30,
    helo_host: str = "shabakeban.local",
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> dict:
    """Deliver directly to recipient domain MX — no Gmail/relay account needed."""
    if not _looks_like_email(dest):
        raise ValueError("آدرس گیرنده معتبر نیست")
    if not _looks_like_email(from_email):
        raise ValueError("فرستنده باید یک ایمیل باشد (مثال: alert@yourdomain.com)")

    domain = dest.split("@", 1)[1].lower()
    mx_hosts = resolve_mx(domain, timeout=min(timeout, 8))
    if not mx_hosts:
        raise ValueError(f"رکورد MX برای دامنه {domain} پیدا نشد")

    msg = _build_message(subject, body, from_email, from_name, dest, attachments)
    # Try common outbound paths per MX host
    attempts: list[tuple[str, int, str]] = []
    for h in mx_hosts[:5]:
        attempts.append((h, 25, "plain"))
        attempts.append((h, 587, "starttls"))

    errors: list[str] = []
    saw_not_authorized = False
    for host, port, mode in attempts:
        try:
            _smtp_send_once(host, port, "", "", msg, timeout, mode, helo=helo_host)
            return {
                "ok": True,
                "mode": "direct",
                "to": dest,
                "from": from_email,
                "mx": host,
                "port": port,
                "transport": mode,
                "subject": subject,
            }
        except smtplib.SMTPRecipientsRefused as e:
            errors.append(f"{host}:{port} گیرنده رد شد")
            if "NotAuthorized" in str(e) or "not authorized" in str(e).lower():
                saw_not_authorized = True
        except smtplib.SMTPSenderRefused as e:
            errors.append(f"{host}:{port} فرستنده رد شد")
            if "NotAuthorized" in str(e) or "not authorized" in str(e).lower():
                saw_not_authorized = True
        except smtplib.SMTPDataError as e:
            err_s = str(e)
            if "NotAuthorized" in err_s or "not authorized" in err_s.lower() or "5.7.1" in err_s:
                saw_not_authorized = True
                errors.append(f"{host}:{port} IP شما برای ارسال مستقیم مجاز نیست (550)")
            else:
                errors.append(f"{host}:{port} داده رد شد")
        except (smtplib.SMTPException, OSError, TimeoutError, ConnectionError) as e:
            errors.append(f"{host}:{port} {type(e).__name__}")
            continue

    if saw_not_authorized:
        hint = (
            "Gmail/Yahoo و بیشتر سرویس‌های بزرگ، ارسال مستقیم از IP خانگی را مسدود می‌کنند. "
            "حالت Direct برای تحویل به Gmail از اینترنت خانگی کار نمی‌کند. "
            "راه حل: حالت «رله» را انتخاب کنید و SMTP هاست ایرانی، VPS، یا Yahoo/Gmail با App Password بگذارید."
        )
    else:
        hint = (
            "ارسال مستقیم نیاز به پورت خروجی ۲۵ دارد یا سرور گیرنده پاسخ نداد. "
            "از حالت «رله SMTP» روی هاست ایرانی یا VPS استفاده کنید."
        )
    raise ValueError("ارسال مستقیم ناموفق. " + " | ".join(errors[:6]) + " — " + hint)


def send_relay(
    subject: str,
    body: str,
    to_email: str | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> dict:
    cfg = _plain_config()
    host = (cfg.get("host") or "").strip()
    try:
        port = int(cfg.get("port") or 587)
    except (TypeError, ValueError):
        port = 587
    username = (cfg.get("username") or "").strip()
    password = "".join(str(cfg.get("password") or "").split())
    from_email = (cfg.get("from_email") or "").strip()
    from_name = (cfg.get("from_name") or "شبکه‌بان").strip()
    dest = (to_email or cfg.get("to_email") or "").strip()
    helo = (cfg.get("helo_host") or "shabakeban.local").strip()
    timeout = float(cfg.get("timeout") or 30)

    if not host:
        raise ValueError("آدرس SMTP رله مشخص نشده است")
    if not _looks_like_email(dest):
        raise ValueError("آدرس گیرنده معتبر نیست")
    if not username or not password:
        raise ValueError("برای حالت رله، نام کاربری و رمز SMTP لازم است")
    if not _looks_like_email(from_email):
        if _looks_like_email(username):
            from_email = username
        else:
            raise ValueError("فرستنده باید ایمیل معتبر باشد")

    msg = _build_message(subject, body, from_email, from_name, dest, attachments)

    if port == 465:
        attempts = [(465, "ssl")]
    elif port == 587:
        attempts = [(587, "starttls")]
    else:
        attempts = [(port, "ssl" if cfg.get("use_ssl") else "starttls")]

    host_l = host.lower()
    if "gmail" in host_l or "google" in host_l or "yahoo" in host_l or "mailfa" in host_l:
        if port == 587:
            attempts.append((465, "ssl"))
        elif port == 465:
            attempts.append((587, "starttls"))

    last_err: Exception | None = None
    used_port, used_mode = attempts[0]
    for try_port, mode in attempts:
        try:
            _smtp_send_once(host, try_port, username, password, msg, timeout, mode, helo=helo)
            used_port, used_mode = try_port, mode
            last_err = None
            break
        except smtplib.SMTPAuthenticationError as e:
            raise ValueError(
                "احراز هویت SMTP رد شد. برای Gmail از App Password استفاده کنید. "
                f"جزئیات: {e}"
            ) from e
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, ConnectionError, OSError, TimeoutError) as e:
            last_err = e
            continue
        except smtplib.SMTPException as e:
            last_err = e
            continue

    if last_err is not None:
        raise ValueError(f"اتصال SMTP رله برقرار نشد ({host}:{port}): {last_err}") from last_err

    return {
        "ok": True,
        "mode": "relay",
        "to": dest,
        "from": from_email,
        "host": host,
        "port": used_port,
        "transport": used_mode,
        "subject": subject,
    }


def send_mail(
    subject: str,
    body: str,
    to_email: str | None = None,
    attachments: list[tuple[str, bytes, str]] | None = None,
) -> dict:
    cfg = _plain_config()
    mode = str(cfg.get("mode") or "direct").lower()
    dest = (to_email or cfg.get("to_email") or "").strip()
    from_email = (cfg.get("from_email") or cfg.get("username") or "").strip()
    from_name = (cfg.get("from_name") or "شبکه‌بان").strip()
    timeout = float(cfg.get("timeout") or 30)
    helo = (cfg.get("helo_host") or "shabakeban.local").strip()

    if mode == "direct":
        if not _looks_like_email(from_email):
            raise ValueError(
                "در حالت ارسال مستقیم، فیلد From را با یک ایمیل پر کنید "
                "(مثلاً alert@yourdomain.com یا هر آدرس شناسایی‌کننده)"
            )
        return send_direct(
            subject=subject,
            body=body,
            from_email=from_email,
            from_name=from_name,
            dest=dest,
            timeout=timeout,
            helo_host=helo,
            attachments=attachments,
        )
    return send_relay(subject, body, to_email=to_email, attachments=attachments)


def send_test(to_email: str | None = None, message: str | None = None) -> dict:
    from datetime import datetime, timezone, timedelta
    try:
        from zoneinfo import ZoneInfo
        now = datetime.now(ZoneInfo("Asia/Tehran"))
    except Exception:
        now = datetime.now(timezone(timedelta(hours=3, minutes=30)))
    stamp = now.strftime("%Y-%m-%d %H:%M:%S %Z")
    cfg = get_config(mask_password=True)
    mode = cfg.get("mode") or "direct"
    body = message or (
        "این یک پیام آزمایشی از نرم‌افزار شبکه‌بان است.\n"
        f"حالت ارسال: {mode}\n"
        f"زمان ارسال (تهران): {stamp}\n"
        "اگر این ایمیل را دریافت کردید، مسیر ارسال درست کار می‌کند."
    )
    return send_mail(subject="[شبکه‌بان] تست ارسال", body=body, to_email=to_email or None)
