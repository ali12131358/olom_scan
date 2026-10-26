"""RouterOS binary API helpers used by the device-management endpoints.

This module uses the RouterOS API TCP protocol directly and has no third-party
runtime dependency. Only connect to devices you are authorized to administer.
"""
from __future__ import annotations

import hashlib
import ipaddress
import shlex
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        return bytes([(length >> 8) | 0x80, length & 0xFF])
    if length < 0x200000:
        return bytes([(length >> 16) | 0xC0, (length >> 8) & 0xFF, length & 0xFF])
    if length < 0x10000000:
        return bytes([(length >> 24) | 0xE0, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    return b"\xF0" + length.to_bytes(4, "big")


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("RouterOS API connection closed unexpectedly")
        chunks.extend(chunk)
    return bytes(chunks)


def _read_length(sock: socket.socket) -> int:
    first = _read_exact(sock, 1)[0]
    if first < 0x80:
        return first
    if first < 0xC0:
        return ((first & 0x3F) << 8) + _read_exact(sock, 1)[0]
    if first < 0xE0:
        b = _read_exact(sock, 2)
        return ((first & 0x1F) << 16) + (b[0] << 8) + b[1]
    if first < 0xF0:
        b = _read_exact(sock, 3)
        return ((first & 0x0F) << 24) + (b[0] << 16) + (b[1] << 8) + b[2]
    if first == 0xF0:
        return int.from_bytes(_read_exact(sock, 4), "big")
    raise ValueError("Invalid RouterOS API length prefix")


def _write_sentence(sock: socket.socket, words: list[str]) -> None:
    data = bytearray()
    for word in words:
        raw = str(word).encode("utf-8")
        data.extend(_encode_length(len(raw)))
        data.extend(raw)
    data.append(0)
    sock.sendall(data)


def _read_sentence(sock: socket.socket) -> list[str]:
    words = []
    while True:
        length = _read_length(sock)
        if length == 0:
            return words
        words.append(_read_exact(sock, length).decode("utf-8", errors="replace"))


def _read_reply(sock: socket.socket) -> list[tuple[str, dict]]:
    reply = []
    while True:
        sentence = _read_sentence(sock)
        if not sentence:
            continue
        kind = sentence[0]
        attrs = {}
        for word in sentence[1:]:
            if word.startswith("="):
                key, sep, value = word[1:].partition("=")
                if sep:
                    attrs[key] = value
        reply.append((kind, attrs))
        if kind in ("!done", "!fatal"):
            return reply
        if kind == "!trap":
            # A trap is normally followed by !done; keep reading for protocol sync.
            continue


class _RouterOS:
    def __init__(self, ip: str, username: str, password: str, port: int, timeout: float):
        self.sock = socket.create_connection((ip, int(port)), timeout=timeout)
        self.sock.settimeout(timeout)
        _write_sentence(self.sock, ["/login", f"=name={username}", f"=password={password}"])
        reply = _read_reply(self.sock)
        done = next((attrs for kind, attrs in reply if kind == "!done"), {})
        challenge = done.get("ret")
        if challenge:
            digest = hashlib.md5(b"\x00" + password.encode("utf-8") + bytes.fromhex(challenge)).hexdigest()
            _write_sentence(self.sock, ["/login", f"=name={username}", f"=response=00{digest}"])
            reply = _read_reply(self.sock)
        if any(kind in ("!trap", "!fatal") for kind, _ in reply) or not any(kind == "!done" for kind, _ in reply):
            self.sock.close()
            msg = next((attrs.get("message", "ورود به RouterOS ناموفق بود") for kind, attrs in reply if kind in ("!trap", "!fatal")), "ورود به RouterOS ناموفق بود")
            raise PermissionError(msg)

    def command(self, path: str, attrs: dict | None = None) -> list[dict]:
        words = [path]
        for key, value in (attrs or {}).items():
            words.append(f"={key}={value}")
        _write_sentence(self.sock, words)
        reply = _read_reply(self.sock)
        err = next((a.get("message", "RouterOS API command failed") for k, a in reply if k in ("!trap", "!fatal")), None)
        if err:
            raise RuntimeError(err)
        return [attrs for kind, attrs in reply if kind == "!re"]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def _text(rows: list[dict], fields: tuple[str, ...] | None = None) -> str:
    lines = []
    for row in rows:
        if fields:
            values = [f"{k}={row[k]}" for k in fields if row.get(k) not in (None, "")]
        else:
            values = [f"{k}={v}" for k, v in row.items() if v not in (None, "")]
        if values:
            lines.append(" ".join(values))
    return "\n".join(lines)


def _one_probe(ip, username, password, port, timeout):
    result = {"ip": ip, "ok": False, "device_name": "", "device_type": "", "interfaces": "", "ip_addresses": "", "ip_neighbors": "", "wireless_info": "", "device_log": "", "mac_info": ""}
    try:
        ipaddress.ip_address(ip)
        api = _RouterOS(ip, username, password, port, timeout)
        try:
            identity = api.command("/system/identity/print")
            resources = api.command("/system/resource/print")
            interfaces = api.command("/interface/print")
            addresses = api.command("/ip/address/print")
            routes = api.command("/ip/route/print")
            neighbors = api.command("/ip/neighbor/print")
            wireless = api.command("/interface/wireless/print")
            logs = api.command("/log/print", {"=without-paging": ""}) if False else []
            arp = api.command("/ip/arp/print")
            result.update({
                "ok": True,
                "device_name": (identity[0].get("name", "") if identity else ""),
                "device_type": "wireless" if wireless else "router",
                "interfaces": _text(interfaces),
                "ip_addresses": _text(addresses) + ("\n--- routes ---\n" + _text(routes) if routes else ""),
                "ip_neighbors": _text(neighbors),
                "wireless_info": _text(wireless),
                "device_log": _text(logs),
                "mac_info": _text(arp),
                "resource": resources[0] if resources else {},
            })
        finally:
            api.close()
    except Exception as exc:
        result["error"] = str(exc)
    return result


def _many(ips, worker, cancel_event=None, progress=None, max_workers=16):
    ips = [str(ip).strip() for ip in (ips or []) if str(ip).strip()]
    results = []
    if progress is not None:
        progress.update({"total": len(ips), "done": 0, "current_ip": "", "running": True, "canceled": False})
    try:
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(ips) or 1))) as pool:
            futures = {}
            for ip in ips:
                if cancel_event is not None and cancel_event.is_set():
                    break
                futures[pool.submit(worker, ip)] = ip
            for future in as_completed(futures):
                ip = futures[future]
                if cancel_event is not None and cancel_event.is_set():
                    break
                try:
                    results.append(future.result())
                except Exception as exc:
                    results.append({"ip": ip, "ok": False, "error": str(exc)})
                if progress is not None:
                    progress.update({"done": len(results), "current_ip": ip})
    finally:
        if progress is not None:
            progress.update({"running": False, "canceled": bool(cancel_event and cancel_event.is_set()), "done": len(results)})
    order = {ip: i for i, ip in enumerate(ips)}
    results.sort(key=lambda item: order.get(item.get("ip"), len(order)))
    return results


def probe_devices_via_api_many(ips, username, password="", port=8728, timeout=12.0, cancel_event=None, progress=None):
    return _many(ips, lambda ip: _one_probe(ip, username, password, port, timeout), cancel_event, progress)


def collect_ip_info_many(ips, username, password="", port=8728, timeout=12.0):
    def collect(ip):
        result = {"ip": ip, "ok": False, "ip_addresses": "", "ip_neighbors": ""}
        try:
            ipaddress.ip_address(ip)
            api = _RouterOS(ip, username, password, port, timeout)
            try:
                addresses = api.command("/ip/address/print")
                routes = api.command("/ip/route/print")
                neighbors = api.command("/ip/neighbor/print")
                result.update({"ok": True, "ip_addresses": _text(addresses) + ("\n--- routes ---\n" + _text(routes) if routes else ""), "ip_neighbors": _text(neighbors)})
            finally:
                api.close()
        except Exception as exc:
            result["error"] = str(exc)
        return result
    return _many(ips, collect, max_workers=16)


def push_config_many(ips, username, password="", script="", port=8728, timeout=12.0):
    """Apply RouterOS CLI-style commands through API, respecting slash sections."""
    def push(ip):
        result = {"ip": ip, "ok": False}
        try:
            ipaddress.ip_address(ip)
            api = _RouterOS(ip, username, password, port, timeout)
            try:
                section = ""
                executed = 0
                for raw in str(script).splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("/"):
                        words = shlex.split(line)
                        if len(words) == 1:
                            section = words[0].rstrip("/")
                            continue
                        path = words[0]
                        args = words[1:]
                    else:
                        words = shlex.split(line)
                        if not words:
                            continue
                        if not section:
                            raise ValueError("هر دستور باید با مسیر /menu یا یک بخش /menu آغاز شود")
                        path = section + "/" + words[0]
                        args = words[1:]
                    attrs = {}
                    for word in args:
                        if "=" in word:
                            key, value = word.split("=", 1)
                            attrs[key] = value
                    api.command(path, attrs)
                    executed += 1
                result.update({"ok": True, "commands": executed, "message": f"{executed} دستور اجرا شد"})
            finally:
                api.close()
        except Exception as exc:
            result["error"] = str(exc)
        return result
    return _many(ips, push, max_workers=8)
