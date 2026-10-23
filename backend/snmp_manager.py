"""SNMP community profiles (MikroTik-style) and probe for RouterOS /system identity.

On MikroTik, SNMP sysName.0 (1.3.6.1.2.1.1.5.0) is the same value as:
  /system identity print
So probing sysName is the correct way to read the device identity over SNMP.
"""
from __future__ import annotations

import json
import os
import re
import socket
import struct
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILE_FILE = Path(os.environ.get("MIKROTIK_SNMP_PROFILES", ROOT / "snmp_profiles.json"))
LOCK = threading.RLock()
PROFILES: dict = {}
PROBE_PROGRESS = {"total": 0, "done": 0, "current_ip": "", "running": False, "canceled": False}

_ID = re.compile(r"^[a-zA-Z0-9_@.-]{1,64}$")

# SNMP sysName.0 == MikroTik /system identity name
SYS_NAME_OID = (1, 3, 6, 1, 2, 1, 1, 5, 0)  # maps to /system identity


def _load():
    global PROFILES
    try:
        value = json.loads(PROFILE_FILE.read_text(encoding="utf-8"))
        PROFILES = value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        PROFILES = {}
    if not PROFILES:
        # seed a default inspired by the user's MikroTik snippet
        PROFILES = {
            "olom-pez": {
                "name": "Olom@Pez",
                "community": "Olom@Pez",
                "addresses": "0.0.0.0/0",
                "write_access": False,
                "version": "2c",
                "port": 161,
                "timeout": 2.0,
                "is_default": True,
                "raw": (
                    "/snmp set enabled=yes trap-version=2\n"
                    "/snmp community\n"
                    "set [ find default=yes ] addresses=0.0.0.0/0 name=Olom@Pez write-access=no\n"
                    '/snmp community remove [ find name="public" ]'
                ),
            }
        }
        _save()


def _save():
    PROFILE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = PROFILE_FILE.with_suffix(PROFILE_FILE.suffix + ".tmp")
    tmp.write_text(json.dumps(PROFILES, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(PROFILE_FILE)


def list_profiles():
    with LOCK:
        _load()
        out = []
        for k, v in PROFILES.items():
            out.append({"id": k, **v})
        out.sort(key=lambda x: (0 if x.get("is_default") else 1, x.get("name") or x["id"]))
        return out


def get_default():
    with LOCK:
        _load()
        for k, v in PROFILES.items():
            if v.get("is_default"):
                return {"id": k, **v}
        if PROFILES:
            k = next(iter(PROFILES))
            return {"id": k, **PROFILES[k]}
        return None


def parse_mikrotik_snmp(text: str) -> dict:
    """Parse MikroTik /snmp community style lines into structured fields."""
    text = text or ""
    name = ""
    addresses = "0.0.0.0/0"
    write_access = False
    # name=...
    m = re.search(r"\bname=([^\s\]]+)", text, re.I)
    if m:
        name = m.group(1).strip().strip('"')
    m = re.search(r"\baddresses=([^\s\]]+)", text, re.I)
    if m:
        addresses = m.group(1).strip().strip('"')
    if re.search(r"write-access\s*=\s*yes", text, re.I):
        write_access = True
    elif re.search(r"write-access\s*=\s*no", text, re.I):
        write_access = False
    return {
        "name": name or "community",
        "community": name or "public",
        "addresses": addresses,
        "write_access": write_access,
        "raw": text.strip(),
    }


def save_profile(data: dict):
    if not isinstance(data, dict):
        raise ValueError("پروفایل SNMP نامعتبر")
    pid = str(data.get("id") or "").strip()
    raw = str(data.get("raw") or "").strip()
    if raw and not data.get("community") and not data.get("name"):
        parsed = parse_mikrotik_snmp(raw)
        data = {**parsed, **{k: v for k, v in data.items() if v not in (None, "")}}
    if not pid:
        base = re.sub(r"[^a-zA-Z0-9_@.-]+", "-", str(data.get("name") or data.get("community") or "snmp"))
        pid = base[:48] or "snmp"
    if not _ID.fullmatch(pid):
        # soften id
        pid = re.sub(r"[^a-zA-Z0-9_@.-]", "-", pid)[:48]
        if not _ID.fullmatch(pid):
            raise ValueError("شناسه پروفایل SNMP نامعتبر")
    community = str(data.get("community") or data.get("name") or "").strip()
    if not community:
        raise ValueError("community / name لازم است")
    port = int(data.get("port") or 161)
    timeout = float(data.get("timeout") or 2.0)
    safe = {
        "name": str(data.get("name") or community)[:64],
        "community": community[:64],
        "addresses": str(data.get("addresses") or "0.0.0.0/0")[:128],
        "write_access": bool(data.get("write_access")),
        "version": str(data.get("version") or "2c")[:8],
        "port": port,
        "timeout": timeout,
        "is_default": bool(data.get("is_default")),
        "raw": str(data.get("raw") or "")[:4000],
    }
    with LOCK:
        _load()
        if safe["is_default"]:
            for k, v in PROFILES.items():
                if k != pid and isinstance(v, dict):
                    v["is_default"] = False
        PROFILES[pid] = safe
        _save()
    return {"id": pid, **safe}


def delete_profile(pid: str) -> bool:
    with LOCK:
        _load()
        if pid not in PROFILES:
            return False
        del PROFILES[pid]
        _save()
        return True


def set_default(pid: str):
    with LOCK:
        _load()
        if pid not in PROFILES:
            raise KeyError(pid)
        for k, v in PROFILES.items():
            v["is_default"] = k == pid
        _save()
        return {"id": pid, **PROFILES[pid]}


# ---- minimal SNMPv2c GET (no third-party deps) ----

def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2:
        raise ValueError("OID")
    body = bytes([40 * oid[0] + oid[1]])
    for x in oid[2:]:
        if x < 0:
            raise ValueError("OID")
        if x < 0x80:
            body += bytes([x])
        else:
            stack = [x & 0x7F]
            x >>= 7
            while x:
                stack.append(0x80 | (x & 0x7F))
                x >>= 7
            body += bytes(reversed(stack))
    return _tlv(0x06, body)


def _encode_null() -> bytes:
    return b"\x05\x00"


def _encode_int(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        length = max(1, (n.bit_length() + 8) // 8)
        body = n.to_bytes(length, "big", signed=True)
    return _tlv(0x02, body)


def _encode_octet(s: str | bytes) -> bytes:
    if isinstance(s, str):
        s = s.encode("utf-8", errors="replace")
    return _tlv(0x04, s)


def _encode_seq(items: bytes, tag: int = 0x30) -> bytes:
    return _tlv(tag, items)



def build_snmp_get(community: str, oid: tuple[int, ...] = SYS_NAME_OID, request_id: int = 1) -> bytes:
    pdu = _encode_seq(
        _encode_int(request_id)
        + _encode_int(0)  # error-status
        + _encode_int(0)  # error-index
        + _encode_seq(_encode_seq(_encode_oid(oid) + _encode_null())),
        tag=0xA0,  # GetRequest
    )
    msg = _encode_seq(_encode_int(1) + _encode_octet(community) + pdu)  # version 1 = SNMPv2c
    return msg


def build_snmp_getnext(community: str, oid: tuple[int, ...], request_id: int = 1) -> bytes:
    pdu = _encode_seq(
        _encode_int(request_id)
        + _encode_int(0)
        + _encode_int(0)
        + _encode_seq(_encode_seq(_encode_oid(oid) + _encode_null())),
        tag=0xA1,  # GetNextRequest
    )
    msg = _encode_seq(_encode_int(1) + _encode_octet(community) + pdu)
    return msg


def _parse_tlv(data: bytes, i: int = 0):
    if i >= len(data):
        raise ValueError("truncated")
    tag = data[i]
    i += 1
    if i >= len(data):
        raise ValueError("truncated")
    ln = data[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        if n == 0 or i + n > len(data):
            raise ValueError("length")
        ln = int.from_bytes(data[i : i + n], "big")
        i += n
    if i + ln > len(data):
        raise ValueError("overflow")
    return tag, data[i : i + ln], i + ln


def _parse_oid(body: bytes) -> tuple[int, ...]:
    if not body:
        return ()
    first = body[0]
    out = [first // 40, first % 40]
    i = 1
    while i < len(body):
        val = 0
        while i < len(body):
            b = body[i]
            i += 1
            val = (val << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        out.append(val)
    return tuple(out)


def _parse_varbind_value(vtag: int, vbody: bytes):
    if vtag == 0x04:  # OCTET STRING
        return vbody.decode("utf-8", errors="replace")
    if vtag == 0x02:  # INTEGER
        return int.from_bytes(vbody, "big", signed=True)
    if vtag == 0x40:  # IpAddress
        if len(vbody) == 4:
            return ".".join(str(b) for b in vbody)
        return vbody.hex()
    if vtag == 0x05:  # NULL
        return None
    if vtag == 0x06:  # OID
        return ".".join(map(str, _parse_oid(vbody)))
    if vtag in (0x80, 0x81, 0x82):  # noSuchObject / noSuchInstance / endOfMibView
        return None
    return None


def _parse_snmp_varbind(data: bytes):
    """Return (oid_tuple, value) from a Get/GetNext response, or (None, None)."""
    try:
        tag, body, _ = _parse_tlv(data, 0)
        if tag != 0x30:
            return None, None
        i = 0
        for _ in range(2):
            _, _, i = _parse_tlv(body, i)
        pdu_tag, pdu_body, _ = _parse_tlv(body, i)
        j = 0
        for _ in range(3):
            _, _, j = _parse_tlv(pdu_body, j)
        _, vb_list, _ = _parse_tlv(pdu_body, j)
        _, vb, _ = _parse_tlv(vb_list, 0)
        k = 0
        otag, obody, k = _parse_tlv(vb, k)
        if otag != 0x06:
            return None, None
        oid = _parse_oid(obody)
        vtag, vbody, _ = _parse_tlv(vb, k)
        return oid, _parse_varbind_value(vtag, vbody)
    except Exception:
        return None, None


def _parse_snmp_string(data: bytes) -> str | None:
    """Walk a response and return the first OCTET STRING / printable value."""
    _, val = _parse_snmp_varbind(data)
    if val is None:
        return None
    return str(val)


def snmp_get(host: str, community: str, oid: tuple[int, ...], port: int = 161, timeout: float = 2.0):
    payload = build_snmp_get(community, oid=oid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, int(port)))
        data, _ = sock.recvfrom(8192)
        return _parse_snmp_varbind(data)
    except OSError:
        return None, None
    finally:
        sock.close()


def snmp_getnext(host: str, community: str, oid: tuple[int, ...], port: int = 161, timeout: float = 2.0):
    payload = build_snmp_getnext(community, oid=oid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, int(port)))
        data, _ = sock.recvfrom(8192)
        return _parse_snmp_varbind(data)
    except OSError:
        return None, None
    finally:
        sock.close()


def snmp_walk(host: str, community: str, base_oid: tuple[int, ...], port: int = 161,
              timeout: float = 2.0, max_items: int = 200) -> list[tuple[tuple[int, ...], object]]:
    """Simple SNMPv2c GetNext walk under base_oid."""
    results = []
    current = base_oid
    for _ in range(max_items):
        oid, val = snmp_getnext(host, community, current, port=port, timeout=timeout)
        if oid is None or val is None:
            break
        if oid[: len(base_oid)] != base_oid:
            break
        results.append((oid, val))
        current = oid
    return results


def snmp_get_sysname(host: str, community: str, port: int = 161, timeout: float = 2.0) -> str | None:
    oid, val = snmp_get(host, community, SYS_NAME_OID, port=port, timeout=timeout)
    if val is None:
        return None
    return str(val)


# IF-MIB ifName  1.3.6.1.2.1.31.1.1.1.1
# IF-MIB ifDescr 1.3.6.1.2.1.2.2.1.2
IF_NAME_OID = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
IF_DESCR_OID = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
# IP-MIB ipAdEntAddr 1.3.6.1.2.1.4.20.1.1
IP_ADDR_OID = (1, 3, 6, 1, 2, 1, 4, 20, 1, 1)


def collect_interfaces(host: str, community: str, port: int = 161, timeout: float = 2.0) -> str:
    """Walk ifName (preferred) or ifDescr and return multi-line text like /interface print."""
    rows = snmp_walk(host, community, IF_NAME_OID, port=port, timeout=timeout, max_items=128)
    if not rows:
        rows = snmp_walk(host, community, IF_DESCR_OID, port=port, timeout=timeout, max_items=128)
    if not rows:
        return ""
    lines = ["=== /interface (SNMP) ==="]
    for i, (oid, name) in enumerate(rows, 1):
        if_index = oid[-1] if oid else i
        lines.append(f"{i:3d}  name={name}  index={if_index}")
    return "\n".join(lines)


def collect_ip_addresses_snmp(host: str, community: str, port: int = 161, timeout: float = 2.0) -> str:
    """Walk IP-MIB address table; limited equivalent of /ip address print."""
    rows = snmp_walk(host, community, IP_ADDR_OID, port=port, timeout=timeout, max_items=64)
    if not rows:
        return ""
    lines = ["=== /ip address (SNMP ipAdEntAddr) ==="]
    for i, (_, addr) in enumerate(rows, 1):
        lines.append(f"{i:3d}  address={addr}")
    return "\n".join(lines)



def classify_device_type(interfaces_text: str, device_name: str = "", wireless_info: str = "", api_hint: str = "") -> str:
    """MikroTik role: AP | ST | Router.

    Priority:
      1) explicit API hint (from /interface wireless mode)
      2) mode strings in wireless_info / interfaces text (station-bridge, ap-bridge, ...)
      3) identity name heuristics (Client, CPE, ...)
      4) presence of wireless iface without mode → AP
      5) no wireless → Router
    """
    if api_hint in ("AP", "ST", "Router"):
        return api_hint

    text = (interfaces_text or "").lower()
    wireless = (wireless_info or "").lower()
    name = (device_name or "").lower()
    combined = text + "\n" + wireless + "\n" + name

    # --- explicit wireless modes (RouterOS) ---
    # station* always wins over ap/bridge substrings
    station_modes = (
        "station-bridge", "station bridge", "stationbridge",
        "station-wds", "station wds",
        "mode=station", "mode:station", "mode=station-bridge",
        " mode=station", " mode: station",
    )
    if any(k in combined for k in station_modes) or (
        "station" in combined and "bridge" in combined and "ap-bridge" not in combined
    ):
        return "ST"
    if "station" in combined and "ap-bridge" not in combined and "ap bridge" not in combined:
        # bare station / station-pseudobridge etc.
        if any(k in combined for k in ("station", "mode=station", "mode:station")):
            return "ST"

    ap_modes = ("ap-bridge", "ap bridge", "ap_bridge", "mode=ap-bridge", "mode=ap", "access-point")
    if any(k in combined for k in ap_modes):
        return "AP"

    # interface name tokens
    names = []
    for line in (interfaces_text or "").splitlines():
        line = line.strip().lower()
        if "name=" in line:
            part = line.split("name=", 1)[1].split()[0].strip()
            names.append(part)
        elif line and not line.startswith("==="):
            names.append(line)

    wireless_names = [
        n for n in names
        if any(k in n for k in ("wlan", "wifi", "wireless", "wwan", "cap", "radio"))
    ]
    has_wireless = bool(wireless_names) or any(
        k in combined for k in ("wlan", "wifi1", "wireless")
    ) or bool(wireless.strip())

    if has_wireless:
        # identity heuristics
        if any(k in name for k in ("cpe", "station", "client", "st-", ".client", "-client")):
            return "ST"
        if any(k in name for k in ("ap", "cap", "wap")) and "station" not in name:
            return "AP"
        # default wireless without mode text → AP (unknown mode)
        return "AP"

    return "Router"


def collect_wireless_info(host: str, community: str, port: int = 161, timeout: float = 2.0,
                          interfaces_text: str = "") -> str:
    """Collect best-effort wireless summary from interface names (SNMP).

    Full /interface wireless print needs RouterOS API; SNMP gives interface list.
    """
    names = []
    for line in (interfaces_text or "").splitlines():
        line = line.strip()
        if "name=" in line.lower():
            # name=wlan1  index=...
            low = line.lower()
            idx = low.find("name=")
            rest = line[idx + 5 :].strip()
            token = rest.split()[0] if rest else ""
            if token:
                names.append(token)
    wireless = [
        n for n in names
        if any(k in n.lower() for k in ("wlan", "wifi", "wireless", "wwan", "cap", "radio"))
    ]
    if not wireless and not interfaces_text:
        # try a fresh walk focused on ifName
        try:
            interfaces_text = collect_interfaces(host, community, port=port, timeout=timeout)
            return collect_wireless_info(host, community, port, timeout, interfaces_text)
        except Exception:
            return ""
    if not wireless:
        return ""
    lines = ["=== wireless interfaces (SNMP) ==="]
    for i, n in enumerate(wireless, 1):
        lines.append(f"{i:3d}  name={n}")
    lines.append(f"count={len(wireless)}")
    return "\n".join(lines)


def probe_names(ips: list[str], profile_id: str | None = None, cancel_event=None, api_username: str | None = None, api_password: str | None = None, api_port: int = 8728) -> list[dict]:
    """Probe devices via SNMP. If cancel_event is set between IPs, stop early."""
    with LOCK:
        _load()
        if profile_id and profile_id in PROFILES:
            prof = PROFILES[profile_id]
        else:
            prof = None
            for v in PROFILES.values():
                if v.get("is_default"):
                    prof = v
                    break
            if prof is None and PROFILES:
                prof = next(iter(PROFILES.values()))
    if not prof:
        raise RuntimeError("پروفایل SNMP تعریف نشده است")
    community = prof.get("community") or prof.get("name") or "public"
    port = int(prof.get("port") or 161)
    timeout = float(prof.get("timeout") or 2.0)
    results = []
    PROBE_PROGRESS.update({"total": len([x for x in ips if str(x).strip()]), "done": 0, "current_ip": "", "running": True, "canceled": False})
    try:
      for ip in ips:
        if cancel_event is not None and cancel_event.is_set():
            PROBE_PROGRESS["canceled"] = True
            break
        ip = str(ip).strip()
        if not ip:
            continue
        PROBE_PROGRESS["current_ip"] = ip
        name = snmp_get_sysname(ip, community, port=port, timeout=timeout)
        if cancel_event is not None and cancel_event.is_set():
            break
        interfaces = ""
        ip_addrs = ""
        wireless = ""
        try:
            interfaces = collect_interfaces(ip, community, port=port, timeout=timeout)
        except Exception:
            interfaces = ""
        if cancel_event is not None and cancel_event.is_set():
            pass
        else:
            try:
                ip_addrs = collect_ip_addresses_snmp(ip, community, port=port, timeout=timeout)
            except Exception:
                ip_addrs = ""
            try:
                wireless = collect_wireless_info(ip, community, port=port, timeout=timeout, interfaces_text=interfaces)
            except Exception:
                wireless = ""
        api_hint = ""
        if api_username:
            try:
                from backend import routeros_api as _ros
            except ImportError:
                import routeros_api as _ros
            try:
                wapi = _ros.fetch_wireless_info(ip, api_username, api_password or "", port=api_port, timeout=4.0)
                if wapi.get("ok") and wapi.get("text"):
                    wireless = (wireless + "\n" + wapi["text"]).strip() if wireless else wapi["text"]
                    api_hint = wapi.get("device_type_hint") or ""
            except Exception:
                pass
        device_type = classify_device_type(interfaces, name or "", wireless_info=wireless, api_hint=api_hint)
        ok = bool(name) or bool(interfaces) or bool(ip_addrs) or bool(wireless)
        results.append({
            "ip": ip,
            "device_name": name or "",
            "system_identity": name or "",
            "interfaces": interfaces,
            "ip_addresses": ip_addrs,
            "wireless_info": wireless,
            "device_type": device_type,
            "ok": ok,
            "community": community,
            "source": "snmp" if ok else None,
            "canceled": bool(cancel_event is not None and cancel_event.is_set()),
        })
        PROBE_PROGRESS["done"] = len(results)
    finally:
        PROBE_PROGRESS["running"] = False
        PROBE_PROGRESS["current_ip"] = ""
    return results


_load()
