import platform
import socket
import subprocess
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from threading import Event, Lock

from .models import HostResult, ScanReport

_IS_WINDOWS = platform.system().lower().startswith("win")
# Hide console windows when spawning ping.exe under Windows (GUI / service hosts).
_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if _IS_WINDOWS else 0


def ping_host(ip, ms):
    """ICMP echo via system ping. Returns (alive: bool, error: str|None)."""
    timeout_s = max(0.05, ms / 1000.0)
    if _IS_WINDOWS:
        # -n 1: one echo; -w: timeout in milliseconds
        cmd = ["ping", "-n", "1", "-w", str(int(ms)), ip]
    else:
        # -c 1: one echo; -W: timeout in whole seconds (Linux)
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout_s)))), ip]
    try:
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "timeout": timeout_s + 1.5,
        }
        if _IS_WINDOWS:
            kwargs["creationflags"] = _CREATE_NO_WINDOW
        completed = subprocess.run(cmd, **kwargs)
        return completed.returncode == 0, None
    except subprocess.TimeoutExpired:
        return False, "ping timeout"
    except OSError as e:
        return False, f"ping error: {e}"


def probe_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        if code == 0:
            return "open"
        # ECONNREFUSED: Linux 111, macOS 61, Windows 10061
        if code in (111, 61, 10061):
            return "refused"
        # ETIMEDOUT: Linux 110, macOS 60, Windows 10060
        if code in (110, 60, 10060):
            return "timeout"
        return "error"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "error"
    finally:
        try:
            s.close()
        except OSError:
            pass


def scan_targets(targets, config, progress=None, cancel_event=None):
    """Scan targets: ICMP ping + TCP port probes (ports always probed).

    Important: many MikroTik / firewall setups disable ICMP while leaving
    Winbox (8291) / API (8728) open. We therefore always probe configured
    ports, and count a host as a "responder" if it answers ping OR has any
    open TCP port.
    """
    cancel_event = cancel_event or Event()
    lock = Lock()
    state = {"done": 0, "responders": 0, "errors": 0}

    def one(ip):
        if cancel_event.is_set():
            return None
        alive, err = ping_host(ip, config.ping_timeout_ms)
        result = HostResult(ip, alive, error=err)

        # Always probe MikroTik signature ports even when ICMP is blocked.
        # Other ports are only probed on ICMP-alive hosts to keep large scans fast.
        mt_ports = {8291, 8728}
        for port in config.ports:
            if cancel_event.is_set():
                break
            if alive or port in mt_ports:
                result.ports[port] = probe_port(ip, port, config.port_timeout)

        # Count as responder if ICMP answered OR any TCP port is open.
        is_responder = bool(alive or result.open_ports)
        with lock:
            state["responders"] += int(is_responder)
            state["errors"] += int(bool(err) and not is_responder)
            state["done"] += 1
            completed = state["done"]
            responders = state["responders"]
        if progress:
            progress(
                {
                    "completed": completed,
                    "total": len(targets),
                    "ping_responders": responders,
                    "last_ip": ip,
                }
            )
        return result

    records = []
    executor = ThreadPoolExecutor(max_workers=config.workers)
    futures = {executor.submit(one, ip) for ip in targets}
    pending = set(futures)
    try:
        while pending:
            finished, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
            if cancel_event.is_set():
                for future in pending:
                    future.cancel()
            for future in finished:
                if future.cancelled():
                    continue
                try:
                    result = future.result()
                except Exception:
                    with lock:
                        state["errors"] += 1
                    continue
                if result is not None:
                    records.append(result)
    finally:
        executor.shutdown(wait=True, cancel_futures=True)

    def _ip_key(x):
        try:
            return tuple(map(int, x.ip.split(".")))
        except ValueError:
            return (0, 0, 0, 0)

    records.sort(key=_ip_key)
    return ScanReport(
        records,
        len(targets),
        state["responders"],
        state["done"],
        state["errors"],
        cancel_event.is_set(),
    )
