"""Locate the MikroTik WinBox desktop client on the local machine."""
from __future__ import annotations

import os
import shutil
from pathlib import Path


def find_winbox() -> str | None:
    """Return a local WinBox executable path, if installed.

    This helper only discovers an executable on the machine running the
    application/agent. It does not download or install third-party software.
    """
    candidates = []
    for command in ("winbox", "winbox.exe", "WinBox.exe", "winbox64.exe"):
        found = shutil.which(command)
        if found:
            candidates.append(found)

    if os.name == "nt":
        roots = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
            Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")),
            Path.home() / "Downloads",
        ]
        names = ("winbox64.exe", "winbox.exe", "WinBox.exe")
        for root in roots:
            for name in names:
                candidates.append(str(root / name))
                candidates.append(str(root / "MikroTik" / name))

    for candidate in candidates:
        try:
            if Path(candidate).is_file():
                return str(Path(candidate))
        except (OSError, TypeError, ValueError):
            continue
    return None
