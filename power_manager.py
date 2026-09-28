"""Keep the test machine awake and on a high-performance power plan for long runs.

Hours-long, wide-scope scans must not be interrupted by the machine sleeping,
the display turning off, or the disk spinning down. On Windows this uses the
Win32 SetThreadExecutionState API (so the box stays awake for the life of the
process, no matter how idle it looks) plus `powercfg` to switch to a
high/ultimate performance plan and zero the idle timeouts. Everything is
best-effort and never raises — power management can never abort a scan — and it
is a safe no-op on non-Windows so the test suite runs anywhere.
"""
from __future__ import annotations

import os
import re
import subprocess

# SetThreadExecutionState flags.
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ES_DISPLAY_REQUIRED = 0x00000002

# Built-in power scheme GUIDs.
HIGH_PERFORMANCE = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
ULTIMATE_PERFORMANCE = "e9a42b02-d5df-448d-aa00-03f14749eb61"  # may be absent; tried first

_awake = False


def _is_windows() -> bool:
    return os.name == "nt"


def _run(args, timeout=15):
    return subprocess.run(args, capture_output=True, text=True, errors="replace",
                          timeout=timeout, check=False)


def stay_awake() -> bool:
    """Prevent system sleep + display-off for the life of this process.

    ES_CONTINUOUS makes the request persist until released or the process exits,
    so a single call covers the whole scan. Idempotent. Returns True if applied.
    """
    global _awake
    if not _is_windows():
        return False
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(
            ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED)
        _awake = True
        return True
    except Exception:
        return False


def release() -> None:
    """Clear the keep-awake request (let normal power policy resume)."""
    global _awake
    if not _is_windows() or not _awake:
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
    except Exception:
        pass
    _awake = False


def active_scheme() -> str:
    """Return the current power scheme GUID, or '' if it cannot be read."""
    if not _is_windows():
        return ""
    try:
        out = _run(["powercfg", "/getactivescheme"])
        match = re.search(r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                          r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", out.stdout or "")
        return match.group(1) if match else ""
    except Exception:
        return ""


def high_performance() -> str:
    """Switch to Ultimate/High performance. Returns the previous scheme GUID ('' if unknown)."""
    if not _is_windows():
        return ""
    previous = active_scheme()
    for guid in (ULTIMATE_PERFORMANCE, HIGH_PERFORMANCE):
        try:
            if _run(["powercfg", "/setactive", guid]).returncode == 0:
                return previous
        except Exception:
            continue
    return previous


def restore_scheme(guid: str) -> None:
    if not _is_windows() or not guid:
        return
    try:
        _run(["powercfg", "/setactive", guid])
    except Exception:
        pass


class KeepAwake:
    """Context manager: keep awake (+ optional high-performance plan) for a scan.

    Restores the previous power scheme on exit; the keep-awake request is left in
    place if the surrounding process (e.g. the web server) already asserted it.
    """
    def __init__(self, high_perf: bool = True):
        self.high_perf = high_perf
        self._prev_scheme = ""
        self._owns_awake = False

    def __enter__(self):
        global _awake
        if not _awake:
            self._owns_awake = stay_awake()
        else:
            stay_awake()
        if self.high_perf:
            self._prev_scheme = high_performance()
        return self

    def __exit__(self, *exc):
        if self.high_perf:
            restore_scheme(self._prev_scheme)
        if self._owns_awake:
            release()
        return False
