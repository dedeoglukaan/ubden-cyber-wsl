"""Windows-safe external-process runner for the native UBDEN uPenetrator.

Portable equivalent of ``wizard.command()`` (which is Linux-only: it relies on
``start_new_session`` + ``os.killpg`` + ``SIGKILL``). This module produces the
SAME step/event record shape so ``steps.json`` and the report engine stay
identical, but controls processes with Windows semantics (a new process group
and ``taskkill /T /F`` for the whole tree). It has no ANSI/TUI dependency; a
caller may pass ``on_tick`` to receive live progress for the web UI.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path

CREATE_NEW_PROCESS_GROUP = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
_VERSIONS: dict[str, str] = {}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _exe_base(executable: str) -> str:
    return os.path.basename(executable).lower().rsplit(".", 1)[0]


def tool_version(executable: str) -> str:
    """Best-effort first line of ``<tool> --version`` (cached, Windows-friendly).

    Replaces the apt/dpkg-based version lookup in ``tool_catalog`` which is not
    available on Windows.
    """
    if executable in _VERSIONS:
        return _VERSIONS[executable]
    version = ""
    if shutil.which(executable):
        for flag in ("--version", "-version", "-V", "version"):
            try:
                result = subprocess.run([executable, flag], capture_output=True,
                                        text=True, timeout=8, errors="replace", check=False)
            except (OSError, subprocess.TimeoutExpired):
                continue
            lines = [ln.strip() for ln in ((result.stdout or "") + "\n" +
                                           (result.stderr or "")).splitlines() if ln.strip()]
            if lines:
                version = lines[0][:120]
                break
    _VERSIONS[executable] = version
    return version


def _terminate(process: subprocess.Popen) -> None:
    """Kill the whole process tree without POSIX-only calls."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(process.pid)],
                           capture_output=True, timeout=15, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:  # keeps the module importable/testable on non-Windows CI
        try:
            process.kill()
        except (ProcessLookupError, OSError):
            pass
    try:
        process.wait(timeout=10)
    except (subprocess.TimeoutExpired, OSError):
        pass


class _StopPattern(Exception):
    pass


# One shared five-request/second budget for direct web probes (curl/nikto/nuclei),
# mirroring wizard.web_budget_wait().
_web_lock = threading.Lock()
_web_next = [0.0]


def web_budget_wait() -> None:
    with _web_lock:
        moment = time.monotonic()
        if _web_next[0] > moment:
            time.sleep(_web_next[0] - moment)
        _web_next[0] = max(_web_next[0], time.monotonic()) + 0.2


def _classify_exit(base, code):
    """Map a tool exit code to (status, detail). Benign "no service" outcomes during a
    broad sweep must NOT be counted as errors (they otherwise drown real failures and
    alarm the reader). curl 5/6/7/28 = DNS/connect/timeout; ping non-zero = no reply ->
    no_response. curl 35/52/60 = live service but empty/TLS-cert issue (recovered by the
    --insecure retry) -> review. Everything else non-zero -> error."""
    if code == 0:
        return "ok", ""
    if base == "ping":
        return "no_response", "ICMP yaniti yok; TCP servis bulgulari bundan etkilenmez"
    if base == "curl" and code in (5, 6, 7, 28):
        return "no_response", "Baglanti kurulamadi/zaman asimi; bu portta servis yok sayilir"
    if base == "curl" and code in (35, 52, 60):
        return "review", ("TLS/HTTP yaniti dogrulanamadi (sertifika IP ile eslesmeyebilir veya bos "
                          "yanit); servis acik, --insecure denemesiyle incelenir")
    return "error", ""


def run(name, argv, folder, events, timeout=900, stop_on=(), on_tick=None):
    """Run ``argv`` writing ``<name>.txt`` into ``folder`` and append a record.

    ``folder`` must be ``<run>/targets/<safe>/raw`` so ``output`` is recorded
    relative to the run root, exactly like wizard.command().
    """
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.txt"
    started = time.monotonic()
    executable = argv[0]
    base = _exe_base(executable)
    record = {"step": name, "tool": executable, "tool_version": tool_version(executable),
              "started_at": now(), "command": list(argv),
              "output": path.relative_to(folder.parent.parent.parent).as_posix(), "status": "pending"}
    if not shutil.which(executable):
        record.update(status="missing_tool", detail=f"{executable} kurulu değil")
    else:
        try:
            if base in ("curl", "nikto", "nuclei"):
                web_budget_wait()
            with path.open("w", encoding="utf-8", errors="replace") as handle:
                process = subprocess.Popen(argv, stdout=handle, stderr=subprocess.STDOUT,
                                           creationflags=CREATE_NEW_PROCESS_GROUP)
                last_stop = 0.0
                last_tick = 0.0
                try:
                    while True:
                        try:
                            code = process.wait(timeout=0.2)
                            break
                        except subprocess.TimeoutExpired:
                            if stop_on and time.monotonic() - last_stop >= 0.5:
                                last_stop = time.monotonic()
                                try:
                                    with path.open("rb") as snapshot:
                                        snapshot.seek(max(0, path.stat().st_size - 8192))
                                        tail = snapshot.read().decode("utf-8", "replace").lower()
                                    if any(pattern.lower() in tail for pattern in stop_on):
                                        raise _StopPattern()
                                except OSError:
                                    pass
                            # Throttle progress ticks to ~1 every 2s (avoids flooding the UI/log).
                            if on_tick and time.monotonic() - last_tick >= 2.0:
                                last_tick = time.monotonic()
                                try:
                                    on_tick(name, time.monotonic() - started, timeout)
                                except Exception:  # progress must never break a scan
                                    pass
                            if time.monotonic() - started >= timeout:
                                raise subprocess.TimeoutExpired(argv, timeout)
                except (subprocess.TimeoutExpired, _StopPattern) as exc:
                    _terminate(process)
                    if isinstance(exc, _StopPattern):
                        record.update(status="blocked", detail="Durdurma kosulu ciktiya yansidi")
                    else:
                        record.update(status="timeout", detail=f"{timeout} saniye aşıldı")
                else:
                    status, detail = _classify_exit(base, code)
                    record.update(status=status, exit_code=code)
                    if detail:
                        record["detail"] = detail
        except (OSError, ValueError) as exc:
            record.update(status="error", detail=str(exc))
    record.update(finished_at=now(), seconds=round(time.monotonic() - started, 2))
    if path.exists():
        record["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    events.append(record)
    return record
