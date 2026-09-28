"""Windows -> WSL/Kali bridge for the OPTIONAL offensive-ext attack stage.

100% isolated addon. Nothing here runs unless the operator triggers it (the webapp
"Attack Mode & Auto Analist" button or `ubden-win offensive`). It is NEVER imported
by the scan/report path — win_scan.py / report_v2.py / wizard.py do not reference it.

Flow: the UBDEN Windows scan already produced a run folder. This module runs the
Linux-only offensive-ext chain inside Kali WSL against that folder (reached over
/mnt), streaming the console line-by-line, then regenerates REPORT.html on the
Windows side. offensive-ext appends its findings to the run folder's review.json
(it preserves the existing analyst ledger). Read-only by default; writes + DCSync
only when the caller explicitly opts in.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

# Where `ubden-win setup-offensive` installs offensive-ext inside Kali (a bash
# expression, so $HOME expands in a login shell). Kept unquoted on purpose.
KALI_DIR = "$HOME/ubden-offensive"
WSL = "wsl.exe"


def _decode(raw: bytes) -> str:
    """wsl.exe -l output is UTF-16LE on many Windows builds; plain output is UTF-8."""
    if b"\x00" in (raw or b""):
        return raw.decode("utf-16-le", "ignore")
    return (raw or b"").decode("utf-8", "ignore")


def find_distro(preferred: str = "kali") -> str:
    """Return a WSL distro name (prefer one containing 'kali'), or '' if none."""
    try:
        out = subprocess.run([WSL, "-l", "-q"], capture_output=True, timeout=20, check=False)
    except Exception:
        return ""
    names = [n.strip() for n in _decode(out.stdout).replace("\r", "").splitlines() if n.strip()]
    kali = [n for n in names if preferred.lower() in n.lower()]
    return kali[0] if kali else (names[0] if names else "")


def to_wsl_path(winpath, distro: str) -> str:
    """Translate a Windows path to its /mnt/... path inside the distro via wslpath."""
    try:
        out = subprocess.run([WSL, "-d", distro, "wslpath", "-a", str(winpath)],
                             capture_output=True, timeout=20, check=False)
        return _decode(out.stdout).strip()
    except Exception:
        return ""


def write_scope(run_dir) -> str:
    """Write offensive-ext's mandatory allowlist from engagement.json targets.

    offensive-ext scope is an allowlist only (no exclusion syntax); we reuse the
    engagement's frozen targets so the attack can never exceed the scan's scope.
    """
    run_dir = Path(run_dir)
    try:
        meta = json.loads((run_dir / "engagement.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    targets = [str(t).strip() for t in meta.get("targets", []) if str(t).strip()]
    path = run_dir / "offensive-ext-scope.txt"
    body = "# UBDEN engagement scope (auto) — offensive-ext allowlist\n" + "\n".join(targets) + "\n"
    path.write_text(body, encoding="utf-8")
    return str(path)


def kali_offensive_installed(distro: str) -> bool:
    """True if `ubden-win setup-offensive` has installed offensive-ext in Kali."""
    try:
        out = subprocess.run([WSL, "-d", distro, "--", "bash", "-lic",
                              f'test -f "{KALI_DIR}/pipeline.py" && echo OK'],
                             capture_output=True, timeout=20, check=False)
        return "OK" in _decode(out.stdout)
    except Exception:
        return False


def _kali_python() -> str:
    """Prefer offensive-ext's own venv, fall back to system python3."""
    return f'PY="{KALI_DIR}/.venv/bin/python3"; [ -x "$PY" ] || PY=python3; '


def build_pipeline_argv(wsl_run: str, wsl_scope: str, opts: dict, *, dry_run=False) -> list[str]:
    """The pipeline.py argument list (POSIX-quoted), read-only unless opts['writes']."""
    args = ["pipeline.py", "--run-dir", shlex.quote(wsl_run),
            "--scope", shlex.quote(wsl_scope), "--no-report"]
    if opts.get("user"):
        args += ["--user", shlex.quote(str(opts["user"]))]
    if opts.get("password"):
        args += ["--password", shlex.quote(str(opts["password"]))]
    elif opts.get("hashes"):
        args += ["--hashes", shlex.quote(str(opts["hashes"]))]
    if opts.get("dc"):
        args += ["--dc", shlex.quote(str(opts["dc"]))]
    if opts.get("domain"):
        args += ["--domain", shlex.quote(str(opts["domain"]))]
    if opts.get("dc_ip"):
        args += ["--ip", shlex.quote(str(opts["dc_ip"]))]
    if opts.get("reviewer"):
        args += ["--reviewer", shlex.quote(str(opts["reviewer"]))]
    if dry_run:
        args += ["--dry-run"]
    if opts.get("writes"):
        # Full exploitation incl. DCSync, unattended (owner opt-in only).
        args += ["--enable-writes", "--allow-dcsync", "--assume-yes"]
    return args


def build_wsl_command(distro: str, wsl_run: str, wsl_scope: str, opts: dict) -> list[str]:
    argv = build_pipeline_argv(wsl_run, wsl_scope, opts)
    inner = f'cd "{KALI_DIR}" && {_kali_python()}"$PY" ' + " ".join(argv)
    return [WSL, "-d", distro, "--", "bash", "-lic", inner]


def build_doctor_command(distro: str, wsl_run: str, wsl_scope: str, opts: dict) -> list[str]:
    args = ["doctor.py", "--run-dir", shlex.quote(wsl_run), "--scope", shlex.quote(wsl_scope)]
    for flag, key in (("--user", "user"), ("--password", "password"), ("--hashes", "hashes"),
                      ("--dc", "dc"), ("--domain", "domain"), ("--ip", "dc_ip")):
        if opts.get(key):
            args += [flag, shlex.quote(str(opts[key]))]
    inner = f'cd "{KALI_DIR}" && {_kali_python()}"$PY" ' + " ".join(args)
    return [WSL, "-d", distro, "--", "bash", "-lic", inner]


def _stream(cmd: list[str], progress, mask=(), control=None) -> tuple[int, str]:
    """Run cmd, stream stdout line-by-line to progress(), return (exit_code, full_text).
    Secrets in `mask` are redacted from every emitted line. If `control` is a dict,
    the live process is registered as control['proc'] so an emergency stop can kill it."""
    masks = [m for m in mask if m]
    collected = []
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1, encoding="utf-8", errors="replace")
    except Exception as exc:
        progress(f"Komut başlatılamadı: {exc}", "warn")
        return 1, ""
    if isinstance(control, dict):
        control["proc"] = proc
    for line in proc.stdout:
        line = line.rstrip()
        for m in masks:
            line = line.replace(m, "***")
        if line:
            collected.append(line)
            progress(line, "info")
    proc.wait()
    return proc.returncode, "\n".join(collected)


def _regenerate_report(run_dir, progress) -> None:
    """Rebuild REPORT.html on the Windows side (same call win_scan uses)."""
    report = Path(__file__).resolve().parent / "report_v2.py"
    try:
        result = subprocess.run([sys.executable, str(report), str(run_dir)],
                                capture_output=True, text=True, errors="replace",
                                timeout=1800, check=False)
        if result.returncode == 0:
            progress("Rapor güncellendi (saldırı bulguları işlendi).", "done")
        else:
            progress("Rapor üretimi hata döndü: " + (result.stderr or "").strip()[:300], "warn")
    except (OSError, subprocess.TimeoutExpired) as exc:
        progress(f"Rapor yeniden üretilemedi: {exc}", "warn")


def request_stop(control: dict) -> dict:
    """Emergency stop for a running attack. Three layers, best-effort:
    1. STOP file in the run dir — offensive-ext honors it BEFORE the next step
       (cooperative, clean abort; partial evidence retained).
    2. Kill the Windows-side wsl.exe process tree (taskkill /T).
    3. pkill the Kali-side offensive tools so nothing is orphaned in the WSL VM.
    """
    if not isinstance(control, dict):
        return {"ok": False, "detail": "no_control"}
    control["stopped"] = True
    run_dir = control.get("run_dir")
    distro = control.get("distro")
    proc = control.get("proc")
    out = {"ok": True, "stop_file": False, "proc_killed": False, "wsl_pkill": False}
    try:
        if run_dir:
            (Path(run_dir) / "STOP").write_text("stop\n", encoding="utf-8")  # /mnt/.../STOP in Kali
            out["stop_file"] = True
    except OSError:
        pass
    try:
        if proc is not None and proc.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                               capture_output=True, timeout=20, check=False)
            else:
                proc.terminate()
            out["proc_killed"] = True
    except Exception:
        pass
    try:
        if distro:
            subprocess.run([WSL, "-d", distro, "--", "bash", "-lic",
                            "for p in pipeline.py GetUserSPNs GetNPUsers certipy nxc netexec "
                            "bloodhound secretsdump coercer hashcat john; do pkill -f \"$p\"; done; true"],
                           capture_output=True, timeout=25, check=False)
            out["wsl_pkill"] = True
    except Exception:
        pass
    return out


def run(run_dir, opts: dict, progress, control=None) -> dict:
    """Run the offensive-ext chain in Kali against run_dir. Never raises.
    If `control` is a dict, it is populated so request_stop(control) can abort."""
    def emit(line, level="info"):
        try:
            progress(line, level)
        except Exception:
            pass

    run_dir = str(run_dir)
    if isinstance(control, dict):
        control["run_dir"] = run_dir
    distro = opts.get("distro") or find_distro()
    if not distro:
        emit("Kali WSL bulunamadı. Önce çalıştırın: ubden-win setup-offensive", "warn")
        return {"status": "error", "reason": "no_kali_distro"}
    if isinstance(control, dict):
        control["distro"] = distro
    if not kali_offensive_installed(distro):
        emit(f"offensive-ext Kali'de kurulu değil ({distro}). Önce: ubden-win setup-offensive", "warn")
        return {"status": "error", "reason": "not_installed", "distro": distro}
    if not opts.get("user") or not (opts.get("password") or opts.get("hashes")):
        emit("Kullanıcı ve parola/hash gerekli (yetkili test hesabı).", "warn")
        return {"status": "error", "reason": "missing_credentials"}

    wsl_run = to_wsl_path(run_dir, distro)
    if not wsl_run:
        emit("Run klasörü WSL yoluna çevrilemedi (wslpath).", "warn")
        return {"status": "error", "reason": "wslpath_failed"}
    scope_win = write_scope(run_dir)
    wsl_scope = to_wsl_path(scope_win, distro)
    mask = [opts.get("password"), opts.get("hashes")]

    emit(f"Kali/WSL: {distro} · hedef klasör: {wsl_run}", "info")
    emit("Ön-uçuş kontrolü (doctor.py — salt-okunur GO/NO-GO)…", "info")
    _, doctor_text = _stream(build_doctor_command(distro, wsl_run, wsl_scope, opts), progress, mask, control)
    if isinstance(control, dict) and control.get("stopped"):
        emit("Kullanıcı durdurdu (ön-uçuştan sonra).", "warn")
        return {"status": "stopped", "distro": distro, "run_dir": run_dir}
    if "NO-GO" in doctor_text.upper() and not opts.get("force"):
        emit("doctor NO-GO verdi; saldırı başlatılmadı. Eksikleri giderin veya force ile geçin.", "warn")
        return {"status": "no_go", "distro": distro, "run_dir": run_dir}

    mode = "TAM (writes + DCSync)" if opts.get("writes") else "salt-okunur zincir"
    emit(f"Saldırı zinciri çalışıyor (Kali/WSL) — mod: {mode}…", "info")
    emit("Acil durdurma: web arayüzündeki ⛔ DURDUR düğmesi (STOP dosyası + süreç sonlandırma).", "info")
    code, _ = _stream(build_wsl_command(distro, wsl_run, wsl_scope, opts), progress, mask, control)
    if isinstance(control, dict) and control.get("stopped"):
        emit("Saldırı kullanıcı tarafından durduruldu (STOP + süreç sonlandırma).", "warn")
        _regenerate_report(run_dir, emit)
        return {"status": "stopped", "distro": distro, "run_dir": run_dir}

    emit("Rapor Windows tarafında yeniden üretiliyor…", "info")
    _regenerate_report(run_dir, emit)
    status = "completed" if code == 0 else "attack_error"
    emit("Attack Mode tamamlandı." if code == 0 else f"Saldırı zinciri hata döndü (kod {code}).",
         "done" if code == 0 else "warn")
    return {"status": status, "distro": distro, "run_dir": run_dir, "exit_code": code}


if __name__ == "__main__":
    import argparse
    import getpass
    ap = argparse.ArgumentParser(description="UBDEN offensive-ext (Kali/WSL) — opsiyonel saldırı aşaması")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--hashes")
    ap.add_argument("--dc")
    ap.add_argument("--domain")
    ap.add_argument("--ip", dest="dc_ip")
    ap.add_argument("--reviewer", default="Analist")
    ap.add_argument("--writes", action="store_true", help="Tam istismar: writes + DCSync (yazılı onay şart)")
    ap.add_argument("--force", action="store_true", help="doctor NO-GO'yu geç")
    a = ap.parse_args()
    pw = a.password
    if a.user and not pw and not a.hashes:
        pw = getpass.getpass("Parola (ekrana yazılmaz): ")  # never on the command line
    out = run(a.run_dir, {"user": a.user, "password": pw, "hashes": a.hashes, "dc": a.dc,
                          "domain": a.domain, "dc_ip": a.dc_ip, "reviewer": a.reviewer,
                          "writes": a.writes, "force": a.force},
              progress=lambda line, level="info": print(("[!] " if level == "warn" else "") + line, flush=True))
    raise SystemExit(0 if out.get("status") == "completed" else 1)
