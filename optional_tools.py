"""Opt-in, authorization-gated extra test modules (offensive/intrusive).

These are NEVER run by default. They execute only when the operator explicitly
enables the matching module (an `enabled_modules` flag), inside a scope-frozen,
route-guarded engagement with a written authorization reference. Results are
recorded with SHA-256 evidence and remain DRAFT (`taslak`) until an analyst
verifies them — the evidence-led invariant is unchanged.

This turn ships live runners for sqlmap (authorized SQL-injection testing) and
sipvicious (VoIP/SIP enumeration). The CATALOG also declares heavier offensive
and commercial modules (credential brute, exploit frameworks, commercial
scanners) with `live_runner=False`; those are the documented opt-in menu and get
their own gated runners in later increments. The analyst workplan's no-live-brute
guardrail is untouched: enabling a module here is an explicit operator action,
not a plan suggestion.
"""
from __future__ import annotations

import re
import shutil

# --------------------------------------------------------------------------- #
# Opt-in module catalogue (the menu). `flag` gates execution via enabled_modules.
# --------------------------------------------------------------------------- #
CATALOG = [
    {"id": "sqlmap", "name": "sqlmap — yetkili SQL enjeksiyon testi", "kind": "injection",
     "flag": "sql_injection_test", "feeds_case": ["INPUT", "DATABASE"], "live_runner": True,
     "install": "pip/apt (sqlmap)", "intrusive": True, "auth_required": True,
     "note": "Sınırlı (--batch, level/risk 1, crawl 1); veri dökme/OS kabuğu kapalı."},
    {"id": "sipvicious", "name": "SIPVicious — VoIP/SIP cihaz keşfi", "kind": "enumeration",
     "flag": "voip_scan", "feeds_case": ["ASSET", "PROTOCOL"], "live_runner": True,
     "install": "pip (sipvicious → svmap)", "intrusive": False, "auth_required": True,
     "note": "UDP/5060 SIP cihaz numaralandırma; parola denemesi yok (svwar hariç)."},
    # Catalogue-only for now (heavier / need candidate lists, daemons or licences):
    {"id": "hydra", "name": "Hydra — yetkili kimlik denemesi (sınırlı)", "kind": "brute",
     "flag": "credential_brute", "feeds_case": ["AUTH"], "live_runner": False,
     "install": "apt (hydra)", "intrusive": True, "auth_required": True,
     "note": "Yalnız operatörün verdiği küçük aday listesiyle, kilitleme eşiği altında; ayrı gated runner."},
    {"id": "medusa", "name": "Medusa — yetkili kimlik denemesi (sınırlı)", "kind": "brute",
     "flag": "credential_brute", "feeds_case": ["AUTH"], "live_runner": False,
     "install": "apt (medusa)", "intrusive": True, "auth_required": True, "note": "hydra alternatifi."},
    {"id": "ncrack", "name": "Ncrack — yetkili kimlik denemesi (sınırlı)", "kind": "brute",
     "flag": "credential_brute", "feeds_case": ["AUTH"], "live_runner": False,
     "install": "apt (ncrack)", "intrusive": True, "auth_required": True, "note": "hydra alternatifi."},
    {"id": "hashcat", "name": "hashcat — çevrimdışı hash kırma", "kind": "offline_crack",
     "flag": "offline_cracking", "feeds_case": ["AUTH", "AD-POLICY"], "live_runner": False,
     "install": "apt (hashcat)", "intrusive": False, "auth_required": True,
     "note": "Yalnız yetkiyle ele geçirilmiş hash'ler üzerinde, çevrimdışı; canlı hedefe dokunmaz."},
    {"id": "john", "name": "John the Ripper — çevrimdışı hash kırma", "kind": "offline_crack",
     "flag": "offline_cracking", "feeds_case": ["AUTH", "AD-POLICY"], "live_runner": False,
     "install": "apt (john)", "intrusive": False, "auth_required": True, "note": "hashcat alternatifi."},
    {"id": "nessus", "name": "Nessus — ticari zafiyet tarayıcı (API)", "kind": "scanner",
     "flag": "commercial_scanner", "feeds_case": ["CONFIG", "PATCH"], "live_runner": False,
     "install": "Tenable Nessus (lisans + API)", "intrusive": True, "auth_required": True,
     "note": "Lisanslı; sonuçlar API ile alınıp taslak bulguya dönüştürülür."},
    {"id": "burp", "name": "Burp Suite Pro — web tarayıcı (REST API)", "kind": "scanner",
     "flag": "commercial_scanner", "feeds_case": ["INPUT", "API", "AUTH"], "live_runner": False,
     "install": "PortSwigger Burp (lisans + REST API)", "intrusive": True, "auth_required": True,
     "note": "Lisanslı; enterprise/REST API ile tarama tetiklenir."},
    {"id": "acunetix", "name": "Acunetix — web tarayıcı (API)", "kind": "scanner",
     "flag": "commercial_scanner", "feeds_case": ["INPUT", "API"], "live_runner": False,
     "install": "Acunetix (lisans + API)", "intrusive": True, "auth_required": True, "note": "Lisanslı."},
]


def enabled(meta, flag):
    return flag in (meta.get("enabled_modules", []) or [])


_AUTH_PLACEHOLDERS = {"", "belirtilmedi", "yok", "none", "n/a", "na", "demo-only", "test"}


def authorized(meta):
    """Intrusive opt-in modules require a real written authorization reference.

    A placeholder (e.g. the win_scan default 'Belirtilmedi') does not count.
    """
    ref = str(meta.get("authorization_reference", "")).strip().lower()
    return bool(ref) and ref not in _AUTH_PLACEHOLDERS


# --------------------------------------------------------------------------- #
# sqlmap — bounded, authorized SQL-injection testing
# --------------------------------------------------------------------------- #
_SQLI_MARKERS = (
    "is vulnerable", "appears to be injectable",
    "parameter '", "sqlmap identified the following injection point",
)


def parse_sqlmap_output(text: str) -> dict:
    """Pure parser: detect injectable markers, parameters and DBMS from stdout."""
    low = (text or "").lower()
    injectable = ("sqlmap identified the following injection point" in low
                  or "is vulnerable" in low
                  or "appears to be injectable" in low)
    params = sorted(set(re.findall(r"(?im)^\s*parameter:\s*([^\s(]+)", text or "")))
    dbms = ""
    m = re.search(r"(?im)back-end DBMS:\s*([^\r\n]+)", text or "")
    if m:
        dbms = m.group(1).strip()[:80]
    return {"injectable": bool(injectable), "parameters": params[:20], "dbms": dbms}


def run_sqlmap(web_targets, raw, events, command, meta, timeout=900):
    """Run bounded sqlmap against explicitly-scoped web roots. web_targets: [(ip, url)].

    Gated by the 'sql_injection_test' module flag + a written authorization
    reference. Never dumps data, never spawns an OS shell.
    """
    import json
    if not enabled(meta, "sql_injection_test"):
        return
    if not authorized(meta):
        events.append({"step": "sqlmap", "tool": "sqlmap", "status": "skipped",
                       "detail": "Yazılı yetki referansı yok; intrusive modül çalıştırılmadı"})
        return
    if not shutil.which("sqlmap"):
        events.append({"step": "sqlmap", "tool": "sqlmap", "status": "missing_tool",
                       "detail": "sqlmap kurulu değil"})
        return
    seen = set()
    for ip, url in web_targets:
        if ip in seen:
            continue
        seen.add(ip)
        safe_ip = re.sub(r"[^A-Za-z0-9._-]", "_", str(ip))[:60]
        name = f"sqlmap_{safe_ip}"
        argv = ["sqlmap", "-u", url, "--batch", "--crawl=1", "--level=1", "--risk=1",
                "--technique=BEUST", "--threads=2", "--timeout=15", "--retries=1",
                "--random-agent", "--disable-coloring", "--flush-session", "--answers=quit=N,crack=N,dict=N"]
        record = command(name, argv, raw, events, timeout)
        record["target"] = ip
        out_file = raw / f"{name}.txt"
        try:
            text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.is_file() else ""
        except OSError:
            text = ""
        summary = parse_sqlmap_output(text)
        summary.update({"ip": ip, "url": url})
        (raw / f"sqlmap_result_{safe_ip}.json").write_text(
            json.dumps(summary, ensure_ascii=False), encoding="utf-8")


# --------------------------------------------------------------------------- #
# sipvicious (svmap) — SIP/VoIP device enumeration
# --------------------------------------------------------------------------- #
def run_sipvicious(target, raw, events, command, meta, timeout=600):
    """Enumerate SIP devices with svmap (no password guessing). target: CIDR or IP."""
    import json
    if not enabled(meta, "voip_scan"):
        return
    tool = shutil.which("svmap") or shutil.which("sipvicious")
    if not tool:
        events.append({"step": "sipvicious", "tool": "svmap", "status": "missing_tool",
                       "detail": "sipvicious/svmap kurulu değil"})
        return
    name = "sipvicious_svmap"
    argv = [tool, target] if tool.endswith("svmap") or "svmap" in tool else ["sipvicious", target]
    record = command(name, argv, raw, events, timeout)
    record["target"] = target
    out_file = raw / f"{name}.txt"
    try:
        text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.is_file() else ""
    except OSError:
        text = ""
    # svmap prints one line per responding SIP device (SIP/2.0 UA banner).
    hosts = sorted(set(re.findall(r"(?m)^\s*(\d{1,3}(?:\.\d{1,3}){3}):\d+", text)))
    (raw / "sipvicious_result.json").write_text(
        json.dumps({"target": target, "sip_hosts": hosts[:200]}, ensure_ascii=False), encoding="utf-8")
