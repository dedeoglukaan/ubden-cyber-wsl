"""Canlı NVD CVE zenginleştirme — tespit edilen platform+sürüm için CVE adayları.

Yalnız GÜVENİLİR CPE eşlemesi ve gözlenen sürümü olan platformlar için NVD 2.0
API'sine `virtualMatchString` sorgusu atar. Gönderilen tek şey teknoloji kimliği
(ör. cpe:2.3:o:fortinet:fortios:7.2.4:*) — müşteri sırrı değildir. Sonuçlar
analist doğrulaması bekleyen ADAYLARDIR; boş sonuç "açık yok" anlamına gelmez.

Ağ katmanı enjekte edilebilir (`fetch`); canlı yol urllib + kısa timeout kullanır,
çevrimdışında veya hata durumunda zarifçe atlar ve raporu bloke etmez.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Yalnız güvenilir CPE eşlemesi olan aileler sorgulanır (part, vendor, product).
CPE_MAP = {
    "VMware ESXi": ("o", "vmware", "esxi"),
    "VMware vCenter": ("a", "vmware", "vcenter_server"),
    "Proxmox VE": ("a", "proxmox", "virtual_environment"),
    "Fortinet FortiGate / FortiOS": ("o", "fortinet", "fortios"),
    "Sophos Firewall (SFOS/XG)": ("o", "sophos", "sfos"),
    "Synology DSM": ("o", "synology", "diskstation_manager"),
    "QNAP QTS": ("o", "qnap", "qts"),
}
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def _default_fetch(url: str, api_key: str = "", timeout: float = 15) -> dict:
    headers = {"User-Agent": "UBDEN-Cyber/1.0"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (sabit NVD host)
        return json.loads(response.read().decode("utf-8", "replace"))


def _cve_severity(metrics: dict) -> tuple[str, str]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return str(data.get("baseScore", "")), str(data.get("baseSeverity", ""))
    entries = metrics.get("cvssMetricV2") or []
    if entries:
        data = entries[0].get("cvssData", {})
        return str(data.get("baseScore", "")), str(entries[0].get("baseSeverity", ""))
    return "", ""


def query_nvd(cpe23: str, fetch=_default_fetch, api_key: str = "", limit: int = 8) -> list:
    """virtualMatchString ile sürümü kapsayan CVE'leri getirir (en şiddetliden)."""
    url = NVD_URL + "?" + urllib.parse.urlencode(
        {"virtualMatchString": cpe23, "resultsPerPage": 30})
    data = fetch(url, api_key)
    results = []
    for item in (data.get("vulnerabilities") or []):
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        if not cid:
            continue
        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value", "")[:280]
                break
        score, severity = _cve_severity(cve.get("metrics", {}))
        results.append({"id": cid, "cvss": score, "severity": severity.upper(), "summary": summary})
    results.sort(key=lambda c: (-_SEV_RANK.get(c["severity"], 0), c["id"]))
    return results[:limit]


def _targets(tech: dict) -> list:
    """CPE eşlemesi + gözlenen sürümü olan benzersiz (aile, sürüm, cpe) hedefleri.

    Önce maçın kendi `cpe_parts` alanını (tech_fingerprint'ten) kullanır; yoksa
    aile adına göre CPE_MAP'e düşer.
    """
    seen = {}
    for match in (tech or {}).get("matches", []):
        family = match.get("family", "")
        version = str(match.get("version") or "").strip()
        parts = match.get("cpe_parts") or CPE_MAP.get(family)
        if not parts or not version:
            continue
        part, vendor, product = parts
        cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
        key = (vendor, product, version)
        if key not in seen:
            seen[key] = {"family": family, "version": version, "cpe": cpe,
                         "assets": sorted({m.get("ip", "") for m in tech["matches"]
                                           if m.get("family") == family and m.get("version") == version})}
    return list(seen.values())


def enrich(root: Path, tech: dict, fetch=_default_fetch, api_key: str = "",
           max_queries: int = 6, sleep=time.sleep, delay: float = 6.0) -> dict:
    """Tespit edilen platform+sürümler için NVD CVE adayları toplar (best-effort)."""
    targets = _targets(tech)[:max_queries]
    items, errors, queried = [], 0, 0
    for index, target in enumerate(targets):
        if index and delay:
            sleep(delay)  # keyless NVD rate limiti (5/30s) için nazik ara
        try:
            cves = query_nvd(target["cpe"], fetch, api_key)
            queried += 1
            items.append({"family": target["family"], "version": target["version"],
                          "cpe": target["cpe"], "assets": target["assets"],
                          "cve_count": len(cves), "cves": cves})
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError,
                ValueError, KeyError):
            errors += 1
    critical_high = sum(1 for it in items for c in it["cves"] if c["severity"] in ("CRITICAL", "HIGH"))
    return {
        "schema": 1, "queried": queried, "errors": errors,
        "candidate_platforms": len(_targets(tech)),
        "items": items, "critical_high_count": critical_high,
        "note": ("NVD adayları gözlenen sürüme göre CPE eşlemesiyle çekilir ve analist "
                 "doğrulaması bekler; boş/eksik sonuç 'açık yok' anlamına gelmez. "
                 "Yalnız güvenilir CPE eşlemesi olan platformlar sorgulanır."),
    }


def write(root: Path, tech: dict, fetch=_default_fetch) -> dict:
    """UBDEN_CVE.json üretir; çevrimdışı/kapalıysa boş sonucu zarifçe yazar."""
    root = Path(root)
    if os.environ.get("UBDEN_OFFLINE"):
        result = {"schema": 1, "queried": 0, "errors": 0, "items": [],
                  "critical_high_count": 0, "candidate_platforms": len(_targets(tech)),
                  "note": "UBDEN_OFFLINE ayarlı; NVD sorgusu yapılmadı."}
    else:
        api_key = os.environ.get("NVD_API_KEY", "")
        try:
            result = enrich(root, tech, fetch=fetch, api_key=api_key)
        except Exception as exc:  # rapor üretimini asla bloke etme
            result = {"schema": 1, "queried": 0, "errors": 1, "items": [],
                      "critical_high_count": 0, "candidate_platforms": len(_targets(tech)),
                      "note": f"NVD sorgusu tamamlanamadı ({type(exc).__name__}); rapor kayıtlı kanıtla üretildi."}
    temp = root / ".UBDEN_CVE.pending.json"
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(root / "UBDEN_CVE.json")
    return result
