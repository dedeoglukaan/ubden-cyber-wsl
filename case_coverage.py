"""Derive automated + AI draft coverage for the 20-item manual analyst checklist.

Answers the question "how much of the manual test log did automation and the AI
operator already cover as drafts?" — WITHOUT flipping the analyst's own state.
The evidence-led invariant is preserved: report_v2 still treats only
analyst + SHA-256 as `doğrulandı`. This module only annotates each checklist
case with the draft evidence already gathered (automated findings, recorded
steps, AI drafts), so the analyst reviews drafts instead of 20 blank rows.

Pure/read-only: takes the already-parsed findings + steps and reads a few JSON
artefacts. No network, fully unit-testable.
"""
from __future__ import annotations

import json
from pathlib import Path

# A draft finding covers a case when its title/category contains any keyword.
FINDING_KEYWORDS = {
    "AD-POLICY": ("parola politikas", "karmaşıklık", "kilitleme eşiği", "kilitleme esigi",
                  "machineaccountquota", "domain admin"),
    "SHARES": ("smb paylaşım", "smb payla", "ileti imzalama", "nfs paylaş"),
    "DATABASE": ("sql server", "veritaban", "mssql", "mysql", "postgres", "sqlmap",
                 "sql enjeksiyon", "sql injection"),
    "PATCH": ("kullanım ömrü", "kullanim omru", "eol", "yaşam döngüsü"),
    "PROTOCOL": ("telnet", "anonim ftp", "ftp erişim", "sslv3", "tlsv1", "eski protokol",
                 "ileti imzalama", "düz metin", "duz metin"),
    "SNMP": ("snmp",),
    # NOTE: no generic "varsayılan" (=default) here — it also occurs in the SNMP-public
    # and default-credential finding titles, which belong to SNMP/AUTH, not CONFIG.
    "CONFIG": ("hsts", "x-content-type", "trace ", "nuclei", "başlık", "baslik",
               "http uç", "http uc", "güvenlik başlığı"),
    "AUTH": ("varsayılan/zayıf kimlik", "zayıf kimlik", "oturum", "kimlik bilgisi geçerli"),
    "INPUT": ("enjeksiyon", "xss", "injection", "sqlmap"),
    "API": ("swagger", "openapi", " api "),
    "WIRELESS": ("açık kablosuz", "wpa", "wifi", "kablosuz"),
    "PERIMETER": ("güvenlik duvarı", "ağ geçidi", "vpn", "firewall"),
}

# Recorded step-name prefixes that show a case's automation actually ran.
STEP_PREFIXES = {
    "SCOPE": ("route_scope", "freeze_scope", "scope", "windows_local_address"),
    "SNMP": ("snmp_v1_public", "snmpcheck_", "onesixtyone_", "snmp_extras"),
    "WIRELESS": ("wireless_", "wifi_"),
    "DATABASE": ("sql_browser", "discover_sql", "sqlmap_", "ms_sql"),
    "SHARES": ("smbclient_", "smb_enum"),
    "PROTOCOL": ("audit_", "tls_", "cidr_tls_"),
    "CONFIG": ("headers_", "methods_", "nuclei_", "default_cred", "audit_"),
    "API": ("swagger_", "web_extras", "whatweb_", "nikto"),
    "PERIMETER": ("traceroute_", "tcptraceroute_", "ikescan_"),
    "AD": ("ad_assessment", "ad_rootdse"),
}

STATUS_LABEL = {
    "otomatik-bulgu": "otomatik taslak bulgu",
    "ai-taslağı": "AI taslak analizi",
    "otomatik-tarandı": "otomatik kontrol çalıştı",
    "analist": "analist doğrulaması gerekli",
    "kayıt-yok": "kayıt yok",
}


def _load(root: Path, name: str):
    path = root / name
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return None
    return None


def _finding_blob(finding: dict) -> str:
    return (str(finding.get("title", "")) + " " + str(finding.get("category", ""))).lower()


def derive(root, meta, steps, findings) -> dict:
    """Return {'cases': {id: {...}}, 'summary': {...}} of draft coverage."""
    root = Path(root)
    steps = steps or []
    findings = findings or []
    meta = meta or {}
    auto_findings = [f for f in findings if f.get("source") in ("Otomatik gözlem", "AI (otomatik analiz)")]
    ai_data = _load(root, "AI_FINDINGS.json") or {}
    ai_cases = {}
    for item in ai_data.get("case_assessments", []) if isinstance(ai_data, dict) else []:
        if isinstance(item, dict) and item.get("case"):
            ai_cases[str(item["case"]).upper()] = item
    inv_raw = _load(root, "DEVICE_INVENTORY.json")
    inventory = inv_raw if isinstance(inv_raw, dict) else {}
    ad_raw = _load(root, "AD_ASSESSMENT.json")
    ad = ad_raw if isinstance(ad_raw, dict) else {}
    wifi = _load(root, "WIFI_SCAN.json")

    def steps_ran(case_id):
        prefixes = STEP_PREFIXES.get(case_id, ())
        return [s for s in steps if isinstance(s, dict) and str(s.get("status", "")).lower() in ("ok", "completed")
                and any(str(s.get("step", "")).startswith(p) for p in prefixes)]

    def matched_findings(case_id):
        keys = FINDING_KEYWORDS.get(case_id, ())
        if not keys:
            return []
        return [f for f in auto_findings if any(k in _finding_blob(f) for k in keys)]

    cases = {}

    def record(case_id, status, detail, finding_ids=(), sources=()):
        cases[case_id] = {"status": status, "status_label": STATUS_LABEL[status],
                          "detail": detail, "finding_ids": list(finding_ids),
                          "sources": list(sources)}

    all_ids = ["AUTH", "ROLES", "IDOR", "INPUT", "API", "LOGIC", "CONFIG", "RETEST",
               "SCOPE", "ASSET", "AD", "AD-POLICY", "SHARES", "DATABASE", "PATCH",
               "PROTOCOL", "SNMP", "PERIMETER", "WIRELESS", "EVIDENCE"]

    for cid in all_ids:
        mf = matched_findings(cid)
        ran = steps_ran(cid)
        ai = ai_cases.get(cid)
        # 1) Automated draft finding is the strongest signal.
        if mf:
            record(cid, "otomatik-bulgu",
                   f"{len(mf)} otomatik taslak bulgu üretildi.",
                   finding_ids=[f.get("id") for f in mf], sources=["findings"])
            continue
        # 2) Case-specific artefact presence (no finding needed to prove it ran).
        if cid == "ASSET" and inventory.get("host_count"):
            record(cid, "otomatik-tarandı",
                   f"{inventory.get('host_count')} adres için cihaz envanteri çıkarıldı "
                   f"(MAC görülen: {inventory.get('mac_count', 0)}).", sources=["DEVICE_INVENTORY.json"])
            continue
        if cid == "AD" and isinstance(ad, dict) and ad.get("status") == "ok":
            inv = ad.get("inventory", {}) if isinstance(ad.get("inventory"), dict) else {}
            record(cid, "otomatik-tarandı",
                   f"Salt okunur AD envanteri alındı ({ad.get('domain', '?')}); "
                   f"kullanıcı/grup/bilgisayar sayıları kaydedildi.", sources=["AD_ASSESSMENT.json"])
            continue
        if cid == "AD-POLICY" and isinstance(ad, dict) and ad.get("password_policy"):
            record(cid, "otomatik-tarandı",
                   "Parola politikası, MachineAccountQuota ve Domain Admins üyeliği LDAP ile okundu.",
                   sources=["AD_ASSESSMENT.json"])
            continue
        if cid == "WIRELESS" and (wifi or ran):
            n = len(wifi.get("networks", [])) if isinstance(wifi, dict) else 0
            record(cid, "otomatik-tarandı",
                   f"Wi-Fi taraması çalıştı; {n} ağ görüldü." if wifi else "Kablosuz modülü çalıştı.",
                   sources=["WIFI_SCAN.json"] if wifi else ["steps"])
            continue
        if cid == "PERIMETER" and inventory.get("observed_gateways"):
            record(cid, "otomatik-tarandı",
                   "Ağ geçitleri gözlendi; güvenlik duvarı kimliği ve segmentasyon analistçe teyit edilmeli.",
                   sources=["DEVICE_INVENTORY.json"])
            continue
        if cid == "EVIDENCE" and (any(f.get("evidence") for f in findings)
                                  or any(isinstance(s, dict) and s.get("sha256") for s in steps)):
            record(cid, "otomatik-tarandı",
                   "Adım çıktıları ve bulgular SHA-256 kanıt zinciriyle kaydedildi.", sources=["steps"])
            continue
        # 3) AI operator draft for the human-logic cases.
        if ai:
            record(cid, "ai-taslağı", str(ai.get("assessment", ""))[:400] or "AI taslak değerlendirmesi hazır.",
                   sources=["AI_FINDINGS.json"])
            continue
        # 4) A relevant automated check ran but produced no draft finding.
        if ran:
            record(cid, "otomatik-tarandı",
                   f"{len(ran)} ilgili otomatik kontrol çalıştı; taslak bulgu üretilmedi.", sources=["steps"])
            continue
        # 5) Genuinely analyst-driven (web logic / retest) or nothing ran.
        if cid in ("AUTH", "ROLES", "IDOR", "INPUT", "API", "LOGIC"):
            record(cid, "analist", "Uygulama mantığı testi; AI taslağı yoksa analist yürütmeli.")
        elif cid == "RETEST":
            record(cid, "analist", "Yalnız doğrulanmış bulgular düzeltildikten sonra ikinci geçişte yapılır.")
        else:
            record(cid, "kayıt-yok", "Bu görevde ilgili otomatik kayıt bulunmuyor.")

    covered = [c for c in cases.values() if c["status"] in ("otomatik-bulgu", "ai-taslağı", "otomatik-tarandı")]
    auto = [c for c in cases.values() if c["status"] in ("otomatik-bulgu", "otomatik-tarandı")]
    ai = [c for c in cases.values() if c["status"] == "ai-taslağı"]
    summary = {"total": len(all_ids), "covered": len(covered), "automated": len(auto),
               "ai": len(ai), "analyst_only": len([c for c in cases.values() if c["status"] == "analist"]),
               "no_record": len([c for c in cases.values() if c["status"] == "kayıt-yok"])}
    return {"cases": cases, "summary": summary}
