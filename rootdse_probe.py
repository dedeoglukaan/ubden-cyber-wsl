"""Kredi-siz anonim LDAP RootDSE keşfi — Active Directory alan/orman tespiti.

Bir dizin sunucusunun RootDSE'si genellikle kimlik doğrulamasız okunabilir ve
alan adı, orman ve fonksiyonel seviye ile AD yetenek OID'ini açığa çıkarır. Bu
probe parola kullanmaz, yazma yapmaz; yalnız açık 389/636 portunda tek bir
anonim RootDSE okuması dener. Sonuç analist doğrulaması bekleyen bir keşiftir.

ldap3 I/O ile ayrıştırma ayrıdır: parse_rootdse() saf ve test edilebilirdir.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

# AD alan/orman fonksiyonel seviyeleri (msDS-Behavior-Version).
FUNCTIONAL_LEVELS = {
    "0": "Windows 2000", "1": "Windows Server 2003 interim",
    "2": "Windows Server 2003", "3": "Windows Server 2008",
    "4": "Windows Server 2008 R2", "5": "Windows Server 2012",
    "6": "Windows Server 2012 R2", "7": "Windows Server 2016",
}
# Eski/EOL kabul edilen seviyeler (analist bilgisi için).
LEGACY_LEVELS = {"0", "1", "2", "3", "4"}
AD_CAPABILITY_OID = "1.2.840.113556.1.4.800"


def _first(value):
    if isinstance(value, (list, tuple)):
        return str(value[0]) if value else ""
    return str(value or "")


def _domain_from_dn(dn: str) -> str:
    parts = [p.split("=", 1)[1] for p in str(dn).split(",")
             if p.strip().lower().startswith("dc=") and "=" in p]
    return ".".join(parts)


def parse_rootdse(attributes: dict, capabilities=None) -> dict:
    """RootDSE öznitelik sözlüğünden alan/orman/seviye özetini çıkarır (saf)."""
    attributes = {str(k).lower(): v for k, v in (attributes or {}).items()}
    caps = [str(c) for c in (capabilities or attributes.get("supportedcapabilities") or [])]
    default_nc = _first(attributes.get("defaultnamingcontext"))
    domain = _domain_from_dn(default_nc)
    dfl = _first(attributes.get("domainfunctionality"))
    ffl = _first(attributes.get("forestfunctionality"))
    is_ad = AD_CAPABILITY_OID in caps or bool(default_nc and dfl)
    return {
        "is_ad": is_ad,
        "domain": domain,
        "dc_dns_name": _first(attributes.get("dnshostname")),
        "default_naming_context": default_nc,
        "domain_functional_level": FUNCTIONAL_LEVELS.get(dfl, dfl or "bilinmiyor"),
        "forest_functional_level": FUNCTIONAL_LEVELS.get(ffl, ffl or "bilinmiyor"),
        "domain_level_legacy": dfl in LEGACY_LEVELS,
        "server_name": _first(attributes.get("servername")),
    }


def probe(ip: str, port: int = 389, timeout: float = 4, use_tls: bool = False,
          connector=None) -> dict:
    """Tek anonim RootDSE okuması dener; ağ katmanı ldap3'tür (enjekte edilebilir)."""
    result = {"ip": ip, "port": port, "tls": use_tls, "status": "no_response"}
    try:
        if connector is not None:
            attributes, capabilities = connector(ip, port, timeout, use_tls)
        else:
            from ldap3 import ALL, ANONYMOUS, Connection, Server
            server = Server(ip, port=port, use_ssl=use_tls, get_info=ALL,
                            connect_timeout=timeout)
            conn = Connection(server, authentication=ANONYMOUS, receive_timeout=timeout)
            if not conn.bind():
                result.update(status="bind_failed",
                              detail="Anonim bağlanma reddedildi; RootDSE anonim okunamıyor olabilir")
                conn.unbind()
                return result
            info = server.info
            attributes = dict(info.other) if info and info.other else {}
            if info and info.naming_contexts and "defaultnamingcontext" not in {k.lower() for k in attributes}:
                attributes["defaultNamingContext"] = list(info.naming_contexts)[0]
            capabilities = list(info.supported_capabilities) if info and info.supported_capabilities else []
            conn.unbind()
    except ImportError:
        result.update(status="missing_lib", detail="ldap3 kurulu değil")
        return result
    except Exception as exc:  # ağ/protokol hatası — hedef başına izole
        result.update(status="error", detail=f"{type(exc).__name__}")
        return result
    parsed = parse_rootdse(attributes, capabilities)
    result.update(status="ok" if parsed["is_ad"] or parsed["domain"] else "unrecognized_response",
                  **parsed)
    return result


def discover(assets, opened: dict, raw, events: list, timeout: float = 4) -> None:
    """Açık 389/636 olan her yetkili adreste tek anonim RootDSE okuması."""
    raw = Path(raw)
    found = []
    for ip in assets:
        ports = set(opened.get(ip, []))
        if 636 in ports:
            port, tls = 636, True
        elif 389 in ports:
            port, tls = 389, False
        else:
            continue
        result = probe(str(ip), port, timeout, tls)
        path = raw / ("ad_rootdse_" + str(ip).replace(":", "_") + ".json")
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        found.append({"ip": str(ip), "status": result.get("status"),
                      "is_ad": bool(result.get("is_ad")), "domain": result.get("domain", ""),
                      "evidence": str(path.relative_to(raw.parents[2]))})
    if not found:
        return
    ad_count = sum(item["is_ad"] for item in found)
    summary = {"step": "ad_rootdse", "tool": "UBDEN RootDSE probe",
               "status": "ok" if ad_count else "no_response",
               "target_count": len(found), "ad_count": ad_count,
               "detail": (f"Anonim RootDSE: {ad_count}/{len(found)} adreste AD dizini gözlendi; "
                          "kimlik doğrulamasız okuma, yetki/parola ilkesi testinin yerine geçmez"),
               "evidence": found}
    summary_path = raw / "ad_rootdse_summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary["output"] = str(summary_path.relative_to(raw.parents[2]))
    summary["sha256"] = hashlib.sha256(summary_path.read_bytes()).hexdigest()
    events.append(summary)
