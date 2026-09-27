"""OSINT olguları — UBDEN'in zaten topladığı kanıttan, dış API'siz.

Yetkili alan adlarının DMARC/SPF kayıtlarını (görevde çalıştırılan `dig` çıktıları)
okuyup e-posta sahtelenebilirliğini ve bir insan-riski skorunu çıkarır. Bu olgular
korelasyon motoruna verilir; böylece dış e-posta duruşu ile iç ağ yüzeyi arasında
oltalama gibi çapraz-katman köprüler kurulabilir. Ağ isteği yapmaz; yalnız kayıtlı
kanıtı okur. Sonuçlar analist doğrulaması bekleyen adaylardır.
"""
from __future__ import annotations

import re
from pathlib import Path


def _is_domain(value: str) -> bool:
    value = str(value or "").strip()
    if not value or "/" in value or ":" in value:
        return False
    if re.fullmatch(r"[0-9.]+", value):  # düz IPv4 değil
        return False
    return "." in value and bool(re.search(r"[A-Za-z]", value))


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _dmarc_policy(text: str) -> str:
    """dig +noall +answer çıktısından DMARC uygulama politikasını döndürür.

    'reject' / 'quarantine' / 'none' / '' (kayıt yok).
    """
    if "v=DMARC1" not in text:
        return ""
    match = re.search(r"[;\"\s]p\s*=\s*(reject|quarantine|none)", text, re.I)
    return match.group(1).lower() if match else "none"


def _spf_qualifier(text: str) -> str:
    """SPF 'all' niteleyicisini döndürür: '-' hardfail, '~' softfail, '?'/'+' zayıf, '' yok."""
    match = re.search(r"v=spf1[^\"]*?([\-~?+])all", text, re.I)
    if match:
        return match.group(1)
    return "spf1" if "v=spf1" in text else ""


def build(root: Path, meta: dict) -> dict:
    """Yetkili alanların e-posta duruşundan OSINT olguları üretir."""
    root = Path(root)
    domains = [t for t in meta.get("targets", []) if _is_domain(t)]
    raw_dir = root / "targets"
    dmarc_files = sorted(raw_dir.glob("*/raw/dns_dmarc.txt")) if raw_dir.exists() else []

    worst = "korumalı"       # reject > quarantine(kısmi) > yok
    order = {"korumalı": 0, "kısmi": 1, "yok": 2}
    spoofable = False
    spf_present = False
    evaluated = []
    for path in dmarc_files:
        text = _read(path)
        policy = _dmarc_policy(text)
        spf_text = _read(path.parent / "dns_txt.txt")
        spf_q = _spf_qualifier(spf_text)
        spf_present = spf_present or bool(spf_q)
        if policy == "reject":
            level = "korumalı"
        elif policy == "quarantine":
            level = "kısmi"
        else:
            level = "yok"  # none veya kayıt yok
        if order[level] > order[worst]:
            worst = level
        if level in ("yok", "kısmi"):
            spoofable = True
        label = path.parent.parent.name
        evaluated.append({"domain": label, "dmarc": policy or "yok",
                          "spf": spf_q or "yok", "spoofable": level})

    # İnsan-riski skoru (100 en iyi). DMARC en ağır faktördür.
    score = 100
    factors = []
    if domains and not dmarc_files:
        factors.append("Alan adı hedefi var ancak DMARC kanıtı kaydedilmedi")
    if worst == "yok" and dmarc_files:
        score -= 35
        factors.append("Uygulanan DMARC yok (p=none / kayıt yok): alan sahtelenebilir")
    elif worst == "kısmi":
        score -= 20
        factors.append("DMARC yalnız quarantine: sınırlı sahtekârlık koruması")
    if dmarc_files and not spf_present:
        score -= 10
        factors.append("SPF kaydı görülmedi")
    score = max(0, min(100, score))
    grade = ("A" if score >= 85 else "B" if score >= 70 else "C" if score >= 50
             else "D" if score >= 30 else "E")

    return {
        "schema": 1,
        "available": bool(dmarc_files),
        "domains": [e["domain"] for e in evaluated] or domains,
        "email_spoofable": spoofable,
        "email_posture": worst,
        "spf_present": spf_present,
        "records": evaluated,
        "human_score": score,
        "human_grade": grade,
        "factors": factors,
        "note": ("E-posta duruşu yalnız DMARC/SPF kayıtlarından çıkarıldı; "
                 "çalışan e-posta filtreleme ve gerçek teslimat analistçe doğrulanmalı."),
    }
