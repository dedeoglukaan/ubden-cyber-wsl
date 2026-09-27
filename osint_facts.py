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


def _read(path: Path, limit: int = 200_000) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _harvest(root: Path, domains: list) -> tuple[list, list, list]:
    """theHarvester/dnsenum/fierce çıktısından e-posta ve alt alan toplar.

    Ham e-posta/kullanıcı adları yalnız OSINT kanıt dosyasında tutulur; rapor
    anlatısına yalnız sayıları geçer (kişisel veriyi derlemekten kaçınmak için).
    """
    raw_dir = root / "targets"
    if not raw_dir.exists():
        return [], [], []
    emails, subs = set(), set()
    # Kayıtlı ana alan (son iki etiket) bazında eşleştir: portal.ornek.com → ornek.com.
    bases = sorted({".".join(d.lower().split(".")[-2:]) for d in domains if "." in d})
    for path in sorted(raw_dir.glob("*/raw/*_recon.txt"))[:40]:
        text = _read(path)
        for match in _EMAIL_RE.findall(text):
            dom = match.partition("@")[2].lower()
            if not bases or any(dom == b or dom.endswith("." + b) for b in bases):
                emails.add(match.lower())
        for b in bases:
            for match in re.findall(r"\b([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\." + re.escape(b) + r")\b", text, re.I):
                if match.lower() != b:
                    subs.add(match.lower())
    usernames = sorted({e.split("@", 1)[0] for e in emails})
    return sorted(emails), sorted(subs), usernames


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

    emails, subdomains, usernames = _harvest(root, [e["domain"] for e in evaluated] or domains)

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
    if usernames:
        score -= 14 if len(usernames) >= 5 else 8
        factors.append(f"OSINT ile {len(usernames)} kullanıcı adı adayı elde edildi")
    if subdomains:
        factors.append(f"{len(subdomains)} alt alan gözlendi")
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
        "email_count": len(emails),
        "subdomain_count": len(subdomains),
        "username_count": len(usernames),
        "usernames_discovered": bool(usernames),
        "emails": emails,
        "subdomains": subdomains,
        "usernames": usernames,
        "human_score": score,
        "human_grade": grade,
        "factors": factors,
        "note": ("E-posta duruşu yalnız DMARC/SPF kayıtlarından çıkarıldı; "
                 "çalışan e-posta filtreleme ve gerçek teslimat analistçe doğrulanmalı."),
    }
