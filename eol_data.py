"""Curated end-of-life (EOL) dataset and matcher for common enterprise products.

Detection is evidence-led: a match is a *draft* observation built from the
product/version strings Nmap already reports.  The analyst confirms the exact
build/SP level and business impact before it becomes a verified finding.  Dates
are vendor lifecycle end dates (extended support where applicable); the note
records the SP/build caveat because Nmap version banners rarely carry the SP.

No network access, no third-party dependency — a pure lookup so it is fully
unit-testable and runs identically on Kali and Windows.
"""
from __future__ import annotations

import datetime as _dt
import re

# Each rule: product substrings (any match, case-insensitive) + a version regex
# whose first group (or the whole match) identifies the release, mapped to its
# EOL date.  `severity` is the draft severity; `note` carries the SP/build
# caveat the analyst must confirm.
_RULES = [
    # --- VMware ESXi / ESX -------------------------------------------------
    {"name": "VMware ESXi", "products": ["vmware esxi", "vmware esx", "esxi"],
     "versions": {r"^3\.": "2010-05-21", r"^4\.": "2014-05-21",
                  r"^5\.0": "2016-08-24", r"^5\.1": "2016-08-24",
                  r"^5\.5": "2020-09-19", r"^6\.0": "2022-03-12",
                  r"^6\.5": "2022-10-15", r"^6\.7": "2022-10-15",
                  r"^7\.0": "2025-10-02"},
     "severity": "high",
     "note": "ESXi sürüm/derleme ve yama seviyesi analistçe doğrulanmalı."},
    # --- Microsoft SQL Server ---------------------------------------------
    # Nmap 1433 servisi genelde yıl ('2014') veya iç sürüm ('12.00') verir.
    {"name": "Microsoft SQL Server", "products": ["microsoft sql server", "ms-sql", "mssql"],
     "versions": {r"2000": "2013-04-09", r"\b9\.": "2016-04-12", r"2005": "2016-04-12",
                  r"\b10\.5": "2019-07-09", r"\b10\.0": "2019-07-09",
                  r"2008": "2019-07-09", r"\b11\.": "2022-07-12", r"2012": "2022-07-12",
                  r"\b12\.": "2024-07-09", r"2014": "2024-07-09",
                  r"\b13\.": "2026-07-14", r"2016": "2026-07-14"},
     "severity": "high",
     "note": "MSSQL SP/CU seviyesine göre EOL değişir; kesin tarih analistçe doğrulanmalı."},
    # --- Microsoft Windows (OS via smb-os-discovery / service extrainfo) ---
    {"name": "Microsoft Windows Server", "products": ["windows server"],
     "versions": {r"2003": "2015-07-14", r"2008 r2": "2020-01-14", r"2008": "2020-01-14",
                  r"2012 r2": "2023-10-10", r"2012": "2023-10-10",
                  r"2016": "2027-01-12"},
     "severity": "high",
     "note": "Windows Server yapı/SP seviyesi ve ESU durumu analistçe doğrulanmalı."},
    {"name": "Microsoft Windows (istemci)", "products": ["windows xp", "windows vista",
                                                          "windows 7", "windows 8"],
     "versions": {r".": "2020-01-14"},
     "severity": "high",
     "note": "İstemci Windows sürümü ve ESU durumu analistçe doğrulanmalı."},
    # --- Microsoft Exchange -----------------------------------------------
    {"name": "Microsoft Exchange Server", "products": ["exchange"],
     "versions": {r"2007": "2017-04-11", r"2010": "2020-10-13",
                  r"2013": "2023-04-11", r"2016": "2025-10-14"},
     "severity": "high",
     "note": "Exchange CU seviyesi analistçe doğrulanmalı."},
    # --- Web / app servers -------------------------------------------------
    {"name": "Apache httpd", "products": ["apache httpd", "apache/"],
     "versions": {r"^1\.3": "2010-02-03", r"^2\.0": "2013-07-10", r"^2\.2": "2017-12-31"},
     "severity": "medium",
     "note": "Apache 2.2 ve öncesi bakım almıyor; 2.4 destekleniyor."},
    {"name": "nginx", "products": ["nginx"],
     "versions": {r"^0\.": "2012-01-01", r"^1\.0": "2012-01-01", r"^1\.1": "2012-01-01"},
     "severity": "medium",
     "note": "Çok eski nginx dalı; güncel kararlı sürüme yükseltilmeli."},
    {"name": "Microsoft IIS", "products": ["microsoft-iis", "microsoft iis"],
     "versions": {r"^5\.": "2015-07-14", r"^6\.": "2015-07-14", r"^7\.0": "2020-01-14",
                  r"^7\.5": "2020-01-14", r"^8\.": "2023-10-10"},
     "severity": "medium",
     "note": "IIS sürümü ana Windows sürümüne bağlıdır; EOL Windows ile birlikte gelir."},
    {"name": "OpenSSL", "products": ["openssl"],
     "versions": {r"^0\.9": "2015-12-31", r"^1\.0\.0": "2016-12-31",
                  r"^1\.0\.1": "2016-12-31", r"^1\.0\.2": "2019-12-31", r"^1\.1\.0": "2019-09-11"},
     "severity": "medium",
     "note": "OpenSSL dalı bakım almıyor; 3.x/1.1.1+ güncel dal doğrulanmalı."},
    {"name": "PHP", "products": ["php/", "php "],
     "versions": {r"^5\.": "2019-01-01", r"^7\.0": "2019-01-10", r"^7\.1": "2019-12-01",
                  r"^7\.2": "2020-11-30", r"^7\.3": "2021-12-06", r"^7\.4": "2022-11-28"},
     "severity": "medium",
     "note": "PHP dalı güvenlik bakımı almıyor; desteklenen 8.x dalı doğrulanmalı."},
    {"name": "ProFTPD", "products": ["proftpd"],
     "versions": {r"^1\.2": "2011-01-01", r"^1\.3\.[0-4]\b": "2017-01-01"},
     "severity": "medium",
     "note": "Eski ProFTPD dalı; güncel sürüm doğrulanmalı."},
]


def _matches_version(version: str, extra: str, pattern: str) -> bool:
    blob = f"{version} {extra}".strip().lower()
    return re.search(pattern, blob) is not None


def detect(product: str, version: str = "", extrainfo: str = "",
           today: _dt.date | None = None) -> dict | None:
    """Return an EOL record when (product, version) is a known past-EOL release.

    The comparison is against `today` (defaults to the current date), so a
    version whose EOL date is still in the future is not flagged.  Returns None
    when nothing matches or the version cannot be pinned.
    """
    product = (product or "").strip().lower()
    version = (version or "").strip()
    extrainfo = (extrainfo or "").strip()
    if not product:
        return None
    today = today or _dt.date.today()
    for rule in _RULES:
        if not any(token in product for token in rule["products"]):
            continue
        for pattern, eol_str in rule["versions"].items():
            if _matches_version(version, extrainfo, pattern):
                eol_date = _dt.date.fromisoformat(eol_str)
                if eol_date <= today:
                    return {"name": rule["name"], "eol_date": eol_str,
                            "severity": rule["severity"], "note": rule["note"],
                            "matched_version": (version or extrainfo or "?")}
                return None  # known product but a still-supported release
    return None
