"""data/default_credentials.json'u onaylı kamuya açık kaynaktan günceller.

Kaynak: DefaultCreds-Cheat-Sheet (ihebski) — kamuya açık üretici varsayılan
kimlik bilgileri CSV'si. Yalnız BİZİM tanıdığımız markalara uyan satırlar alınır
ve marka başına sınır uygulanır; böylece varsayılan-kimlik testi sınırlı kalır
(sözlük/kaba-kuvvet setine dönüşmez). Kürasyonlu mevcut girişler korunur, yenileri
tekrarsız eklenir. Yalnız kamuya açık referans veri indirilir; müşteri verisi/sır
gönderilmez.

Kullanım:  python update_default_creds.py            (indirir, birleştirir, yazar)
           python update_default_creds.py --dry-run  (yazmadan özet)
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import urllib.request
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "data" / "default_credentials.json"
SOURCE_URL = "https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv"
PER_BRAND_CAP = 8

# Aile → productvendor sütununda aranacak anahtar kelimeler (küçük harf).
BRAND_KEYWORDS = {
    "Fortinet FortiGate / FortiOS": ["fortinet", "fortigate", "fortios"],
    "Sophos Firewall (SFOS/XG)": ["sophos"],
    "Cisco IOS": ["cisco"],
    "Cisco IOS-XE": ["cisco"],
    "Cisco ASA": ["asa", "adaptive security", "cisco asa"],
    "Ruijie / Reyee": ["ruijie", "reyee"],
    "MikroTik RouterOS": ["mikrotik", "routeros"],
    "Ubiquiti UniFi": ["ubiquiti", "unifi", "ubnt"],
    "Zyxel cihazı": ["zyxel"],
    "Dahua kamera/NVR": ["dahua"],
    "Hikvision kamera/NVR": ["hikvision"],
    "Axis kamera": ["axis"],
    "Synology DSM": ["synology"],
    "QNAP QTS": ["qnap"],
    "TrueNAS / FreeNAS": ["truenas", "freenas"],
    "HPE iLO": ["ilo", "integrated lights", "proliant"],
    "Dell iDRAC": ["idrac", "drac", "dell remote"],
    "IPMI / BMC (genel)": ["ipmi", "supermicro", "ilom", "baseboard"],
    "Proxmox VE": ["proxmox"],
    "VMware ESXi": ["esxi", "vmware esx"],
    "VMware vCenter": ["vcenter"],
}
_BLANK = {"<blank>", "(none)", "none", "n/a", "blank", "-", "empty", ""}
# Gerçek literal olmayan (talimat/serial/üretilen) parolaları ele.
_NON_LITERAL = ("per device", "per-device", "unique", "documentation", "see ", "printed",
                "random", "your ", "sticker", "label", "generated", "varies", "depends",
                "serial", "mac address", "cloud key", "address of", "key of", "add-serial",
                "uppercase", "ex:", "no.]")


def _literal(value: str) -> bool:
    """Kısa, sabit bir kimlik bilgisi mi? Talimat/şablon/uzun değerleri ele."""
    low = value.lower()
    if any(token in low for token in _NON_LITERAL):
        return False
    if any(ch in value for ch in "[]()"):
        return False
    return len(value) <= 32


def fetch(url: str = SOURCE_URL, timeout: float = 30) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "UBDEN-Cyber/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (sabit host)
        return response.read().decode("utf-8", "replace")


def parse(text: str) -> list:
    """CSV metnini (product_lower, username, password) üçlülerine ayrıştırır."""
    rows = []
    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    for row in reader:
        if len(row) < 3:
            continue
        product, username, password = row[0].strip(), row[1].strip(), row[2].strip()
        if not product or not username:
            continue
        if password.lower() in _BLANK:
            password = ""
        elif not _literal(password):
            continue  # talimat/serial/üretilen parola — literal değil, atla
        if username.lower() in _BLANK or not _literal(username):
            continue
        rows.append((product.lower(), username, password))
    return rows


def merge(db: dict, rows: list, cap: int = PER_BRAND_CAP) -> dict:
    """Eşleşen varsayılanları markalara ekler (kürasyonlu koru, tekrarsız, sınırlı)."""
    brands = db.setdefault("brands", {})
    added = {}
    for family, keywords in BRAND_KEYWORDS.items():
        existing = [tuple(x) for x in brands.get(family, []) if isinstance(x, (list, tuple)) and len(x) == 2]
        seen = {(str(u), str(p)) for u, p in existing}
        out = list(existing)
        for product, username, password in rows:
            if len(out) >= cap:
                break
            if not any(kw in product for kw in keywords):
                continue
            key = (username, password)
            if key in seen:
                continue
            seen.add(key)
            out.append([username, password])
        gained = len(out) - len(existing)
        if gained:
            added[family] = gained
        brands[family] = [list(x) for x in out]
    return added


def update(path: Path = DB_PATH, source: str = SOURCE_URL, fetcher=fetch,
           cap: int = PER_BRAND_CAP, write: bool = True) -> dict:
    path = Path(path)
    db = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {"schema": 1, "brands": {}}
    rows = parse(fetcher(source))
    added = merge(db, rows, cap)
    db["source_url"] = source
    if write:
        temp = path.with_suffix(".json.tmp")
        temp.write_text(json.dumps(db, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temp.replace(path)
    return {"source_rows": len(rows), "added_per_brand": added,
            "total_added": sum(added.values()),
            "brand_totals": {f: len(db["brands"].get(f, [])) for f in BRAND_KEYWORDS}}


def main() -> None:
    parser = argparse.ArgumentParser(description="UBDEN varsayılan-kimlik veri setini günceller")
    parser.add_argument("--source", default=SOURCE_URL)
    parser.add_argument("--cap", type=int, default=PER_BRAND_CAP)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    summary = update(source=args.source, cap=args.cap, write=not args.dry_run)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
