"""Refresh public IEEE MAC assignments for offline device inventory.

Kaynak sırası: (1) sistemde kurulu `ieee-data` paketinin yerel CSV'leri
(indirme gerektirmez), (2) yoksa IEEE'den tarayıcı-benzeri User-Agent ile
indirme. IEEE sunucusu düz `urllib` User-Agent'ına sık sık HTTP 403 döndürür;
yerel paket varken indirmeye hiç gerek kalmaz. Başarısız güncelleme önceki
dosyaları korur; envanter Nmap'in yerel OUI veritabanına düşer.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import urllib.request

REGISTRIES = {
    "oui.csv": ("https://standards-oui.ieee.org/oui/oui.csv", 6),
    "mam.csv": ("https://standards-oui.ieee.org/oui28/mam.csv", 7),
    "mas.csv": ("https://standards-oui.ieee.org/oui36/oui36.csv", 9),
}
# Debian/Kali `ieee-data` paketinin kurduğu yerel CSV dizinleri ve olası dosya adları.
LOCAL_DIRS = (Path("/usr/share/ieee-data"), Path("/var/lib/ieee-data"))
LOCAL_ALIASES = {"oui.csv": ("oui.csv",), "mam.csv": ("mam.csv", "oui28.csv"),
                 "mas.csv": ("mas.csv", "oui36.csv")}
USER_AGENT = "Mozilla/5.0 (compatible; UBDEN-Cyber/1.0; +offline-inventory)"
MAX_BYTES = 45_000_000


def _valid_count(data: bytes, width: int):
    """IEEE CSV'sini doğrular; geçerli atama sayısını, geçersizse None döner."""
    if not data or len(data) > MAX_BYTES:
        return None
    try:
        decoded = data.decode("utf-8-sig")
    except UnicodeError:
        return None
    reader = csv.DictReader(io.StringIO(decoded))
    if not reader.fieldnames or not {"Assignment", "Organization Name"}.issubset(reader.fieldnames):
        return None
    valid = 0
    for row in reader:
        assignment = re.sub("[^0-9A-Fa-f]", "", row.get("Assignment") or "")
        if len(assignment) == width and row.get("Organization Name"):
            valid += 1
    return valid if valid >= 10 else None


def _download(opener, url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with opener(request, timeout=30) as response:
        return response.read(MAX_BYTES + 1)


def refresh(destination: Path, opener=urllib.request.urlopen) -> dict:
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    results = {}
    for name, (url, width) in REGISTRIES.items():
        chosen = None
        # 1) Yerel ieee-data paketi (ağ gerektirmez, güvenilir).
        for directory in LOCAL_DIRS:
            for filename in LOCAL_ALIASES.get(name, (name,)):
                candidate = directory / filename
                try:
                    if not candidate.is_file():
                        continue
                    data = candidate.read_bytes()
                except OSError:
                    continue
                valid = _valid_count(data, width)
                if valid:
                    chosen = (data, valid, str(candidate))
                    break
            if chosen:
                break
        # 2) Yerel yoksa/geçersizse indir (tarayıcı-benzeri UA ile 403 azaltılır).
        if chosen is None:
            try:
                data = _download(opener, url)
                valid = _valid_count(data, width)
                if valid:
                    chosen = (data, valid, url)
            except (OSError, TimeoutError, ValueError):
                chosen = None
        if chosen is None:
            results[name] = {"status": "unavailable", "reason": "no_valid_source",
                             "cached": (destination / name).is_file()}
            continue
        data, valid, source = chosen
        temp = destination / ("." + name + ".pending")
        temp.write_bytes(data)
        temp.replace(destination / name)
        results[name] = {"status": "ok", "assignments": valid,
                         "sha256": hashlib.sha256(data).hexdigest(), "source": source}
    manifest = destination / "SOURCE_MANIFEST.json"
    temp = destination / ".SOURCE_MANIFEST.pending"
    temp.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(manifest)
    return results


def main():
    parser = argparse.ArgumentParser(description="Resmî IEEE MAC/OUI veri kümelerini yenile")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps(refresh(args.destination), ensure_ascii=False))


if __name__ == "__main__":
    main()
