"""Ek servis keşif araçları — açık ön koşullarla, kanıt kaydıyla, kapsam içinde.

UBDEN'in `command()` çalıştırıcısını enjekte alır (supplemental_scans ile aynı
desen): her araç yalnız kurulu ve ön koşulu karşılandığında çalışır, aksi halde
'missing_tool' / 'skipped' adımı yazılır. Bu modül yeni ağ kararı üretmez; yalnız
zaten yetkili kapsamdaki hedef/alan üzerinde ek keşif aracı çalıştırır. Katalog ve
kapsam matrisi bu adımları otomatik olarak 'çalıştırıldı' sayar.
"""
from __future__ import annotations

import json
import shutil
from pathlib import Path


def _skip(events, step, tool, target, detail):
    events.append({"step": step, "tool": tool, "target": target,
                   "status": "missing_tool", "detail": detail})


def _tag(ip: str) -> str:
    return str(ip).replace(":", "_")


def web_extras(prefix, url, target, raw, events, command):
    """Web uç noktasında WAF tespiti (wafw00f). Tek sınırlı çalıştırma."""
    if shutil.which("wafw00f"):
        result = command(f"wafw00f_{prefix}", ["wafw00f", url], raw, events, 45)
        result["target"] = target
        result.setdefault("detail", "WAF/ürün tespiti adayı; koruma varlığı zafiyet değildir")
    else:
        _skip(events, f"wafw00f_{prefix}", "wafw00f", target, "wafw00f kurulu değil")


def domain_recon(target, raw, events, command):
    """Yetkili alan adı için sınırlı DNS/alt alan/OSINT keşfi.

    Yalnız alan adı hedeflerinde çağrılır (IP değil). Her araç ayrı kayıt üretir;
    dışa dönük sorgular whois/dig ile aynı düzeydedir.
    """
    tools = (
        ("dnsenum", ["dnsenum", "--nocolor", "--noreverse", "--timeout", "5", target], 120,
         "Alt alan ve DNS kayıt keşfi"),
        ("dnstracer", ["dnstracer", "-q", "A", "-r", "1", "-s", ".", target], 45,
         "Yetkili ad sunucusu zinciri izleme"),
        ("fierce", ["fierce", "--domain", target], 120,
         "Alt alan keşfi (varsayılan sözlük)"),
        ("theHarvester", ["theHarvester", "-d", target, "-b", "crtsh,hackertarget", "-l", "100"], 120,
         "Pasif OSINT: alt alan ve e-posta yüzeyi (yalnız pasif kaynaklar)"),
    )
    for step, argv, timeout, detail in tools:
        executable = argv[0]
        if not shutil.which(executable):
            _skip(events, f"{step}_recon", executable, target, f"{executable} kurulu değil")
            continue
        result = command(f"{step}_recon", argv, raw, events, timeout)
        result["target"] = target
        result.setdefault("detail", detail + "; sonuçlar kapsam ve analist doğrulaması bekler")


def network_extras(assets, opened: dict, raw, events, command) -> None:
    """Sınırlı, salt okunur ağ keşif araçları: yol izleme, IKE yoklaması, SMB liste.

    Her biri kurulu olduğunda ve ön koşulu karşılandığında az sayıda hedefte
    çalışır; yeni ağ kararı üretmez, yalnız yetkili adreslerde ek keşif yapar.
    """
    if shutil.which("traceroute"):
        for ip in list(assets)[:4]:
            command(f"traceroute_{_tag(ip)}",
                    ["traceroute", "-n", "-q", "1", "-w", "1", "-m", "15", str(ip)],
                    raw, events, 45)["target"] = str(ip)
    if shutil.which("ike-scan"):
        for ip in list(assets)[:8]:
            command(f"ikescan_{_tag(ip)}", ["ike-scan", "-r", "1", str(ip)],
                    raw, events, 20)["target"] = str(ip)
    if shutil.which("smbclient"):
        for ip in assets:
            if 445 not in set(opened.get(ip, [])):
                continue
            host = f"[{ip}]" if ":" in str(ip) else str(ip)
            result = command(f"smbclient_{_tag(ip)}",
                             ["smbclient", "-L", f"//{host}", "-N", "-g"], raw, events, 30)
            result["target"] = str(ip)
            result.setdefault("detail", "Null oturum paylaşım listeleme adayı; erişim analistçe doğrulanmalı")


def snmp_extras(assets, raw, events, command) -> None:
    """Yalnız UBDEN SNMP yoklamasının yanıt doğruladığı adreslerde ek SNMP araçları."""
    raw = Path(raw)
    responders = set()
    for path in raw.glob("snmp_v1_public_*.json"):
        if path.name.endswith("summary.json"):
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and data.get("confirmed_response") and data.get("target"):
            responders.add(str(data["target"]))
    snmp_check = "snmp-check" if shutil.which("snmp-check") else ("snmpcheck" if shutil.which("snmpcheck") else None)
    for ip in assets:
        if str(ip) not in responders:
            continue
        if snmp_check:
            command(f"snmpcheck_{_tag(ip)}", [snmp_check, str(ip)], raw, events, 60)["target"] = str(ip)
        if shutil.which("onesixtyone"):
            command(f"onesixtyone_{_tag(ip)}", ["onesixtyone", str(ip), "public"],
                    raw, events, 20)["target"] = str(ip)
