"""Ek servis keşif araçları — açık ön koşullarla, kanıt kaydıyla, kapsam içinde.

UBDEN'in `command()` çalıştırıcısını enjekte alır (supplemental_scans ile aynı
desen): her araç yalnız kurulu ve ön koşulu karşılandığında çalışır, aksi halde
'missing_tool' / 'skipped' adımı yazılır. Bu modül yeni ağ kararı üretmez; yalnız
zaten yetkili kapsamdaki hedef/alan üzerinde ek keşif aracı çalıştırır. Katalog ve
kapsam matrisi bu adımları otomatik olarak 'çalıştırıldı' sayar.
"""
from __future__ import annotations

import shutil


def _skip(events, step, tool, target, detail):
    events.append({"step": step, "tool": tool, "target": target,
                   "status": "missing_tool", "detail": detail})


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
