"""UBDEN çapraz-katman maruziyet korelasyonu — deterministik, kanıt-temelli.

Tek tek bulguları silo halinde bırakmak yerine, tarama kanıtını (açık servisler,
cihaz sınıfları, AD, analist bulguları) birbirine bağlayıp adlandırılmış maruziyet
zincirleri ve bir saldırı-yüzeyi grafiği üretir. Skorlar ve graf YALNIZ kurallardan
gelir (yeniden üretilebilir, denetlenebilir); hiçbir istismar yapılmaz.

Çıktı statüsü doğası gereği ADAY/TASLAK'tır: her zincir analist doğrulaması
gerektirir. Maruziyet indeksi bir güvenlik duruşu göstergesidir, kanıtlanmış
zafiyet iddiası değildir. OSINT katmanı ileride `osint` argümanıyla eklenebilir;
şu an ağ tarafı kanıtıyla çalışır.
"""
from __future__ import annotations

import json
from pathlib import Path

# Uzaktan yönetim / erişim yüzeyi ve veritabanı servis portları.
REMOTE_PORTS = {22: "SSH", 3389: "RDP", 5900: "VNC", 5985: "WinRM",
                5986: "WinRM-TLS", 4443: "SSL-VPN", 8443: "HTTPS-yönetim",
                23: "Telnet"}
DB_PORTS = {1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 1521: "Oracle",
            27017: "MongoDB", 6379: "Redis", 5984: "CouchDB", 9200: "Elasticsearch"}
AD_PORTS = {88: "Kerberos", 389: "LDAP", 636: "LDAPS", 445: "SMB", 3268: "GC"}

_SEV_PENALTY = {"critical": 18, "high": 10, "medium": 4, "low": 1, "info": 0}
_SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "E"


def _host_ports(host: dict) -> list[int]:
    ports = []
    for port in host.get("ports", []):
        try:
            if str(port.get("protocol", "tcp")) == "tcp":
                ports.append(int(port.get("port")))
        except (TypeError, ValueError):
            continue
    return ports


def _facts(meta: dict, hosts: list, findings: list, devices: dict, ad: dict) -> dict:
    remote, database, ad_hosts = [], [], []
    for host in hosts:
        ip = host.get("ip", "")
        opened = set(_host_ports(host))
        for port in sorted(opened):
            if port in REMOTE_PORTS:
                remote.append((ip, port, REMOTE_PORTS[port]))
            if port in DB_PORTS:
                database.append((ip, port, DB_PORTS[port]))
        if opened & set(AD_PORTS):
            ad_hosts.append(ip)

    def has(*keywords):
        found = []
        for f in findings:
            hay = " ".join(str(f.get(k, "")) for k in ("type", "title", "category")).lower()
            if any(k in hay for k in keywords):
                found.append(f)
        return found

    confirmed = [f for f in findings if f.get("status") == "doğrulandı"]
    categories = devices.get("categories", {}) if isinstance(devices, dict) else {}
    return {
        "remote": remote, "database": database, "ad_hosts": ad_hosts,
        "ad_present": bool(ad) or bool(ad_hosts),
        "weak_cred": has("cracked", "zayıf parola"),
        "ad_cred": has("kerberoast", "asrep", "adcs"),
        "default_snmp": has("public toplulu", "snmpv1"),
        "legacy_tls": has("sslv3", "tlsv1", "protokolü kabul"),
        "plain_http": has("http uç", "telnet", "ftp servisi"),
        "confirmed": confirmed,
        "confirmed_by_sev": {s: sum(f.get("severity") == s for f in confirmed)
                             for s in _SEV_PENALTY},
        "categories": categories,
        "targets": [str(t) for t in meta.get("targets", [])],
    }


def build(meta: dict, hosts: list, findings: list, devices: dict,
          ad: dict | None = None, osint: dict | None = None) -> dict:
    """Ağ (ve varsa OSINT) kanıtından maruziyet korelasyonu üretir."""
    ad = ad or {}
    facts = _facts(meta, hosts, findings, devices, ad)
    correlations, chains, actions = [], [], []

    def add(title, severity, detail, chain=None, action=None):
        correlations.append({"title": title, "severity": severity, "detail": detail,
                             "network_side": detail, "social_side": ""})
        if chain:
            chains.append(chain)
        if action:
            actions.append(action)

    # 1) Sızıntı/zayıf kimlik + uzaktan erişim yüzeyi.
    if facts["remote"] and facts["weak_cred"]:
        svc = ", ".join(f"{ip}:{p} ({n})" for ip, p, n in facts["remote"][:6])
        add("Zayıf kimlik bilgisi + uzaktan erişim yüzeyi", "critical",
            f"Doğrulanmış zayıf/kırılabilir kimlik bilgisi ile açık uzaktan erişim servisleri bir arada: {svc}.",
            chain={"name": "Kimlik bilgisi → uzaktan erişim", "likelihood": "yüksek",
                   "impact": "Yetkili oturum ele geçirme",
                   "steps": ["Doğrulanan zayıf/kırık parolayı ilgili hesapla dene",
                             "Açık RDP/SSH/WinRM üzerinden oturum aç",
                             "Erişim doğrulanırsa yanal hareket ve yetki yükseltmeyi değerlendir"]},
            action={"priority": "kritik", "effort": "orta",
                    "action": "Uzaktan erişimde MFA zorunlu kıl; parola politikasını sıkılaştır; yönetim erişimini sınırla",
                    "rationale": "Zayıf kimlik bilgisi + açık uzaktan erişim doğrudan ele geçirme yolu"})

    # 2) Dışa açık veritabanı servisi.
    if facts["database"]:
        svc = ", ".join(f"{ip}:{p} ({n})" for ip, p, n in facts["database"][:8])
        add("Kimlik doğrulaması test edilmemiş veritabanı yüzeyi", "high",
            f"Kapsam içinde erişilebilir veritabanı servisleri: {svc}. Kimlik doğrulama ve yetki analist tarafından doğrulanmalı.",
            chain={"name": "Açık veritabanı → veri erişimi", "likelihood": "orta",
                   "impact": "Yetkisiz veri erişimi olasılığı",
                   "steps": ["Servis sürümünü ve kimlik doğrulama modunu doğrula",
                             "Varsayılan/zayıf hesap ve ağ erişim listesini kontrol et",
                             "Erişim doğrulanırsa veri maruziyetini kanıtla"]},
            action={"priority": "yüksek", "effort": "orta",
                    "action": "Veritabanı dinleme arayüzünü sınırla; ağ erişim listesi + en az yetki uygula",
                    "rationale": "Doğrudan ağdan erişilebilen veritabanı yüksek etkili yüzeydir"})

    # 3) AD ortamı + AD kimlik bulgusu.
    if facts["ad_present"] and facts["ad_cred"]:
        add("Active Directory kimlik bilgisi zinciri", "high",
            "AD ortamı gözlendi ve kerberoast/AS-REP/ADCS türü bir analist bulgusu var; alan içi yetki yükseltme değerlendirilmeli.",
            chain={"name": "AD kimlik bilgisi → alan yetkisi", "likelihood": "orta",
                   "impact": "Alan içi yetki yükseltme",
                   "steps": ["Kerberoast/AS-REP hash'ini çevrimdışı (yetkili örnekle) değerlendir",
                             "Kırılan servis hesabının ayrıcalıklarını haritala",
                             "Yetki yükseltme yolunu analist doğrulamasıyla kanıtla"]},
            action={"priority": "yüksek", "effort": "yüksek",
                    "action": "Servis hesaplarında gMSA/uzun parola; ADCS şablon izinlerini gözden geçir",
                    "rationale": "AD kimlik bilgisi zincirleri alan geneli etkiye ulaşabilir"})

    # 4) Varsayılan SNMP topluluğu + cihaz yüzeyi.
    if facts["default_snmp"]:
        add("Varsayılan SNMP topluluğu ile cihaz bilgisi", "medium",
            "SNMPv1/public yanıtı gözlendi; cihaz ve sürüm bilgisi sızabilir, SNMPv1 trafiği şifrelemez.",
            action={"priority": "orta", "effort": "düşük",
                    "action": "SNMPv1/v2c ve varsayılan toplulukları kapat; SNMPv3 + erişim kontrolü uygula",
                    "rationale": "Varsayılan topluluk keşif ve olası yapılandırma sızıntısı sağlar"})

    # 5) Eski TLS birden çok varlıkta (sistemik).
    if len(facts["legacy_tls"]) >= 2:
        assets = sorted({str(f.get("asset", "")) for f in facts["legacy_tls"] if f.get("asset")})
        add("Sistemik eski TLS/SSL kullanımı", "medium",
            f"Birden çok varlıkta eski TLS/SSL sürümü gözlendi: {', '.join(assets[:8])}.",
            action={"priority": "orta", "effort": "orta",
                    "action": "Uyumluluk etkisini değerlendirip TLS 1.2/1.3'e geçir",
                    "rationale": "Yaygın eski TLS modern gereksinimleri karşılamaz"})

    # 6) Segmentasyon: sunucu + istemci/IoT aynı kategori kümesinde.
    cats = facts["categories"]
    if cats.get("server") and (cats.get("pc") or cats.get("iot") or cats.get("camera")):
        add("Düz ağ / segmentasyon eksikliği adayı", "medium",
            "Sunucu sınıfı cihazlarla istemci/IoT/kamera aynı gözlem kümesinde; VLAN/segmentasyon analistçe doğrulanmalı.",
            action={"priority": "orta", "effort": "yüksek",
                    "action": "Sunucu, istemci ve IoT segmentlerini VLAN/erişim listeleriyle ayır",
                    "rationale": "Düz ağ bir cihazdan diğerine yanal hareketi kolaylaştırır"})

    confirmed_penalty = sum(_SEV_PENALTY.get(f.get("severity"), 0) for f in facts["confirmed"])
    corr_penalty = min(45, sum({"critical": 8, "high": 5, "medium": 2, "low": 1}.get(c["severity"], 0)
                               for c in correlations))
    network_score = max(0, 100 - confirmed_penalty - corr_penalty)
    exposure = {
        "score": network_score, "grade": _grade(network_score),
        "network_score": network_score, "network_grade": _grade(network_score),
        "comment": ("Skor hem analistçe doğrulanmış bulguları hem de gözlenen çapraz-katman "
                    "maruziyet kesişimlerini yansıtır; kanıtlanmış tek bir açık iddiası değildir."),
    }
    if osint:  # OSINT katmanı (Faz C) eklendiğinde insan tarafı skoru burada harmanlanır.
        human = int(osint.get("human_score", 100))
        exposure["human_score"] = human
        exposure["human_grade"] = _grade(human)
        exposure["score"] = (network_score + human) // 2
        exposure["grade"] = _grade(exposure["score"])

    return {
        "schema": 1,
        "exposure_index": exposure,
        "correlations": sorted(correlations, key=lambda c: -_SEV_RANK.get(c["severity"], 0)),
        "attack_chains": chains,
        "combined_actions": sorted(actions, key=lambda a: {"kritik": 0, "yüksek": 1, "orta": 2, "düşük": 3}.get(a["priority"], 4)),
        "graph": _build_graph(facts),
        "source": "kural",
        "meaning": ("Korelasyon dış/iç kanıtı birbirine bağlar; skor ve graf yalnız kurallardan üretilir. "
                    "Zincirler saldırı başarısı değil, analist doğrulaması bekleyen maruziyet hipotezleridir."),
    }


def _build_graph(facts: dict) -> dict:
    """Saldırı-yüzeyi grafiği: kapsam (dış) ↔ servis/veritabanı/AD (iç)."""
    nodes, edges = [], []
    seen = set()

    def node(nid, label, ntype, risk="info"):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "label": label[:44], "type": ntype, "risk": risk})

    scope_id = "scope"
    node(scope_id, "Yetkili kapsam", "external", "info")
    for ip, port, name in facts["remote"][:8]:
        nid = f"svc-{ip}-{port}"
        node(nid, f"{ip}:{port} {name}", "service", "high")
        edges.append({"source": scope_id, "target": nid, "label": "uzaktan erişim"})
    for ip, port, name in facts["database"][:8]:
        nid = f"db-{ip}-{port}"
        node(nid, f"{ip}:{port} {name}", "database", "high")
        edges.append({"source": scope_id, "target": nid, "label": "veritabanı"})
    for ip in facts["ad_hosts"][:4]:
        nid = f"ad-{ip}"
        node(nid, f"{ip} (AD)", "device", "medium")
        edges.append({"source": scope_id, "target": nid, "label": "dizin"})
    # Analist doğrulanmış kritik/yüksek bulguları iç düğüm olarak.
    for f in facts["confirmed"]:
        if f.get("severity") in ("critical", "high") and f.get("asset"):
            nid = f"find-{f.get('id')}"
            node(nid, f"{f.get('id')} {f.get('title','')}", "cve",
                 "critical" if f.get("severity") == "critical" else "high")
            edges.append({"source": scope_id, "target": nid, "label": f.get("severity")})
    return {"nodes": nodes, "edges": edges}


def write(root: Path, meta: dict, hosts: list, findings: list,
          devices: dict, ad: dict | None = None, osint: dict | None = None) -> dict:
    result = build(meta, hosts, findings, devices, ad, osint)
    temp = root / ".UBDEN_CORRELATION.pending.json"
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(root / "UBDEN_CORRELATION.json")
    return result
