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
import re
from pathlib import Path

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

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
          ad: dict | None = None, osint: dict | None = None,
          tech: dict | None = None) -> dict:
    """Ağ (ve varsa OSINT / platform tespiti) kanıtından maruziyet korelasyonu üretir."""
    ad = ad or {}
    facts = _facts(meta, hosts, findings, devices, ad)
    correlations, chains, actions = [], [], []

    _corr_weight = {"critical": 8, "high": 5, "medium": 2, "low": 1}

    def add(title, severity, detail, chain=None, action=None, scored=True):
        # scored=False: korelasyon görünür ama maruziyet cezasına EKLENMEZ
        # (ör. doğrulanmış CVE bulguları zaten confirmed_penalty'de sayılır).
        correlations.append({"title": title, "severity": severity, "detail": detail,
                             "network_side": detail, "social_side": "",
                             "_penalty": _corr_weight.get(severity, 0) if scored else 0})
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

    # OSINT çapraz-katman köprüsü (Faz C beslemesi): zayıf e-posta duruşu + iç yüzey.
    if osint and osint.get("email_spoofable"):
        internal = ("AD ortamı" if facts["ad_present"] else
                    "uzaktan erişim servisleri" if facts["remote"] else
                    "iç ağ uç noktaları")
        posture = osint.get("email_posture", "yok")
        add("Sahtelenebilir e-posta + iç ağ uç noktaları", "high",
            f"Alan e-posta duruşu '{posture}' (DMARC uygulaması zayıf/yok) ve {internal} erişilebilir; "
            "oltalama ile ilk erişim riski yükselir.",
            chain={"name": "Oltalama → uç nokta → iç ağ", "likelihood": "orta",
                   "impact": "İlk erişim ve yanal hareket başlangıcı",
                   "steps": ["Yetkili senaryoda alanın DMARC/SPF zayıflığıyla sahte e-posta hazırla",
                             "Hedef çalışan uç noktasında kod çalıştırmayı değerlendir",
                             "İç ağa erişim doğrulanırsa yanal hareket yolunu haritala"]},
            action={"priority": "yüksek", "effort": "düşük",
                    "action": "DMARC'ı p=reject'e taşı; SPF/DKIM'i sıkılaştır; oltalama farkındalık eğitimi ver",
                    "rationale": "Zayıf e-posta kimlik doğrulaması en yaygın ilk erişim vektörüdür"})

    # OSINT: keşfedilen kullanıcı adları + AD → parola püskürtme köprüsü.
    if osint and osint.get("usernames_discovered") and facts["ad_present"]:
        count = osint.get("username_count", 0)
        add("Keşfedilen kullanıcı adları + AD ortamı", "high",
            f"OSINT ile {count} kullanıcı adı adayı elde edildi ve AD ortamı gözlendi; "
            "kilitleme eşiği altında parola püskürtme ilk erişim riski oluşturur.",
            chain={"name": "Parola püskürtme → alan hesabı", "likelihood": "orta",
                   "impact": "Alan hesabı ele geçirme",
                   "steps": ["Kilitleme ve gözlem eşiklerini doğrula (yetkili senaryo)",
                             "Elde edilen kullanıcı adlarıyla eşik altında az sayıda yaygın parola dene",
                             "Erişim doğrulanırsa hesap ayrıcalıklarını ve yanal hareketi haritala"]},
            action={"priority": "yüksek", "effort": "düşük",
                    "action": "Parola politikası + kilitleme eşiği uygula; MFA; tahmin edilebilir parolaları engelle",
                    "rationale": "Bilinen kullanıcı adları + zayıf parola politikası püskürtmeyi kolaylaştırır"})

    # Platform tespiti: kritik yönetim düzlemi (hipervizör/güvenlik duvarı/BMC) maruziyeti.
    if tech:
        crit = [m for m in tech.get("matches", [])
                if m.get("category") in ("hypervisor", "firewall", "ilo") and m.get("mgmt_ports_observed")]
        if crit:
            fams = ", ".join(sorted({f"{m['family']} ({m['ip']})" for m in crit})[:6])
            add("Kritik yönetim düzlemi platformu erişilebilir", "high",
                f"Sanallaştırma/güvenlik duvarı/donanım yönetimi platformlarının yönetim arayüzleri kapsamda gözlendi: {fams}. "
                "Yönetim düzlemi ele geçirilirse çok sayıda sisteme tek noktadan erişim doğar.",
                chain={"name": "Yönetim düzlemi → toplu erişim", "likelihood": "orta",
                       "impact": "Hipervizör/güvenlik duvarı/BMC üzerinden geniş erişim",
                       "steps": ["Gözlenen sürümü üretici danışmaları (VMSA/PSIRT) ile karşılaştır",
                                 "Yönetim arayüzü erişimini ayrı yönetim ağıyla sınırla",
                                 "Varsayılan hesap ve MFA durumunu yetkili test hesabıyla doğrula"]},
                action={"priority": "yüksek", "effort": "orta",
                        "action": "Yönetim düzlemi arayüzlerini ayrı yönetim ağına al; MFA + güncel yama uygula",
                        "rationale": "Yönetim düzlemi tek noktadan geniş erişim sağlar; sürüm/yama kritiktir"})

    # Analistçe DOĞRULANMIŞ CVE'leri görünür kıl (NVD adayları değil; adaylar
    # UBDEN_CVE.json'da kalır ve maruziyeti düşürmez). Bu bulgular zaten
    # confirmed_penalty'de sayıldığından korelasyon scored=False eklenir.
    confirmed_cves = []
    for finding in facts["confirmed"]:
        hay = " ".join(str(finding.get(k, "")) for k in ("id", "title", "reference", "cwe", "description"))
        for cid in _CVE_RE.findall(hay):
            confirmed_cves.append((cid.upper(), finding.get("severity", "info"), str(finding.get("asset", ""))))
    if confirmed_cves:
        ids = sorted({c[0] for c in confirmed_cves})
        top = max((c[1] for c in confirmed_cves), key=lambda s: _SEV_RANK.get(s, 0))
        assets = sorted({c[2] for c in confirmed_cves if c[2]})
        add("Doğrulanmış CVE maruziyeti", top,
            f"Analistçe doğrulanmış CVE bulguları: {', '.join(ids[:10])}"
            + (f" · varlıklar: {', '.join(assets[:6])}" if assets else "")
            + ". Bu bulgular maruziyet indeksine doğrulanmış bulgu cezasıyla yansır; NVD adayları yansımaz.",
            action={"priority": "kritik" if top == "critical" else "yüksek", "effort": "orta",
                    "action": "Doğrulanan CVE'ler için üretici yamasını/azaltımını öncelikle uygulayın ve yeniden test edin",
                    "rationale": "Analistçe doğrulanmış CVE'ler somut, kanıtlı maruziyettir"},
            scored=False)

    confirmed_penalty = sum(_SEV_PENALTY.get(f.get("severity"), 0) for f in facts["confirmed"])
    corr_penalty = min(45, sum(c["_penalty"] for c in correlations))
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
        "correlations": [{k: v for k, v in c.items() if k != "_penalty"}
                         for c in sorted(correlations, key=lambda c: -_SEV_RANK.get(c["severity"], 0))],
        "attack_chains": chains,
        "combined_actions": sorted(actions, key=lambda a: {"kritik": 0, "yüksek": 1, "orta": 2, "düşük": 3}.get(a["priority"], 4)),
        "graph": _build_graph(facts, osint),
        "source": "kural",
        "meaning": ("Korelasyon dış/iç kanıtı birbirine bağlar; skor ve graf yalnız kurallardan üretilir. "
                    "Zincirler saldırı başarısı değil, analist doğrulaması bekleyen maruziyet hipotezleridir."),
    }


def _build_graph(facts: dict, osint: dict | None = None) -> dict:
    """Saldırı-yüzeyi grafiği: kapsam/e-posta (dış) ↔ servis/veritabanı/AD (iç)."""
    nodes, edges = [], []
    seen = set()

    def node(nid, label, ntype, risk="info"):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "label": label[:44], "type": ntype, "risk": risk})

    scope_id = "scope"
    node(scope_id, "Yetkili kapsam", "external", "info")
    # OSINT dış düğümleri: alan ve (varsa) sahtelenebilir e-posta yüzeyi.
    first_internal = None
    if facts["ad_hosts"]:
        first_internal = f"ad-{facts['ad_hosts'][0]}"
    elif facts["remote"]:
        ip, port, _ = facts["remote"][0]
        first_internal = f"svc-{ip}-{port}"
    if osint:
        for dom in (osint.get("domains") or [])[:2]:
            node(f"dom-{dom}", dom, "domain", "info")
            edges.append({"source": scope_id, "target": f"dom-{dom}", "label": "alan"})
        if osint.get("email_spoofable"):
            node("email", "Sahtelenebilir e-posta", "email", "high")
            edges.append({"source": scope_id, "target": "email", "label": "DMARC zayıf"})
        if osint.get("usernames_discovered"):
            node("users", f"{osint.get('username_count', 0)} kullanıcı adı", "person", "high")
            edges.append({"source": scope_id, "target": "users", "label": "OSINT"})
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
    # Çapraz köprü: sahtelenebilir e-posta → ilk iç uç nokta (oltalama ile ilk erişim).
    if osint and osint.get("email_spoofable") and first_internal and first_internal in seen:
        edges.append({"source": "email", "target": first_internal, "label": "oltalama"})
    ad_target = f"ad-{facts['ad_hosts'][0]}" if facts["ad_hosts"] else first_internal
    if osint and osint.get("usernames_discovered") and ad_target and ad_target in seen:
        edges.append({"source": "users", "target": ad_target, "label": "parola püskürtme"})
    return {"nodes": nodes, "edges": edges}


def write(root: Path, meta: dict, hosts: list, findings: list,
          devices: dict, ad: dict | None = None, osint: dict | None = None,
          tech: dict | None = None) -> dict:
    result = build(meta, hosts, findings, devices, ad, osint, tech)
    temp = root / ".UBDEN_CORRELATION.pending.json"
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(root / "UBDEN_CORRELATION.json")
    return result
