"""Cihaz/platform teknoloji parmak izi — sanallaştırma, ağ güvenliği, depolama, kamera.

Tarama kanıtından (servis/ürün/sürüm banner'ları, HTTP Server/başlık, TLS CN,
SNMP sysDescr, üretici/OUI, karakteristik portlar) bilinen platformları tanır;
gözlenebilen sürümü, yönetim portlarını/arayüzlerini ve doğrulanması gereken
üretici/CVE danışmalarını çıkarır.

Kanıt-temellidir: eşleşme bir "inceleme adayıdır", istismar değil. Listelenen
CVE'ler gözlenen sürüme karşı DOĞRULANMASI gereken danışmalardır; mevcudiyet
iddiası taşımaz. Ağ isteği yapmaz; yalnız kayıtlı kanıtı okur.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

# Her profil: aile, kategori, üretici/metin sinyalleri, karakteristik portlar,
# yönetim portları/arayüzü, sürüm regex'i (opsiyonel) ve doğrulanacak danışmalar.
PROFILES = [
    # --- Sanallaştırma ---
    {"family": "VMware ESXi", "category": "hypervisor", "cpe": ("o", "vmware", "esxi"),
     "text": [r"vmware esxi", r"\besxi\b", r"vmware/\d"], "vendors": ["vmware"],
     "ports": {443, 902, 5988, 5989, 8000},
     "mgmt": "ESXi Host Client (443), vSphere API, hostd/vpxa (902)",
     "version_re": r"esxi[^0-9]{0,8}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["OpenSLP CVE-2021-21974 (427/902) — SLP kapalı mı doğrula",
                    "ESXiArgs fidye kampanyası — yama/patch seviyesini doğrula",
                    "Gözlenen build'i VMware VMSA danışmalarıyla karşılaştır"]},
    {"family": "VMware vCenter", "category": "hypervisor", "cpe": ("a", "vmware", "vcenter_server"),
     "text": [r"vcenter", r"vsphere", r"vsphere client"], "vendors": ["vmware"],
     "ports": {443, 5480, 9443},
     "mgmt": "vSphere Client (443), VAMI (5480)",
     "version_re": r"(?:vcenter|vsphere)[^0-9]{0,10}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["CVE-2021-21985 (vSAN Health RCE), CVE-2021-22005 (analytics) — build'e karşı doğrula",
                    "5480 VAMI ve 443 yönetim erişiminin ağ sınırını doğrula"]},
    {"family": "Proxmox VE", "category": "hypervisor", "cpe": ("a", "proxmox", "virtual_environment"),
     "text": [r"proxmox"], "vendors": ["proxmox"], "ports": {8006, 3128, 111},
     "mgmt": "Proxmox web arayüzü (8006)",
     "version_re": r"proxmox[^0-9]{0,10}(\d+\.\d+)",
     "advisories": ["8006 yönetim arayüzü erişim sınırını doğrula", "pve-manager sürümünü ve yama durumunu doğrula"]},
    {"family": "Microsoft Hyper-V / Windows host", "category": "hypervisor",
     "text": [r"hyper-v", r"hyperv"], "vendors": ["microsoft"], "ports": {5985, 5986, 2179},
     "mgmt": "WinRM (5985/5986), VMConnect (2179), SCVMM",
     "advisories": ["Uzak yönetim (WinRM/2179) erişim sınırını doğrula", "Windows/Hyper-V yama seviyesini doğrula"]},
    # --- Ağ güvenliği ---
    {"family": "Fortinet FortiGate / FortiOS", "category": "firewall", "cpe": ("o", "fortinet", "fortios"),
     "text": [r"fortigate", r"fortios", r"fortinet"], "vendors": ["fortinet"],
     "ports": {443, 10443, 4443, 541, 8443},
     "mgmt": "FortiOS admin (443/8443), SSL-VPN (10443/4443)",
     "version_re": r"fortios[^0-9]{0,8}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["CVE-2022-42475, CVE-2024-21762 (SSL-VPN RCE), CVE-2023-27997 — FortiOS sürümüne karşı doğrula",
                    "SSL-VPN portalının internete açıklığını ve sürümünü doğrula"]},
    {"family": "Sophos Firewall (SFOS/XG)", "category": "firewall", "cpe": ("o", "sophos", "sfos"),
     "text": [r"sophos", r"\bsfos\b", r"sophos firewall"], "vendors": ["sophos"],
     "ports": {443, 4444, 4443},
     "mgmt": "SFOS admin (4444), kullanıcı portalı (443)",
     "advisories": ["CVE-2022-1040, CVE-2020-12271 — SFOS sürümüne karşı doğrula",
                    "Admin (4444) ve portal (443) WAN erişimini doğrula"]},
    {"text_only": True, "family": "Cisco IOS-XE", "category": "router",
     "text": [r"ios-xe", r"ios xe"], "vendors": ["cisco"], "ports": {22, 23, 443, 80, 161},
     "mgmt": "SSH/Telnet CLI, Web UI (443/80)", "cpe": ("o", "cisco", "ios_xe"),
     "version_re": r"ios[ -]xe.{0,30}?(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["Web UI CVE-2023-20198/20273 — sürüme karşı doğrula",
                    "Web yönetim arayüzünün internete açıklığını doğrula"]},
    {"text_only": True, "family": "Cisco ASA", "category": "firewall",
     "text": [r"adaptive security", r"cisco asa"], "vendors": ["cisco"], "ports": {22, 443, 80},
     "mgmt": "SSH CLI, ASDM (443)", "cpe": ("o", "cisco", "adaptive_security_appliance_software"),
     "version_re": r"(?:asa|adaptive security).{0,30}?(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["CVE-2020-3452 (path traversal), AnyConnect danışmaları — sürüme karşı doğrula"]},
    {"text_only": True, "family": "Cisco IOS", "category": "router",
     "text": [r"cisco ios software", r"cisco internetwork operating"], "vendors": ["cisco"],
     "ports": {22, 23, 161, 80, 443}, "mgmt": "SSH/Telnet CLI", "cpe": ("o", "cisco", "ios"),
     "version_re": r"ios software[^0-9]{0,20}(\d+\.\d+)",
     "advisories": ["Cisco IOS PSIRT danışmalarını gözlenen sürüme karşı doğrula"]},
    {"family": "Ruijie / Reyee", "category": "router",
     "text": [r"ruijie", r"reyee"], "vendors": ["ruijie"], "ports": {80, 443, 23, 22},
     "mgmt": "Web yönetim arayüzü, bulut yönetimi",
     "advisories": ["Bulut/AP yönetim danışmalarını gözlenen firmware'e karşı doğrula",
                    "Yönetim arayüzü ve bulut kaydının erişim sınırını doğrula"]},
    # --- Depolama / sunucu yönetimi ---
    {"family": "Synology DSM", "category": "nas", "cpe": ("o", "synology", "diskstation_manager"),
     "text": [r"synology", r"diskstation", r"\bdsm\b"], "vendors": ["synology"],
     "ports": {5000, 5001, 443},
     "mgmt": "DSM web arayüzü (5000/5001)",
     "version_re": r"dsm[^0-9]{0,6}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["DSM sürümünü Synology-SA danışmalarıyla doğrula", "DSM yönetim portlarının internete açıklığını doğrula"]},
    {"family": "QNAP QTS", "category": "nas", "cpe": ("o", "qnap", "qts"),
     "text": [r"qnap", r"\bqts\b"], "vendors": ["qnap"], "ports": {8080, 443, 8081},
     "mgmt": "QTS web arayüzü (8080/443)",
     "advisories": ["DeadBolt/eCh0raix kampanyaları — QTS sürüm/yamasını doğrula",
                    "QTS yönetim erişiminin internete açıklığını doğrula"]},
    {"family": "Dell iDRAC", "category": "ilo",
     "text": [r"idrac", r"integrated dell remote", r"\bdrac\b"], "vendors": ["dell"],
     "ports": {443, 5900, 623, 5000},
     "mgmt": "iDRAC web/virtual console (443), IPMI (623/udp)",
     "advisories": ["iDRAC firmware sürümünü Dell DSA danışmalarıyla doğrula",
                    "IPMI (623) ve iDRAC web erişiminin yönetim ağıyla sınırını doğrula"]},
    {"family": "HPE iLO", "category": "ilo",
     "text": [r"\bilo\b", r"integrated lights-out", r"hpe ilo", r"hp ilo"], "vendors": ["hewlett", "hpe", "hp "],
     "ports": {443, 17988, 17990, 623},
     "mgmt": "iLO web/console (443), IPMI (623/udp)",
     "advisories": ["iLO4 CVE-2017-12542 (auth bypass) — iLO sürümüne karşı doğrula",
                    "iLO yönetim erişiminin ayrı yönetim ağıyla sınırını doğrula"]},
    {"family": "IPMI / BMC (genel)", "category": "ilo",
     "text": [r"\bipmi\b", r"\bbmc\b"], "vendors": [], "ports": {623},
     "mgmt": "IPMI (623/udp)",
     "advisories": ["IPMI cipher-0 / anonim erişim ve varsayılan hesapları doğrula",
                    "IPMI'nin yalnız ayrı yönetim ağından erişilebilir olduğunu doğrula"]},
    # --- Kamera / güvenlik sistemleri ---
    {"family": "Dahua kamera/NVR", "category": "camera",
     "text": [r"dahua", r"\bdh[-_]", r"webrec"], "vendors": ["dahua"],
     "ports": {37777, 80, 554, 37778},
     "mgmt": "Web arayüzü (80), özel istemci (37777), RTSP (554)",
     "advisories": ["CVE-2021-33044/33045 (auth bypass) — firmware'e karşı doğrula",
                    "37777/80 arayüzlerinin internete açıklığını ve varsayılan hesabı doğrula"]},
    {"family": "Hikvision kamera/NVR", "category": "camera",
     "text": [r"hikvision", r"\bhik[-_]"], "vendors": ["hikvision"],
     "ports": {8000, 80, 554},
     "mgmt": "Web arayüzü (80), SDK (8000), RTSP (554)",
     "advisories": ["CVE-2021-36260 (RCE) — firmware'e karşı doğrula", "Web arayüzü ve varsayılan hesabı doğrula"]},
    {"family": "Avenir kamera/güvenlik", "category": "camera",
     "text": [r"avenir"], "vendors": ["avenir"], "ports": {80, 554, 37777, 8000},
     "mgmt": "Web arayüzü (80), RTSP (554)",
     "advisories": ["OEM tabanını (sık Dahua/Hikvision) ve firmware'i doğrula; ilgili OEM danışmalarını uygula",
                    "Arayüz internete açıklığını ve varsayılan hesabı doğrula"]},
    {"family": "Neutron kamera/güvenlik", "category": "camera",
     "text": [r"neutron"], "vendors": ["neutron"], "ports": {80, 554, 37777, 8000},
     "mgmt": "Web arayüzü (80), RTSP (554)",
     "advisories": ["OEM tabanını (sık Dahua/Hikvision) ve firmware'i doğrula; ilgili OEM danışmalarını uygula",
                    "Arayüz internete açıklığını ve varsayılan hesabı doğrula"]},
    # --- Ek ağ/altyapı platformları ---
    {"family": "MikroTik RouterOS", "category": "router",
     "text": [r"mikrotik", r"routeros"], "vendors": ["mikrotik", "routerboard"],
     "ports": {8291, 8728, 8729, 80, 443, 22, 23}, "cpe": ("o", "mikrotik", "routeros"),
     "mgmt": "Winbox (8291), WebFig (80/443), API (8728/8729)",
     "version_re": r"routeros[^0-9]{0,10}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["Winbox CVE-2018-14847 (kimlik sızıntısı) — sürüme karşı doğrula",
                    "Winbox/API'nin internete açıklığını doğrula"]},
    {"family": "Ubiquiti UniFi", "category": "router",
     "text": [r"unifi", r"ubiquiti", r"ubnt"], "vendors": ["ubiquiti"],
     "ports": {8443, 8080, 8880, 6789, 443, 22},
     "mgmt": "UniFi Network denetleyici (8443)",
     "advisories": ["UniFi Network sürümünü Ubiquiti güvenlik danışmalarıyla doğrula",
                    "Denetleyici (8443) erişim sınırını doğrula"]},
    {"family": "Zyxel cihazı", "category": "firewall",
     "text": [r"zyxel"], "vendors": ["zyxel"], "ports": {443, 80, 8443, 22, 23, 161},
     "mgmt": "Web yönetim arayüzü",
     "advisories": ["Zyxel firmware'ini Zyxel danışmalarıyla doğrula (ör. CVE-2022-30525, CVE-2023-28771)",
                    "Yönetim arayüzünün internete açıklığını doğrula"]},
    {"family": "pfSense", "category": "firewall",
     "text": [r"pfsense"], "vendors": ["netgate"], "ports": {443, 80, 22},
     "mgmt": "pfSense web arayüzü (443)", "cpe": ("o", "pfsense", "pfsense"),
     "version_re": r"pfsense[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["pfSense sürümünü Netgate danışmalarıyla doğrula"]},
    {"family": "OPNsense", "category": "firewall",
     "text": [r"opnsense"], "vendors": [], "ports": {443, 80, 22},
     "mgmt": "OPNsense web arayüzü (443)", "cpe": ("o", "opnsense", "opnsense"),
     "version_re": r"opnsense[^0-9]{0,12}(\d+\.\d+(?:\.\d+)?)",
     "advisories": ["OPNsense sürümünü proje danışmalarıyla doğrula"]},
    {"family": "Aruba (ArubaOS / Instant)", "category": "ap",
     "text": [r"arubaos", r"aruba instant", r"\baruba\b"], "vendors": ["aruba"],
     "ports": {443, 4343, 80, 22}, "mgmt": "ArubaOS web/CLI (4343/443)",
     "advisories": ["ArubaOS sürümünü HPE Aruba PSIRT danışmalarıyla doğrula"]},
    {"family": "TrueNAS / FreeNAS", "category": "nas",
     "text": [r"truenas", r"freenas"], "vendors": ["ixsystems"], "ports": {443, 80, 22},
     "mgmt": "TrueNAS web arayüzü (443)",
     "advisories": ["TrueNAS sürümünü iXsystems danışmalarıyla doğrula"]},
    {"family": "Veeam Backup & Replication", "category": "server",
     "text": [r"veeam"], "vendors": ["veeam"], "ports": {9392, 9401, 9443, 443},
     "mgmt": "Veeam B&R konsol/servisleri (9392/9401)",
     "advisories": ["CVE-2023-27532, CVE-2024-40711 — Veeam B&R sürümüne karşı doğrula",
                    "Yedekleme altyapısı erişim sınırını doğrula"]},
    {"family": "Axis kamera", "category": "camera",
     "text": [r"\baxis\b"], "vendors": ["axis"], "ports": {80, 443, 554},
     "mgmt": "VAPIX web arayüzü (80/443), RTSP (554)",
     "advisories": ["Axis OS sürümünü Axis güvenlik danışmalarıyla doğrula",
                    "Varsayılan hesap ve arayüz maruziyetini doğrula"]},
]


def identify(ports: set, blob: str, vendor: str = "") -> list:
    """Açık portlar + metin kanıtından eşleşen platform profillerini döndürür."""
    blob = (blob or "").lower()
    vendor = (vendor or "").lower()
    matches = []
    for profile in PROFILES:
        text_hit = any(re.search(pattern, blob) for pattern in profile["text"])
        # text_only profiller (ör. aynı üreticiyi paylaşan Cisco alt ürünleri)
        # yalnız açık ürün metniyle eşleşir; üretici+port yolu kapalıdır.
        vendor_hit = (not profile.get("text_only")
                      and (any(v in vendor or v in blob for v in profile["vendors"]) if profile["vendors"] else False))
        # Üretici+port yolu için ayırt edici port gerekir (80/443 tek başına her
        # yerde bulunduğu için yanlış eşleşme üretir).
        distinctive = profile["ports"] - {80, 443}
        port_hit = bool(ports & distinctive)
        if text_hit:
            confidence = "yüksek"
        elif vendor_hit and port_hit:
            confidence = "orta"
        else:
            continue
        version = ""
        if profile.get("version_re"):
            found = re.search(profile["version_re"], blob)
            if found:
                version = found.group(1)
        matches.append({
            "family": profile["family"], "category": profile["category"],
            "confidence": confidence, "version": version,
            "mgmt": profile["mgmt"],
            "mgmt_ports_observed": sorted(ports & profile["ports"]),
            "advisories": profile["advisories"],
            "signal": "ürün metni" if text_hit else "üretici + port",
            "cpe_parts": list(profile["cpe"]) if profile.get("cpe") else None,
        })
    return matches


def _host_blob(root: Path, ip: str, ports_meta: list, device: dict) -> tuple[set, str, str]:
    """Bir adres için port kümesi, birleşik metin kanıtı ve üretici döndürür."""
    ports = set()
    parts = []
    for port in ports_meta:
        try:
            ports.add(int(port.get("port")))
        except (TypeError, ValueError):
            pass
        parts.append(" ".join(str(port.get(k, "")) for k in ("service", "product", "version")))
    vendor = ""
    if device:
        vendor = str(device.get("vendor", ""))
        parts.append(vendor)
        parts.extend(str(x) for x in device.get("hostnames", []))
        parts.extend(str(x.get("name", "")) for x in device.get("os_matches", []))
        parts.extend(str(x) for x in device.get("signals", []))
        for port in device.get("ports", []):
            try:
                ports.add(int(port.get("port")))
            except (TypeError, ValueError):
                pass
    ipsafe_variants = {ip, ip.replace(":", "_")}
    targets = root / "targets"
    if targets.exists():
        for variant in ipsafe_variants:
            for path in targets.glob(f"*/raw/headers_{variant}_*.txt"):
                try:
                    parts.append(path.read_text(encoding="utf-8", errors="replace")[:8192])
                except OSError:
                    pass
            for path in targets.glob(f"*/raw/snmp_v1_public_{variant}.json"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    if isinstance(data, dict):
                        parts.append(str(data.get("sysdescr") or data.get("sysDescr") or ""))
                except (OSError, ValueError):
                    pass
    return ports, " ".join(parts), vendor


def build(root: Path, meta: dict, hosts: list, devices: dict) -> dict:
    """Kanıttan platform tespit tablosu üretir (inceleme adayları)."""
    root = Path(root)
    device_by_ip = {}
    for item in (devices or {}).get("devices", []) if isinstance(devices, dict) else []:
        if isinstance(item, dict) and item.get("ip"):
            device_by_ip[str(item["ip"])] = item
    ports_by_ip = {}
    for host in hosts or []:
        ports_by_ip.setdefault(str(host.get("ip", "")), []).extend(host.get("ports", []))
    all_ips = set(ports_by_ip) | set(device_by_ip)
    results = []
    family_counts = {}
    for ip in sorted(all_ips):
        if not ip:
            continue
        ports, blob, vendor = _host_blob(root, ip, ports_by_ip.get(ip, []), device_by_ip.get(ip, {}))
        for match in identify(ports, blob, vendor):
            match["ip"] = ip
            results.append(match)
            family_counts[match["family"]] = family_counts.get(match["family"], 0) + 1
    results.sort(key=lambda m: ({"yüksek": 0, "orta": 1, "düşük": 2}.get(m["confidence"], 3), m["family"], m["ip"]))
    return {
        "schema": 1, "matches": results, "families": family_counts,
        "match_count": len(results),
        "note": ("Platform eşleşmeleri gözlenen kanıta dayanan inceleme adaylarıdır; istismar değildir. "
                 "Listelenen CVE/danışmalar gözlenen sürüme karşı DOĞRULANMALIDIR, mevcudiyet iddiası taşımaz."),
    }


def write(root: Path, meta: dict, hosts: list, devices: dict) -> dict:
    result = build(root, meta, hosts, devices)
    temp = Path(root) / ".UBDEN_TECH_PROFILE.pending.json"
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(Path(root) / "UBDEN_TECH_PROFILE.json")
    return result
