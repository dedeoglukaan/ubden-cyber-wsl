"""Windows tool catalogue + installer for UBDEN uPenetrator (Faz 2).

Goal: bring the FULL tool set to Windows. Every tool the Kali probe suite runs is
either (a) installed here (winget native or pip CLI), (b) already shipped by
Windows (curl, nslookup, tracert), or (c) covered by an Nmap NSE equivalent.
Genuinely unavailable tools are reported, never silently skipped.

Native (winget) installs are driven by ubden-win.ps1; this module handles the
pip-installable CLIs into the active venv and reports presence for every tool.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# pip-installable CLI tools (land in the venv's Scripts dir).
PIP_TOOLS = [
    ("wafw00f", "wafw00f", "WAF/ürün tespiti (web)"),
    ("fierce", "fierce", "Alt alan keşfi"),
    ("theHarvester", "theHarvester", "Pasif OSINT (alt alan/e-posta)"),
]

# Full catalogue: exe -> how it is provided on Windows and its NSE/pure fallback.
# 'source': winget | pip | builtin | nse | manual
CATALOG = [
    {"exe": "nmap", "source": "winget", "id": "Insecure.Nmap",
     "purpose": "Port/servis + ARP/MAC keşfi (Npcap)", "fallback": ""},
    {"exe": "nuclei", "source": "winget", "id": "ProjectDiscovery.Nuclei",
     "purpose": "Şablon tabanlı zafiyet taraması", "fallback": ""},
    {"exe": "curl", "source": "builtin", "id": "",
     "purpose": "HTTP başlık/OPTIONS yoklaması", "fallback": ""},
    {"exe": "nslookup", "source": "builtin", "id": "",
     "purpose": "DNS sorgusu", "fallback": ""},
    {"exe": "whois", "source": "winget", "id": "Microsoft.Sysinternals.Whois",
     "purpose": "WHOIS kaydı", "fallback": "nse: whois-ip"},
    {"exe": "sslscan", "source": "manual", "id": "",
     "purpose": "TLS şifre paketi denetimi", "fallback": "nse: ssl-enum-ciphers (audit)"},
    {"exe": "nikto", "source": "manual", "id": "",
     "purpose": "Web sunucu yanlış yapılandırma taraması", "fallback": "nse: http-* betikleri"},
    {"exe": "dig", "source": "manual", "id": "",
     "purpose": "Ayrıntılı DNS kayıtları", "fallback": "nslookup + osint (kısmi)"},
    {"exe": "wafw00f", "source": "pip", "id": "", "purpose": "WAF tespiti", "fallback": ""},
    {"exe": "fierce", "source": "pip", "id": "", "purpose": "Alt alan keşfi", "fallback": ""},
    {"exe": "theHarvester", "source": "pip", "id": "", "purpose": "Pasif OSINT", "fallback": ""},
    {"exe": "snmpget", "source": "manual", "id": "",
     "purpose": "SNMPv1 sysDescr okuması", "fallback": "nse: snmp-info / snmp-sysdescr"},
    {"exe": "smbclient", "source": "manual", "id": "",
     "purpose": "SMB paylaşım listesi", "fallback": "nse: smb-os-discovery / smb-enum-shares"},
    {"exe": "traceroute", "source": "builtin", "id": "",
     "purpose": "Yol izleme", "fallback": "tracert (yerleşik)"},
    {"exe": "fping", "source": "manual", "id": "", "purpose": "Toplu ICMP", "fallback": "nmap -sn"},
    {"exe": "nbtscan", "source": "manual", "id": "", "purpose": "NetBIOS tarama",
     "fallback": "nbtstat / nse: nbstat"},
    {"exe": "ike-scan", "source": "manual", "id": "", "purpose": "IKE/VPN yoklaması",
     "fallback": "nse: ike-version"},
    {"exe": "dnsenum", "source": "manual", "id": "", "purpose": "DNS/alt alan keşfi",
     "fallback": "fierce (pip)"},
]


def venv_scripts_dir() -> Path:
    """Scripts dir of the current interpreter (venv), where pip CLIs land."""
    return Path(sys.prefix) / ("Scripts" if os.name == "nt" else "bin")


def ensure_path() -> None:
    """Prepend the venv Scripts dir and common tool dirs to PATH for this process
    so shutil.which() (used by the probe suite) finds pip- and winget-installed CLIs."""
    extra = [str(venv_scripts_dir()),
             r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap"]
    current = os.environ.get("PATH", "")
    parts = current.split(os.pathsep)
    for directory in extra:
        if directory and directory not in parts and Path(directory).exists():
            current = directory + os.pathsep + current
    os.environ["PATH"] = current


def install_pip(python: str | None = None) -> list:
    """Install the pip CLI tools into the active (or given) interpreter."""
    python = python or sys.executable
    results = []
    for _, package, _ in PIP_TOOLS:
        try:
            proc = subprocess.run([python, "-m", "pip", "install", "--disable-pip-version-check", package],
                                  capture_output=True, text=True, timeout=600, check=False)
            results.append({"package": package, "ok": proc.returncode == 0,
                            "detail": (proc.stderr or "").strip()[-200:] if proc.returncode else ""})
        except (OSError, subprocess.TimeoutExpired) as exc:
            results.append({"package": package, "ok": False, "detail": str(exc)})
    return results


def report() -> dict:
    """Presence of every catalogued tool (after ensure_path)."""
    ensure_path()
    rows = []
    for tool in CATALOG:
        rows.append({"exe": tool["exe"], "present": bool(shutil.which(tool["exe"])),
                     "source": tool["source"], "purpose": tool["purpose"],
                     "fallback": tool["fallback"]})
    present = sum(1 for r in rows if r["present"])
    return {"schema": 1, "present_count": present, "total": len(rows), "tools": rows}


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    action = argv[0] if argv else "report"
    if action == "install":
        print(json.dumps({"pip": install_pip()}, ensure_ascii=False))
    else:
        print(json.dumps(report(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
