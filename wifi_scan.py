"""Passive Wi-Fi visibility via Windows `netsh wlan` — no tool, no monitor mode.

Lists the SSIDs/BSSIDs the test machine's Wi-Fi adapter currently sees, with signal
and channel, plus the connected interface. Locale-tolerant parsing (labels differ on
Turkish Windows), so it keeps stable tokens (SSID/BSSID) and the signal '%'. Writes
WIFI_SCAN.json for the report/AI. Read-only; does not connect, deauth or capture frames.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


def _netsh(args, timeout=25):
    if not shutil.which("netsh"):
        return ""
    try:
        return subprocess.run(["netsh"] + args, capture_output=True, text=True,
                              timeout=timeout, errors="replace", check=False).stdout or ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def scan() -> dict:
    out = _netsh(["wlan", "show", "networks", "mode=bssid"])
    if "SSID" not in out:
        # No wireless service/adapter, or WLAN AutoConfig disabled.
        return {"available": False, "networks": [], "note": (out.strip()[:200] or "Wi-Fi adaptörü/servisi yok")}
    networks, current = [], None
    for line in out.splitlines():
        m = re.match(r"\s*SSID\s+\d+\s*:\s*(.*)", line)
        if m:
            current = {"ssid": m.group(1).strip() or "(gizli)", "auth": "", "encryption": "", "bssids": []}
            networks.append(current)
            continue
        if current is None:
            continue
        b = re.match(r"\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})", line)
        if b:
            current["bssids"].append({"bssid": b.group(1).upper(), "signal": "", "channel": ""})
            continue
        if "%" in line and current["bssids"] and not current["bssids"][-1]["signal"]:
            sig = re.search(r"(\d{1,3})\s*%", line)
            if sig:
                current["bssids"][-1]["signal"] = sig.group(1) + "%"
            continue
        if current["bssids"] and not current["bssids"][-1]["channel"]:
            ch = re.match(r"\s*(?:Channel|Kanal)\s*:\s*(\d+)", line, re.I)
            if ch:
                current["bssids"][-1]["channel"] = ch.group(1)
                continue
        if not current["auth"]:
            a = re.match(r"\s*(?:Authentication|Kimlik Do.rulamas.)\s*:\s*(.*)", line, re.I)
            if a:
                current["auth"] = a.group(1).strip()
                continue
        if not current["encryption"]:
            e = re.match(r"\s*(?:Encryption|.ifreleme)\s*:\s*(.*)", line, re.I)
            if e:
                current["encryption"] = e.group(1).strip()
    ap_count = sum(len(n["bssids"]) for n in networks)
    open_nets = [n["ssid"] for n in networks if re.search(r"open|a.ık|yok|none", n["auth"], re.I)]
    return {"available": True, "network_count": len(networks), "ap_count": ap_count,
            "open_networks": open_nets, "networks": networks[:80],
            "interface": _netsh(["wlan", "show", "interfaces"])[:1500]}


def run(root, events) -> dict:
    data = scan()
    root = Path(root)
    path = root / "WIFI_SCAN.json"
    tmp = path.with_suffix(".pending.json")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)
    if data.get("available"):
        detail = (f"{data['network_count']} SSID / {data['ap_count']} BSSID görüldü"
                  + (f"; açık ağ: {', '.join(data['open_networks'][:5])}" if data["open_networks"] else ""))
        status = "ok"
    else:
        detail = data.get("note", "Wi-Fi yok")
        status = "skipped"
    events.append({"step": "wifi_scan", "tool": "netsh wlan", "status": status, "detail": detail,
                   "output": "WIFI_SCAN.json",
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    return data
