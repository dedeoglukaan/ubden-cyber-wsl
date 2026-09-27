"""Small numeric-IP probes with explicit preconditions and one packet per host.

Cross-platform: prefers the Linux tools (fping/nbtscan) when present, else uses the
Windows built-ins (ping/nbtstat) so the checks actually run on Windows instead of
being recorded as missing_tool. hping3 (raw SYN) has no Windows equivalent; the
SYN reachability it would give is already covered by the nmap -sS/-sT pass.
"""
from __future__ import annotations

import ipaddress
import os
import shutil


def run(target: str, assets: list[str], opened: dict[str, list[int]], raw,
        events: list[dict], command, profile: str) -> None:
    if profile not in ("network", "full"):
        return
    win = os.name == "nt"
    has_fping = bool(shutil.which("fping"))
    has_nbtscan = bool(shutil.which("nbtscan"))
    has_hping = bool(shutil.which("hping3"))
    for index, value in enumerate(assets, 1):
        ip = str(ipaddress.ip_address(value))
        suffix = f"{index:03d}"
        if has_fping:
            result = command(f"fping_{suffix}", ["fping", "-c", "1", "-t", "1000", ip], raw, events, 5)
        else:  # Windows/Unix built-in ping fallback (single packet)
            args = ["ping", "-n", "1", "-w", "1000", ip] if win else ["ping", "-c", "1", "-W", "1", ip]
            result = command(f"ping_{suffix}", args, raw, events, 6)
        result["target"] = ip
        ports = set(opened.get(ip, []))
        if (139 in ports or 445 in ports) and ":" not in ip:
            if has_nbtscan:
                result = command(f"nbtscan_{suffix}", ["nbtscan", "-t", "1", ip], raw, events, 10)
            elif shutil.which("nbtstat"):  # Windows built-in NetBIOS name query
                result = command(f"nbtstat_{suffix}", ["nbtstat", "-A", ip], raw, events, 10)
            else:
                result = {"step": f"nbtscan_{suffix}"}
                events.append({"step": f"nbtscan_{suffix}", "tool": "nbtscan", "target": ip,
                               "status": "missing_tool", "detail": "NetBIOS aracı yok"})
            result["target"] = ip
        elif 139 in ports or 445 in ports:
            events.append({"step": f"nbtscan_{suffix}", "tool": "nbtscan", "target": ip,
                           "status": "skipped", "detail": "NetBIOS IPv4 gerektirir"})
        if ports and has_hping:
            result = command(f"hping3_{suffix}",
                             ["hping3", "-S", "-c", "1", "-p", str(min(ports)), ip],
                             raw, events, 8)
            result["target"] = ip
