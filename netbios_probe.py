"""Pure-stdlib NetBIOS node-status (NBSTAT) probe — no external binary.

Sends a single UDP/137 node-status request per in-scope host with 139/445 open and
parses the name table for the computer name, workgroup/domain, DC/file-server role
(name-table suffixes 0x1B/0x1C/0x20) and the adapter MAC. This recovers real device
NAMES and roles on a Windows LAN — a capability the WSL scanner never had — and
feeds device_inventory.build_inventory() via netbios_<ip>.json evidence files.
"""
from __future__ import annotations

import hashlib
import json
import re
import socket
import struct
from pathlib import Path


def _encode_name(name: str = "*") -> bytes:
    raw = name.encode("ascii")[:16]
    raw = raw + b"\x00" * (16 - len(raw))
    out = bytearray()
    for byte in raw:
        out.append(0x41 + (byte >> 4))
        out.append(0x41 + (byte & 0x0F))
    return bytes(out)


def _build_query() -> bytes:
    header = struct.pack(">HHHHHH", 0x4242, 0x0000, 1, 0, 0, 0)
    qname = b"\x20" + _encode_name("*") + b"\x00"
    return header + qname + struct.pack(">HH", 0x0021, 0x0001)  # NBSTAT, class IN


def _parse(ip: str, data: bytes) -> dict | None:
    if len(data) < 57:
        return None
    off = 50  # 12 header + 34 echoed qname + 2 qtype + 2 qclass
    if off >= len(data):
        return None
    name_len = 2 if (data[off] & 0xC0) == 0xC0 else 34  # pointer or repeated name
    off += name_len + 2 + 2 + 4 + 2  # + type + class + ttl + rdlength
    if off >= len(data):
        return None
    count = data[off]
    off += 1
    names = []
    for _ in range(count):
        if off + 18 > len(data):
            break
        # NetBIOS name bytes are OEM-encoded; cp850 maps every byte (no U+FFFD),
        # then keep only printable characters so junk/control bytes don't reach the report.
        label = data[off:off + 15].rstrip(b"\x00 ").decode("cp850", "replace")
        label = "".join(ch for ch in label if ch.isprintable()).strip()
        suffix = data[off + 15]
        flags = struct.unpack(">H", data[off + 16:off + 18])[0]
        names.append((label, suffix, bool(flags & 0x8000)))
        off += 18
    mac = ""
    if off + 6 <= len(data):
        mac = ":".join("%02X" % b for b in data[off:off + 6])
        if mac in ("00:00:00:00:00:00",):
            mac = ""
    computer = next((n for n, s, g in names if s == 0x00 and not g and n), "")
    domain = next((n for n, s, g in names if g and s in (0x00, 0x1C, 0x1E) and n), "")
    suffixes = {s for _, s, _ in names}
    role = ""
    if suffixes & {0x1B, 0x1C}:
        role = "domain controller"
    elif 0x20 in suffixes:
        role = "file server"
    if not computer and not names:
        return None
    return {"target": ip, "name": computer, "domain": domain, "role": role,
            "mac": mac, "names": [{"name": n, "suffix": s, "group": g} for n, s, g in names]}


def probe(ip: str, timeout: float = 2.0) -> dict | None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(_build_query(), (ip, 137))
            data, _ = sock.recvfrom(2048)
        finally:
            sock.close()
    except (OSError, socket.timeout):
        return None
    return _parse(ip, data)


def run(assets, opened, raw, events, max_hosts: int = 64) -> None:
    """Probe hosts with 139/445 open; write netbios_<ip>.json + one summary event."""
    raw = Path(raw)
    targets = [str(ip) for ip in assets
               if ":" not in str(ip) and ({139, 445} & set(opened.get(ip, [])))][:max_hosts]
    if not targets:
        return
    found = 0
    for ip in targets:
        info = probe(ip)
        if not info or not info.get("name"):
            continue
        found += 1
        path = raw / f"netbios_{re.sub(r'[^A-Za-z0-9._-]', '_', ip)[:90]}.json"
        tmp = path.with_suffix(".pending.json")
        tmp.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    summary = raw / "netbios_summary.json"
    tmp = summary.with_suffix(".pending.json")
    tmp.write_text(json.dumps({"tested": len(targets), "named": found}, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    tmp.replace(summary)
    events.append({"step": "netbios", "tool": "netbios(stdlib)", "status": "ok",
                   "detail": f"{found}/{len(targets)} host NetBIOS adı verdi",
                   "output": str(summary.relative_to(raw.parent.parent.parent)),
                   "sha256": hashlib.sha256(summary.read_bytes()).hexdigest()})
