"""Pure-stdlib HTTP identity probe (device 'view-source') — no external tool.

For in-scope hosts with a web management port, fetch the root page and capture the
<title>, Server header and a sanitized body snippet. This is a strong device-identity
signal the header-only probes miss (e.g. a Vantiva/Technicolor DOCSIS gateway that
nmap -O ambiguously guessed as MikroTik). device_inventory.build_inventory reads
web_id_<ip>.json into the classifier's text blob and as a display signal.

Read-only, bounded, no redirects (stays on the pinned host), TLS verification off,
size-capped. Secrets are stripped before writing.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
import urllib.request
from pathlib import Path

from ai_analyst import strip_common_secrets

WEB_PORTS = [443, 80, 8443, 8080, 8006, 10443, 7547, 8000, 8888, 9443]
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_MAX_BODY = 200_000


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # do not follow redirects (stay on the in-scope host)


def _fetch(ip: str, port: int, timeout: float = 8.0):
    scheme = "https" if port in (443, 8443, 10443, 8006, 9443) else "http"
    host = f"[{ip}]" if ":" in ip else ip
    suffix = "" if port in (80, 443) else f":{port}"
    url = f"{scheme}://{host}{suffix}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(),
        urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "UBDEN-uPenetrator"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(_MAX_BODY).decode("utf-8", "replace")
            server = resp.headers.get("Server", "")
            status = getattr(resp, "status", 0)
    except Exception:
        return None
    title = ""
    m = _TITLE.search(body)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()[:200]
    snippet = strip_common_secrets(re.sub(r"\s+", " ", body))[:1800]
    return {"scheme": scheme, "port": port, "status": status,
            "server": server[:160], "title": title, "snippet": snippet, "url": url}


def run(assets, opened, raw, events, max_hosts: int = 32) -> None:
    raw = Path(raw)
    hosts = [str(ip) for ip in assets if set(opened.get(ip, [])) & set(WEB_PORTS)][:max_hosts]
    if not hosts:
        return
    found = 0
    for ip in hosts:
        ports = [p for p in WEB_PORTS if p in set(opened.get(ip, []))]
        info = None
        for port in ports:
            info = _fetch(ip, port)
            if info and (info.get("title") or info.get("server")):
                break
        if not info:
            continue
        found += 1
        info["target"] = ip
        path = raw / f"web_id_{re.sub(r'[^A-Za-z0-9._-]', '_', ip)[:90]}.json"
        tmp = path.with_suffix(".pending.json")
        tmp.write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        tmp.replace(path)
    summary = raw / "web_id_summary.json"
    tmp = summary.with_suffix(".pending.json")
    tmp.write_text(json.dumps({"tested": len(hosts), "identified": found}, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    tmp.replace(summary)
    events.append({"step": "web_identify", "tool": "http(stdlib)", "status": "ok",
                   "detail": f"{found}/{len(hosts)} web arayüzü kimliği alındı",
                   "output": str(summary.relative_to(raw.parent.parent.parent)),
                   "sha256": hashlib.sha256(summary.read_bytes()).hexdigest()})
