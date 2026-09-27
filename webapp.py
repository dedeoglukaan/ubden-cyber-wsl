"""Local browser UI for UBDEN uPenetrator (Windows-native).

Zero external dependencies: a stdlib ``http.server`` bound to 127.0.0.1 on an
ephemeral port, gated by a one-time token in the URL. It is the browser
equivalent of the Kali ``tui.py`` wizard: an operator fills the engagement form,
picks the physical adapter, launches the scan, watches live progress, and opens
the finished report. All scanning/reporting is delegated to ``win_scan``.

Not exposed to the network: the socket binds to loopback only and every request
must carry the process-lifetime token. It runs no request whose token is wrong.
"""
from __future__ import annotations

import json
import os
import secrets
import subprocess
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

import win_scan

TOKEN = secrets.token_urlsafe(18)
_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _new_job() -> str:
    job_id = secrets.token_hex(8)
    with _LOCK:
        _JOBS[job_id] = {"lines": [], "status": "running", "result": None}
    return job_id


def _emit(job_id: str, line: str, level: str) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is not None:
            job["lines"].append({"t": line, "level": level})


def _run_job(job_id: str, form: dict) -> None:
    try:
        result = win_scan.run_scan(form, progress=lambda line, level="info": _emit(job_id, line, level))
        with _LOCK:
            _JOBS[job_id]["result"] = result
            _JOBS[job_id]["status"] = "done"
    except Exception as exc:  # a crash must surface, not hang the UI
        _emit(job_id, f"Beklenmeyen hata: {type(exc).__name__}: {exc}", "warn")
        with _LOCK:
            _JOBS[job_id]["status"] = "error"


# The page is a plain string with a single __TOKEN__ placeholder (str.replace,
# NOT str.format) — so braces below are literal CSS/JS braces.
PAGE = """<!doctype html><html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>UBDEN uPenetrator</title><style>
:root{--bg:#080d1b;--panel:#0f1830;--line:#1e2b4a;--ink:#e8f0fc;--dim:#93a6c8;
--green:#22d3a0;--teal:#00b9bd;--red:#ef6a6a;--yellow:#e9c46a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 "Segoe UI",system-ui,Arial,sans-serif}
header{padding:18px 22px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:14px;flex-wrap:wrap;background:linear-gradient(180deg,#0c1a33,transparent)}
h1{font-size:18px;margin:0;letter-spacing:.5px}h1 b{color:var(--green)}
.sub{color:var(--dim);font-size:13px}main{max-width:900px;margin:0 auto;padding:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:18px}
label{display:block;font-size:13px;color:var(--dim);margin:10px 0 4px}
input,select,textarea{width:100%;background:#0a1226;color:var(--ink);
border:1px solid var(--line);border-radius:8px;padding:9px 10px;font:inherit}
textarea{min-height:70px;resize:vertical}.row{display:flex;gap:14px;flex-wrap:wrap}
.row>div{flex:1;min-width:180px}.adapters label{display:flex;align-items:center;gap:8px;
color:var(--ink);margin:6px 0;font-size:14px}.adapters input{width:auto}
button{background:var(--green);color:#04140d;border:0;border-radius:9px;padding:11px 18px;
font-weight:700;font-size:15px;cursor:pointer}button.sec{background:#16233f;color:var(--ink)}
button:disabled{opacity:.5;cursor:not-allowed}
#log{background:#060a15;border:1px solid var(--line);border-radius:8px;padding:12px;
height:260px;overflow:auto;font:13px/1.5 Consolas,monospace;white-space:pre-wrap}
.l-info{color:var(--ink)}.l-tick{color:var(--dim)}.l-warn{color:var(--yellow)}
.l-done{color:var(--green);font-weight:700}.hint{color:var(--dim);font-size:12px;margin-top:6px}
a{color:var(--teal)}.pill{display:inline-block;background:#16233f;border:1px solid var(--line);
border-radius:999px;padding:3px 10px;font-size:12px;color:var(--dim);margin-left:8px}
</style></head><body>
<header><h1><b>UBDEN</b> uPenetrator <span class="pill">Windows-native</span></h1>
<span class="sub">Yetkili, kayitli ve sinirli guvenlik degerlendirmesi &middot; https://www.ubden.com</span></header>
<main>
<div class="card"><div class="row">
<div><label>Musteri</label><input id="client" placeholder="Musteri adi"></div>
<div><label>Proje</label><input id="project" placeholder="Gorev adi"></div>
</div><div class="row">
<div><label>Yetki referansi</label><input id="auth" placeholder="Yazili izin no/kaynak"></div>
<div><label>Test eden</label><input id="tester" placeholder="Analist"></div>
</div>
<label>Hedefler (her satira bir IP / CIDR / FQDN)</label>
<textarea id="targets" placeholder="192.168.1.0/24&#10;10.0.0.5&#10;portal.ornek.com"></textarea>
<label>Haric tutulanlar (istege bagli)</label>
<textarea id="exclusions" placeholder="192.168.1.1"></textarea>
<div class="row">
<div><label>Profil</label><select id="profile">
<option value="network">Network (servis + NSE guvenlik denetimi)</option>
<option value="full">Full (tum otomatik moduller)</option>
<option value="web">Web (web portlari + baslik/TLS)</option>
<option value="external">External (dis yuzey)</option>
</select></div>
<div><label>En cok TCP portu</label><input id="top_ports" type="number" value="200" min="1" max="1000"></div>
<div><label>Hiz (paket/sn)</label><input id="max_rate" type="number" value="100" min="1" max="500"></div>
</div>
<label class="adapters" style="margin-top:12px"><input type="checkbox" id="defcred"> Varsayilan kimlik denemesi (opt-in, sinirli, kilitlenme-farkinda)</label>
<div id="adapters" class="adapters"><label>Ag adaptorleri yukleniyor...</label></div>
<div class="hint">Adaptor secimi kapsam guvenligi icindir: yalniz secilen adaptorden erisilebilen IP'ler taranir (tek host hedeflerinde). Yonetici yetkisi + Npcap ARP/MAC icin gereklidir.</div>
<div style="margin-top:16px"><button id="go">YETKILIYIM &mdash; Taramayi baslat</button></div>
</div>
<div class="card" id="progress" style="display:none">
<div style="display:flex;justify-content:space-between;align-items:center">
<strong>Ilerleme</strong><span id="state" class="pill">calisiyor</span></div>
<div id="log"></div>
<div id="done" style="display:none;margin-top:12px"></div>
</div>
</main>
<script>
const T="__TOKEN__";
async function loadAdapters(){
 try{const r=await fetch("/api/adapters?t="+T);const d=await r.json();
 const box=document.getElementById("adapters");box.innerHTML="";
 const ad=(d.adapters||[]).filter(a=>(a.addresses||[]).length);
 if(!ad.length){box.innerHTML="<label>Adresli adaptor bulunamadi (kopru yoksa tarama yine calisir).</label>";return;}
 ad.forEach(a=>{const ips=(a.addresses||[]).map(x=>x.address).join(", ");
 box.insertAdjacentHTML("beforeend",
 `<label><input type="checkbox" class="adp" value="${a.index}" ${/Up/i.test(a.status)?"checked":""}> ${a.name} &mdash; <span class="sub">${ips||a.status}</span></label>`);});
 }catch(e){document.getElementById("adapters").innerHTML="<label>Adaptor listesi alinamadi.</label>";}
}
function lines(v){return v.split("\\n").map(s=>s.trim()).filter(Boolean);}
let JOB=null,timer=null;
async function start(){
 const body={client:c("client"),project:c("project"),authorization_reference:c("auth"),
 tester:c("tester"),targets:lines(v("targets")),exclusions:lines(v("exclusions")),
 profile:v("profile"),top_ports:v("top_ports"),max_rate:v("max_rate"),
 default_cred_test:document.getElementById("defcred").checked,
 selected_interfaces:[...document.querySelectorAll(".adp:checked")].map(x=>x.value)};
 if(!body.targets.length){alert("En az bir hedef girin.");return;}
 document.getElementById("go").disabled=true;
 document.getElementById("progress").style.display="block";
 const r=await fetch("/api/start?t="+T,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 const d=await r.json();JOB=d.job;timer=setInterval(poll,1200);poll();
}
async function poll(){
 if(!JOB)return;const r=await fetch("/api/status?t="+T+"&job="+JOB);const d=await r.json();
 const log=document.getElementById("log");
 log.innerHTML=(d.lines||[]).map(l=>`<div class="l-${l.level}">${esc(l.t)}</div>`).join("");
 log.scrollTop=log.scrollHeight;
 document.getElementById("state").textContent=d.status;
 if(d.status==="done"||d.status==="error"){clearInterval(timer);
 document.getElementById("go").disabled=false;showDone(d);}
}
function showDone(d){const el=document.getElementById("done");el.style.display="block";
 const s=(d.result&&d.result.device_summary)||{};
 let out=`<div><strong>Cihaz envanteri:</strong> ${s.host_count||0} cihaz &middot; <b>${s.mac_count||0} MAC</b> &middot; ${s.unknown_count||0} siniflandirilmamis</div>`;
 if(d.result&&d.result.report_html){
 out+=`<p><a href="/r/REPORT.html?t=${T}&job=${JOB}" target="_blank">HTML raporu ac</a> &middot; `;
 out+=`<a href="/r/YONETICI_OZETI.pdf?t=${T}&job=${JOB}" target="_blank">Yonetici ozeti (PDF)</a> &middot; `;
 out+=`<a href="/r/TEKNIK_RAPOR.pdf?t=${T}&job=${JOB}" target="_blank">Teknik rapor (PDF)</a></p>`;
 out+=`<button class="sec" onclick="openFolder()">Rapor klasorunu ac</button>`;}
 else{out+=`<p class="l-warn">Rapor uretilemedi; ilerleme kaydini inceleyin.</p>`;}
 el.innerHTML=out;}
async function openFolder(){await fetch("/api/open?t="+T+"&job="+JOB,{method:"POST"});}
function v(id){return document.getElementById(id).value;}
function c(id){return document.getElementById(id).value.trim();}
function esc(s){return (s+"").replace(/[&<>]/g,m=>({"&":"&amp;","<":"&lt;",">":"&gt;"}[m]));}
document.getElementById("go").addEventListener("click",start);loadAdapters();
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    server_version = "UBDEN-uPenetrator"

    def log_message(self, *args):  # silence default stderr logging
        pass

    def _tok_ok(self, query) -> bool:
        return secrets.compare_digest((query.get("t", [""])[0]), TOKEN)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        data = body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionError):
            pass

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/":
            if not self._tok_ok(query):
                return self._send(403, "Forbidden", "text/plain; charset=utf-8")
            return self._send(200, PAGE.replace("__TOKEN__", TOKEN), "text/html; charset=utf-8")
        if not self._tok_ok(query):
            return self._send(403, json.dumps({"error": "forbidden"}))
        if parsed.path == "/api/adapters":
            return self._send(200, json.dumps(win_scan.windows_inventory()))
        if parsed.path == "/api/status":
            job = query.get("job", [""])[0]
            with _LOCK:
                data = _JOBS.get(job)
                payload = json.dumps(data) if data else json.dumps({"error": "unknown_job"})
            return self._send(200, payload)
        if parsed.path.startswith("/r/"):
            return self._serve_report(parsed, query)
        return self._send(404, json.dumps({"error": "not_found"}))

    def do_POST(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if not self._tok_ok(query):
            return self._send(403, json.dumps({"error": "forbidden"}))
        if parsed.path == "/api/start":
            length = int(self.headers.get("Content-Length", "0") or "0")
            try:
                form = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except (ValueError, UnicodeDecodeError):
                return self._send(400, json.dumps({"error": "bad_json"}))
            if not isinstance(form, dict):
                return self._send(400, json.dumps({"error": "bad_form"}))
            job_id = _new_job()
            threading.Thread(target=_run_job, args=(job_id, form), daemon=True).start()
            return self._send(200, json.dumps({"job": job_id}))
        if parsed.path == "/api/open":
            job = query.get("job", [""])[0]
            with _LOCK:
                data = _JOBS.get(job)
            run_dir = (data or {}).get("result", {}).get("run_dir") if data else None
            if run_dir and Path(run_dir).is_dir() and os.name == "nt":
                try:
                    subprocess.Popen(["explorer.exe", str(Path(run_dir))])
                except OSError:
                    pass
            return self._send(200, json.dumps({"ok": True}))
        return self._send(404, json.dumps({"error": "not_found"}))

    def _serve_report(self, parsed, query):
        job = query.get("job", [""])[0]
        with _LOCK:
            data = _JOBS.get(job)
        run_dir = (data or {}).get("result", {}).get("run_dir") if data else None
        if not run_dir:
            return self._send(404, "Rapor hazir degil", "text/plain; charset=utf-8")
        base = Path(run_dir).resolve()
        rel = parsed.path[len("/r/"):]
        target = (base / rel).resolve()
        if os.path.commonpath([str(base), str(target)]) != str(base) or not target.is_file():
            return self._send(404, "Bulunamadi", "text/plain; charset=utf-8")  # path containment
        ctype = {".html": "text/html; charset=utf-8", ".pdf": "application/pdf",
                 ".png": "image/png", ".json": "application/json; charset=utf-8",
                 ".txt": "text/plain; charset=utf-8", ".md": "text/plain; charset=utf-8",
                 ".csv": "text/plain; charset=utf-8"}.get(target.suffix.lower(),
                                                          "application/octet-stream")
        return self._send(200, target.read_bytes(), ctype)


def serve(open_browser: bool = True):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"
    print(f"UBDEN uPenetrator: {url}", flush=True)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    serve()
