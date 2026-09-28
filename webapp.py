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
        _JOBS[job_id] = {"lines": [], "lanes": {}, "status": "running", "result": None}
    return job_id


def _emit(job_id: str, line: str, level: str = "info", lane: dict | None = None) -> None:
    with _LOCK:
        job = _JOBS.get(job_id)
        if job is None:
            return
        if lane and lane.get("id"):
            job["lanes"][lane["id"]] = lane  # live multi-lane panel state
        if line:
            job["lines"].append({"t": line, "level": level})


def _run_job(job_id: str, form: dict) -> None:
    try:
        result = win_scan.run_scan(
            form, progress=lambda line, level="info", lane=None: _emit(job_id, line, level, lane))
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
<title>UBDEN uPenetrator</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Archivo:wght@600;800&family=IBM+Plex+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--bg-deep:#05080f;--bg:#080d1b;--panel:#0c1426;--surface:#101a31;--line:#1e2b4a;
--ink:#e6ecf9;--dim:#90a0c4;--faint:#5c6c90;--accent:#3b6bff;--teal:#00b9bd;
--green:#22d3a0;--red:#ff5c6e;--critical:#ff2d4e;--yellow:#ffb020;--glow:rgba(59,107,255,.28)}
*{box-sizing:border-box}
body{margin:0;background:var(--bg-deep);color:var(--ink);
font:15px/1.55 "Segoe UI",system-ui,Arial,sans-serif;min-height:100vh}
body::before{content:"";position:fixed;inset:0;z-index:0;pointer-events:none;
background:radial-gradient(1200px 620px at 12% -8%,rgba(59,107,255,.16),transparent 60%),
linear-gradient(rgba(126,158,224,.05) 1px,transparent 1px) 0 0/34px 34px,
linear-gradient(90deg,rgba(126,158,224,.05) 1px,transparent 1px) 0 0/34px 34px}
code,.mono,.ip,.mac{font-family:"IBM Plex Mono",Consolas,monospace;font-variant-numeric:tabular-nums}
header{position:relative;z-index:1;padding:18px 26px;border-bottom:1px solid var(--line);display:flex;
align-items:center;gap:14px;flex-wrap:wrap;background:linear-gradient(180deg,#0b1730,transparent)}
.shield{width:30px;height:30px;filter:drop-shadow(0 0 6px var(--glow))}
h1{font-family:Archivo,sans-serif;font-size:19px;margin:0;letter-spacing:.3px;font-weight:800}h1 b{color:var(--green)}
.sub{color:var(--dim);font-size:13px}main{position:relative;z-index:1;max-width:1040px;margin:0 auto;padding:22px}
h2,h3{font-family:Archivo,sans-serif;letter-spacing:.2px}
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
#lanes{display:flex;flex-direction:column;gap:8px;margin:10px 0}
.lane{display:flex;align-items:center;gap:10px;background:#0a1226;border:1px solid var(--line);
border-radius:8px;padding:8px 12px}
.lane .id{font:12px Consolas,monospace;color:var(--teal);min-width:28px}
.lane .tgt{font-weight:600;min-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lane .step{color:var(--dim);flex:1;font:13px Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.lane .badge{font-size:12px;border-radius:999px;padding:2px 9px;border:1px solid var(--line)}
.lane .badge.run{color:var(--yellow)}.lane .badge.done{color:var(--green)}
.lane .cnt{font:12px Consolas,monospace;color:var(--dim)}.lane .cnt b{color:var(--red)}
a{color:var(--teal)}.pill{display:inline-block;background:#16233f;border:1px solid var(--line);
border-radius:999px;padding:3px 10px;font-size:12px;color:var(--dim);margin-left:8px}
.eyebrow{font-family:"IBM Plex Mono",monospace;text-transform:uppercase;letter-spacing:.14em;
font-size:11px;color:var(--teal);margin-bottom:6px}
.hostgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:6px}
.hostgrid .k{font-size:11px;color:var(--faint);text-transform:uppercase;letter-spacing:.08em}
.hostgrid .v{font-family:"IBM Plex Mono",monospace;font-size:13.5px;color:var(--ink);margin-top:2px;word-break:break-word}
.chip{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;border:1px solid var(--line)}
.chip.ok{color:var(--green);border-color:rgba(34,211,160,.4)}.chip.warn{color:var(--yellow);border-color:rgba(255,176,32,.4)}
.adp{display:flex;align-items:center;gap:10px;background:#0a1226;border:1px solid var(--line);
border-radius:9px;padding:9px 12px;margin:7px 0;cursor:pointer;transition:border-color .15s}
.adp:has(input:checked){border-color:var(--accent);box-shadow:0 0 0 1px var(--glow)}
.adp .an{font-weight:600;min-width:150px}.adp .ai{color:var(--dim);font-family:"IBM Plex Mono",monospace;font-size:12.5px;flex:1}
.adp .ac{font-family:"IBM Plex Mono",monospace;color:var(--teal)}.adp .kind{font-size:11px;color:var(--faint)}
.statrow{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin:12px 0}
.stat{background:var(--surface);border:1px solid var(--line);border-top:3px solid var(--teal);border-radius:10px;padding:12px 14px}
.stat .n{font-family:Archivo,sans-serif;font-size:26px;font-weight:800}.stat .l{font-size:12px;color:var(--dim)}
.dtbl{width:100%;border-collapse:collapse;font-size:13px;margin-top:8px}
.dtbl th,.dtbl td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.dtbl th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.dtbl code{color:#7fe0e4}.catrow td{background:#0b1428;font-family:Archivo,sans-serif;color:var(--teal);font-weight:600}
.cm{display:inline-block;width:70px;height:8px;background:#20304d;border-radius:5px;overflow:hidden;vertical-align:middle}
.cm i{display:block;height:8px;background:linear-gradient(90deg,var(--teal),var(--green))}
.pchip{display:inline-block;background:#12203c;border:1px solid var(--line);border-radius:5px;padding:0 6px;margin:1px;
font-family:"IBM Plex Mono",monospace;font-size:11.5px}.pchip.risk{color:var(--red);border-color:rgba(255,92,110,.5)}
.toast{position:fixed;right:18px;bottom:18px;z-index:50;background:var(--surface);border:1px solid var(--line);
border-left:3px solid var(--teal);border-radius:8px;padding:11px 16px;color:var(--ink);box-shadow:0 8px 30px #0008;animation:sl .26s}
@keyframes sl{from{transform:translateX(40px);opacity:0}to{transform:none;opacity:1}}
@media(prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style></head><body>
<header>
<svg class="shield" viewBox="0 0 24 24" fill="none"><path d="M12 2l8 3v6c0 5-3.4 8.5-8 11-4.6-2.5-8-6-8-11V5l8-3z" stroke="#22d3a0" stroke-width="1.6" fill="rgba(34,211,160,.08)"/><path d="M8.5 12l2.4 2.4 4.6-5" stroke="#00b9bd" stroke-width="1.6" stroke-linecap="round"/></svg>
<h1><b>UBDEN</b> uPenetrator <span class="pill">Windows-native</span></h1>
<span class="sub">Yetkili, kayıtlı ve sınırlı güvenlik değerlendirmesi &middot; https://www.ubden.com</span></header>
<main>
<div class="card" id="hostcard"><div class="eyebrow">Bu Makine — Test Bilgisayarı</div>
<div id="hostgrid" class="hostgrid"><div class="v">Bilgiler yükleniyor…</div></div></div>
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
<div><label>Es zamanli serit</label><input id="lanes" type="number" value="3" min="1" max="6"></div>
</div>
<label class="adapters" style="margin-top:12px"><input type="checkbox" id="defcred"> Varsayilan kimlik denemesi (opt-in, sinirli, kilitlenme-farkinda)</label>
<label class="adapters"><input type="checkbox" id="sqli"> SQL enjeksiyon testi — sqlmap (opt-in, YETKILI; sinirli: veri dokme/OS kabuk yok)</label>
<label class="adapters"><input type="checkbox" id="voip"> VoIP/SIP cihaz kesfi — sipvicious/svmap (opt-in)</label>
<div class="hint">sqlmap davetsiz (intrusive) bir testtir: yalnizca <b>Yetki referansi</b> girildiginde ve bu kutu isaretliyken calisir; web portu (80/443/8080/8443) acik kapsam ici adreslerde yururlur.</div>
<div id="adapters" class="adapters"><label>Ag adaptorleri yukleniyor...</label></div>
<div class="hint">Adaptor secimi kapsam guvenligi icindir: yalniz secilen adaptorden erisilebilen IP'ler taranir (tek host hedeflerinde). Yonetici yetkisi + Npcap ARP/MAC icin gereklidir.</div>
<details style="margin-top:14px"><summary style="cursor:pointer;color:var(--teal);font-family:'IBM Plex Mono',monospace">▸ Kimlikli / kurumsal testler (opsiyonel) — AD/LDAP · Web/Swagger · SSH</summary>
<div style="margin-top:12px">
<div class="eyebrow">Active Directory / LDAP</div>
<div class="row">
<div><label>Alan adı (domain)</label><input id="ad_domain" placeholder="ornek.local"></div>
<div><label>DC IP / ad</label><input id="ad_dc" placeholder="10.0.0.5"></div>
</div><div class="row">
<div><label>LDAP kullanıcı (salt-okunur)</label><input id="ad_user" placeholder="okuma@ornek.local"></div>
<div><label>LDAP parola</label><input id="ad_pass" type="password" placeholder="••••••"></div>
</div>
<label class="adapters"><input type="checkbox" id="ad_plain"> Şifreli LDAP yoksa düz metin LDAP'a (389) izin ver — kimlik bilgisi şifrelenmeden iletilir (opt-in)</label>
<div class="hint">Sıra: LDAPS 636 (sertifika doğrulanır) → LDAPS 636 (sertifika doğrulanmaz, self-signed için) → StartTLS 389. Çoğu DC'de self-signed sertifika bu fallback ile çözülür; düz metin yalnız bu kutu işaretliyse denenir.</div>
<button class="sec" type="button" onclick="testConn('ldap')">LDAP bağlantı testi</button> <span id="t_ldap" class="dim"></span>
<div class="eyebrow" style="margin-top:16px">Web uygulaması / API</div>
<div class="row">
<div><label>Giriş adresi (base URL)</label><input id="web_url" placeholder="https://uygulama.ornek.com"></div>
<div><label>Swagger / OpenAPI URL</label><input id="swagger_url" placeholder="https://.../swagger.json"></div>
</div>
<button class="sec" type="button" onclick="testConn('http')">Web bağlantı testi</button> <span id="t_http" class="dim"></span>
<div class="eyebrow" style="margin-top:16px">SSH (opsiyonel)</div>
<div class="row">
<div><label>SSH host</label><input id="ssh_host" placeholder="10.0.0.20"></div>
<div><label>SSH kullanıcı</label><input id="ssh_user" placeholder="test"></div>
<div><label>SSH parola</label><input id="ssh_pass" type="password" placeholder="••••••"></div>
</div>
<button class="sec" type="button" onclick="testConn('ssh')">SSH bağlantı testi</button> <span id="t_ssh" class="dim"></span>
<div class="eyebrow" style="margin-top:16px">Claude AI analist (opsiyonel)</div>
<div class="row">
<div><label>Claude API anahtarı</label><input id="claude_key" type="password" placeholder="sk-ant-… (bulgu triyajı için)"></div>
<div style="display:flex;align-items:end"><label style="display:flex;align-items:center;gap:8px;color:var(--ink)"><input type="checkbox" id="claude_raw" style="width:auto"> Ham kanıt gönder (aksi halde anonim özet)</label></div>
</div>
<label style="display:flex;align-items:center;gap:8px;color:var(--ink);margin-top:8px"><input type="checkbox" id="ai_actions" checked style="width:auto"> AI operatör takip kontrolleri çalıştırsın (allowlist: NSE/HTTP; kapsam içi, salt-okunur)</label>
<div class="hint">Anahtar verilirse tarama sonunda Claude otomatik triyaj/analiz üretir (raporda "AI analist taslağı"); anahtar yalnız bellekte kullanılır. Parolalar yalnız bu yerel oturumda bellekte kullanılır; rapora veya görev dosyasına yazılmaz. AD host domain'e üyeyse kimlik bilgisiz de yerel AD envanteri çekilir.</div>
</div></details>
<div style="margin-top:16px"><button id="go">YETKILIYIM &mdash; Taramayi baslat</button></div>
</div>
<div class="card" id="progress" style="display:none">
<div style="display:flex;justify-content:space-between;align-items:center">
<strong>Ilerleme</strong><span id="state" class="pill">calisiyor</span></div>
<div id="lanes"></div>
<div id="log"></div>
<div id="done" style="display:none;margin-top:12px"></div>
</div>
</main>
<script>
const T="__TOKEN__";
function kv(k,v){return `<div><div class="k">${esc(k)}</div><div class="v">${esc(v||"—")}</div></div>`;}
async function loadAdapters(){
 let d={};
 try{const r=await fetch("/api/adapters?t="+T);d=await r.json();}catch(e){}
 renderHost(d);
 const box=document.getElementById("adapters");box.innerHTML="";
 const ad=(d.adapters||[]).filter(a=>(a.addresses||[]).length);
 if(!ad.length){box.innerHTML="<div class='hint'>Adresli adaptör bulunamadı (köprü yoksa tarama yine çalışır).</div>";return;}
 ad.forEach(a=>{const ips=(a.addresses||[]).map(x=>x.address);
 const v4=ips.filter(x=>x.indexOf(":")<0).length;
 const kind=a.is_vpn?"VPN":"fiziksel";
 box.insertAdjacentHTML("beforeend",
 `<label class="adp"><input type="checkbox" class="adpk" value="${a.index}" ${/Up/i.test(a.status)?"checked":""}>`+
 `<span class="an">${esc(a.name)}</span>`+
 `<span class="ai">${esc(ips.slice(0,3).join(", ")||a.status)}</span>`+
 `<span class="ac">${ips.length} IP</span> <span class="kind">${kind}</span></label>`);});
}
function renderHost(d){const g=document.getElementById("hostgrid");
 if(!d||d.status!=="ok"){g.innerHTML="<div class='v'>Windows köprüsü yok; bilgiler kısıtlı.</div>";return;}
 const dom = d.part_of_domain ? `<span class="chip warn">Domain: ${esc(d.domain)}</span>`
   : (d.aad_joined ? `<span class="chip ok">Entra/AAD üyesi</span>` : `<span class="chip">Çalışma grubu</span>`);
 g.innerHTML=kv("Bilgisayar",d.fqdn||d.host)+kv("Aktif kullanıcı",d.active_user)+
 kv("İşletim sistemi",d.os_caption)+kv("Üretici / Model",(d.manufacturer||"")+" "+(d.model||""))+
 kv("CPU",d.cpu)+kv("Bellek",(d.memory_mb?Math.round(d.memory_mb)+" MB":""))+
 kv("Çalışma süresi",d.uptime)+kv("Toplam IPv4",d.ipv4_total)+
 `<div><div class="k">AD / katılım</div><div class="v">${dom} ${d.domain_role?('<span class="chip">'+esc(d.domain_role)+'</span>'):''}</div></div>`;
}
function lines(v){return v.split("\\n").map(s=>s.trim()).filter(Boolean);}
let JOB=null,timer=null;
async function start(){
 const body={client:c("client"),project:c("project"),authorization_reference:c("auth"),
 tester:c("tester"),targets:lines(v("targets")),exclusions:lines(v("exclusions")),
 profile:v("profile"),top_ports:v("top_ports"),max_rate:v("max_rate"),lanes:v("lanes"),
 default_cred_test:document.getElementById("defcred").checked,
 sql_injection_test:document.getElementById("sqli").checked,
 voip_scan:document.getElementById("voip").checked,
 ad_domain:c("ad_domain"),ad_dc:c("ad_dc"),ad_user:c("ad_user"),ad_pass:v("ad_pass"),
 ad_allow_plaintext:document.getElementById("ad_plain").checked,
 web_url:c("web_url"),swagger_url:c("swagger_url"),
 ssh_host:c("ssh_host"),ssh_user:c("ssh_user"),ssh_pass:v("ssh_pass"),
 claude_api_key:v("claude_key"),claude_raw:document.getElementById("claude_raw").checked,
 ai_actions:document.getElementById("ai_actions").checked,
 selected_interfaces:[...document.querySelectorAll(".adpk:checked")].map(x=>x.value)};
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
 renderLanes(d.lanes||{});
 document.getElementById("state").textContent=d.status;
 if(d.status==="done"||d.status==="error"){clearInterval(timer);
 document.getElementById("go").disabled=false;showDone(d);}
}
function renderLanes(lanes){const box=document.getElementById("lanes");
 const ids=Object.keys(lanes).sort();
 if(!ids.length){box.innerHTML="";return;}
 box.innerHTML=ids.map(id=>{const l=lanes[id];const done=l.status==="bitti";
 const issues=l.issues?`<b>${l.issues} sorun</b>`:"";
 return `<div class="lane"><span class="id">${esc(id)}</span>`+
 `<span class="tgt">${esc(l.target||"")}</span>`+
 `<span class="step">${esc(l.step||"")}</span>`+
 `<span class="cnt">${l.steps||0} adim ${issues}</span>`+
 `<span class="badge ${done?"done":"run"}">${done?"bitti":"calisiyor"}</span></div>`;}).join("");
}
const RISKY=new Set([21,23,135,139,445,3389,5900,1433,3306,5432,6379,9200,161]);
async function showDone(d){const el=document.getElementById("done");el.style.display="block";
 const s=(d.result&&d.result.device_summary)||{};
 let out="";
 if(d.result&&d.result.report_html){
 out+=`<p><a href="/r/REPORT.html?t=${T}&job=${JOB}" target="_blank">HTML raporu aç</a> &middot; `;
 out+=`<a href="/r/YONETICI_OZETI.pdf?t=${T}&job=${JOB}" target="_blank">Yönetici özeti (PDF)</a> &middot; `;
 out+=`<a href="/r/TEKNIK_RAPOR.pdf?t=${T}&job=${JOB}" target="_blank">Teknik rapor (PDF)</a> &middot; `;
 out+=`<a href="#" onclick="openFolder();return false;">Klasörü aç</a></p>`;}
 else{out+=`<p class="l-warn">Rapor üretilemedi; ilerleme kaydını inceleyin.</p>`;}
 el.innerHTML=out;
 // Rich device results from DEVICE_INVENTORY.json (category-grouped, like the report).
 try{
 const r=await fetch(`/r/DEVICE_INVENTORY.json?t=${T}&job=${JOB}`);const inv=await r.json();
 const devs=inv.devices||[];
 const cats=Object.keys(inv.categories||{}).length;
 const openPorts=devs.reduce((n,x)=>n+((x.ports||[]).length),0);
 el.insertAdjacentHTML("beforeend",
  `<div class="statrow">`+
  stat(inv.host_count||devs.length,"Cihaz")+stat(inv.mac_count||0,"MAC görüldü")+
  stat(cats,"Kategori")+stat(openPorts,"Açık port")+stat(inv.unknown_count||0,"Sınıflandırılmamış")+`</div>`);
 el.insertAdjacentHTML("beforeend",deviceTable(devs));
 toast(`${devs.length} cihaz, ${inv.mac_count||0} MAC tespit edildi`);
 }catch(e){}
}
function stat(n,l){return `<div class="stat"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`;}
function deviceTable(devs){
 if(!devs.length)return "";
 const order=["firewall","router","switch","ap","hypervisor","server","db","nas","printer","camera","voip","pc","mobile","iot","ups","unknown"];
 const groups={};devs.forEach(x=>{(groups[x.category_key||"unknown"]=groups[x.category_key||"unknown"]||[]).push(x);});
 let rows="";
 const keys=order.filter(k=>groups[k]).concat(Object.keys(groups).filter(k=>order.indexOf(k)<0));
 keys.forEach(k=>{const g=groups[k];const label=(g[0].category||k);
  rows+=`<tr class="catrow"><td colspan="5">${esc(label)} &middot; ${g.length}</td></tr>`;
  g.forEach(x=>{const pct=x.confidence_pct||0;
   const ports=(x.ports||[]).map(p=>`<span class="pchip ${RISKY.has(+p.port)?"risk":""}">${esc(p.port)}</span>`).join("")||'<span class="dim">—</span>';
   rows+=`<tr><td><code>${esc(x.ip)}</code></td><td>${esc(x.display_name||(x.hostnames||[])[0]||"—")}</td>`+
   `<td>${esc(x.vendor||"—")}<br><span class="dim mac">${esc(x.mac||"görülmedi")}</span></td>`+
   `<td>${ports}</td><td><span class="cm"><i style="width:${Math.max(4,Math.min(100,pct))}%"></i></span> ${pct}%</td></tr>`;});
 });
 return `<h3 style="margin-top:16px">Cihaz envanteri</h3><table class="dtbl"><thead><tr><th>IP</th><th>Ad</th><th>Üretici / MAC</th><th>Portlar</th><th>Güven</th></tr></thead><tbody>${rows}</tbody></table>`;
}
function toast(msg){const t=document.createElement("div");t.className="toast";t.textContent=msg;
 document.body.appendChild(t);setTimeout(()=>t.remove(),4200);}
async function testConn(kind){
 const out=document.getElementById("t_"+kind);out.textContent="test ediliyor…";out.style.color="";
 let body={};
 if(kind==="ldap")body={dc:c("ad_dc"),domain:c("ad_domain"),user:c("ad_user"),password:v("ad_pass"),allow_plaintext:document.getElementById("ad_plain").checked};
 else if(kind==="http")body={url:c("web_url")||c("swagger_url")};
 else if(kind==="ssh")body={host:c("ssh_host"),user:c("ssh_user"),password:v("ssh_pass")};
 try{const r=await fetch("/api/test/"+kind+"?t="+T,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
 const d=await r.json();
 out.textContent=(d.ok?"✔ ":"✕ ")+(d.detail||(d.ok?"başarılı":"başarısız"));
 out.style.color=d.ok?"var(--green)":"var(--red)";
 }catch(e){out.textContent="✕ istek hatası";out.style.color="var(--red)";}
}
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
        if parsed.path.startswith("/api/test/"):
            length = int(self.headers.get("Content-Length", "0") or "0")
            try:
                body = json.loads(self.rfile.read(length).decode("utf-8")) if length else {}
            except (ValueError, UnicodeDecodeError):
                return self._send(400, json.dumps({"ok": False, "detail": "bad_json"}))
            kind = parsed.path[len("/api/test/"):]
            return self._send(200, json.dumps(win_scan.test_connection(kind, body if isinstance(body, dict) else {})))
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
    # Keep the test machine awake for the whole server session (covers idle time
    # between scans too); best-effort, no-op off Windows.
    try:
        import power_manager
        power_manager.stay_awake()
    except Exception:
        power_manager = None
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
        try:
            if power_manager:
                power_manager.release()
        except Exception:
            pass


if __name__ == "__main__":
    serve()
