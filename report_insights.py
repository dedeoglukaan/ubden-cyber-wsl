"""Offline UBDEN report enrichment. Never changes findings or sends network traffic."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re

from assessment_coverage import build_coverage


TECHNIQUES = {
    "NET-DISC": ("T1018", "Remote System Discovery"),
    "NET-PORT": ("T1046", "Network Service Discovery"),
    "AD-READ": ("T1087.002", "Domain Account Discovery"),
}
FINDING_TECHNIQUES = {
    "kerberoast": ("T1558.003", "Kerberoasting"),
    "asrep_roast": ("T1558.004", "AS-REP Roasting"),
    "adcs_esc": ("T1649", "Steal or Forge Authentication Certificates"),
    "cracked_credential": ("T1110.002", "Password Cracking"),
}
# Starting vectors for analyst review. A type or real context is needed; port exposure alone is insufficient.
CVSS_VECTORS = {
    "kerberoast": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "asrep_roast": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "cracked_credential": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
}
_HASH_MODES = {("tgs", 23): 13100, ("tgs", 17): 19600, ("tgs", 18): 19700,
               ("asrep", 23): 18200, ("asrep", 17): 19800, ("asrep", 18): 19900}
_SEVERITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def cvss31(vector: str) -> float:
    """CVSS v3.1 base score for a complete suggested vector."""
    parts = dict(re.findall(r"(?:^|/)(AV|AC|PR|UI|S|C|I|A):([A-Z])", vector))
    if not vector.startswith("CVSS:3.1/") or set(parts) != {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}:
        raise ValueError("Incomplete CVSS:3.1 vector")
    av = {"N": .85, "A": .62, "L": .55, "P": .2}[parts["AV"]]
    ac = {"L": .77, "H": .44}[parts["AC"]]
    pr = ({"N": .85, "L": .68, "H": .5} if parts["S"] == "C" else
          {"N": .85, "L": .62, "H": .27})[parts["PR"]]
    ui = {"N": .85, "R": .62}[parts["UI"]]
    c, i, a = ({"H": .56, "L": .22, "N": 0}[parts[k]] for k in ("C", "I", "A"))
    iss = 1 - (1-c)*(1-i)*(1-a)
    impact = (7.52*(iss-.029)-3.25*(iss-.02)**15 if parts["S"] == "C" else 6.42*iss)
    if impact <= 0:
        return 0.0
    exploitability = 8.22*av*ac*pr*ui
    import math
    raw = min((impact+exploitability)*(1.08 if parts["S"] == "C" else 1), 10)
    return math.ceil(round(raw, 5)*10)/10


def classify_hash_samples(root: Path) -> dict:
    """Classify supplied hashes without storing any hash or account value in report data."""
    folder = root / "offline_samples"
    files = []
    if folder.is_dir() and not folder.is_symlink():
        for path in sorted(folder.iterdir())[:30]:
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in (".hash", ".txt"):
                continue
            if path.stat().st_size > 25_000_000:
                continue
            counts = Counter()
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for line in stream:
                    digest.update(line)
                    if len(line) > 200_000:
                        continue
                    match = re.search(rb"\$krb5(tgs|asrep)\$(17|18|23)\$", line, re.I)
                    if match:
                        kind, etype = match.group(1).decode().lower(), int(match.group(2))
                        counts[f"{kind.upper()} etype {etype} / hashcat {_HASH_MODES[(kind, etype)]}"] += 1
                    elif re.fullmatch(rb"[0-9a-fA-F]{32}", line.strip()):
                        counts["32 hex karakter / algoritma doğrulanmadı"] += 1
            files.append({"file": str(path.relative_to(root)), "sha256": digest.hexdigest(),
                          "counts": dict(counts), "recognized": sum(counts.values())})
    return {"status": "classified" if files else "no_samples", "files": files,
            "note": "Sınıflandırma çevrimdışıdır; parola denemesi veya kırma işlemi yapılmaz. Ham hash değerleri rapora alınmaz."}


def build(root: Path, meta: dict, steps: list, findings: list, review: dict) -> dict:
    ledger = build_coverage(root, meta, steps, review)
    techniques = []
    for control in ledger["controls"]:
        mapped = TECHNIQUES.get(control["id"])
        if mapped and control["status"] in ("çalıştı", "kısmi"):
            techniques.append({"techniqueID": mapped[0], "techniqueName": mapped[1],
                               "source": "test yöntemi", "status": control["status"],
                               "evidence": control.get("evidence", [])[:3]})
    suggestions = []
    for finding in findings:
        kind = str(finding.get("type", ""))
        mapped = FINDING_TECHNIQUES.get(kind)
        if mapped:
            techniques.append({"techniqueID": mapped[0], "techniqueName": mapped[1],
                               "source": "bulgu adayı", "status": finding.get("status", "taslak"),
                               "evidence": [finding.get("evidence", "")] if finding.get("evidence") else []})
        vector = CVSS_VECTORS.get(kind)
        if vector:
            suggestions.append({"finding_id": finding.get("id", ""), "title": finding.get("title", ""),
                                "vector": vector, "base_score": cvss31(vector),
                                "status": "analist incelemesi gerekli",
                                "note": "Öneri yalnız tip eşleşmesine dayanır; erişim, etki ve ortam metrikleri doğrulanmalıdır."})
    actions = {}
    for finding in findings:
        if finding.get("status") != "doğrulandı":
            continue
        fix = str(finding.get("recommendation") or "Analist düzeltme önerisi bekleniyor").strip()
        group = actions.setdefault(fix, {"recommendation": fix, "findings": [], "assets": set(), "priority": 0})
        group["findings"].append(str(finding.get("id", "")))
        group["assets"].add(str(finding.get("asset", "")))
        group["priority"] = max(group["priority"], _SEVERITY.get(finding.get("severity"), 0))
    roadmap = sorted(({**group, "assets": sorted(group["assets"])} for group in actions.values()),
                     key=lambda item: (-item["priority"], -len(item["findings"]), item["recommendation"]))
    return {"schema": 1, "product": "UBDEN®", "attck": techniques,
            "cvss_suggestions": suggestions, "remediation": roadmap,
            "draft_count": sum(f.get("status") == "taslak" for f in findings),
            "hash_samples": classify_hash_samples(root),
            "meaning": "ATT&CK test yöntemi eşlemesi saldırı başarısı değildir. CVSS değerleri öneridir. Düzeltme sırası yalnız analistçe doğrulanmış bulguları içerir."}


def _atomic_json(path: Path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def write(root: Path, meta: dict, steps: list, findings: list, review: dict) -> dict:
    result = build(root, meta, steps, findings, review)
    _atomic_json(root / "UBDEN_INSIGHTS.json", result)
    layer = {"name": "UBDEN® test tekniği eşlemesi", "domain": "enterprise-attack", "version": "4.5",
             "description": result["meaning"], "techniques": [
                 {"techniqueID": item["techniqueID"], "color": "#167c94",
                  "comment": f"{item['source']}: {item['status']}"} for item in result["attck"]]}
    _atomic_json(root / "ATTACK_LAYER.json", layer)
    lines = ["# UBDEN® Düzeltme Yol Haritası", "",
             "Yalnız analist tarafından doğrulanmış bulgular önceliklendirilir.", "",
             "| Öncelik | Bulgu | Varlık | Düzeltme |", "|---|---|---|---|"]
    for index, item in enumerate(result["remediation"], 1):
        cells = (str(index), ", ".join(item["findings"]), ", ".join(item["assets"][:6]),
                 item["recommendation"])
        lines.append("| " + " | ".join(re.sub(r"[|\r\n]", " ", value)[:280] for value in cells) + " |")
    if not result["remediation"]:
        lines.append("| — | — | — | Henüz analistçe doğrulanmış bulgu yok. |")
    lines += ["", f"Analist incelemesi bekleyen aday bulgu: {result['draft_count']}.",
              "", "CVSS taslakları: `UBDEN_INSIGHTS.json`; ATT&CK katmanı: `ATTACK_LAYER.json`."]
    temporary = root / "REMEDIATION_ROADMAP.md.tmp"
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(root / "REMEDIATION_ROADMAP.md")
    return result
