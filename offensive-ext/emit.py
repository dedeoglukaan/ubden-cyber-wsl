"""Fold offensive-ext findings back into UBDEN's report.

Maps our normalized+scored findings to UBDEN's finding schema and writes them into
`review.json['findings']`.

EVERYTHING WE WRITE IS A DRAFT ('taslak'), ALWAYS. In UBDEN a finding becomes 'doğrulandı'
only when a human sets it in analyst_review.edit_finding and signs `reviewed_by`; the
approval prompt makes them type ONAYLIYORUM first. A machine cannot satisfy that, and
promoting our own output would put "Doğrulayan analist" on a client PDF nobody read. We used
to self-promote whenever the evidence hash matched -- but we compute that hash ourselves, so
it checked our arithmetic, not our work. The analyst promotes; we only ever propose.

`reviewed_by` is likewise left EMPTY unless the operator passes --reviewer / $UBDEN_REVIEWER.
An unset signature must read as unsigned, not as a plausible-looking default.

Adding findings also RETRACTS any prior sign-off on the file (see emit_findings): a review.json
approved before our findings existed has not approved them.

After writing, run `report_v2.py <run_dir>` to regenerate the PDFs/HTML with our findings.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time

# report_v2.py mints its own ids as PX-NNN when a finding arrives without one, so ours must
# not be PX- too: two different findings answering to PX-001 is a report that contradicts itself.
ID_PREFIX = "OFF-"

_REQUIRED = ("title", "asset", "description", "impact", "recommendation", "reproduction", "reviewed_by")

# The analyst signature printed in the client PDF as "Doğrulayan analist". Empty by default and
# it stays empty: a default here would be a machine signing a human's name. Set --reviewer (or
# $UBDEN_REVIEWER) to sign, and note that signing still does not make a finding verified -- only
# a human working through analyst_review.py does that.
DEFAULT_REVIEWER = os.environ.get("UBDEN_REVIEWER", "")


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def to_ubden_finding(f: dict, run_dir: str, idx: int, reviewer: str = "") -> dict:
    """Map a normalized offensive-ext finding to UBDEN's finding schema."""
    evidence_rel = f.get("evidence", "")
    evidence_abs = os.path.join(run_dir, evidence_rel) if evidence_rel else ""
    # Mirror UBDEN's verified_finding/evidence() gate so we never mark 'verified' something report_v2
    # will silently demote: real file, no symlink, not absolute, no '..', <= 25 MB.
    have_evidence = bool(evidence_rel) and os.path.isfile(evidence_abs) and not os.path.islink(evidence_abs) \
        and not os.path.isabs(evidence_rel) and ".." not in evidence_rel.replace("\\", "/").split("/")
    if have_evidence:
        try:
            have_evidence = os.path.getsize(evidence_abs) <= 25_000_000  # match analyst_review.evidence() exactly
        except OSError:
            have_evidence = False
    reproduction = (f.get("reproduction")
                    or (f"Kanıt dosyası: {evidence_rel}. " if evidence_rel else "")
                    + f.get("description", ""))
    finding = {
        "id": f"{ID_PREFIX}{idx:03d}",
        "title": f.get("title", "Başlıksız bulgu"),
        "severity": (f.get("severity") or "info").lower(),
        "status": "taslak",
        "asset": f.get("asset", ""),
        "affected_assets": f.get("affected_assets", []),
        "description": f.get("description", ""),
        "impact": f.get("impact", ""),
        "recommendation": f.get("recommendation", ""),
        "evidence": evidence_rel,
        "evidence_sha256": _sha256(evidence_abs) if have_evidence else "",
        "evidence_items": [],
        "reference": f.get("reference", ""),
        "cvss": f.get("cvss", ""),
        "reproduction": reproduction,
        "reviewed_by": reviewer or DEFAULT_REVIEWER,
        "category": f.get("category", "Active Directory"),
        "access_point": f.get("access_point", "İç Ağ"),
        "user_profile": f.get("user_profile", "Kurum Çalışanı / düşük yetkili"),
        "root_cause": f.get("root_cause", ""),
        "remediation_priority": f.get("remediation_priority", ""),
        "retest_status": "",
        "disposition_reason": "",
        "attack_technique": f.get("technique", ""),
        "attack_technique_name": f.get("attack_technique_name", ""),
    }
    # NO promotion to "doğrulandı" here, deliberately -- see the module docstring. The status set
    # further up stays 'taslak' and the analyst is the only one who can change it.
    return finding


def _blank_review() -> dict:
    return {"schema": 3, "analyst_summary": "", "reviewer": "",
            "approved_at": "", "cases": [], "findings": []}


def load_review(run_dir: str) -> dict:
    """Load review.json, preserving whatever the analyst already put there.

    A file that exists but does not parse is NEVER discarded: it is renamed aside first. It holds
    the analyst's cases, notes and dispositions, and starting from a blank dict on top of it would
    delete hours of somebody's work to save one error message.
    """
    path = os.path.join(run_dir, "review.json")
    if not os.path.exists(path):
        return _blank_review()
    try:
        data = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        keep = f"{path}.corrupt-{int(time.time())}"
        try:
            os.replace(path, keep)
            where = keep
        except OSError:
            where = "could not be renamed -- DO NOT let anything overwrite it"
        print(f"[emit] WARNING: review.json is unreadable ({exc}). Preserved at {where}; "
              f"continuing with a fresh one. Anything the analyst had recorded is in that file.",
              file=sys.stderr)
        return _blank_review()
    if not isinstance(data, dict):
        keep = f"{path}.corrupt-{int(time.time())}"
        try:
            os.replace(path, keep)
        except OSError:
            keep = "could not be renamed"
        print(f"[emit] WARNING: review.json is not an object. Preserved at {keep}.", file=sys.stderr)
        return _blank_review()
    data.setdefault("findings", [])
    return data


def _next_index(review: dict) -> int:
    """First OFF- number not already used in the file.

    Not len(findings): UBDEN numbers its own findings separately, and a re-run that adds two more
    must not reuse an id an earlier run already handed out.
    """
    used = set()
    for f in review.get("findings", []):
        if isinstance(f, dict) and str(f.get("id", "")).startswith(ID_PREFIX):
            try:
                used.add(int(str(f["id"])[len(ID_PREFIX):]))
            except ValueError:
                continue
    n = 1
    while n in used:
        n += 1
    return n


def emit_findings(run_dir: str, findings: list[dict], reviewer: str = "") -> dict:
    """Write findings into review.json as DRAFTS (dedupe by title). Returns counts.

    Writing retracts any existing sign-off on the file. `assess()` reads `reviewer` +
    `approved_at` to decide whether the run is approved; leaving them in place after appending
    findings nobody has read would report machine output as analyst-approved.
    """
    review = load_review(run_dir)
    existing = {f.get("title") for f in review.get("findings", []) if isinstance(f, dict)}
    idx = _next_index(review)
    added = with_evidence = 0
    for f in findings:
        if f.get("title") in existing:
            continue
        uf = to_ubden_finding(f, run_dir, idx, reviewer)
        review["findings"].append(uf)
        existing.add(uf["title"])
        idx += 1
        added += 1
        if uf["evidence_sha256"]:
            with_evidence += 1

    if added and (review.get("reviewer") or review.get("approved_at")):
        print(f"[emit] NOTE: retracting the previous sign-off ({review.get('reviewer') or '?'}) -- "
              f"{added} new finding(s) were added after it and have not been reviewed.",
              file=sys.stderr)
        review["reviewer"] = ""
        review["approved_at"] = ""

    os.umask(0o077)
    rpath = os.path.join(run_dir, "review.json")
    # Atomic: a crash mid-write must not leave a truncated analyst ledger. Same tmp+replace
    # UBDEN's own analyst_review.save() uses.
    tmp = rpath + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(review, fh, indent=2, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, rpath)
    try:
        os.chmod(rpath, 0o600)  # review.json can hold sensitive finding detail
    except OSError:
        pass
    # No "verified" count: everything we write is a draft by construction. `with_evidence` is the
    # number an analyst can promote without collecting anything further.
    return {"added": added, "draft": added, "with_evidence": with_evidence,
            "total_in_review": len(review["findings"])}


def regenerate_report(run_dir: str) -> int:
    """Re-run UBDEN's report_v2.py to fold our findings into the PDFs/HTML.

    report_v2.py needs reportlab, which install.sh puts in /opt/ubden-cyber/.venv — NOT in system
    python. So prefer the installed copy+venv; fall back to a report_v2.py sitting next to offensive-ext."""
    installed_report = "/opt/ubden-cyber/report_v2.py"
    installed_py = "/opt/ubden-cyber/.venv/bin/python"
    parent_report = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "report_v2.py")
    tries = []
    if os.path.exists(installed_report):
        tries.append((installed_py if os.path.exists(installed_py) else sys.executable, installed_report))
    if os.path.exists(parent_report):
        tries.append((sys.executable, parent_report))
    if not tries:
        print("[emit] report_v2.py not found (checked /opt/ubden-cyber and offensive-ext parent); "
              "findings ARE in review.json — run report_v2.py manually to render.")
        return 1
    py, rep = tries[0]
    rc = subprocess.run([py, rep, run_dir]).returncode
    if rc != 0:
        print(f"[emit] report_v2.py exited {rc}; findings are still in review.json (re-run manually).")
    return rc


def _self_test() -> int:
    ok = 0

    def check(name, cond):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
        if cond:
            ok += 1

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "offensive-ext"))
        ev = os.path.join(d, "offensive-ext", "kerberoast.txt")
        open(ev, "w").write("$krb5tgs$23$*svc_sql$CORP.LOCAL$...")
        f_with = {"type": "kerberoast", "title": "Kerberoastable: svc_sql", "asset": "CORP\\svc_sql",
                  "description": "d", "impact": "i", "recommendation": "r", "root_cause": "rc",
                  "severity": "high", "cvss": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
                  "evidence": "offensive-ext/kerberoast.txt", "technique": "T1558.003"}
        f_noev = {"type": "asrep_roast", "title": "AS-REP: jdoe", "asset": "CORP\\jdoe",
                  "description": "d", "impact": "i", "recommendation": "r", "severity": "high",
                  "evidence": "offensive-ext/missing.txt"}
        res = emit_findings(d, [f_with, f_noev])
        check("both findings added", res["added"] == 2)
        check("both written as drafts", res["draft"] == 2)
        check("evidence counted separately from status", res["with_evidence"] == 1)
        check("no verified count is reported at all", "verified" not in res)

        review = json.load(open(os.path.join(d, "review.json")))
        byid = {f["id"]: f for f in review["findings"]}
        v = byid["OFF-001"]
        check("id prefix does not collide with report_v2's PX-", set(byid) == {"OFF-001", "OFF-002"})
        check("finding with good evidence is STILL taslak", v["status"] == "taslak")
        check("finding without evidence is taslak", byid["OFF-002"]["status"] == "taslak")
        check("evidence_sha256 matches file", v["evidence_sha256"] == _sha256(ev))
        check("reviewed_by is EMPTY when unsigned", v["reviewed_by"] == "")
        # UBDEN must agree it is not verified -- that is the invariant this file exists to respect.
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        try:
            import pathlib
            import analyst_review
            check("UBDEN verified_finding() rejects it",
                  analyst_review.verified_finding(pathlib.Path(d), v) is False)
        except ImportError:
            check("UBDEN verified_finding() rejects it (skipped: analyst_review not importable)", True)

        check("explicit --reviewer is honoured",
              to_ubden_finding(f_with, d, 9, "Jane")["reviewed_by"] == "Jane")

        # idempotent: re-emit same titles doesn't duplicate
        res2 = emit_findings(d, [f_with, f_noev])
        check("dedupe by title on re-emit", res2["added"] == 0)

        # a prior sign-off is retracted when new findings land on top of it
        rp = os.path.join(d, "review.json")
        rev = json.load(open(rp))
        rev["reviewer"], rev["approved_at"] = "Jane", "2026-09-28T00:00:00"
        json.dump(rev, open(rp, "w"))
        f_new = dict(f_with, title="Kerberoastable: svc_web", asset="CORP\\svc_web")
        emit_findings(d, [f_new])
        rev2 = json.load(open(rp))
        check("sign-off retracted after new findings", not rev2["reviewer"] and not rev2["approved_at"])
        check("new id does not reuse an existing one",
              sorted(f["id"] for f in rev2["findings"]) == ["OFF-001", "OFF-002", "OFF-003"])

    with tempfile.TemporaryDirectory() as d2:
        # a corrupt review.json is preserved, never silently replaced
        rp = os.path.join(d2, "review.json")
        open(rp, "w").write("{ this is not json")
        emit_findings(d2, [])
        kept = [x for x in os.listdir(d2) if x.startswith("review.json.corrupt-")]
        check("corrupt review.json preserved aside", len(kept) == 1)
        check("its bytes are intact", open(os.path.join(d2, kept[0])).read() == "{ this is not json")
        check("no leftover .tmp file", not any(x.endswith(".tmp") for x in os.listdir(d2)))

    total = 17
    print(f"\n{ok}/{total} checks passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(_self_test() if "--self-test" in sys.argv else 0)
