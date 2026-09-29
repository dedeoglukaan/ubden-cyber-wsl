"""Read and normalize an UBDEN report without changing its source evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote
import xml.etree.ElementTree as ET


ROOT_JSON = (
    "engagement.json", "DEVICE_INVENTORY.json", "ANALIST_GOREV_RAPORU.json",
    "ASSESSMENT_COVERAGE.json", "AD_ASSESSMENT.json", "UBDEN_CORRELATION.json",
    "UBDEN_CVE.json", "UBDEN_TECH_PROFILE.json", "UBDEN_INSIGHTS.json",
    "UBDEN_OSINT.json", "WIFI_SCAN.json", "UBDEN_EXECUTION.json",
    "AI_FINDINGS.json", "AI_OPERATOR.json", "ATTACK_LAYER.json",
    "HOST_CAPABILITIES.json", "steps.json",
)
FINDING_STATUSES = ("taslak", "inceleniyor", "doğrulandı", "yanlış pozitif", "giderildi")
TASK_STATUSES = ("bekliyor", "devam ediyor", "tamamlandı", "engellendi")
PDF_NAMES = ("YONETICI_OZETI.pdf", "TEKNIK_RAPOR.pdf", "ANALIST_GOREV_RAPORU.pdf")
MAX_PREVIEW = 512_000


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_report(root: Path) -> bool:
    try:
        data = json.loads((root / "engagement.json").read_text(encoding="utf-8-sig"))
        return isinstance(data, dict) and bool(data.get("id")) and any(
            (root / name).is_file() for name in ("REPORT.html", "DEVICE_INVENTORY.json", "steps.json")
        )
    except (OSError, ValueError, TypeError):
        return False


def safe_report_path(root: Path, relative: str, *, must_exist: bool = True) -> Path:
    """Resolve evidence paths and reject absolute, hidden state and traversal paths."""
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise ValueError("Geçersiz dosya yolu")
    value = unquote(relative).replace("\\", "/")
    if value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError("Mutlak dosya yolu kullanılamaz")
    parts = Path(value).parts
    if any(part in ("..", ".webui", "webui") for part in parts):
        raise ValueError("Rapor dışındaki dosya erişilemez")
    target = (root / value).resolve()
    try:
        target.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError("Rapor dışındaki dosya erişilemez") from exc
    if must_exist and not target.is_file():
        raise ValueError("Kanıt dosyası bulunamadı")
    return target


class FindingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.findings: list[dict] = []
        self.current: dict | None = None
        self.depth = 0
        self.capture: str | None = None
        self.text: list[str] = []
        self.skip_links = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if tag == "section" and "finding" in (attributes.get("class") or "").split():
            self.current = {"id": "", "title": "", "severity": "", "status": "taslak",
                            "source": "", "asset": "", "cwe": "", "description": "",
                            "impact": "", "remediation": "", "evidence": []}
            self.depth = 1
            return
        if self.current is None:
            return
        if tag == "section":
            self.depth += 1
        if tag in ("h3", "p") and self.capture is None:
            self.capture, self.text = tag, []
            if tag == "p":
                self.skip_links = attributes.get("class") in ("review-evidence", "retest-evidence")
        if tag == "a":
            href = attributes.get("href") or ""
            if not self.skip_links and href and not href.startswith(("#", "http:", "https:", "mailto:")):
                self.current["evidence"].append(href.replace("\\", "/"))

    def handle_data(self, data: str) -> None:
        if self.current is not None and self.capture is not None:
            self.text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if self.current is None:
            return
        if tag == self.capture:
            value = " ".join("".join(self.text).split())
            if tag == "h3":
                match = re.match(r"(OBS-\d+)\s*[·\-]\s*(.*)", value)
                if match:
                    self.current["id"], self.current["title"] = match.groups()
            else:
                if value.startswith("Şiddet:"):
                    self.current["severity"] = value.split("Şiddet:", 1)[1].split("·", 1)[0].strip()
                    verified = re.search(r"Doğrulama:\s*([^·]+)", value)
                    if verified:
                        self.current["status"] = verified.group(1).strip()
                else:
                    labels = {"Kaynak:": "source", "Durum:": "status", "Varlık:": "asset",
                              "CWE sınıfı:": "cwe", "Açıklama:": "description",
                              "İş etkisi:": "impact", "Düzeltme önerisi:": "remediation"}
                    for label, key in labels.items():
                        if value.startswith(label):
                            self.current[key] = value[len(label):].strip()
                            break
            self.capture, self.text = None, []
            self.skip_links = False
        if tag == "section":
            self.depth -= 1
            if self.depth == 0:
                if self.current.get("id"):
                    self.current["evidence"] = list(dict.fromkeys(self.current["evidence"]))
                    self.findings.append(self.current)
                self.current = None


def load_findings(root: Path) -> list[dict]:
    source = root / "REPORT.html"
    if not source.is_file():
        return []
    parser = FindingParser()
    parser.feed(source.read_text(encoding="utf-8-sig", errors="replace").replace("\x00", ""))
    return parser.findings


def load_reviews(root: Path) -> dict:
    path = root / ".webui" / "review.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return {"schema": 1, "engagement_id": "", "findings": {}, "tasks": {}, "history": []}


def _json(root: Path, name: str, errors: list[str]):
    path = root / name
    if not path.is_file():
        errors.append(f"{name}: eksik")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError) as exc:
        errors.append(f"{name}: okunamadı ({exc})")
        return None


def file_manifest(root: Path) -> dict:
    expected: dict[str, str] = {}
    sums = root / "SHA256SUMS.txt"
    if sums.is_file():
        for line in sums.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            hash_value, sep, rel = line.partition("  ")
            if sep and re.fullmatch(r"[0-9a-fA-F]{64}", hash_value):
                expected[rel.lstrip("*").replace("\\", "/")] = hash_value.lower()
    files = []
    states = Counter()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if rel.startswith(("webui/", ".webui/", ".playwright-cli/")) or rel.split("/", 1)[0].startswith("ubden-pdf-path-"):
            continue
        if rel == "SHA256SUMS.txt":
            state = "manifest"
        elif rel in expected:
            state = "eşleşiyor" if sha256(path) == expected[rel] else "uyuşmuyor"
            states[state] += 1
        else:
            state = "listede yok"
            states[state] += 1
        files.append({"path": rel, "name": path.name, "size": path.stat().st_size,
                      "type": path.suffix.lower() or "dosya", "sha_status": state})
    missing = [name for name in expected if not (root / name).is_file()]
    states["eksik"] = len(missing)
    return {"files": files, "hash_counts": dict(states), "missing_hash_files": missing,
            "listed_count": len(expected)}


def raw_summary(root: Path) -> list[dict]:
    result = []
    targets = root / "targets"
    if not targets.is_dir():
        return result
    for folder in sorted(targets.iterdir()):
        if not folder.is_dir():
            continue
        row = {"target": folder.name, "files": 0, "types": {}, "scans": []}
        for path in folder.rglob("*"):
            if not path.is_file():
                continue
            row["files"] += 1
            suffix = path.suffix.lower() or "other"
            row["types"][suffix] = row["types"].get(suffix, 0) + 1
            if suffix == ".xml":
                try:
                    doc = ET.parse(path).getroot()
                    row["scans"].append({"path": path.relative_to(root).as_posix(),
                                         "hosts": len(doc.findall("host"))})
                except ET.ParseError:
                    row["scans"].append({"path": path.relative_to(root).as_posix(), "error": "XML okunamadı"})
        result.append(row)
    return result


def report_signature(root: Path) -> str:
    h = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if relative.startswith(("webui/", ".webui/", ".playwright-cli/")) or relative.split("/", 1)[0].startswith("ubden-pdf-path-"):
            continue
        h.update(relative.encode("utf-8"))
        h.update(sha256(path).encode("ascii"))
    return h.hexdigest()


def load_report(root: Path) -> dict:
    if not is_report(root):
        raise ValueError("Lütfen Pentest Raporu seçin")
    errors: list[str] = []
    data = {name.removesuffix(".json"): _json(root, name, errors) for name in ROOT_JSON}
    findings = load_findings(root)
    reviews = load_reviews(root)
    inventory = data.get("DEVICE_INVENTORY") or {}
    tasks = (data.get("ANALIST_GOREV_RAPORU") or {}).get("tasks", [])
    steps = data.get("steps") or []
    coverage = data.get("ASSESSMENT_COVERAGE") or {}
    files = file_manifest(root)
    confirmed = sum(1 for item in findings if (reviews.get("findings", {}).get(item["id"], {})
                    .get("status", item.get("status")) == "doğrulandı"))
    warnings = []
    if not (data.get("UBDEN_OSINT") or {}).get("available", False):
        warnings.append("OSINT kullanılamaz; kaynakta görünen insan skoru doğrulanmış ölçüm değildir.")
    credential_confirmed = any(
        "kimlik bilgisi" in item.get("title", "").lower() and
        reviews.get("findings", {}).get(item["id"], {}).get("status", item.get("status")) == "doğrulandı"
        for item in findings)
    if not credential_confirmed and (data.get("UBDEN_CORRELATION") or {}).get("correlations"):
        warnings.append("Korelasyon metnindeki doğrulanmış kimlik bilgisi ifadesi, analistçe doğrulanmış bulgu kaydıyla desteklenmiyor.")
    if (data.get("AI_OPERATOR") or {}).get("findings", 0) == 0:
        warnings.append("AI bulgu kaydı yok; otomatik gözlemler analist onayı bekliyor.")
    manifest_files = files["files"]
    overview = {
        "hosts": len(inventory.get("devices", [])), "findings": len(findings),
        "confirmed": confirmed, "tasks": len(tasks), "steps": len(steps),
        "severity": dict(Counter(x.get("severity", "Bilinmiyor") for x in findings)),
        "step_status": dict(Counter(x.get("status", "bilinmiyor") for x in steps)),
        "coverage": coverage.get("counts", {}), "files": len(manifest_files),
        "cve_candidates": sum(len(x.get("cves", [])) for x in (data.get("UBDEN_CVE") or {}).get("items", [])),
    }
    return {"root_name": root.name, "signature": report_signature(root),
            "datasets": data, "findings": findings, "reviews": reviews,
            "overview": overview, "manifest": files, "raw_summary": raw_summary(root),
            "warnings": warnings, "load_errors": errors}
