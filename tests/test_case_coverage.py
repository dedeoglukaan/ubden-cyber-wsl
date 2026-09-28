"""Manual-checklist automation coverage + opt-in tool modules."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import case_coverage
import optional_tools
import ai_operator


class CaseCoverageTests(unittest.TestCase):
    def _root(self):
        return Path(tempfile.mkdtemp())

    def test_automated_findings_cover_their_cases(self):
        root = self._root()
        findings = [
            {"id": "OBS-001", "source": "Otomatik gözlem", "title": "Anonim FTP erişimine izin veriliyor", "category": ""},
            {"id": "OBS-002", "source": "Otomatik gözlem", "title": "VMware ESXi kullanım ömrü (EOL) dolmuş sürüm", "category": ""},
            {"id": "OBS-003", "source": "Otomatik gözlem", "title": "SMB paylaşımlarına erişilebiliyor", "category": ""},
            {"id": "OBS-004", "source": "Otomatik gözlem", "title": "Fazla sayıda Domain Admin hesabı", "category": ""},
            {"id": "OBS-005", "source": "Otomatik gözlem", "title": "SNMP varsayılan public topluluğuyla bilgi okunabiliyor", "category": ""},
        ]
        cov = case_coverage.derive(root, {}, [], findings)
        cases = cov["cases"]
        self.assertEqual(cases["PROTOCOL"]["status"], "otomatik-bulgu")
        self.assertEqual(cases["PATCH"]["status"], "otomatik-bulgu")
        self.assertEqual(cases["SHARES"]["status"], "otomatik-bulgu")
        self.assertEqual(cases["AD-POLICY"]["status"], "otomatik-bulgu")
        self.assertEqual(cases["SNMP"]["status"], "otomatik-bulgu")
        self.assertIn("OBS-001", cases["PROTOCOL"]["finding_ids"])
        self.assertGreaterEqual(cov["summary"]["automated"], 5)
        # Regression: the generic word "varsayılan" in the SNMP/default-cred titles must
        # NOT wrongly credit CONFIG (it belongs to SNMP/AUTH).
        self.assertNotEqual(cases["CONFIG"]["status"], "otomatik-bulgu")
        self.assertNotIn("OBS-005", cases["CONFIG"]["finding_ids"])

    def test_default_cred_finding_maps_to_auth_not_config(self):
        root = self._root()
        findings = [{"id": "OBS-010", "source": "Otomatik gözlem",
                     "title": "HTTP varsayılan/zayıf kimlik bilgisi geçerli", "category": ""}]
        cov = case_coverage.derive(root, {}, [], findings)
        self.assertEqual(cov["cases"]["AUTH"]["status"], "otomatik-bulgu")
        self.assertNotEqual(cov["cases"]["CONFIG"]["status"], "otomatik-bulgu")

    def test_non_object_inventory_json_does_not_crash(self):
        root = self._root()
        (root / "DEVICE_INVENTORY.json").write_text('["a","b"]', encoding="utf-8")  # valid JSON, not an object
        cov = case_coverage.derive(root, {}, [], [])  # must not raise
        self.assertEqual(cov["cases"]["ASSET"]["status"], "kayıt-yok")

    def test_artefacts_mark_scanned_without_findings(self):
        root = self._root()
        (root / "DEVICE_INVENTORY.json").write_text(json.dumps({"host_count": 12, "mac_count": 5}), encoding="utf-8")
        (root / "AD_ASSESSMENT.json").write_text(json.dumps(
            {"status": "ok", "domain": "x.local", "inventory": {"users": {"observed_count": 5}},
             "password_policy": {"min_length": 12}}), encoding="utf-8")
        cov = case_coverage.derive(root, {}, [], [])
        self.assertEqual(cov["cases"]["ASSET"]["status"], "otomatik-tarandı")
        self.assertEqual(cov["cases"]["AD"]["status"], "otomatik-tarandı")
        self.assertEqual(cov["cases"]["AD-POLICY"]["status"], "otomatik-tarandı")

    def test_ai_case_assessment_marks_web_logic(self):
        root = self._root()
        (root / "AI_FINDINGS.json").write_text(json.dumps({
            "findings": [],
            "case_assessments": [{"case": "AUTH", "assessment": "Login formu görüldü; MFA test edilmeli.",
                                  "severity": "medium", "ai_confidence": 60}]}), encoding="utf-8")
        cov = case_coverage.derive(root, {}, [], [])
        self.assertEqual(cov["cases"]["AUTH"]["status"], "ai-taslağı")
        self.assertIn("MFA", cov["cases"]["AUTH"]["detail"])
        # A web-logic case with no AI draft stays analyst-driven.
        self.assertEqual(cov["cases"]["LOGIC"]["status"], "analist")

    def test_summary_counts_and_no_record(self):
        root = self._root()
        cov = case_coverage.derive(root, {}, [], [])
        self.assertEqual(cov["summary"]["total"], 20)
        # With nothing run, web-logic + retest are analyst; the rest have no record.
        self.assertGreaterEqual(cov["summary"]["analyst_only"], 6)
        self.assertGreaterEqual(cov["summary"]["no_record"], 1)


class OptionalToolsTests(unittest.TestCase):
    def test_sqlmap_skips_without_flag(self):
        events = []
        optional_tools.run_sqlmap([("10.0.0.1", "http://10.0.0.1/")], Path("."), events, None, {})
        self.assertEqual(events, [])  # no flag -> silent no-op, nothing executed

    def test_sqlmap_requires_authorization_reference(self):
        events = []
        optional_tools.run_sqlmap([("10.0.0.1", "http://10.0.0.1/")], Path("."), events, None,
                                  {"enabled_modules": ["sql_injection_test"]})
        self.assertEqual(events[0]["status"], "skipped")
        self.assertIn("yetki", events[0]["detail"].lower())

    def test_sqlmap_reports_missing_tool_when_authorized(self):
        events = []
        from unittest.mock import patch
        with patch.object(optional_tools.shutil, "which", return_value=None):
            optional_tools.run_sqlmap([("10.0.0.1", "http://10.0.0.1/")], Path("."), events, None,
                                      {"enabled_modules": ["sql_injection_test"], "authorization_reference": "AUTH-1"})
        self.assertEqual(events[0]["status"], "missing_tool")

    def test_sqlmap_runs_and_writes_summary_when_present(self):
        from unittest.mock import patch
        raw = Path(tempfile.mkdtemp())
        def fake_command(name, argv, folder, events, timeout):
            (folder / f"{name}.txt").write_text(
                "Parameter: id (GET)\nback-end DBMS: MySQL\nsqlmap identified the following injection point",
                encoding="utf-8")
            rec = {"step": name, "status": "ok"}
            events.append(rec)
            return rec
        events = []
        with patch.object(optional_tools.shutil, "which", return_value="/usr/bin/sqlmap"):
            optional_tools.run_sqlmap([("10.0.0.7", "http://10.0.0.7/")], raw, events, fake_command,
                                      {"enabled_modules": ["sql_injection_test"], "authorization_reference": "AUTH-1"})
        summary = json.loads((raw / "sqlmap_result_10.0.0.7.json").read_text(encoding="utf-8"))
        self.assertTrue(summary["injectable"])
        self.assertEqual(summary["ip"], "10.0.0.7")

    def test_catalog_flags_are_declared(self):
        for entry in optional_tools.CATALOG:
            self.assertIn("flag", entry)
            self.assertIn("feeds_case", entry)
            self.assertIn(entry["kind"], {"injection", "enumeration", "brute", "offline_crack", "scanner"})


class AiCaseNormalizeTests(unittest.TestCase):
    def test_normalize_cases_filters_and_bounds(self):
        out = ai_operator._normalize_cases([
            {"case": "auth", "assessment": "Test MFA", "severity": "medium", "ai_confidence": 200},
            {"case": "NOPE", "assessment": "x"},
            {"case": "IDOR", "assessment": ""},
            {"case": "AUTH", "assessment": "duplicate"},
            {"case": "LOGIC", "assessment": "İş akışı", "severity": "weird", "ai_confidence": "bad"},
        ])
        cases = {c["case"]: c for c in out}
        self.assertIn("AUTH", cases)
        self.assertEqual(cases["AUTH"]["ai_confidence"], 100)  # clamped
        self.assertNotIn("NOPE", cases)
        self.assertNotIn("IDOR", cases)  # empty assessment dropped
        self.assertEqual(cases["LOGIC"]["severity"], "info")  # invalid severity normalized
        self.assertEqual(len([c for c in out if c["case"] == "AUTH"]), 1)  # deduped


if __name__ == "__main__":
    unittest.main()
