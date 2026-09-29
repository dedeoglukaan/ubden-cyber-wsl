"""Focused checks for report interpretation, review gates and safe publishing."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from publisher import OUTPUTS, publish, recover_incomplete
from report_data import is_report, load_report, report_signature, safe_report_path, sha256
from serve import AppServer, Handler


class WebUITest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ubden-webui-test-")
        self.root = Path(self.temp.name) / "PENTEST_fixture"
        self.root.mkdir()
        (self.root / "targets" / "demo" / "raw").mkdir(parents=True)
        self.evidence = "targets/demo/raw/evidence.txt"
        (self.root / self.evidence).write_text("verified source", encoding="utf-8")
        (self.root / "engagement.json").write_text(json.dumps({"schema": 1, "id": "fixture-1", "client": "Demo", "targets": ["10.0.0.0/24"]}), encoding="utf-8")
        (self.root / "DEVICE_INVENTORY.json").write_text(json.dumps({"devices": [{"ip": "10.0.0.1", "ports": []}], "categories": {"Server": 1}}), encoding="utf-8")
        (self.root / "ANALIST_GOREV_RAPORU.json").write_text(json.dumps({"engagement_id": "fixture-1", "tasks": [{"id": "T-01", "title": "Check", "status": "bekliyor", "steps": [], "evidence_required": []}]}), encoding="utf-8")
        (self.root / "steps.json").write_text("[]", encoding="utf-8")
        (self.root / "REPORT.html").write_text(
            '<!doctype html><html><body><section class="finding" id="bulgu-1">'
            '<h3>OBS-001 · Demo finding</h3><p><b>Şiddet:</b> Yüksek · <b>Doğrulama:</b> taslak</p>'
            '<p><b>Kaynak:</b> Otomatik gözlem</p><p><b>Varlık:</b> 10.0.0.1:80</p>'
            '<p><b>Açıklama:</b> Evidence based observation</p><p><b>İş etkisi:</b> Candidate</p>'
            '<p><b>Düzeltme önerisi:</b> Review</p><a href="targets/demo/raw/evidence.txt">evidence</a>'
            '</section></body></html>', encoding="utf-8")
        self.originals = {name: sha256(self.root / name) for name in ("REPORT.html", "ANALIST_GOREV_RAPORU.json")}

    def tearDown(self):
        self.temp.cleanup()

    def test_report_and_path_boundary(self):
        self.assertTrue(is_report(self.root))
        model = load_report(self.root)
        self.assertEqual((model["overview"]["hosts"], model["overview"]["findings"], model["overview"]["confirmed"]), (1, 1, 0))
        self.assertEqual(model["findings"][0]["evidence"], [self.evidence])
        self.assertEqual(safe_report_path(self.root, self.evidence), (self.root / self.evidence).resolve())
        for bad in ("../outside.txt", ".webui/review.json", "C:/Windows/win.ini", "targets/%2e%2e/../engagement.json"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                safe_report_path(self.root, bad)

    def test_review_gate_and_audit(self):
        base = {"kind": "findings", "id": "OBS-001", "status": "doğrulandı", "reviewer": "Analyst", "note": "Observed", "evidence": [], "retest_evidence": []}
        with self.assertRaisesRegex(ValueError, "kanıt"):
            Handler._save_review(None, self.root, base)
        result = Handler._save_review(None, self.root, {**base, "evidence": [self.evidence]})
        self.assertTrue(result["saved"])
        model = load_report(self.root)
        self.assertEqual(model["overview"]["confirmed"], 1)
        self.assertEqual(len(model["reviews"]["history"]), 1)
        with self.assertRaisesRegex(ValueError, "yeniden test"):
            Handler._save_review(None, self.root, {**base, "status": "giderildi", "evidence": [self.evidence]})

    def test_publish_failure_keeps_original_outputs(self):
        original_signature = report_signature(self.root)
        def fail_pdf(*_args):
            raise RuntimeError("render failed")
        with patch("publisher.browser_binary", return_value=Path("edge")), patch("publisher.render_pdf", side_effect=fail_pdf):
            with self.assertRaisesRegex(RuntimeError, "render failed"):
                publish(self.root, original_signature)
        self.assertEqual(report_signature(self.root), original_signature)
        self.assertEqual({name: sha256(self.root / name) for name in self.originals}, self.originals)
        self.assertFalse((self.root / "WEBUI_PUBLISHED_REVIEW.json").exists())

    def test_portable_parent_detection(self):
        with patch("serve.WEBUI", self.root / "webui"):
            server = AppServer(("127.0.0.1", 0))
            try:
                self.assertEqual(server.report_root, self.root.resolve())
            finally:
                server.server_close()
        empty = Path(self.temp.name) / "outside" / "webui"
        with patch("serve.WEBUI", empty):
            server = AppServer(("127.0.0.1", 0))
            try:
                self.assertIsNone(server.report_root)
            finally:
                server.server_close()

    def test_incomplete_publish_recovers_backup(self):
        state = self.root / ".webui"
        backup = state / "backups" / "fixture-backup"
        backup.mkdir(parents=True)
        shutil.copy2(self.root / "REPORT.html", backup / "REPORT.html")
        shutil.copy2(self.root / "ANALIST_GOREV_RAPORU.json", backup / "ANALIST_GOREV_RAPORU.json")
        (self.root / "REPORT.html").write_text("interrupted replacement", encoding="utf-8")
        (state / "publish-journal.json").write_text(json.dumps({
            "backup": ".webui/backups/fixture-backup", "outputs": list(OUTPUTS),
            "original_names": ["REPORT.html", "ANALIST_GOREV_RAPORU.json"]}), encoding="utf-8")
        self.assertTrue(recover_incomplete(self.root))
        self.assertEqual(sha256(self.root / "REPORT.html"), self.originals["REPORT.html"])
        self.assertEqual(sha256(self.root / "ANALIST_GOREV_RAPORU.json"), self.originals["ANALIST_GOREV_RAPORU.json"])
        self.assertFalse((state / "publish-journal.json").exists())


if __name__ == "__main__":
    unittest.main()
