"""AI operator: allowlist/scope enforcement, evidence bundle sanitization, and a
mocked end-to-end run producing AI_FINDINGS.json merged by the report. No real API.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ai_operator


class _FakeResp:
    def __init__(self, obj):
        self._data = json.dumps({"content": [{"type": "text", "text": json.dumps(obj)}]}).encode("utf-8")
        self.status = 200
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def read(self, n=-1):
        return self._data


def _run_dir(devices=None):
    root = Path(tempfile.mkdtemp())
    (root / "engagement.json").write_text(json.dumps({
        "schema": 8, "client": "T", "project": "P", "product": "UBDEN", "tester": "t",
        "targets": ["192.168.0.0/24"], "exclusions": [], "profile": "network",
        "status": "completed", "started_at": "x", "tool_version": "5",
        "max_rate": 100, "top_ports": 100, "selected_interfaces": [], "host_snapshot": {}}),
        encoding="utf-8")
    inv = {"schema": 1, "host_count": len(devices or []), "mac_count": 0, "devices": devices or []}
    (root / "DEVICE_INVENTORY.json").write_text(json.dumps(inv), encoding="utf-8")
    return root


META = {"targets": ["192.168.0.0/24"], "exclusions": [], "profile": "network"}


class ValidateActionsTests(unittest.TestCase):
    def setUp(self):
        self.root = _run_dir()

    def test_allowlist_and_scope_enforced(self):
        actions = [
            {"type": "nse", "target": "192.168.0.5", "port": "445", "script": "smb-os-discovery"},  # ok
            {"type": "nse", "target": "192.168.0.6", "port": "22", "script": "ssh-brute"},          # bad script
            {"type": "nse", "target": "8.8.8.8", "port": "53", "script": "dns-nsid"},               # out of scope
            {"type": "http", "target": "192.168.0.7", "port": "443", "path": "/../etc/passwd"},     # traversal
            {"type": "http", "target": "192.168.0.7", "port": "443", "path": "/status"},            # ok
            {"type": "exec", "target": "192.168.0.8", "cmd": "rm -rf /"},                           # not a type
            {"type": "snmp", "target": "192.168.0.9"},                                              # ok
        ]
        valid = ai_operator.validate_actions(actions, self.root, META)
        kinds = [(a["type"], a["target"]) for a in valid]
        self.assertIn(("nse", "192.168.0.5"), kinds)
        self.assertIn(("http", "192.168.0.7"), kinds)
        self.assertIn(("snmp", "192.168.0.9"), kinds)
        self.assertNotIn(("nse", "192.168.0.6"), kinds)   # ssh-brute rejected
        self.assertNotIn(("nse", "8.8.8.8"), kinds)       # out of scope
        self.assertFalse(any(a["type"] == "exec" for a in valid))
        self.assertTrue(all("/.." not in (a.get("path") or "") for a in valid))

    def test_cap_and_dedupe(self):
        dup = [{"type": "snmp", "target": "192.168.0.5"}] * 5
        self.assertEqual(len(ai_operator.validate_actions(dup, self.root, META)), 1)
        many = [{"type": "snmp", "target": f"192.168.0.{i}"} for i in range(1, 60)]
        self.assertLessEqual(len(ai_operator.validate_actions(many, self.root, META)),
                             ai_operator.MAX_ACTIONS)


class BundleTests(unittest.TestCase):
    def test_bundle_structure_and_secret_stripping(self):
        root = _run_dir([{"ip": "192.168.0.5", "category": "İstemci PC", "vendor": "Intel",
                          "confidence_pct": 88, "ports": [{"port": "445", "protocol": "tcp",
                          "service": "microsoft-ds", "product": "", "version": ""}],
                          "os_matches": [], "role_candidates": [], "snmp_sysdescr": "password=SeCrEtValue123"}])
        bundle = ai_operator.evidence_bundle(root, META, [{"status": "ok"}])
        self.assertEqual(bundle["profile"], "network")
        self.assertEqual(len(bundle["devices"]), 1)
        self.assertNotIn("SeCrEtValue123", json.dumps(bundle, ensure_ascii=False))


class NormalizeTests(unittest.TestCase):
    def test_normalize_clamps_and_ids(self):
        out = ai_operator._normalize_findings([
            {"title": "AD zayıf parola", "severity": "HIGH", "ai_confidence": 250, "domain": "AD"},
            {"severity": "high"},               # no title -> dropped
            {"title": "x", "severity": "weird"},  # bad severity -> info
        ])
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["id"], "AI-001")
        self.assertEqual(out[0]["severity"], "high")
        self.assertEqual(out[0]["ai_confidence"], 100)
        self.assertEqual(out[0]["status"], "taslak")
        self.assertEqual(out[1]["severity"], "info")


class RunTests(unittest.TestCase):
    def test_run_writes_findings_with_mock_claude(self):
        root = _run_dir([{"ip": "192.168.0.1", "category": "Yönlendirici / Modem", "vendor": "Vantiva",
                          "confidence_pct": 99, "ports": [], "os_matches": [], "role_candidates": []}])
        analysis = {"executive_summary": "Özet", "overall_risk": "Orta", "attack_chains": ["a->b"],
                    "findings": [{"title": "RDP açık", "domain": "network", "severity": "medium",
                                  "asset": "192.168.0.1", "cwe": "CWE-284", "cvss": "5.0",
                                  "description": "d", "impact": "i", "recommendation": "r",
                                  "evidence_refs": ["nmap_cidr"], "ai_confidence": 70}]}
        request_fn = lambda req: _FakeResp(analysis)  # only analyze() is called (actions disabled)
        status = ai_operator.run(root, META, [{"status": "ok"}],
                                 {"key": "sk-test", "enable_actions": False, "request_fn": request_fn})
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["findings"], 1)
        data = json.loads((root / "AI_FINDINGS.json").read_text(encoding="utf-8"))
        self.assertEqual(data["findings"][0]["title"], "RDP açık")
        self.assertTrue((root / "AI_ANALIST_YORUMU.md").is_file())
        self.assertTrue((root / "AI_OPERATOR.json").is_file())

    def test_run_never_raises_on_api_error(self):
        root = _run_dir()
        def boom(req):
            raise OSError("network down")
        status = ai_operator.run(root, META, [], {"key": "sk", "enable_actions": False, "request_fn": boom})
        self.assertEqual(status["status"], "failed")
        self.assertTrue((root / "AI_OPERATOR.json").is_file())


if __name__ == "__main__":
    unittest.main()
