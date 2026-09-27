import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import cve_enrich as C

PAYLOAD = {"vulnerabilities": [
    {"cve": {"id": "CVE-2022-42475",
             "descriptions": [{"lang": "tr", "value": "yok"}, {"lang": "en", "value": "sslvpnd heap overflow"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}}},
    {"cve": {"id": "CVE-2020-0001",
             "descriptions": [{"lang": "en", "value": "medium issue"}],
             "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}]}}},
]}


def fake_fetch(url, api_key="", timeout=15):
    fake_fetch.urls.append(url)
    return PAYLOAD
fake_fetch.urls = []


class QueryTests(unittest.TestCase):
    def test_parse_and_sort(self):
        cves = C.query_nvd("cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", fetch=fake_fetch)
        self.assertEqual(cves[0]["id"], "CVE-2022-42475")
        self.assertEqual(cves[0]["severity"], "CRITICAL")
        self.assertEqual(cves[0]["summary"], "sslvpnd heap overflow")
        self.assertEqual([c["severity"] for c in cves], ["CRITICAL", "MEDIUM"])

    def test_targets_only_mapped_with_version(self):
        tech = {"matches": [
            {"family": "Fortinet FortiGate / FortiOS", "version": "7.2.4", "ip": "10.0.0.1"},
            {"family": "VMware ESXi", "version": "", "ip": "10.0.0.2"},          # sürüm yok → atla
            {"family": "Avenir kamera/güvenlik", "version": "1.0", "ip": "10.0.0.3"},  # CPE yok → atla
        ]}
        targets = C._targets(tech)
        self.assertEqual(len(targets), 1)
        self.assertTrue(targets[0]["cpe"].startswith("cpe:2.3:o:fortinet:fortios:7.2.4"))

    def test_enrich_collects_and_counts(self):
        tech = {"matches": [{"family": "Fortinet FortiGate / FortiOS", "version": "7.2.4", "ip": "10.0.0.1"}]}
        result = C.enrich(Path("."), tech, fetch=fake_fetch, sleep=lambda *a: None, delay=0)
        self.assertEqual(result["queried"], 1)
        self.assertEqual(result["items"][0]["cve_count"], 2)
        self.assertEqual(result["critical_high_count"], 1)

    def test_enrich_isolates_fetch_errors(self):
        def boom(url, api_key="", timeout=15):
            raise TimeoutError("nvd slow")
        tech = {"matches": [{"family": "QNAP QTS", "version": "5.0", "ip": "10.0.0.9"}]}
        result = C.enrich(Path("."), tech, fetch=boom, sleep=lambda *a: None, delay=0)
        self.assertEqual(result["queried"], 0)
        self.assertEqual(result["errors"], 1)
        self.assertEqual(result["items"], [])

    def test_write_offline_skips_network(self):
        import os
        folder = Path(tempfile.mkdtemp())
        os.environ["UBDEN_OFFLINE"] = "1"
        try:
            result = C.write(folder, {"matches": [{"family": "QNAP QTS", "version": "5.0", "ip": "1.1.1.1"}]})
        finally:
            del os.environ["UBDEN_OFFLINE"]
        self.assertEqual(result["queried"], 0)
        self.assertIn("UBDEN_OFFLINE", result["note"])
        self.assertTrue((folder / "UBDEN_CVE.json").is_file())


if __name__ == "__main__":
    unittest.main()
