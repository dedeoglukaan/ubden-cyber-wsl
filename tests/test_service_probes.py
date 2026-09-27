import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import service_probes
from assessment_coverage import build_coverage


def fake_command(name, argv, raw, events, timeout=900, stop_on=()):
    record = {"step": name, "tool": argv[0], "status": "ok", "argv": argv, "timeout": timeout}
    events.append(record)
    return record


class ServiceProbeTests(unittest.TestCase):
    def test_web_extras_runs_wafw00f_when_installed(self):
        events = []
        with patch("service_probes.shutil.which", return_value="/usr/bin/wafw00f"):
            service_probes.web_extras("h1_https_443", "https://192.0.2.10/", "192.0.2.10",
                                      None, events, fake_command)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["tool"], "wafw00f")
        self.assertEqual(events[0]["argv"], ["wafw00f", "https://192.0.2.10/"])
        self.assertEqual(events[0]["target"], "192.0.2.10")

    def test_web_extras_skips_when_missing(self):
        events = []
        with patch("service_probes.shutil.which", return_value=None):
            service_probes.web_extras("h1_https_443", "https://192.0.2.10/", "192.0.2.10",
                                      None, events, fake_command)
        self.assertEqual(events[0]["status"], "missing_tool")

    def test_domain_recon_runs_installed_tools_only(self):
        events = []
        present = {"dnsenum", "theHarvester"}
        with patch("service_probes.shutil.which", side_effect=lambda name: name if name in present else None):
            service_probes.domain_recon("ornek.com", None, events, fake_command)
        ran = {e["tool"]: e["status"] for e in events}
        self.assertEqual(ran["dnsenum"], "ok")
        self.assertEqual(ran["theHarvester"], "ok")
        self.assertEqual(ran["dnstracer"], "missing_tool")
        self.assertEqual(ran["fierce"], "missing_tool")
        # theHarvester step keeps its exact executable name for catalog matching.
        self.assertTrue(any(e["step"] == "theHarvester_recon" for e in events))

    def test_coverage_marks_new_controls_executed(self):
        steps = [
            {"step": "wafw00f_h1_https_443", "status": "ok"},
            {"step": "dnsenum_recon", "status": "ok"},
            {"step": "theHarvester_recon", "status": "ok"},
        ]
        ledger = build_coverage(Path("."), {"id": "x"}, steps, {"cases": []})
        by_id = {row["id"]: row for row in ledger["controls"]}
        self.assertEqual(by_id["WEB-FINGERPRINT"]["status"], "çalıştı")
        self.assertEqual(by_id["OSINT-DNS"]["status"], "çalıştı")


if __name__ == "__main__":
    unittest.main()
