"""win_scan.build_meta must satisfy the report engine's engagement.json contract
(schema 8) so report_v2.read_data accepts it and the report renders. No network.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import win_scan

# Keys report_v2 reads from meta (cover, scope, platform, profile narrative).
REQUIRED_META_KEYS = {
    "schema", "id", "client", "project", "authorization_reference", "product",
    "tester", "targets", "exclusions", "selected_interfaces", "network_mode",
    "profile", "enabled_modules", "host_snapshot", "max_rate", "top_ports",
    "started_at", "status", "tool_version",
}


class WinScanContractTests(unittest.TestCase):
    def test_build_meta_is_schema_8_and_complete(self):
        meta = win_scan.build_meta(
            {"client": "M", "project": "P", "authorization_reference": "A", "tester": "T",
             "targets": ["192.168.1.0/24", "10.0.0.5"], "exclusions": ["192.168.1.1"],
             "profile": "network", "top_ports": "150", "max_rate": "80",
             "selected_interfaces": ["12", "abc", "34"]},
            host_snapshot={"status": "ok", "adapters": [], "default_routes": []})
        self.assertEqual(meta["schema"], 8)
        self.assertEqual(meta["network_mode"], "windows-native")
        self.assertTrue(REQUIRED_META_KEYS.issubset(meta.keys()))
        self.assertEqual(meta["top_ports"], 150)
        self.assertEqual(meta["max_rate"], 80)
        self.assertEqual(meta["selected_interfaces"], [12, 34])  # non-numeric dropped
        json.dumps(meta)  # must be JSON-serialisable for engagement.json

    def test_defaults_and_profile_clamp(self):
        meta = win_scan.build_meta({"targets": ["10.0.0.1"], "profile": "bogus"},
                                   host_snapshot={})
        self.assertEqual(meta["profile"], "network")  # invalid profile clamped
        self.assertEqual(meta["client"], "Belirtilmedi")
        self.assertFalse(meta["default_cred_test"])
        self.assertLessEqual(meta["top_ports"], 1000)
        self.assertLessEqual(meta["max_rate"], 500)

    def test_optin_intrusive_flags_gated(self):
        # sqlmap needs the flag AND a real authorization reference AND network/full.
        with_auth = win_scan.build_meta(
            {"targets": ["10.0.0.0/24"], "profile": "full", "authorization_reference": "PT-2026-01",
             "sql_injection_test": True, "voip_scan": True}, host_snapshot={})
        self.assertIn("sql_injection_test", with_auth["enabled_modules"])
        self.assertIn("voip_scan", with_auth["enabled_modules"])
        # No authorization reference -> sqlmap flag withheld (voip still allowed).
        no_auth = win_scan.build_meta(
            {"targets": ["10.0.0.0/24"], "profile": "full",
             "sql_injection_test": True, "voip_scan": True}, host_snapshot={})
        self.assertNotIn("sql_injection_test", no_auth["enabled_modules"])
        self.assertIn("voip_scan", no_auth["enabled_modules"])
        # Not requested -> absent.
        off = win_scan.build_meta({"targets": ["10.0.0.0/24"], "profile": "full",
                                   "authorization_reference": "PT-1"}, host_snapshot={})
        self.assertNotIn("sql_injection_test", off["enabled_modules"])
        self.assertNotIn("voip_scan", off["enabled_modules"])

    def test_choose_run_base_exists(self):
        base = win_scan.choose_run_base()
        self.assertTrue(base.is_dir())


if __name__ == "__main__":
    unittest.main()
