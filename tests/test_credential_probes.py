import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import credential_probes as C

DB = {"generic": [["admin", "admin"], ["root", "root"]],
      "service": {"telnet": [["cisco", "cisco"]], "http-basic": [["admin", "admin"]]},
      "brands": {"Dahua kamera/NVR": [["admin", "admin"], ["admin", "888888"], ["888888", "888888"]]}}


class SelectTests(unittest.TestCase):
    def test_brand_then_service_then_generic_deduped_capped(self):
        got = C.select_candidates(["Dahua kamera/NVR"], "telnet", DB, cap=5)
        self.assertEqual(got[0], ("admin", "admin"))          # marka önce
        self.assertIn(("admin", "888888"), got)
        self.assertIn(("cisco", "cisco"), got)                # servis
        self.assertIn(("root", "root"), got)                  # genel
        self.assertLessEqual(len(got), 5)
        # admin/admin hem markada hem genelde yok ama tekrarsız olmalı
        self.assertEqual(len(got), len(set(got)))


class RunGatingTests(unittest.TestCase):
    def test_disabled_writes_single_skip_no_attempts(self):
        events = []
        with tempfile.TemporaryDirectory() as folder:
            raw = Path(folder) / "targets" / "t" / "raw"
            raw.mkdir(parents=True)
            calls = []
            conn = {"telnet": lambda *a: calls.append(a) or False}
            C.run("t", ["10.0.0.5"], {"10.0.0.5": [23]}, raw, events,
                  {"default_cred_test": False}, db=DB, connectors=conn, brands_by_ip={})
        self.assertEqual([e["status"] for e in events], ["skipped"])
        self.assertEqual(calls, [])  # kapalıyken hiç deneme yok


class RunAttemptTests(unittest.TestCase):
    def _run(self, connectors):
        events = []
        folder = Path(tempfile.mkdtemp())
        raw = folder / "targets" / "t" / "raw"
        raw.mkdir(parents=True)
        C.run("t", ["10.0.0.5"], {"10.0.0.5": [23, 443]}, raw, events,
              {"default_cred_test": True}, db=DB, connectors=connectors,
              brands_by_ip={"10.0.0.5": ["Dahua kamera/NVR"]})
        return events, raw

    def test_success_records_username_without_password(self):
        conn = {"telnet": lambda ip, port, u, p, t, *a: (u, p) == ("admin", "888888"),
                "http-basic": lambda ip, port, u, p, t, *a: False}
        events, raw = self._run(conn)
        review = next(e for e in events if e["status"] == "review")
        self.assertIn("telnet", review["step"])
        self.assertIn("admin", review["detail"])
        self.assertNotIn("888888", review["detail"])  # parola sızmaz
        evidence = json.loads((raw / "cred_default_telnet_10.0.0.5_23.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence["username"], "admin")
        self.assertTrue(evidence["valid"])
        self.assertNotIn("888888", json.dumps(evidence))       # parola kanıtta yok
        self.assertNotIn("password", evidence)

    def test_no_valid_default_records_ok(self):
        conn = {"telnet": lambda *a: False, "http-basic": lambda *a: False}
        events, raw = self._run(conn)
        self.assertTrue(any(e["status"] == "ok" and "telnet" in e["step"] for e in events))
        self.assertFalse(any(e["status"] == "review" for e in events))
        self.assertFalse((raw / "cred_default_telnet_10.0.0.5_23.json").exists())

    def test_http_basic_receives_scheme(self):
        seen = {}
        def http(ip, port, u, p, t, scheme=None):
            seen["scheme"] = scheme
            return False
        self._run({"telnet": lambda *a: False, "http-basic": http})
        self.assertEqual(seen["scheme"], "https")  # 443 → https


if __name__ == "__main__":
    unittest.main()
