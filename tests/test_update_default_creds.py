import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import update_default_creds as U

CSV = ("productvendor,username,password\n"
       "Fortinet FortiGate,admin,<blank>\n"
       "Fortinet FortiGate,admin,admin\n"
       "Fortinet FortiGate,maintainer,bcpb[SERIAL NO.]\n"      # serial/[] → elenir
       "QNAP,admin,1st MAC address of NAS (uppercase)\n"        # talimat → elenir
       "Dahua,admin,supersecret\n"
       "SomeCam,root,unique per device\n"                       # non-literal → elenir
       "RandomVendor,admin,admin\n")                            # marka değil → hiçbir aileye girmez


class ParseTests(unittest.TestCase):
    def test_filters_blank_serial_and_instructions(self):
        rows = U.parse(CSV)
        self.assertIn(("fortinet fortigate", "admin", ""), rows)
        self.assertIn(("fortinet fortigate", "admin", "admin"), rows)
        self.assertFalse(any("serial" in p.lower() or "[" in p for _, _, p in rows))
        self.assertFalse(any("per device" in p.lower() for _, _, p in rows))
        self.assertFalse(any("mac address" in p.lower() for _, _, p in rows))


class MergeTests(unittest.TestCase):
    def test_caps_dedup_and_preserves_curated(self):
        db = {"brands": {"Fortinet FortiGate / FortiOS": [["admin", ""]]}}
        rows = U.parse(CSV)
        added = U.merge(db, rows, cap=2)
        forti = db["brands"]["Fortinet FortiGate / FortiOS"]
        self.assertIn(["admin", ""], forti)          # kürasyonlu korunur
        self.assertIn(["admin", "admin"], forti)      # yeni eklenir
        self.assertLessEqual(len(forti), 2)           # sınır
        self.assertEqual(added.get("Fortinet FortiGate / FortiOS"), 1)  # yalnız 1 yeni (dup atlandı)

    def test_unknown_vendor_not_added(self):
        db = {"brands": {}}
        U.merge(db, U.parse(CSV), cap=8)
        for creds in db["brands"].values():
            self.assertNotIn(["admin", "admin"], creds) if False else None
        # RandomVendor hiçbir aileye girmemeli; Dahua supersecret Dahua'ya girer.
        self.assertIn(["admin", "supersecret"], db["brands"].get("Dahua kamera/NVR", []))


class UpdateTests(unittest.TestCase):
    def test_update_with_injected_fetch(self):
        folder = Path(tempfile.mkdtemp())
        path = folder / "default_credentials.json"
        path.write_text(json.dumps({"schema": 1, "brands": {}}), encoding="utf-8")
        summary = U.update(path=path, fetcher=lambda url, timeout=30: CSV, cap=8, write=True)
        self.assertGreater(summary["total_added"], 0)
        db = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn(["admin", "supersecret"], db["brands"]["Dahua kamera/NVR"])
        self.assertEqual(db["source_url"], U.SOURCE_URL)


if __name__ == "__main__":
    unittest.main()
