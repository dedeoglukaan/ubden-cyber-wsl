"""The web-researched classification library merges into device_inventory and the
report's real 'unknown' devices now classify correctly (endpoints/infra/appliances)."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import device_inventory as D


def _key(vendor="", ports=(), text="", gateway=False):
    return D.classify_device({"vendor": vendor, "ports": [{"port": p} for p in ports],
                              "text": text, "gateway": gateway})["key"]


class LibraryTests(unittest.TestCase):
    def test_library_file_is_valid_when_present(self):
        path = Path(D.__file__).resolve().parent / "data" / "device_classification.json"
        if not path.is_file():
            self.skipTest("no library file")
        lib = json.loads(path.read_text(encoding="utf-8"))
        self.assertIsInstance(lib.get("rules"), list)
        self.assertTrue(lib["rules"])
        for r in lib["rules"]:
            self.assertIn(r["category"], D.CATEGORIES)

    def test_loader_only_yields_valid_categories_and_weights(self):
        ev, et, ep = D._load_extra_rules()
        for pats, key, weight in list(ev) + list(et):
            self.assertIn(key, D.CATEGORIES)
            self.assertTrue(5 <= weight <= 80)
        for ports, key, weight in ep:
            self.assertIn(key, D.CATEGORIES)


class ClassificationTests(unittest.TestCase):
    def test_report_unknowns_now_classify(self):
        self.assertEqual(_key("PEGATRON CORPORATION", [5357, 7070]), "pc")
        self.assertEqual(_key("LCFC(Hefei) Electronics Technology", [5357, 7070]), "pc")
        self.assertEqual(_key("Motorola (Wuhan) Mobility Technologies"), "mobile")
        self.assertEqual(_key("", [22, 443, 8443], "vmware skyline health diagnostics"), "hypervisor")

    def test_main_router_firewall_recognized(self):
        self.assertEqual(_key("DrayTek Corp.", [21, 22, 23, 80, 443, 445], "draytek vigor", gateway=True), "router")

    def test_infra_and_appliances(self):
        self.assertEqual(_key("Hangzhou Hikvision Digital Technology", [554, 80]), "camera")
        self.assertEqual(_key("Yealink", [5060]), "voip")
        self.assertEqual(_key("Synology", [5000, 443], "diskstation"), "nas")


if __name__ == "__main__":
    unittest.main()
