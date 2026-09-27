import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tech_fingerprint as T


class IdentifyTests(unittest.TestCase):
    def test_esxi_from_banner_and_version(self):
        m = T.identify({443, 902}, "vmware esxi 7.0.3 build-19193900")
        fam = next(x for x in m if x["family"] == "VMware ESXi")
        self.assertEqual(fam["confidence"], "yüksek")
        self.assertEqual(fam["version"], "7.0.3")
        self.assertIn(902, fam["mgmt_ports_observed"])

    def test_fortigate_from_text(self):
        m = T.identify({443, 10443}, "server: fortigate fortios 7.2.4")
        fam = next(x for x in m if "FortiGate" in x["family"])
        self.assertEqual(fam["version"], "7.2.4")
        self.assertTrue(any("CVE-2024-21762" in a for a in fam["advisories"]))

    def test_camera_vendor_plus_port(self):
        m = T.identify({37777, 80}, "", vendor="Dahua Technology")
        self.assertTrue(any(x["family"].startswith("Dahua") for x in m))

    def test_ilo_and_synology(self):
        self.assertTrue(any("iLO" in x["family"] for x in T.identify({443, 17988}, "hp ilo 5")))
        syn = next(x for x in T.identify({5000, 5001}, "synology diskstation dsm 7.1") if x["family"] == "Synology DSM")
        self.assertEqual(syn["version"], "7.1")

    def test_cisco_iosxe_split_and_cpe(self):
        m = T.identify({443, 22}, "cisco ios-xe software, version 17.9.1")
        xe = next(x for x in m if x["family"] == "Cisco IOS-XE")
        self.assertEqual(xe["version"], "17.9.1")
        self.assertEqual(xe["cpe_parts"], ["o", "cisco", "ios_xe"])
        self.assertFalse(any(x["family"] == "Cisco ASA" for x in m))

    def test_mapped_family_carries_cpe_parts(self):
        esxi = next(x for x in T.identify({443, 902}, "vmware esxi 7.0.3") if x["family"] == "VMware ESXi")
        self.assertEqual(esxi["cpe_parts"], ["o", "vmware", "esxi"])

    def test_mikrotik_routeros_with_cpe(self):
        mt = next(x for x in T.identify({8291, 443}, "mikrotik routeros 6.49.7")
                  if x["family"] == "MikroTik RouterOS")
        self.assertEqual(mt["version"], "6.49.7")
        self.assertEqual(mt["cpe_parts"], ["o", "mikrotik", "routeros"])

    def test_veeam_and_axis_detected(self):
        self.assertTrue(any(x["family"].startswith("Veeam")
                            for x in T.identify({9392}, "", vendor="Veeam")))
        self.assertTrue(any(x["family"] == "Axis kamera"
                            for x in T.identify({554, 80}, "axis network camera")))

    def test_no_match_is_empty(self):
        self.assertEqual(T.identify({80}, "apache httpd 2.4"), [])


class BuildTests(unittest.TestCase):
    def test_build_reads_http_evidence(self):
        root = Path(tempfile.mkdtemp())
        raw = root / "targets" / "10.0.0.7" / "raw"
        raw.mkdir(parents=True)
        (raw / "headers_10.0.0.7_https_443.txt").write_text(
            "HTTP/1.1 200 OK\r\nServer: FortiGate\r\n", encoding="utf-8")
        hosts = [{"ip": "10.0.0.7", "ports": [{"port": "443", "service": "https"},
                                              {"port": "10443", "service": "https-alt"}]}]
        result = T.build(root, {"targets": ["10.0.0.0/24"]}, hosts, {"devices": []})
        self.assertTrue(any("FortiGate" in m["family"] for m in result["matches"]))
        forti = next(m for m in result["matches"] if "FortiGate" in m["family"])
        self.assertEqual(forti["ip"], "10.0.0.7")
        self.assertIn(10443, forti["mgmt_ports_observed"])

    def test_write_persists_json(self):
        root = Path(tempfile.mkdtemp())
        T.write(root, {"targets": []}, [], {"devices": []})
        data = json.loads((root / "UBDEN_TECH_PROFILE.json").read_text(encoding="utf-8"))
        self.assertIn("matches", data)
        self.assertIn("note", data)


if __name__ == "__main__":
    unittest.main()
