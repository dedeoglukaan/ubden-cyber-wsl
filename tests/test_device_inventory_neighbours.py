"""Windows L2 recovery: when the ARP neighbour map (or on-link Nmap MAC) is
supplied, device_inventory fills MAC + vendor instead of leaving mac_count=0.

This is the exact capability the Windows-native uPenetrator adds over WSL NAT.
No Kali/network needed.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import device_inventory

NMAP_WITH_MAC = """<?xml version="1.0"?><nmaprun><host>
<address addr="192.168.56.10" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>
</host></nmaprun>"""

NMAP_NO_MAC = """<?xml version="1.0"?><nmaprun><host>
<address addr="192.168.56.10" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>
</host></nmaprun>"""

META = {"targets": ["192.168.56.0/24"], "exclusions": [], "host_snapshot": {},
        "selected_interfaces": []}


def _run_dir(xml_text):
    root = Path(tempfile.mkdtemp())
    raw = root / "targets" / "192.168.56.0_24" / "raw"
    raw.mkdir(parents=True)
    (raw / "nmap_test.xml").write_text(xml_text, encoding="utf-8")
    return root


def _oui_csv(tmp):
    csv = tmp / "oui.csv"
    csv.write_text("Registry,Assignment,Organization Name,Organization Address\n"
                   "MA-L,001122,TestVendor,Yer\n", encoding="utf-8")
    return csv


class DeviceInventoryNeighboursTests(unittest.TestCase):
    def test_onlink_nmap_mac_is_used(self):
        root = _run_dir(NMAP_WITH_MAC)
        oui = _oui_csv(root)
        summary = device_inventory.build_inventory(root, META, neighbours={}, oui_paths=[oui])
        self.assertEqual(summary["mac_count"], 1)
        device = summary["devices"][0]
        self.assertEqual(device["ip"], "192.168.56.10")
        self.assertTrue(device["mac"])
        self.assertEqual(device["vendor"], "TestVendor")
        self.assertEqual(device["mac_source"], "nmap")

    def test_neighbour_map_fills_mac_when_xml_has_none(self):
        root = _run_dir(NMAP_NO_MAC)
        oui = _oui_csv(root)
        neighbours = {"192.168.56.10": {"mac": "00-11-22-33-44-55", "device": "Ethernet"}}
        summary = device_inventory.build_inventory(root, META, neighbours=neighbours, oui_paths=[oui])
        self.assertEqual(summary["mac_count"], 1)
        device = summary["devices"][0]
        self.assertEqual(device["vendor"], "TestVendor")
        self.assertEqual(device["mac_source"], "yerel komşu önbelleği")

    def test_no_l2_data_leaves_mac_empty(self):
        root = _run_dir(NMAP_NO_MAC)
        summary = device_inventory.build_inventory(root, META, neighbours={}, oui_paths=[])
        self.assertEqual(summary["mac_count"], 0)  # the WSL-NAT failure mode

    def test_scanner_own_machine_is_enriched_from_host_snapshot(self):
        root = _run_dir(NMAP_NO_MAC)  # 192.168.56.10, no MAC from nmap
        oui = _oui_csv(root)
        meta = dict(META)
        meta["host_snapshot"] = {"host": "UBNTB001", "fqdn": "UBNTB001",
            "adapters": [{"name": "Wi-Fi", "mac": "00-11-22-33-44-55", "status": "Up",
                          "addresses": [{"address": "192.168.56.10"}]}]}
        summary = device_inventory.build_inventory(root, meta, neighbours={}, oui_paths=[oui])
        dev = summary["devices"][0]
        self.assertTrue(dev["mac"])                       # filled from the local adapter
        self.assertEqual(dev["vendor"], "TestVendor")
        self.assertEqual(dev["display_name"], "UBNTB001")
        self.assertTrue(dev.get("is_scanner"))
        self.assertFalse(any("L2 komşuluk yok" in n for n in dev["notices"]))  # misleading note removed
        self.assertEqual(summary["mac_count"], 1)

    def test_web_identify_signal_feeds_classification(self):
        root = _run_dir(NMAP_NO_MAC)
        raw = root / "targets" / "192.168.56.0_24" / "raw"
        (raw / "web_id_192.168.56.10.json").write_text(json.dumps({
            "target": "192.168.56.10", "title": "Technicolor Gateway",
            "server": "lighttpd", "snippet": "DOCSIS Online model 6442 technicolor"}), encoding="utf-8")
        summary = device_inventory.build_inventory(root, META, neighbours={}, oui_paths=[])
        dev = summary["devices"][0]
        self.assertTrue(any("Web kimliği" in s for s in dev["signals"]))
        self.assertEqual(dev.get("web_id", {}).get("title"), "Technicolor Gateway")


if __name__ == "__main__":
    unittest.main()
