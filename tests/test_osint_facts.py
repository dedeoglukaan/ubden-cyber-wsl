import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import osint_facts
import correlation


def _run(dmarc_text, spf_text="", target="ornek.com"):
    folder = Path(tempfile.mkdtemp())
    raw = folder / "targets" / target / "raw"
    raw.mkdir(parents=True)
    (raw / "dns_dmarc.txt").write_text(dmarc_text, encoding="utf-8")
    (raw / "dns_txt.txt").write_text(spf_text, encoding="utf-8")
    return osint_facts.build(folder, {"targets": [target]})


class OsintFactsTests(unittest.TestCase):
    def test_no_dmarc_is_spoofable(self):
        facts = _run("", spf_text='ornek.com. IN TXT "v=spf1 ~all"')
        self.assertTrue(facts["email_spoofable"])
        self.assertEqual(facts["email_posture"], "yok")
        self.assertTrue(facts["spf_present"])
        self.assertLess(facts["human_score"], 100)

    def test_reject_dmarc_not_spoofable(self):
        facts = _run('_dmarc.ornek.com. IN TXT "v=DMARC1; p=reject; rua=mailto:x@ornek.com"',
                     spf_text='ornek.com. IN TXT "v=spf1 -all"')
        self.assertFalse(facts["email_spoofable"])
        self.assertEqual(facts["email_posture"], "korumalı")
        self.assertEqual(facts["human_score"], 100)

    def test_quarantine_is_partial(self):
        facts = _run('_dmarc.ornek.com. IN TXT "v=DMARC1; p=quarantine"')
        self.assertTrue(facts["email_spoofable"])
        self.assertEqual(facts["email_posture"], "kısmi")

    def test_ip_only_target_has_no_domain(self):
        facts = osint_facts.build(Path(tempfile.mkdtemp()), {"targets": ["192.0.2.10"]})
        self.assertFalse(facts["available"])
        self.assertFalse(facts["email_spoofable"])

    def test_harvest_matches_registrable_domain(self):
        folder = Path(tempfile.mkdtemp())
        raw = folder / "targets" / "portal.ornek.com" / "raw"
        raw.mkdir(parents=True)
        (raw / "dns_dmarc.txt").write_text("", encoding="utf-8")
        (raw / "theHarvester_recon.txt").write_text(
            "Emails found:\nahmet@ornek.com\nayse@ornek.com\nbaska@disalan.net\n"
            "Hosts found:\nvpn.ornek.com\nmail.ornek.com\n", encoding="utf-8")
        facts = osint_facts.build(folder, {"targets": ["portal.ornek.com"]})
        # E-postalar kayıtlı ana alan (ornek.com) ile eşleşir; yabancı alan elenir.
        self.assertEqual(facts["email_count"], 2)
        self.assertEqual(facts["username_count"], 2)
        self.assertIn("ahmet", facts["usernames"])
        self.assertGreaterEqual(facts["subdomain_count"], 2)
        self.assertTrue(facts["usernames_discovered"])


class CorrelationOsintBridgeTests(unittest.TestCase):
    def test_spoofable_email_creates_phishing_chain_and_bridge(self):
        meta = {"targets": ["ornek.com"]}
        hosts = [{"ip": "10.0.0.5", "ports": [{"port": "3389", "protocol": "tcp"}]}]
        osint = {"email_spoofable": True, "email_posture": "yok", "human_score": 60,
                 "human_grade": "D", "domains": ["ornek.com"]}
        result = correlation.build(meta, hosts, [], {"categories": {}}, {}, osint)
        titles = [c["title"] for c in result["correlations"]]
        self.assertTrue(any("Sahtelenebilir e-posta" in t for t in titles))
        self.assertTrue(any(ch["name"].startswith("Oltalama") for ch in result["attack_chains"]))
        # Exposure index blends network and human sides.
        self.assertIn("human_score", result["exposure_index"])
        graph = result["graph"]
        self.assertTrue(any(n["type"] == "email" for n in graph["nodes"]))
        self.assertTrue(any(e.get("label") == "oltalama" for e in graph["edges"]))

    def test_usernames_plus_ad_creates_spraying_bridge(self):
        meta = {"targets": ["ornek.com"]}
        hosts = [{"ip": "10.0.0.20", "ports": [{"port": "88", "protocol": "tcp"},
                                               {"port": "445", "protocol": "tcp"}]}]
        osint = {"usernames_discovered": True, "username_count": 6, "domains": ["ornek.com"],
                 "human_score": 60, "human_grade": "D"}
        result = correlation.build(meta, hosts, [], {"categories": {}}, {"status": "completed"}, osint)
        self.assertTrue(any("kullanıcı adları" in c["title"].lower() for c in result["correlations"]))
        self.assertTrue(any("püskürtme" in ch["name"].lower() for ch in result["attack_chains"]))
        self.assertTrue(any(e.get("label") == "parola püskürtme" for e in result["graph"]["edges"]))

    def test_confirmed_cve_visible_and_not_double_counted(self):
        findings = [{"status": "doğrulandı", "severity": "critical", "id": "PX-1",
                     "title": "FortiOS SSL-VPN RCE", "reference": "CVE-2024-21762",
                     "asset": "10.0.0.1", "type": ""}]
        result = correlation.build({"targets": ["10.0.0.0/24"]}, [], findings, {"categories": {}}, {})
        titles = [c["title"] for c in result["correlations"]]
        self.assertTrue(any("Doğrulanmış CVE" in t for t in titles))
        self.assertTrue(all("_penalty" not in c for c in result["correlations"]))
        # confirmed critical (18) düşer; CVE korelasyonu scored=False → çift sayılmaz.
        self.assertEqual(result["exposure_index"]["score"], 82)

    def test_public_nas_and_camera_internet_exposure(self):
        tech = {"matches": [
            {"family": "Synology DSM", "category": "nas", "ip": "45.33.32.10", "mgmt_ports_observed": [5000]},
            {"family": "Dahua kamera/NVR", "category": "camera", "ip": "45.33.32.20", "mgmt_ports_observed": [37777]},
            {"family": "QNAP QTS", "category": "nas", "ip": "10.0.0.5", "mgmt_ports_observed": [8080]},
        ]}
        result = correlation.build({"targets": ["45.33.32.0/24"]}, [], [], {"categories": {}}, {}, tech=tech)
        titles = [c["title"] for c in result["correlations"]]
        self.assertTrue(any("İnternete açık NAS" in t for t in titles))
        self.assertTrue(any("İnternete açık kamera" in t for t in titles))
        nas = next(c for c in result["correlations"] if "İnternete açık NAS" in c["title"])
        self.assertIn("45.33.32.10", nas["detail"])
        self.assertNotIn("10.0.0.5", nas["detail"])  # private IP internet maruziyeti sayılmaz

    def test_public_management_plane_is_critical(self):
        tech = {"matches": [{"family": "Fortinet FortiGate / FortiOS", "category": "firewall",
                             "ip": "45.33.32.30", "mgmt_ports_observed": [443, 10443]}]}
        result = correlation.build({"targets": ["45.33.32.0/24"]}, [], [], {"categories": {}}, {}, tech=tech)
        titles = [c["title"] for c in result["correlations"]]
        self.assertTrue(any("İnternete açık yönetim düzlemi" in t for t in titles))
        self.assertFalse(any(t == "Kritik yönetim düzlemi platformu erişilebilir" for t in titles))

    def test_private_management_plane_is_high_not_public(self):
        tech = {"matches": [{"family": "VMware ESXi", "category": "hypervisor",
                             "ip": "10.0.0.40", "mgmt_ports_observed": [443, 902]}]}
        result = correlation.build({"targets": ["10.0.0.0/8"]}, [], [], {"categories": {}}, {}, tech=tech)
        titles = [c["title"] for c in result["correlations"]]
        self.assertTrue(any("Kritik yönetim düzlemi platformu erişilebilir" in t for t in titles))
        self.assertFalse(any("İnternete açık yönetim düzlemi" in t for t in titles))

    def test_private_nas_camera_no_internet_exposure(self):
        tech = {"matches": [{"family": "QNAP QTS", "category": "nas", "ip": "10.0.0.5", "mgmt_ports_observed": [8080]},
                            {"family": "Dahua kamera/NVR", "category": "camera", "ip": "192.168.1.9", "mgmt_ports_observed": [37777]}]}
        result = correlation.build({"targets": ["10.0.0.0/8"]}, [], [], {"categories": {}}, {}, tech=tech)
        self.assertFalse(any("İnternete açık" in c["title"] for c in result["correlations"]))

    def test_no_osint_means_no_phishing(self):
        result = correlation.build({"targets": ["10.0.0.1"]},
                                   [{"ip": "10.0.0.5", "ports": [{"port": "3389", "protocol": "tcp"}]}],
                                   [], {"categories": {}}, {})
        self.assertFalse(any("e-posta" in c["title"].lower() for c in result["correlations"]))
        self.assertNotIn("human_score", result["exposure_index"])


if __name__ == "__main__":
    unittest.main()
