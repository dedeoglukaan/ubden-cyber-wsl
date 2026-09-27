import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import rootdse_probe


AD_ATTRS = {
    "defaultNamingContext": "DC=corp,DC=ornek,DC=local",
    "dnsHostName": "dc01.corp.ornek.local",
    "domainFunctionality": "7",
    "forestFunctionality": "4",
    "serverName": "CN=DC01,CN=Servers",
}
AD_CAPS = ["1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670"]


class ParseRootDseTests(unittest.TestCase):
    def test_ad_domain_and_levels(self):
        parsed = rootdse_probe.parse_rootdse(AD_ATTRS, AD_CAPS)
        self.assertTrue(parsed["is_ad"])
        self.assertEqual(parsed["domain"], "corp.ornek.local")
        self.assertEqual(parsed["dc_dns_name"], "dc01.corp.ornek.local")
        self.assertEqual(parsed["domain_functional_level"], "Windows Server 2016")
        self.assertEqual(parsed["forest_functional_level"], "Windows Server 2008 R2")
        self.assertTrue(parsed["domain_level_legacy"] is False)

    def test_legacy_level_flagged(self):
        attrs = dict(AD_ATTRS, domainFunctionality="3")
        parsed = rootdse_probe.parse_rootdse(attrs, AD_CAPS)
        self.assertTrue(parsed["domain_level_legacy"])

    def test_non_ad_service(self):
        parsed = rootdse_probe.parse_rootdse({"defaultNamingContext": "dc=example,dc=com"}, [])
        # No AD capability OID but a naming context + no functionality → not asserted AD.
        self.assertFalse(parsed["is_ad"])


class ProbeTests(unittest.TestCase):
    def test_probe_with_connector_reads_rootdse(self):
        result = rootdse_probe.probe("10.0.0.5", 389, connector=lambda *a: (AD_ATTRS, AD_CAPS))
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["is_ad"])
        self.assertEqual(result["domain"], "corp.ornek.local")

    def test_probe_isolates_errors(self):
        def boom(*a):
            raise TimeoutError("no route")
        result = rootdse_probe.probe("10.0.0.9", 389, connector=boom)
        self.assertEqual(result["status"], "error")


class DiscoverTests(unittest.TestCase):
    def test_discover_writes_evidence_and_event(self):
        folder = Path(tempfile.mkdtemp())
        raw = folder / "targets" / "10.0.0.5" / "raw"
        raw.mkdir(parents=True)
        events = []
        fake = {"ip": "10.0.0.5", "status": "ok", "is_ad": True, "domain": "corp.local"}
        with patch("rootdse_probe.probe", return_value=fake):
            rootdse_probe.discover(["10.0.0.5"], {"10.0.0.5": [389, 445]}, raw, events)
        self.assertTrue((raw / "ad_rootdse_10.0.0.5.json").is_file())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["step"], "ad_rootdse")
        self.assertEqual(events[0]["status"], "ok")
        self.assertEqual(events[0]["ad_count"], 1)

    def test_discover_skips_without_ldap_ports(self):
        folder = Path(tempfile.mkdtemp())
        raw = folder / "targets" / "10.0.0.6" / "raw"
        raw.mkdir(parents=True)
        events = []
        rootdse_probe.discover(["10.0.0.6"], {"10.0.0.6": [80, 443]}, raw, events)
        self.assertEqual(events, [])


if __name__ == "__main__":
    unittest.main()
