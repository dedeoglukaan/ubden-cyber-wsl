"""win_tools catalogue + report structure + PATH augmentation. No network/winget.

Guards the 'all tools' contract: every probe-suite tool appears in the catalogue
(installed, built-in, or with an NSE/pure fallback) so nothing is silently missing.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import win_tools

# Tools the Kali probe suite may invoke; each must be represented in the catalogue.
EXPECTED = {"nmap", "nuclei", "curl", "sslscan", "nikto", "whois", "dig",
            "wafw00f", "fierce", "theHarvester", "snmpget", "smbclient",
            "traceroute", "fping", "nbtscan", "ike-scan", "dnsenum", "nslookup"}


class WinToolsTests(unittest.TestCase):
    def test_catalogue_covers_probe_suite_tools(self):
        catalogued = {t["exe"] for t in win_tools.CATALOG}
        missing = EXPECTED - catalogued
        self.assertEqual(missing, set(), f"katalogda eksik araclar: {missing}")

    def test_every_tool_has_source_and_fallback_field(self):
        for tool in win_tools.CATALOG:
            self.assertIn(tool["source"], {"winget", "pip", "builtin", "nse", "manual"})
            self.assertIn("fallback", tool)
            # A tool with no clean Windows install must name a fallback capability.
            if tool["source"] == "manual":
                self.assertTrue(tool["fallback"], f"{tool['exe']} icin fallback belirtilmemis")

    def test_report_shape(self):
        rep = win_tools.report()
        self.assertEqual(rep["total"], len(win_tools.CATALOG))
        self.assertIn("tools", rep)
        self.assertTrue(all("present" in t for t in rep["tools"]))
        self.assertLessEqual(rep["present_count"], rep["total"])

    def test_ensure_path_adds_venv_scripts(self):
        win_tools.ensure_path()
        scripts = str(win_tools.venv_scripts_dir())
        if Path(scripts).exists():
            self.assertIn(scripts, os.environ.get("PATH", ""))

    def test_pip_tools_declared(self):
        names = {p[0] for p in win_tools.PIP_TOOLS}
        self.assertTrue({"wafw00f", "fierce", "theHarvester"}.issubset(names))


if __name__ == "__main__":
    unittest.main()
