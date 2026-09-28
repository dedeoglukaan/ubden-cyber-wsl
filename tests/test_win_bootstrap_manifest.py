"""The Windows-native one-liner must ship every file its launcher imports, and
the neighbours bridge action must be wired on both the Python and PowerShell
sides. Guards against 'ModuleNotFoundError' style release gaps. No network.
"""
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

WIN_FILES = ["ubden-win.ps1", "windows-bridge.ps1", "webapp.py", "win_scan.py",
             "win_proc.py", "win_tools.py", "report_v2.py", "device_inventory.py",
             "wizard.py", "eol_data.py", "service_probes.py", "credential_probes.py",
             "netbios_probe.py", "ai_operator.py", "web_identify.py", "wifi_scan.py",
             "power_manager.py", "case_coverage.py", "optional_tools.py",
             "attack_bridge.py", "requirements.txt"]


class WinBootstrapManifestTests(unittest.TestCase):
    def test_bootstrap_win_lists_required_windows_files(self):
        text = (REPO / "bootstrap-win.ps1").read_text(encoding="utf-8")
        for name in WIN_FILES:
            self.assertIn(f"'{name}'", text, f"bootstrap-win.ps1 {name} dosyasini listelemiyor")

    def test_windows_native_files_exist(self):
        for name in WIN_FILES:
            self.assertTrue((REPO / name).is_file(), f"{name} depoda yok")

    def test_neighbours_action_wired(self):
        host_bridge = (REPO / "host_bridge.py").read_text(encoding="utf-8")
        self.assertIn('"neighbours"', host_bridge)
        bridge = (REPO / "windows-bridge.ps1").read_text(encoding="utf-8")
        self.assertIn("neighbours", bridge)
        self.assertIn("Get-NetNeighbor", bridge)

    def test_bootstrap_win_uses_windows_entry(self):
        text = (REPO / "bootstrap-win.ps1").read_text(encoding="utf-8")
        self.assertIn("ubden-win.ps1", text)
        # Same repo/tag scheme as the WSL one-liner.
        self.assertRegex(text, r"\$tag = 'v\d+\.\d+\.\d+-wsl\.\d+'")

    def test_tag_is_synced_between_bootstraps(self):
        def tag(name):
            m = re.search(r"\$tag = '([^']+)'", (REPO / name).read_text(encoding="utf-8"))
            return m.group(1) if m else None
        self.assertEqual(tag("bootstrap.ps1"), tag("bootstrap-win.ps1"))


if __name__ == "__main__":
    unittest.main()
