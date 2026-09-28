"""attack_bridge: Windows->WSL orchestration for the optional offensive-ext stage.
All WSL/subprocess calls are mocked — no Kali needed."""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import attack_bridge as ab


class DecodeDistroTests(unittest.TestCase):
    def test_find_distro_prefers_kali_and_decodes_utf16(self):
        utf16 = ("Ubuntu\r\nkali-linux\r\ndocker-desktop\r\n").encode("utf-16-le")

        class R:
            stdout = utf16
        with patch.object(ab.subprocess, "run", return_value=R()):
            self.assertEqual(ab.find_distro(), "kali-linux")

    def test_find_distro_empty_when_none(self):
        class R:
            stdout = b""
        with patch.object(ab.subprocess, "run", return_value=R()):
            self.assertEqual(ab.find_distro(), "")


class ScopeTests(unittest.TestCase):
    def test_write_scope_uses_engagement_targets(self):
        d = Path(tempfile.mkdtemp())
        (d / "engagement.json").write_text(json.dumps(
            {"targets": ["10.11.11.0/24", "192.168.1.0/24"], "exclusions": ["10.11.11.1"]}), encoding="utf-8")
        path = ab.write_scope(d)
        body = Path(path).read_text(encoding="utf-8")
        self.assertIn("10.11.11.0/24", body)
        self.assertIn("192.168.1.0/24", body)


class CommandTests(unittest.TestCase):
    def test_readonly_default_and_writes_optin(self):
        ro = ab.build_wsl_command("kali", "/mnt/c/r", "/mnt/c/r/s.txt",
                                  {"user": "u", "password": "p"})[-1]
        self.assertIn("--no-report", ro)
        self.assertNotIn("--enable-writes", ro)
        self.assertNotIn("--allow-dcsync", ro)
        full = ab.build_wsl_command("kali", "/mnt/c/r", "/mnt/c/r/s.txt",
                                    {"user": "u", "password": "p", "writes": True})[-1]
        for flag in ("--enable-writes", "--allow-dcsync", "--assume-yes"):
            self.assertIn(flag, full)

    def test_password_is_shell_quoted(self):
        cmd = ab.build_wsl_command("kali", "/mnt/c/r", "/mnt/c/r/s.txt",
                                   {"user": "u", "password": "p a$ s;rm"})[-1]
        self.assertIn("--password", cmd)
        # dangerous chars must be quoted, not left bare for the shell
        self.assertNotIn("; rm", cmd)


class RunTests(unittest.TestCase):
    def _run_dir(self):
        d = Path(tempfile.mkdtemp())
        (d / "engagement.json").write_text(json.dumps({"targets": ["10.0.0.0/24"]}), encoding="utf-8")
        return d

    def test_missing_kali_returns_error(self):
        lines = []
        with patch.object(ab, "find_distro", return_value=""):
            res = ab.run(self._run_dir(), {"user": "u", "password": "p"},
                         lambda l, lvl="info": lines.append(l))
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["reason"], "no_kali_distro")

    def test_missing_creds_returns_error(self):
        with patch.object(ab, "find_distro", return_value="kali"), \
                patch.object(ab, "kali_offensive_installed", return_value=True):
            res = ab.run(self._run_dir(), {"user": "u"}, lambda l, lvl="info": None)
        self.assertEqual(res["reason"], "missing_credentials")

    def test_no_go_aborts_before_attack(self):
        calls = []
        with patch.object(ab, "find_distro", return_value="kali"), \
                patch.object(ab, "kali_offensive_installed", return_value=True), \
                patch.object(ab, "to_wsl_path", return_value="/mnt/c/r"), \
                patch.object(ab, "_stream", side_effect=lambda cmd, p, mask=(): calls.append(cmd) or (1, "==> NO-GO: scope")), \
                patch.object(ab, "_regenerate_report") as regen:
            res = ab.run(self._run_dir(), {"user": "u", "password": "p"}, lambda l, lvl="info": None)
        self.assertEqual(res["status"], "no_go")
        self.assertEqual(len(calls), 1)   # only doctor ran, attack did not
        regen.assert_not_called()

    def test_happy_path_runs_attack_and_regenerates_report(self):
        with patch.object(ab, "find_distro", return_value="kali"), \
                patch.object(ab, "kali_offensive_installed", return_value=True), \
                patch.object(ab, "to_wsl_path", return_value="/mnt/c/r"), \
                patch.object(ab, "_stream", side_effect=[(0, "==> GO"), (0, "[01] kerberoast: ok")]), \
                patch.object(ab, "_regenerate_report") as regen:
            res = ab.run(self._run_dir(), {"user": "u", "password": "p", "writes": False},
                         lambda l, lvl="info": None)
        self.assertEqual(res["status"], "completed")
        regen.assert_called_once()


if __name__ == "__main__":
    unittest.main()
