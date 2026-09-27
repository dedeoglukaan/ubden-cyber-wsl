"""win_proc.run must produce the same step-record shape as wizard.command()
and control processes without POSIX-only calls (timeout kill, missing tool).
Cross-platform; no Kali/network needed.
"""
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import win_proc


def _raw():
    root = Path(tempfile.mkdtemp())
    raw = root / "targets" / "t" / "raw"
    raw.mkdir(parents=True)
    return root, raw


class WinProcTests(unittest.TestCase):
    def test_record_shape_and_success(self):
        root, raw = _raw()
        events = []
        rec = win_proc.run("ok_step", [sys.executable, "-c", "print('merhaba')"], raw, events)
        self.assertEqual(rec["status"], "ok")
        self.assertEqual(rec["step"], "ok_step")
        self.assertIn("sha256", rec)
        self.assertEqual(rec["output"], "targets/t/raw/ok_step.txt")
        self.assertEqual(events[-1]["step"], "ok_step")
        self.assertIn("merhaba", (raw / "ok_step.txt").read_text(encoding="utf-8"))

    def test_missing_tool(self):
        root, raw = _raw()
        events = []
        rec = win_proc.run("missing", ["ubden_no_such_tool_xyz", "-h"], raw, events)
        self.assertEqual(rec["status"], "missing_tool")

    def test_timeout_kills_process_promptly(self):
        root, raw = _raw()
        events = []
        start = time.monotonic()
        rec = win_proc.run("slow", [sys.executable, "-c", "import time;time.sleep(30)"],
                           raw, events, timeout=1)
        self.assertEqual(rec["status"], "timeout")
        self.assertLess(time.monotonic() - start, 15)  # was actually killed, not waited out

    def test_tool_version_best_effort(self):
        version = win_proc.tool_version(sys.executable)
        self.assertIsInstance(version, str)
        self.assertTrue(version)  # python --version prints a line


if __name__ == "__main__":
    unittest.main()
