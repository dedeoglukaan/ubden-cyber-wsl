"""Faz 3: concurrent execution lanes + shared rate governor + job ledger.

Hermetic — scan_target and the report subprocess are stubbed, so no nmap/network
and no reportlab dependency. Verifies lane fan-out, per-lane rate splitting,
lane snapshots for the live panel, and the UBDEN_EXECUTION.json ledger.
"""
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import win_scan


class _FakeProc:
    returncode = 0
    stdout = ""
    stderr = ""


class WinScanConcurrencyTests(unittest.TestCase):
    def _run(self, targets, lanes, max_rate=100):
        seen_rates = []
        active = {"n": 0, "max": 0}
        lock = threading.Lock()

        def fake_scan(target, meta, root, events, progress):
            with lock:
                active["n"] += 1
                active["max"] = max(active["max"], active["n"])
                seen_rates.append(meta["max_rate"])
            progress(f"{target}: stub calisiyor", "info")
            events.append({"step": f"stub_{target}", "status": "ok", "target": target})
            import time
            time.sleep(0.15)  # widen the concurrency window
            with lock:
                active["n"] -= 1

        lane_ids = {}

        def progress(line, level="info", lane=None):
            if lane and lane.get("id"):
                lane_ids[lane["id"]] = lane

        with patch.object(win_scan, "scan_target", side_effect=fake_scan), \
             patch.object(win_scan.subprocess, "run", return_value=_FakeProc()), \
             patch.object(win_scan, "windows_inventory", return_value={"status": "unavailable",
                          "adapters": [], "default_routes": []}), \
             patch.object(win_scan, "arp_neighbours", return_value={}), \
             patch.object(win_scan, "ensure_oui_paths", return_value=[]):
            res = win_scan.run_scan(
                {"client": "T", "project": "conc", "authorization_reference": "D", "tester": "d",
                 "targets": targets, "exclusions": [], "profile": "network",
                 "top_ports": "5", "max_rate": str(max_rate), "lanes": str(lanes),
                 "selected_interfaces": []},
                progress=progress)
        return res, seen_rates, active, lane_ids

    def test_two_targets_run_in_two_lanes_with_split_rate(self):
        res, rates, active, lanes = self._run(["10.0.0.1", "10.0.0.2"], lanes=2, max_rate=100)
        self.assertEqual(active["max"], 2)              # both lanes truly ran at once
        self.assertEqual(rates, [50, 50])              # 100 // 2 per lane
        self.assertEqual(set(lanes), {"L1", "L2"})     # live panel got both lanes
        run_dir = Path(res["run_dir"])
        ledger = json.loads((run_dir / "UBDEN_EXECUTION.json").read_text(encoding="utf-8"))
        self.assertEqual(ledger["concurrency"]["lanes"], 2)
        self.assertEqual(ledger["concurrency"]["per_lane_max_rate"], 50)
        steps = json.loads((run_dir / "steps.json").read_text(encoding="utf-8"))
        self.assertTrue({"stub_10.0.0.1", "stub_10.0.0.2"}.issubset({s["step"] for s in steps}))
        import shutil
        shutil.rmtree(run_dir, ignore_errors=True)

    def test_lanes_clamped_to_target_count_and_ceiling(self):
        res, rates, active, lanes = self._run(["10.0.0.1"], lanes=10, max_rate=80)
        self.assertEqual(active["max"], 1)             # only one target -> one lane
        self.assertEqual(rates, [80])                  # full rate to the single lane
        Path(res["run_dir"])
        import shutil
        shutil.rmtree(res["run_dir"], ignore_errors=True)

    def test_per_lane_rate_never_below_one(self):
        res, rates, active, lanes = self._run(["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                                              lanes=6, max_rate=2)
        self.assertTrue(all(r >= 1 for r in rates))    # max(1, ...) guard
        import shutil
        shutil.rmtree(res["run_dir"], ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
