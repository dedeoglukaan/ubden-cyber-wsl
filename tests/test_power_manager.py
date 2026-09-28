"""Keep-awake / high-performance power manager — host-safe (all Windows effects mocked)."""
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import power_manager


def _fake_run(stdout="", returncode=0):
    return types.SimpleNamespace(stdout=stdout, returncode=returncode, stderr="")


class NoOpOffWindowsTests(unittest.TestCase):
    def test_all_calls_are_noops_off_windows(self):
        with patch.object(power_manager, "_is_windows", return_value=False):
            self.assertFalse(power_manager.stay_awake())
            self.assertEqual(power_manager.active_scheme(), "")
            self.assertEqual(power_manager.high_performance(), "")
            power_manager.release()          # must not raise
            power_manager.restore_scheme("x")  # must not raise

    def test_keepawake_is_safe_off_windows(self):
        with patch.object(power_manager, "_is_windows", return_value=False):
            with power_manager.KeepAwake(high_perf=True):
                pass  # no exception, no host effect


class WindowsLogicTests(unittest.TestCase):
    def test_active_scheme_parses_guid(self):
        out = "Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)"
        with patch.object(power_manager, "_is_windows", return_value=True), \
                patch.object(power_manager, "_run", return_value=_fake_run(out)):
            self.assertEqual(power_manager.active_scheme(), "381b4222-f694-41f0-9685-ff5bb260df2e")

    def test_high_performance_returns_previous_and_sets(self):
        calls = []

        def run(args, timeout=15):
            calls.append(args)
            if "/getactivescheme" in args:
                return _fake_run("Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)")
            return _fake_run("", 0)  # setactive succeeds on first (ultimate) try

        with patch.object(power_manager, "_is_windows", return_value=True), \
                patch.object(power_manager, "_run", side_effect=run):
            prev = power_manager.high_performance()
        self.assertEqual(prev, "381b4222-f694-41f0-9685-ff5bb260df2e")
        self.assertTrue(any("/setactive" in c for c in calls))

    def test_high_performance_falls_back_to_high_when_ultimate_absent(self):
        seen = []

        def run(args, timeout=15):
            if "/getactivescheme" in args:
                return _fake_run("GUID: 381b4222-f694-41f0-9685-ff5bb260df2e")
            seen.append(args[-1])
            return _fake_run("", 0 if args[-1] == power_manager.HIGH_PERFORMANCE else 1)

        with patch.object(power_manager, "_is_windows", return_value=True), \
                patch.object(power_manager, "_run", side_effect=run):
            power_manager.high_performance()
        self.assertIn(power_manager.ULTIMATE_PERFORMANCE, seen)  # tried first
        self.assertIn(power_manager.HIGH_PERFORMANCE, seen)      # fell back

    def test_keepawake_restores_previous_scheme(self):
        restored = []
        with patch.object(power_manager, "_is_windows", return_value=True), \
                patch.object(power_manager, "stay_awake", return_value=True) as sa, \
                patch.object(power_manager, "release") as rel, \
                patch.object(power_manager, "high_performance", return_value="PREV-GUID"), \
                patch.object(power_manager, "restore_scheme", side_effect=lambda g: restored.append(g)):
            power_manager._awake = False
            with power_manager.KeepAwake(high_perf=True):
                pass
        self.assertEqual(restored, ["PREV-GUID"])
        sa.assert_called()
        rel.assert_called()  # owned the awake request -> released it


if __name__ == "__main__":
    unittest.main()
