import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ieee_registry


def make_csv(width, n=12):
    lines = ["Registry,Assignment,Organization Name,Organization Address"]
    for i in range(1, n + 1):
        lines.append("R,%s,Org%d,Addr" % (format(i, "0%dX" % width), i))
    return ("\n".join(lines) + "\n").encode("utf-8")


class _Resp:
    def __init__(self, data):
        self.data = data
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def read(self, n=-1):
        return self.data


class IeeeRegistryTests(unittest.TestCase):
    def test_prefers_local_ieee_data_without_download(self):
        tmp = Path(tempfile.mkdtemp())
        local = tmp / "ieee-data"
        local.mkdir()
        (local / "oui.csv").write_bytes(make_csv(6))
        (local / "mam.csv").write_bytes(make_csv(7))
        (local / "mas.csv").write_bytes(make_csv(9))
        called = []
        def opener(*a, **k):
            called.append(a)
            raise AssertionError("yerel varken indirme yapılmamalı")
        with patch.object(ieee_registry, "LOCAL_DIRS", (local,)):
            res = ieee_registry.refresh(tmp / "dest", opener=opener)
        self.assertTrue(all(res[n]["status"] == "ok" for n in ("oui.csv", "mam.csv", "mas.csv")))
        self.assertTrue(res["oui.csv"]["source"].endswith("oui.csv"))
        self.assertEqual(called, [])
        self.assertTrue((tmp / "dest" / "oui.csv").is_file())

    def test_downloads_with_user_agent_when_no_local(self):
        tmp = Path(tempfile.mkdtemp())
        seen = {}
        def opener(request, timeout=30):
            seen["ua"] = request.get_header("User-agent")
            return _Resp(make_csv(6))
        with patch.object(ieee_registry, "LOCAL_DIRS", ()):
            res = ieee_registry.refresh(tmp / "dest", opener=opener)
        self.assertEqual(res["oui.csv"]["status"], "ok")
        self.assertIn("UBDEN", seen["ua"])  # tarayıcı-benzeri UA gönderildi

    def test_invalid_response_is_unavailable_and_preserves_cache(self):
        tmp = Path(tempfile.mkdtemp())
        dest = tmp / "dest"
        dest.mkdir()
        (dest / "oui.csv").write_bytes(b"onceki")  # mevcut önbellek
        with patch.object(ieee_registry, "LOCAL_DIRS", ()):
            res = ieee_registry.refresh(dest, opener=lambda req, timeout=30: _Resp(b"wrong,columns\n"))
        self.assertEqual(res["oui.csv"]["status"], "unavailable")
        self.assertTrue(res["oui.csv"]["cached"])
        self.assertEqual((dest / "oui.csv").read_bytes(), b"onceki")  # önbellek korundu


if __name__ == "__main__":
    unittest.main()
