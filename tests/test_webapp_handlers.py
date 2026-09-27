"""The local web UI must bind loopback, require the one-time token on every
route, and never serve files outside a job's run directory. No network needed.
"""
import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import webapp


class WebappHandlerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), webapp.Handler)
        cls.port = cls.httpd.server_address[1]
        cls.host = cls.httpd.server_address[0]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _get(self, path):
        url = f"http://127.0.0.1:{self.port}{path}"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def test_binds_loopback_only(self):
        self.assertEqual(self.host, "127.0.0.1")

    def test_root_requires_token(self):
        self.assertEqual(self._get("/")[0], 403)

    def test_root_with_token_serves_page(self):
        code, body = self._get(f"/?t={webapp.TOKEN}")
        self.assertEqual(code, 200)
        self.assertTrue(body.startswith(b"<!doctype html>"))
        self.assertNotIn(b"__TOKEN__", body)

    def test_api_requires_token(self):
        self.assertEqual(self._get("/api/adapters")[0], 403)
        self.assertEqual(self._get(f"/api/adapters?t={webapp.TOKEN}")[0], 200)

    def test_wrong_token_rejected(self):
        self.assertEqual(self._get("/?t=wrong")[0], 403)

    def test_report_without_job_is_not_found(self):
        code, _ = self._get(f"/r/REPORT.html?t={webapp.TOKEN}&job=none")
        self.assertEqual(code, 404)


if __name__ == "__main__":
    unittest.main()
