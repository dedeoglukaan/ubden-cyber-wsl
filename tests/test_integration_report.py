"""Kali gerektirmeyen uçtan uca rapor boru hattı entegrasyon testi.

Gerçek wizard→report_v2 çağrısını birebir taklit eder: bir görev fikstürü kurar,
`python report_v2.py <dizin>`'i UBDEN_OFFLINE ile alt süreç olarak çalıştırır ve
tüm zenginleştirme çıktılarının (OSINT, teknoloji tespiti, CVE, korelasyon,
kapsam, analist planı, PDF+HTML) üretildiğini ve beklenen bölümleri içerdiğini
doğrular. Ağ/araç/hedef gerekmez.
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _nmap_xml(ip, ports):
    body = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open"/>'
        f'<service name="{s}"{" product=\"%s\"" % prod if prod else ""}{" version=\"%s\"" % ver if ver else ""}/></port>'
        for p, s, prod, ver in ports)
    return (f'<?xml version="1.0"?><nmaprun><host><address addr="{ip}" addrtype="ipv4"/>'
            f'<ports>{body}</ports></host></nmaprun>')


class ReportPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "engagement.json").write_text(json.dumps({
            "id": "intdemo01", "client": "Örnek A.Ş.", "project": "Entegrasyon",
            "tester": "UBDEN", "authorization_reference": "BT-TEST",
            "profile": "full", "status": "completed",
            "started_at": "2026-09-27T09:00:00+00:00", "finished_at": "2026-09-27T12:00:00+00:00",
            "targets": ["45.33.32.0/24", "portal.ornek.com"], "exclusions": [],
            "max_rate": 250, "top_ports": 1000, "schema": 9}, ensure_ascii=False), encoding="utf-8")
        (self.dir / "review.json").write_text(json.dumps({
            "analyst_summary": "Entegrasyon testi.", "findings": [], "cases": []},
            ensure_ascii=False), encoding="utf-8")
        # Public IP'de FortiGate (internet maruziyeti + platform tespiti).
        raw = self.dir / "targets" / "45.33.32.10" / "raw"
        raw.mkdir(parents=True)
        (raw / "nmap_45.33.32.10.xml").write_text(
            _nmap_xml("45.33.32.10", [(443, "https", "", ""), (10443, "https-alt", "", "")]), encoding="utf-8")
        (raw / "headers_45.33.32.10_https_443.txt").write_text(
            "HTTP/1.1 200 OK\r\nServer: FortiGate\r\nX-Version: FortiOS v7.2.4\r\n", encoding="utf-8")
        # Alan adı hedefi için DMARC kaydı yok → sahtelenebilir (OSINT).
        draw = self.dir / "targets" / "portal.ornek.com" / "raw"
        draw.mkdir(parents=True)
        (draw / "dns_dmarc.txt").write_text("", encoding="utf-8")

    def test_full_pipeline_offline(self):
        env = dict(os.environ, UBDEN_OFFLINE="1", PYTHONIOENCODING="utf-8")
        result = subprocess.run([sys.executable, str(REPO / "report_v2.py"), str(self.dir)],
                                capture_output=True, text=True, env=env, cwd=str(REPO), timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        for name in ("UBDEN_OSINT.json", "UBDEN_TECH_PROFILE.json", "UBDEN_CVE.json",
                     "UBDEN_CORRELATION.json", "ASSESSMENT_COVERAGE.json",
                     "ANALIST_GOREV_RAPORU.json", "REPORT.html",
                     "YONETICI_OZETI.pdf", "TEKNIK_RAPOR.pdf"):
            self.assertTrue((self.dir / name).is_file(), f"eksik çıktı: {name}")

        tech = json.loads((self.dir / "UBDEN_TECH_PROFILE.json").read_text(encoding="utf-8"))
        forti = next(m for m in tech["matches"] if "FortiGate" in m["family"])
        self.assertEqual(forti["version"], "7.2.4")

        corr = json.loads((self.dir / "UBDEN_CORRELATION.json").read_text(encoding="utf-8"))
        titles = [c["title"] for c in corr["correlations"]]
        self.assertTrue(any("İnternete açık yönetim düzlemi" in t for t in titles))

        osint = json.loads((self.dir / "UBDEN_OSINT.json").read_text(encoding="utf-8"))
        self.assertTrue(osint["email_spoofable"])

        cve = json.loads((self.dir / "UBDEN_CVE.json").read_text(encoding="utf-8"))
        self.assertIn("UBDEN_OFFLINE", cve["note"])  # ağ çağrısı yapılmadı

        html = (self.dir / "REPORT.html").read_text(encoding="utf-8")
        self.assertIn("Teknoloji ve platform tespiti", html)
        self.assertIn("Çapraz-katman maruziyet", html)


if __name__ == "__main__":
    unittest.main()
