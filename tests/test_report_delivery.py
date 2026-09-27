"""A header observation must not crash technical PDF or prevent linked HTML."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import report_v2


class ReportDeliveryTests(unittest.TestCase):
    def test_tls_certificate_observation_keeps_port_and_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw=root/'targets'/'192.0.2.5'/'raw';raw.mkdir(parents=True)
            (raw/'audit_192.0.2.5.xml').write_text('''<nmaprun><host><address addr="192.0.2.5" addrtype="ipv4"/><ports><port portid="443"><script id="ssl-cert" output="Subject: commonName=*.example.test&#10;Not valid after: 2026-11-29T04:38:47"/></port></ports></host></nmaprun>''',encoding='utf-8')
            lines=report_v2.platform_lines(root,{'schema':8},[])
            self.assertTrue(any('192.0.2.5:443' in line and 'commonName=*.example.test' in line
                                and 'audit_192.0.2.5.xml' in line for line in lines))

    def test_old_zero_exit_tool_failure_is_reclassified_without_changing_steps(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root)
            raw=root/'targets'/'example.test'/'raw'
            evidence=raw/'nikto_example.txt'
            evidence.write_text('Value "5s" invalid for option timeout\n',encoding='utf-8')
            original=[{'step':'nikto_example','tool':'nikto','status':'ok','exit_code':0,
                       'output':str(evidence.relative_to(root))}]
            (root/'steps.json').write_text(json.dumps(original),encoding='utf-8')
            revised,audit=report_v2.audit_recorded_steps(root,original)
            self.assertEqual(revised[0]['status'],'error')
            self.assertEqual(audit[0]['original_status'],'ok')
            self.assertEqual(json.loads((root/'steps.json').read_text()),original)
            with patch.object(sys,'argv',['report_v2.py',str(root)]):
                report_v2.main()
            self.assertTrue((root/'STEP_AUDIT.json').is_file())
            self.assertIn('Yeniden değerlendirme kaydı',(root/'REPORT.html').read_text())

    def fixture(self,root):
        (root/'engagement.json').write_text(json.dumps({
            'client':'Example','project':'Report QA','tester':'Analyst',
            'targets':['example.test'],'profile':'web','status':'completed_with_errors'}))
        raw=root/'targets'/'example.test'/'raw'
        raw.mkdir(parents=True)
        evidence=raw/'headers_192.0.2.5_https_443.txt'
        evidence.write_text('HTTP/1.1 200 OK\nContent-Type: text/html\n',encoding='utf-8')
        relative=str(evidence.relative_to(root))
        (root/'steps.json').write_text(json.dumps([{
            'step':'headers_192.0.2.5_https_443','status':'ok','output':relative,'seconds':0.2}]))
        return relative

    def test_automatic_findings_generate_both_pdfs_and_linked_html(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            relative=self.fixture(root)
            with patch.object(sys,'argv',['report_v2.py',str(root)]):
                report_v2.main()
            self.assertGreater((root/'TEKNIK_RAPOR.pdf').stat().st_size,1000)
            self.assertGreater((root/'YONETICI_OZETI.pdf').stat().st_size,1000)
            document=(root/'REPORT.html').read_text()
            self.assertIn('href="'+relative+'"',document)
            self.assertIn('id="bulgu-1"',document)
            self.assertIn('href="#bulgu-1"',document)
            self.assertIn('href="TEKNIK_RAPOR.pdf"',document)

    def test_links_reject_traversal_and_script_injection(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'proof.txt').write_text('evidence')
            (root/'link.txt').symlink_to(root/'proof.txt')
            self.assertIn('href="proof.txt"',report_v2.evidence_link(root,'proof.txt'))
            for name in ('../secret.txt','/etc/passwd','link.txt','<img src=x onerror=alert(1)>'):
                self.assertNotIn('href=',report_v2.evidence_link(root,name))
            self.assertIn('&lt;img',report_v2.evidence_link(root,'<img src=x onerror=alert(1)>'))

    def test_html_survives_a_pdf_failure_and_explains_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            self.fixture(root)
            real_pdf=report_v2.pdf
            def fail_technical(*args,**kwargs):
                if args[1].startswith('.TEKNIK_RAPOR'):
                    raise RuntimeError('simulated PDF failure')
                return real_pdf(*args,**kwargs)
            with patch.object(report_v2,'pdf',side_effect=fail_technical), \
                    patch.object(sys,'argv',['report_v2.py',str(root)]):
                with self.assertRaises(SystemExit):
                    report_v2.main()
            document=(root/'REPORT.html').read_text()
            self.assertIn('PDF üretim hatası',document)
            self.assertNotIn('href="TEKNIK_RAPOR.pdf"',document)
            self.assertIn('href="YONETICI_OZETI.pdf"',document)


if __name__=='__main__': unittest.main()
