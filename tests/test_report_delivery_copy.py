"""Windows delivery copies complete run evidence without changing the Kali source."""
import json
from pathlib import Path
import tempfile
import unittest

from report_delivery import deliver, latest_since


class ReportCopyTests(unittest.TestCase):
    def test_verified_copy_is_idempotent_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            source=base/'runs'/'Example_20260927_abc'
            (source/'targets'/'example'/'raw').mkdir(parents=True)
            (source/'engagement.json').write_text('{"schema":8}',encoding='utf-8')
            (source/'REPORT.html').write_text('<h1>Report</h1>',encoding='utf-8')
            (source/'targets'/'example'/'raw'/'proof.txt').write_text('evidence',encoding='utf-8')
            destination=base/'windows'
            result=deliver(source,destination)
            self.assertEqual(result['status'],'copied')
            self.assertEqual(result['files'],3)
            self.assertEqual(deliver(source,destination)['status'],'already_verified')
            (destination/source.name/'REPORT.html').write_text('changed',encoding='utf-8')
            with self.assertRaises(ValueError):
                deliver(source,destination)
            self.assertEqual((source/'REPORT.html').read_text(),'<h1>Report</h1>')

    def test_latest_only_selects_a_new_completed_report(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            source=base/'run'
            source.mkdir()
            (source/'engagement.json').write_text(json.dumps({
                'started_at':'2026-09-27T10:00:00+00:00'}),encoding='utf-8')
            (source/'REPORT.html').write_text('report',encoding='utf-8')
            index=base/'run-locations.json'
            index.write_text(json.dumps([str(source)]),encoding='utf-8')
            self.assertIsNone(latest_since(index,'2026-09-27T10:01:00+00:00'))
            self.assertEqual(latest_since(index,'2026-09-27T09:59:00+00:00'),source)
            self.assertEqual(latest_since(index,'2026-09-27T10:00:00.900000+00:00'),source)

    def test_symlink_in_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            base=Path(folder)
            source=base/'run';source.mkdir()
            (source/'engagement.json').write_text('{}')
            (source/'shortcut').symlink_to(source/'engagement.json')
            with self.assertRaises(ValueError):
                deliver(source,base/'destination')


if __name__=='__main__':
    unittest.main()
