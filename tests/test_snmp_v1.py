"""Read-only SNMPv1/public probe and evidence attribution."""
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import wizard
import report_v2


class SnmpTests(unittest.TestCase):
    def test_only_positive_v1_public_response_creates_draft_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            raw=root/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            (root/'engagement.json').write_text(json.dumps({'targets':['192.0.2.0/24'],
                'client':'Example','project':'SNMP QA','tester':'Tester','status':'completed','profile':'network'}))
            calls=[];events=[]
            def run(args,**kwargs):
                calls.append(args)
                ip=args[-2]
                return types.SimpleNamespace(returncode=0 if ip=='192.0.2.5' else 1,
                    stdout='Example Router OS 1.0\n' if ip=='192.0.2.5' else '',stderr='')
            with patch.object(wizard,'_PURESNMP',None), \
                    patch.object(wizard.shutil,'which',return_value='/usr/bin/snmpget'), \
                    patch.object(wizard.subprocess,'run',side_effect=run):
                wizard.probe_snmp('192.0.2.0/24',['192.0.2.5','192.0.2.37'],raw,events,20)
            self.assertEqual([row[1:5] for row in calls],[['-v1','-c','public','-t']]*2)
            summary=json.loads((raw/'snmp_v1_public_summary.json').read_text(encoding='utf-8'))
            self.assertEqual(summary['responding_count'],1)
            self.assertEqual(summary['tested_count'],2)
            self.assertFalse((raw/'snmp_v1_public_192.0.2.37.json').exists())
            self.assertEqual(events[0]['status'],'ok')
            (root/'steps.json').write_text(json.dumps(events))
            *_,findings,_=report_v2.read_data(root)
            self.assertEqual(len(findings),1)
            self.assertEqual(findings[0]['asset'],'192.0.2.5')
            self.assertEqual(findings[0]['status'],'taslak')
            self.assertIn('public',findings[0]['title'])
            with patch.object(sys,'argv',['report_v2.py',str(root)]):
                report_v2.main()
            self.assertIn('SNMPv1 / public kontrolü',(root/'REPORT.html').read_text(encoding='utf-8'))
            self.assertTrue((root/'TEKNIK_RAPOR.pdf').stat().st_size>1000)

    def test_missing_tool_records_skipped_without_stopping(self):
        with tempfile.TemporaryDirectory() as folder:
            raw=Path(folder)/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            events=[]
            # Neither puresnmp nor the snmpget binary available -> missing_tool.
            with patch.object(wizard,'_PURESNMP',None), \
                    patch.object(wizard.shutil,'which',return_value=None):
                wizard.probe_snmp('192.0.2.0/24',['192.0.2.5'],raw,events,20)
            self.assertEqual(events[0]['status'],'missing_tool')

    def test_puresnmp_backend_records_v2c_and_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            raw=Path(folder)/'targets'/'192.0.2.0_24'/'raw';raw.mkdir(parents=True)
            events=[]
            def fake_get(ip,community,oid,timeout=2):
                if ip=='192.0.2.5':
                    return 'Example Router OS 1.0'
                raise OSError('timeout')
            fake_mod=types.SimpleNamespace(get=fake_get)
            with patch.object(wizard,'_PURESNMP',fake_mod):
                wizard.probe_snmp('192.0.2.0/24',['192.0.2.5','192.0.2.37'],raw,events,20)
            summary=json.loads((raw/'snmp_v1_public_summary.json').read_text(encoding='utf-8'))
            self.assertEqual(summary['responding_count'],1)
            ev=json.loads((raw/'snmp_v1_public_192.0.2.5.json').read_text(encoding='utf-8'))
            self.assertEqual(ev['version'],'2c')
            self.assertEqual(ev['community'],'public')
            self.assertTrue(ev['confirmed_response'])


if __name__=='__main__': unittest.main()
