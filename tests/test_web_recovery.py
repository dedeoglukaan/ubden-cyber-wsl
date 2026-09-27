"""HTTP observations retain TLS identity failures and tool diagnostics."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import wizard


class WebRecoveryTests(unittest.TestCase):
    def test_ip_certificate_mismatch_retries_pinned_headers_then_bounded_get(self):
        with tempfile.TemporaryDirectory() as folder:
            raw=Path(folder)/'targets'/'ip'/'raw';raw.mkdir(parents=True)
            args=['curl','--head','--output','-','--resolve',
                  '192.0.2.5:443:192.0.2.5','https://192.0.2.5/']
            events=[]
            with patch.object(wizard,'command',side_effect=[{'exit_code':52},{'exit_code':0}]) as run:
                result=wizard.recover_http_probe('headers_ip_https_443',args,
                    {'exit_code':60},raw,events,'192.0.2.5','192.0.2.5','https',True)
            self.assertEqual(result['exit_code'],0)
            self.assertEqual(events[0]['step'],'tls_identity')
            self.assertIn('--insecure',run.call_args_list[0].args[1])
            get_args=run.call_args_list[1].args[1]
            self.assertIn('--resolve',get_args)
            self.assertIn('--max-filesize',get_args)
            self.assertEqual(get_args[get_args.index('--output')+1],os.devnull)
            self.assertNotIn('--head',get_args)

    def test_named_target_never_uses_insecure_retry(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(wizard,'command') as run:
                wizard.recover_http_probe('headers',[],{'exit_code':60},Path(folder),[],
                    'app.example.test','192.0.2.5','https',True)
            run.assert_not_called()

    def test_failed_retry_preserves_its_error_detail(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(wizard,'command',return_value={
                'exit_code':52,'status':'error','detail':'Baglanti kuruldu fakat HTTP yaniti bos'}):
                result=wizard.recover_http_probe('headers', ['curl','https://192.0.2.5/'],
                    {'exit_code':60},Path(folder),[],'192.0.2.5','192.0.2.5','https')
            self.assertEqual(result['status'],'error')
            self.assertIn('HTTP yaniti bos',result['detail'])

    def test_zero_exit_with_nikto_usage_error_or_nuclei_error_is_not_success(self):
        class Process:
            def wait(self,timeout=None): return 0
        with tempfile.TemporaryDirectory() as folder:
            raw=Path(folder)/'targets'/'ip'/'raw';raw.mkdir(parents=True)
            output=iter(['Value "5s" invalid for option timeout\n',
                '[ERR] Could not read nuclei-ignore file: missing\n[INF] Templates loaded: 12\n'])
            def start(argv,stdout=None,**kwargs):
                stdout.write(next(output));stdout.flush()
                return Process()
            events=[]
            with patch.object(wizard.shutil,'which',return_value='/usr/bin/tool'), \
                 patch.object(wizard.subprocess,'Popen',side_effect=start), \
                 patch.object(wizard,'recorded_tool_version',return_value='test'), \
                 patch.object(wizard,'web_budget_wait'), \
                 patch.object(wizard.UI,'result'):
                nikto=wizard.command('nikto_test',['nikto','-timeout','5s'],raw,events,5)
                nuclei=wizard.command('nuclei_test',['nuclei','-u','https://192.0.2.5/'],raw,events,5)
            self.assertEqual(nikto['status'],'error')
            self.assertEqual(nuclei['status'],'warning')


if __name__=='__main__':
    unittest.main()
