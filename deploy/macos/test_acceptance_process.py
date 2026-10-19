"""Exercise real diagnostic child execution and timeout without credentials or SE."""
import os
import sys
import unittest

from acceptance_process import execute


class ProcessExecution(unittest.TestCase):
    def request(self, source, input=None, timeout=5):
        return {'argv':[sys.executable,'-I','-c',source], 'credentials':{},
                'env':{'PATH':'/usr/bin:/bin'},'input':input,'timeout':timeout}

    def test_real_child_preserves_input_output_and_exit(self):
        result = execute(self.request('import sys; print(sys.stdin.read()); '
            'print("stage-marker",file=sys.stderr);sys.exit(7)',input='fixture-only'),sample=False)
        self.assertEqual(result, {'returncode':7,'stdout':'fixture-only\n','stderr':'stage-marker\n'})

    def test_timeout_keeps_stderr_and_reaps_real_child(self):
        result = execute(self.request('import sys,time;print("started",file=sys.stderr,flush=True);'
            'time.sleep(30)',timeout=.2),sample=False)
        self.assertTrue(result['timeout'])
        self.assertEqual(result['stderr'],'started\n')
        with self.assertRaises(ProcessLookupError):
            os.kill(result['pid'],0)

    def test_real_child_still_reports_actual_uid(self):
        result = execute(self.request('import os;print(os.getuid())'),sample=False)
        self.assertEqual(int(result['stdout']),os.getuid())
