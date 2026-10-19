"""Exercise real diagnostic child execution and timeout without credentials or SE."""
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock, patch, call
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

from acceptance_process import execute, credential_exec


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

    @unittest.skipUnless(getattr(subprocess, '_USE_POSIX_SPAWN', False), 'posix_spawn unavailable')
    def test_actual_child_uses_posix_spawn(self):
        original = subprocess.Popen._posix_spawn
        calls = []
        def observed(process, *args, **kwargs):
            calls.append(True)
            return original(process, *args, **kwargs)
        with patch.object(subprocess.Popen, '_posix_spawn', observed):
            result = execute(self.request('print("spawned")'),sample=False)
        self.assertEqual(result['stdout'],'spawned\n')
        self.assertEqual(calls,[True])

    def test_explicit_credential_drop_preserves_primary_first_order_before_exec(self):
        creds = {'user':501,'group':20,'extra_groups':[20,602]}
        with patch('acceptance_process.os.geteuid',return_value=0), \
             patch('acceptance_process.os.getuid',return_value=501), \
             patch('acceptance_process.os.getgid',return_value=20), \
             patch('acceptance_process.os.setgroups') as groups, \
             patch('acceptance_process.os.setregid') as gid, \
             patch('acceptance_process.os.setreuid') as uid, \
             patch('acceptance_process.os.execve') as execute_child, \
             patch('acceptance_process.sys.stderr'):
            sequence = Mock()
            for name, method in [('groups',groups),('gid',gid),('uid',uid),('exec',execute_child)]:
                sequence.attach_mock(method,name)
            credential_exec(creds,['/fixture','status'])
        self.assertEqual(sequence.mock_calls[:3],[call.groups([20,602]),call.gid(20,20),call.uid(501,501)])
        self.assertEqual(sequence.mock_calls[3].args[:2],('/fixture',['/fixture','status']))

    def test_unprivileged_wrapper_cannot_attempt_credential_change(self):
        with patch('acceptance_process.os.geteuid',return_value=501), \
             patch('acceptance_process.os.setgroups') as groups:
            with self.assertRaises(ValueError):
                credential_exec({'user':601,'group':601,'extra_groups':[601]},['/fixture'])
        groups.assert_not_called()
