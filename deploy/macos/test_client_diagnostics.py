"""Client timeout diagnostics identify phases without echoing request contents."""
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import acceptance_signing


class ClientDiagnostics(unittest.TestCase):
    def test_timeout_keeps_phase_and_subject_without_request_body(self):
        checks = acceptance_signing.Checks(Path('/tmp'),
            {'sign_socket':'/not-a-real-socket', 'service_uid':600}, None,
            SimpleNamespace(), None, None, None, lambda *args: {}, {}, None)
        failure = subprocess.TimeoutExpired(['client'],20,
            stderr=b'CLIENT_STAGE interpreter-started\nCLIENT_STAGE input-read\n')
        with patch.object(acceptance_signing.subprocess, 'run', side_effect=failure):
            with self.assertRaises(ValueError) as caught:
                checks.request_as(SimpleNamespace(pw_uid=601),
                    {'operation':'SIGN_HTTP','sensitive_body':'not-for-logs'})
        message = str(caught.exception)
        self.assertIn('uid=601',message)
        self.assertIn('operation=SIGN_HTTP',message)
        self.assertIn('input-read',message)
        self.assertNotIn('not-for-logs',message)

    def test_timeout_before_interpreter_start_has_no_fabricated_stage(self):
        checks = acceptance_signing.Checks(Path('/tmp'),
            {'sign_socket':'/not-a-real-socket', 'service_uid':600}, None,
            SimpleNamespace(), None, None, None, lambda *args: {}, {}, None)
        with patch.object(acceptance_signing.subprocess, 'run',
                side_effect=subprocess.TimeoutExpired(['client'],20)):
            with self.assertRaisesRegex(ValueError,"stages=''" ):
                checks.request_as(SimpleNamespace(pw_uid=601),{'operation':'LIST_AUTHORIZED_KEYS'})
