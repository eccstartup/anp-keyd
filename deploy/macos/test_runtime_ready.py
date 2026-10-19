"""Startup readiness must survive stale crash sockets without retrying signing."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('runtime_ready', Path(__file__).with_name('test-runtime.py'))
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

class Ready(unittest.TestCase):
    def test_refused_stale_socket_does_not_mean_ready(self):
        probe = Mock(side_effect=[SimpleNamespace(returncode=1, stderr='Connection refused'),
            SimpleNamespace(returncode=0, stdout=json.dumps({'instance_id': 'expected'}))])
        with patch.object(runtime.time, 'sleep'):
            runtime.wait_ready(SimpleNamespace(poll=lambda: None), probe, 'expected')
        self.assertEqual(probe.call_count, 2)

    def test_wrong_instance_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'instance mismatch'):
            runtime.wait_ready(SimpleNamespace(poll=lambda: None),
                lambda: SimpleNamespace(returncode=0, stdout='{"instance_id":"other"}'), 'expected')

    def test_dead_process_is_not_retried(self):
        probe = Mock()
        with self.assertRaisesRegex(ValueError, 'failed to start'):
            runtime.wait_ready(SimpleNamespace(poll=lambda: -9), probe, 'expected')
        probe.assert_not_called()

    def test_never_ready_is_bounded(self):
        with patch.object(runtime.time, 'monotonic', side_effect=[0, 11]):
            with self.assertRaisesRegex(ValueError, 'timed out'):
                runtime.wait_ready(SimpleNamespace(poll=lambda: None), Mock(), 'expected')
