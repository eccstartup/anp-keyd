"""Fail-closed session transition tests, with no changes to the test process."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('session_policy', Path(__file__).with_name('security-session.py'))
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class SessionIsolation(unittest.TestCase):
    def api(self, **changes):
        old = {'audit_session': 100, 'audit_uid': 501, 'session_attributes': 0x10}
        new = {'audit_session': 200, 'audit_uid': 601, 'session_attributes': 0}
        new.update(changes)
        api = Mock()
        api.context.side_effect = [old, new]
        return api

    def test_creates_new_session_then_assigns_target_audit_uid(self):
        api = self.api()
        with patch.object(policy.os, 'geteuid', return_value=0):
            self.assertEqual(policy.isolate(601, api)['audit_uid'], 601)
        self.assertEqual([c[0] for c in api.mock_calls],
                         ['context', 'create', 'set_audit_uid', 'context'])
        api.set_audit_uid.assert_called_once_with(601)

    def test_inherited_session_wrong_user_or_privileged_attributes_are_refused(self):
        for changes in ({'audit_session': 100}, {'audit_session': 0},
                        {'audit_session': 0xffffffff}, {'audit_uid': 501},
                        {'session_attributes': 1}, {'session_attributes': 0x10},
                        {'session_attributes': 0x1000}):
            with self.subTest(changes=changes), patch.object(policy.os, 'geteuid', return_value=0):
                with self.assertRaises(ValueError):
                    policy.isolate(601, self.api(**changes))

    def test_creation_or_audit_uid_failure_has_no_fallback(self):
        for method in ('create', 'set_audit_uid'):
            api = self.api()
            getattr(api, method).side_effect = ValueError('denied')
            with patch.object(policy.os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(ValueError, 'denied'):
                    policy.isolate(601, api)

    def test_non_root_caller_and_root_target_refused(self):
        for euid, target in ((501, 601), (0, 0), (0, -1), (0, 0xffffffff)):
            api = self.api()
            with patch.object(policy.os, 'geteuid', return_value=euid):
                with self.assertRaises(ValueError):
                    policy.isolate(target, api)
            api.context.assert_not_called()


if __name__ == '__main__':
    unittest.main()
