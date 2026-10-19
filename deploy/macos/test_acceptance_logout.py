"""Logout requires a new graphical audit session, not just console UID changes."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch, call
from types import SimpleNamespace

from acceptance_console import wait_logout
import acceptance_graphical as graphical

spec = importlib.util.spec_from_file_location('logout_launcher', Path(__file__).with_name('launch-logout-test.py'))
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class Logout(unittest.TestCase):
    def run_logout(self, users, times, session=200, check=None):
        users, times = iter(users), iter([*times, times[-1]])
        return wait_logout(501, 100, check or Mock(), lambda: session,
            read_uid=lambda: next(users), clock=lambda: next(times), pause=lambda _: None)

    def test_new_session_after_checks_at_login_window(self):
        check = Mock()
        self.assertEqual(self.run_logout([501, 0, 0, 501], [0, 1, 7, 8], check=check), 200)
        check.assert_called_once_with()

    def test_fast_user_switch_back_is_not_logout(self):
        with self.assertRaisesRegex(ValueError, 'did not change'):
            self.run_logout([501, 0, 0, 501], [0, 1, 7, 8], session=100)

    def test_other_desktop_is_not_logout(self):
        with self.assertRaisesRegex(ValueError, 'unexpected console UID'):
            self.run_logout([501, 504], [0, 1])

    def test_invalid_new_audit_session_is_refused(self):
        for value in (0, 0xffffffff):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'did not change'):
                self.run_logout([501, 0, 0, 501], [0, 1, 7, 8], session=value)

    def test_login_too_soon_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'at least six seconds'):
            self.run_logout([501, 0, 501], [0, 1, 2])

    def test_no_transition_is_bounded(self):
        with self.assertRaisesRegex(ValueError, 'within 90 seconds'):
            self.run_logout([501, 501], [0, 1, 91])

    def test_clock_rollback_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'backwards'):
            self.run_logout([501, 0], [0, 2, 1])

    def test_away_check_failure_stops_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'old authority remains'):
            self.run_logout([501, 0, 0], [0, 1, 7],
                check=Mock(side_effect=ValueError('old authority remains')))

    def test_initial_console_must_be_administrator(self):
        with self.assertRaisesRegex(ValueError, 'initially own'):
            self.run_logout([504], [0])


class SystemJob(unittest.TestCase):
    def test_diagnostic_job_selects_no_logout_diagnostic_branch(self):
        spec = launcher.job_spec(Path('/Library/ANPKeydLogoutChecks-test'),
            Path('/usr/bin/python3'), [], diagnostic=True)
        self.assertIn('--logout-diagnostics', spec['ProgramArguments'])
        self.assertFalse(spec['KeepAlive'])

    def test_one_shot_root_system_job_has_no_restart_or_boot_install(self):
        stage = Path('/Library/ANPKeydLogoutChecks-example')
        job = launcher.job_spec(stage, Path('/usr/bin/python3'), ['--candidate-binary', '/fixture'])
        self.assertFalse(job['KeepAlive'])
        self.assertTrue(job['LaunchOnlyOnce'])
        self.assertEqual(job['WorkingDirectory'], '/')
        self.assertNotIn('UserName', job)  # root runner drops each child's credentials
        self.assertEqual(job['ProgramArguments'][3:5], ['--se-ending', 'logout'])
        self.assertEqual(job['StandardOutPath'], str(stage / 'host.log'))
        self.assertEqual(job['StandardErrorPath'], str(stage / 'host.log'))


class GraphicalBridge(unittest.TestCase):
    def state(self):
        return {'UID':501, 'SessionInfo':[{'kCGSSessionUserIDKey':501,
            'kCGSSessionOnConsoleKey':True, 'kCGSessionLoginDoneKey':True,
            'kCGSSessionAuditIDKey':105604, 'kSCSecuritySessionID':105604}]}

    def test_native_console_requires_unique_active_completed_exact_user(self):
        import copy
        state = self.state()
        self.assertEqual(graphical.console_session_id(state, 501), 105604)
        bad = []
        wrong = copy.deepcopy(state); wrong['UID'] = 504; bad.append(wrong)
        duplicate = copy.deepcopy(state); duplicate['SessionInfo'] *= 2; bad.append(duplicate)
        for field, value in [('kCGSSessionUserIDKey',504), ('kCGSSessionOnConsoleKey',False),
                ('kCGSessionLoginDoneKey',False), ('kSCSecuritySessionID',100),
                ('kCGSSessionAuditIDKey',0), ('kCGSSessionAuditIDKey',True)]:
            wrong = copy.deepcopy(state); wrong['SessionInfo'][0][field] = value; bad.append(wrong)
        for item in bad:
            with self.assertRaises(ValueError):
                graphical.console_session_id(item, 501)

    def test_native_readiness_does_not_spawn_any_subprocess(self):
        with patch.object(graphical, 'console_state', side_effect=[ValueError('not ready'),self.state()]), \
             patch.object(graphical, 'current_session', return_value=105604) as validate, \
             patch.object(graphical.subprocess, 'run') as run, \
             patch.object(graphical.time, 'sleep'):
            self.assertEqual(graphical.relogin_session(SimpleNamespace(pw_uid=501)),105604)
        validate.assert_called_once_with(105604)
        run.assert_not_called()

    def test_bootstrap_readiness_deadline_is_bounded(self):
        with patch.object(graphical.time, 'monotonic', side_effect=[0, 21]):
            with self.assertRaisesRegex(ValueError, 'readiness timed out'):
                graphical.relogin_session(SimpleNamespace(pw_uid=501))

    def test_drops_credentials_before_exec(self):
        with patch.object(graphical.os, 'geteuid', return_value=0), \
             patch.object(graphical.sys, 'argv', ['bridge', '/config', '501', '/helper', 'generate-se']), \
             patch.object(graphical.Path, 'read_text', return_value='{"admin_uids":[501],"admin_gid":602}'), \
             patch.object(graphical.pwd, 'getpwuid', return_value=SimpleNamespace(pw_gid=20)), \
             patch.object(graphical, 'current_session', return_value=123), \
             patch.object(graphical.os, 'setgroups') as groups, \
             patch.object(graphical.os, 'setgid') as gid, \
             patch.object(graphical.os, 'setuid') as uid, \
             patch.object(graphical.os, 'execv') as execute:
            ordering = Mock()
            for name, item in [('groups', groups), ('gid', gid), ('uid', uid), ('execute', execute)]:
                ordering.attach_mock(item, name)
            graphical.main()
        self.assertEqual(ordering.mock_calls, [call.groups([20, 602]), call.gid(20),
            call.uid(501), call.execute('/helper', ['/helper', 'generate-se'])])

    def test_nonadministrator_and_root_targets_are_refused(self):
        for target in ('0', '601'):
            with patch.object(graphical.os, 'geteuid', return_value=0), \
                 patch.object(graphical.sys, 'argv', ['bridge', '/config', target, '/helper']), \
                 patch.object(graphical.Path, 'read_text', return_value='{"admin_uids":[501]}'):
                with self.assertRaisesRegex(ValueError, 'configured non-root administrator'):
                    graphical.main()
