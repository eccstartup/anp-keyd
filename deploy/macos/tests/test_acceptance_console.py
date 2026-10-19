"""Console transitions must be real, bounded and independently checked while away."""
import sys
from pathlib import Path
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'acceptance'))

from acceptance_console import wait_user_switch


class ConsoleTransition(unittest.TestCase):
    def run_transition(self, users, times, check=None):
        users, times = iter(users), iter(times)
        return wait_user_switch(501, check or Mock(), read_uid=lambda: next(users),
            clock=lambda: next(times), pause=lambda _: None)

    def test_other_desktop_checked_before_return(self):
        check = Mock()
        self.assertEqual(self.run_transition([501, 502, 502, 501], [0, 1, 7, 8], check), 502)
        check.assert_called_once_with()

    def test_lock_screen_without_other_user_does_not_pass(self):
        for users in ([501, 501, 501], [501, 0, 501], [501, 0xffffffff, 501]):
            with self.subTest(users=users), self.assertRaisesRegex(ValueError, 'within 90 seconds'):
                self.run_transition(users, [0, 1, 2, 91])

    def test_wrong_initial_user_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'initially own'):
            self.run_transition([502], [0])

    def test_too_fast_return_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'before six seconds'):
            self.run_transition([501, 502, 501], [0, 1, 2])

    def test_third_user_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'third console user'):
            self.run_transition([501, 502, 503], [0, 1, 2])

    def test_clock_rollback_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'backwards'):
            self.run_transition([501, 502], [0, 2, 1])

    def test_away_failure_stops_acceptance(self):
        check = Mock(side_effect=ValueError('cached signature still returned'))
        with self.assertRaisesRegex(ValueError, 'cached signature still returned'):
            self.run_transition([501, 502, 502], [0, 1, 7], check)

    def test_login_window_time_does_not_count_as_other_desktop(self):
        with self.assertRaisesRegex(ValueError, 'before six seconds'):
            self.run_transition([501, 502, 0, 0, 502, 501], [0, 1, 2, 8, 9, 10])
