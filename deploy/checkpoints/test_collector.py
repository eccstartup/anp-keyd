#!/usr/bin/env python3
"""Keeper fault/concurrency tests use temporary stores and no real credentials."""
import json
import multiprocessing
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

import collector as keeper

INSTANCE = '12345678-1234-4234-8234-123456789abc'


def cp(sequence, digest='a'):
    return {'version': 1, 'instance_id': INSTANCE, 'sequence': sequence, 'digest': digest*64}


def crash_worker(directory, config, phase):
    def fetch(*_):
        if phase == 'fetched':
            os._exit(23)
        return cp(2, 'b')
    def commit(_):
        os._exit(24)
    keeper.collect(directory, config, transport=fetch, clock=lambda: 101,
                   before_commit=commit if phase == 'pending' else None)
    os._exit(25)


class KeeperTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='keyd-checkpoints-', dir=Path(__file__).resolve().parent)
        self.root = Path(self.temporary.name).resolve()
        self.store = self.root / 'store'
        self.store.mkdir(mode=0o700)
        self.identity = self.root/'identity'
        self.identity.write_text('temporary test identity, not a key')
        self.identity.chmod(0o600)
        self.hosts = self.root/'known_hosts'
        self.hosts.write_text('temporary pinned test host')
        self.hosts.chmod(0o600)
        self.config = {'version': 1, 'instance_id': INSTANCE, 'host': 'source.invalid',
                       'port': 22, 'user': 'audit', 'identity_file': str(self.identity),
                       'known_hosts_file': str(self.hosts), 'timeout_seconds': 1,
                       'max_age_seconds': 10}
        self.file = self.root/'config.json'
        self.file.write_text(json.dumps(self.config))
        self.file.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def enroll(self):
        return keeper.collect(self.store, self.config, enroll=True,
                              transport=lambda *_: cp(1), clock=lambda: 100)

    def test_enrollment_monotonic_commit_unchanged_and_staleness(self):
        self.assertEqual(keeper.read_config(self.file), self.config)
        self.assertEqual(self.enroll()['checkpoint'], cp(1))
        self.assertFalse(keeper.status(self.store, self.config, clock=lambda: 110)['deadline_exceeded'])
        self.assertTrue(keeper.status(self.store, self.config, clock=lambda: 111)['deadline_exceeded'])
        result = keeper.collect(self.store, self.config, transport=lambda *_: cp(3, 'c'), clock=lambda: 112)
        self.assertTrue(result['observation_deadline_missed'])
        keeper.collect(self.store, self.config, transport=lambda *_: cp(3, 'c'), clock=lambda: 113)
        db = sqlite3.connect(self.store/'checkpoints.sqlite')
        self.assertEqual(db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0], 2)
        with self.assertRaises(sqlite3.IntegrityError):
            db.execute('DELETE FROM checkpoints')
        db.close()
        with self.assertRaises(keeper.Rejected):
            keeper.collect(self.store, self.config, enroll=True, transport=lambda *_: cp(4))

    def test_failures_preserve_previous_and_no_automatic_reenrollment(self):
        self.enroll()
        for bad in [cp(0), cp(1, 'b'), cp(1) | {'version': 2}, cp(2) | {'instance_id': 'wrong'}]:
            with self.assertRaises(keeper.Rejected):
                keeper.collect(self.store, self.config, transport=lambda *_, bad=bad: bad, clock=lambda: 101)
            self.assertEqual(keeper.status(self.store, self.config, clock=lambda: 102)['checkpoint'], cp(1))
        def offline(*_):
            raise OSError('offline')
        with self.assertRaises(OSError):
            keeper.collect(self.store, self.config, transport=offline, clock=lambda: 101)
        with self.assertRaises(keeper.Rejected):
            keeper.status(self.store, self.config, clock=lambda: 99)
        self.hosts.write_text('changed host pin')
        with self.assertRaises(keeper.Rejected):
            keeper.collect(self.store, self.config, transport=lambda *_: cp(2))

    def test_durability_failure_and_store_corruption_fail_closed(self):
        self.enroll()
        def fail(_):
            raise sqlite3.OperationalError('injected durable commit failure')
        with self.assertRaises(sqlite3.Error):
            keeper.collect(self.store, self.config, transport=lambda *_: cp(2),
                           clock=lambda: 101, before_commit=fail)
        self.assertEqual(keeper.status(self.store, self.config, clock=lambda: 102)['checkpoint'], cp(1))
        path = self.store/'checkpoints.sqlite'
        db = sqlite3.connect(path)
        db.execute('PRAGMA user_version=999')
        db.close()
        before = path.read_bytes()
        with self.assertRaises(keeper.Rejected):
            self.enroll()
        self.assertEqual(before, path.read_bytes())
        path.write_bytes(b'corrupt database')
        with self.assertRaises(sqlite3.Error):
            self.enroll()
        self.assertEqual(path.read_bytes(), b'corrupt database')

    def test_commit_error_after_durability_retries_from_committed_tip(self):
        self.enroll()
        connect = sqlite3.connect
        class AmbiguousCommit(sqlite3.Connection):
            def commit(self):
                super().commit()
                raise sqlite3.OperationalError('injected error after durable commit')
        def ambiguous(*args, **kwargs):
            return connect(*args, factory=AmbiguousCommit, **kwargs)
        with patch.object(keeper.sqlite3, 'connect', ambiguous):
            with self.assertRaises(sqlite3.OperationalError):
                keeper.collect(self.store, self.config, transport=lambda *_: cp(2), clock=lambda: 101)
        self.assertEqual(keeper.status(self.store, self.config, clock=lambda: 102)['checkpoint'], cp(2))
        def retry(config, previous):
            self.assertEqual(previous, cp(2))
            return cp(2)
        keeper.collect(self.store, self.config, transport=retry, clock=lambda: 102)
        with sqlite3.connect(self.store/'checkpoints.sqlite') as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM checkpoints').fetchone()[0], 2)

    def test_actual_process_crashes_recover_atomic_old_or_new_state(self):
        self.enroll()
        for phase, code, expected in [('fetched', 23, cp(1)), ('pending', 24, cp(1)),
                                      ('committed', 25, cp(2, 'b'))]:
            child = multiprocessing.get_context('fork').Process(target=crash_worker,
                args=(self.store, self.config, phase))
            child.start()
            child.join(5)
            self.assertFalse(child.is_alive())
            self.assertEqual(child.exitcode, code)
            self.assertEqual(keeper.status(self.store, self.config, clock=lambda: 102)['checkpoint'], expected)

    def test_concurrent_collection_is_serialized_and_stale_result_cannot_replace_tip(self):
        self.enroll()
        db = sqlite3.connect(self.store/'checkpoints.sqlite', isolation_level=None)
        db.execute('BEGIN IMMEDIATE')
        called = []
        try:
            with self.assertRaises(sqlite3.OperationalError):
                keeper.collect(self.store, self.config, transport=lambda *_: called.append(True))
            self.assertFalse(called)
        finally:
            db.rollback()
            db.close()
        keeper.collect(self.store, self.config, transport=lambda *_: cp(3), clock=lambda: 101)
        with self.assertRaises(keeper.Rejected):
            keeper.collect(self.store, self.config, transport=lambda *_: cp(2), clock=lambda: 102)

    def test_strict_config_permissions_and_missing_evidence(self):
        for key, value in [('host', '-oProxyCommand=bad'), ('port', True), ('timeout_seconds', 0),
                           ('extra', True), ('instance_id', 'bad')]:
            config = self.config | {key: value}
            self.file.write_text(json.dumps(config))
            with self.assertRaises(keeper.Rejected):
                keeper.read_config(self.file)
        with self.assertRaises(keeper.Rejected):
            keeper.strict_json('{"a":1,"a":2}')
        with self.assertRaises(keeper.Rejected):
            keeper.status(self.store, self.config)
        self.assertFalse((self.store/'checkpoints.sqlite').exists())
        self.store.chmod(0o777)
        with self.assertRaises(keeper.Rejected):
            self.enroll()
        self.store.chmod(0o700)
        link = self.root/'link'
        link.symlink_to(self.store, target_is_directory=True)
        with self.assertRaises(keeper.Rejected):
            keeper.collect(link, self.config, enroll=True)

    def test_cli_status_codes_and_missing_store_never_recreates(self):
        import subprocess
        self.enroll()
        command = [os.sys.executable, str(Path(keeper.__file__)), 'status',
                   '--config', str(self.file), '--store', str(self.store)]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertTrue(json.loads(result.stdout)['deadline_exceeded'])
        (self.store/'checkpoints.sqlite').unlink()
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['state'], 'unavailable')
        self.assertFalse((self.store/'checkpoints.sqlite').exists())

    def test_transport_has_pins_bounded_output_timeout_and_no_shell(self):
        # Exercise the actual subprocess pipe/deadline handler with a harmless
        # local child in place of ssh. The deployment test uses real sshd.
        real_popen = keeper.subprocess.Popen
        for program in ["print('x'*5000)", "import time;time.sleep(5)", "raise SystemExit(3)",
                        "print('{}')"]:
            def fake_popen(command, **kwargs):
                self.assertEqual(command[0], '/usr/bin/ssh')
                self.assertIn('StrictHostKeyChecking=yes', command)
                self.assertIn('IdentityAgent=none', command)
                self.assertNotIn('shell', kwargs)
                return real_popen([os.sys.executable, '-c', program], **kwargs)
            with patch.object(keeper.subprocess, 'Popen', fake_popen):
                start = time.monotonic()
                with self.assertRaises((keeper.Rejected, BrokenPipeError)):
                    keeper.ssh_request(self.config, cp(1))
                self.assertLess(time.monotonic()-start, 3)
        response = {'version': 1, 'previous': cp(1), 'checkpoint': cp(2)}
        def valid(command, **kwargs):
            return real_popen([os.sys.executable, '-c', 'import sys;sys.stdin.read();print('+repr(json.dumps(response))+')'], **kwargs)
        with patch.object(keeper.subprocess, 'Popen', valid):
            self.assertEqual(keeper.ssh_request(self.config, cp(1)), cp(2))


if __name__ == '__main__':
    unittest.main()
