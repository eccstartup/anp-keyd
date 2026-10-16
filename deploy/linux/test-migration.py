#!/usr/bin/env python3
"""Filesystem-only crash recovery negatives; uses disposable synthetic bytes."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('migration', Path(__file__).with_name('migrate-vault.py'))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class CopyRecovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='keyd-migration-test-')
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        self.source.mkdir(mode=0o700)
        for name in ('keys', 'dids', 'audit'):
            (self.source / name).mkdir(mode=0o700)
        for rel, data in [('device.secret', b'x'*32), ('keys/e1_test.json', b'encrypted'), ('dids/doc.json', b'public')]:
            m.atomic(self.source / rel, data)
        self.manifest = m.inventory(self.source)
        self.dest = self.root / 'copy'

    def tearDown(self):
        self.temp.cleanup()

    def test_partial_copy_and_uncommitted_temp_resume_without_rewriting_verified_files(self):
        self.dest.mkdir(mode=0o700)
        for name in ('keys', 'dids', 'audit'):
            (self.dest / name).mkdir(mode=0o700)
        m.atomic(self.dest / 'device.secret', b'x'*32)
        inode = (self.dest / 'device.secret').stat().st_ino
        m.atomic(self.dest / 'keys/.e1_test.json.new', b'incomplete')
        m.copy_checked(self.source, self.dest, self.manifest)
        self.assertEqual(m.inventory(self.dest), self.manifest)
        self.assertEqual((self.dest / 'device.secret').stat().st_ino, inode)

    def test_unknown_committed_bytes_and_symlinks_are_preserved_and_refused(self):
        m.copy_checked(self.source, self.dest, self.manifest)
        key = self.dest / 'keys/e1_test.json'
        key.write_bytes(b'unknown')
        with self.assertRaises(RuntimeError):
            m.copy_checked(self.source, self.dest, self.manifest)
        self.assertEqual(key.read_bytes(), b'unknown')
        key.unlink()
        key.symlink_to(self.source / 'keys/e1_test.json')
        with self.assertRaises(RuntimeError):
            m.copy_checked(self.source, self.dest, self.manifest)
        self.assertTrue(key.is_symlink())

    def test_umask_does_not_change_config_or_binary_mode(self):
        old = os.umask(0o077)
        try:
            m.atomic(self.root / 'config', b'{}', 0o644)
            m.atomic(self.root / 'binary', b'test', 0o755)
        finally:
            os.umask(old)
        self.assertEqual((self.root / 'config').stat().st_mode & 0o777, 0o644)
        self.assertEqual((self.root / 'binary').stat().st_mode & 0o777, 0o755)


if __name__ == '__main__':
    unittest.main()
