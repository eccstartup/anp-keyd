"""Boundary negatives for the whole-framework launcher; no host mutations."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), Path(__file__).resolve().parents[1] / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = load('launch-agent')
migrator = load('migrate-vault')


class Boundary(unittest.TestCase):
    def setUp(self):
        self.config = {'service_uid': 600, 'admin_uids': [501], 'agent_gid': 602, 'admin_gid': 603,
                       'principals': [{'uid': 601, 'enabled': True}]}
        self.user = NS(pw_uid=601, pw_gid=601, pw_name='isolated-agent')
        self.patches = [patch.object(launcher.pwd, 'getpwuid', return_value=self.user),
                        patch.object(launcher.grp, 'getgrnam', return_value=NS(gr_gid=80)),
                        patch.object(launcher.os, 'getgrouplist', return_value=[601, 602])]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_wrong_disabled_or_ambiguous_principals_refused(self):
        for uid in (0, 501, 600, 999):
            with self.assertRaises(ValueError): launcher.account(self.config, uid)
        self.config['principals'][0]['enabled'] = False
        with self.assertRaises(ValueError): launcher.account(self.config, 601)
        self.config['principals'] = [{'uid': 601, 'enabled': True}] * 2
        with self.assertRaises(ValueError): launcher.account(self.config, 601)

    def test_admin_management_and_missing_transport_memberships_refused(self):
        self.assertEqual(launcher.account(self.config, 601), self.user)
        for groups in ([601], [601, 602, 0], [601, 602, 80], [601, 602, 603]):
            with patch.object(launcher.os, 'getgrouplist', return_value=groups):
                with self.assertRaises(ValueError): launcher.account(self.config, 601)

    def test_no_ambient_credentials_or_host_control_environment(self):
        with patch.dict(os.environ, {'SSH_AUTH_SOCK': '/admin/ssh', 'ANTHROPIC_API_KEY': 'secret',
                                    'DOCKER_HOST': 'unix:///admin/docker', 'DYLD_INSERT_LIBRARIES': 'unsafe'}):
            env = launcher.environment(Path('/agent/home'), 'agent')
        self.assertEqual(env['HOME'], '/agent/home')
        for key in ('SSH_AUTH_SOCK', 'ANTHROPIC_API_KEY', 'DOCKER_HOST', 'DYLD_INSERT_LIBRARIES'):
            self.assertNotIn(key, env)
        self.assertEqual(env['PATH'], '/usr/bin:/bin:/usr/sbin:/sbin')

    def test_symlink_shared_or_foreign_directories_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / 'home'
            home.mkdir(mode=0o700)
            alias = Path(directory) / 'alias'
            alias.symlink_to(home)
            # Temp ancestors need not satisfy the production root/Agent policy;
            # every candidate must still be refused before launching anything.
            for path in (alias, Path('relative'), home / '..'):
                with self.assertRaises(ValueError): launcher.dedicated(path, os.getuid(), lambda p: None)
            home.chmod(0o777)
            with self.assertRaises(ValueError): launcher.dedicated(home, os.getuid(), lambda p: None)

    def test_apfs_requires_ownership_and_rejects_other_filesystems(self):
        import plistlib
        for info in ({'FilesystemType': 'apfs', 'GlobalPermissionsEnabled': False},
                     {'FilesystemType': 'hfs', 'GlobalPermissionsEnabled': True}, {}):
            with patch.object(migrator.subprocess, 'check_output', side_effect=[b'Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk1 100 20 80 20% /Data\n', plistlib.dumps(info)]):
                with self.assertRaises(RuntimeError): migrator.apfs(Path('/test'))
        with patch.object(migrator.subprocess, 'check_output', side_effect=[b'Filesystem Blocks Used Available Capacity Mounted on\n/dev/disk1 100 20 80 20% /Data\n', plistlib.dumps(
                {'FilesystemType': 'apfs', 'GlobalPermissionsEnabled': True})]):
            migrator.apfs(Path('/test'))


if __name__ == '__main__':
    unittest.main()
