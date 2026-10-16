"""Pure installer policy tests; no accounts, services, or system files modified."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('mac_install', Path(__file__).with_name('install.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class Policy(unittest.TestCase):
    def setUp(self):
        self.service = NS(pw_uid=501, pw_gid=601, pw_name='service', pw_shell='/usr/bin/false')
        self.admin = NS(pw_uid=502, pw_gid=602, pw_name='operator')
        self.agent = NS(pw_uid=503, pw_gid=603, pw_name='agent')
        self.groups = {'service': {601, 610, 611}, 'operator': {602, 611}, 'agent': {603, 610}}
        self.sign, self.management = NS(gr_gid=610), NS(gr_gid=611)
        self.getgroup = patch.object(module.grp, 'getgrnam', return_value=NS(gr_gid=80))
        self.members = patch.object(module, 'memberships', side_effect=lambda u: self.groups[u.pw_name])
        self.getgroup.start()
        self.members.start()
        self.addCleanup(self.getgroup.stop)
        self.addCleanup(self.members.stop)

    def config(self):
        return module.configuration(self.service, self.admin, [self.agent], self.sign, self.management)

    def test_preview_only(self):
        config = self.config()
        self.assertEqual(config['mode'], 'macos-boundary-preview')
        self.assertEqual(config['vault_ids'], [])
        self.assertNotEqual(config['admin_uids'][0], config['principals'][0]['uid'])

    def test_shared_uid_refused(self):
        self.agent.pw_uid = self.admin.pw_uid
        with self.assertRaises(ValueError): self.config()

    def test_agent_privilege_groups_refused(self):
        for gid in [0, 80, 611]:
            self.groups['agent'] = {603, 610, gid}
            with self.assertRaises(ValueError): self.config()

    def test_service_needs_socket_groups_but_not_admin(self):
        self.groups['service'] = {601}
        with self.assertRaises(ValueError): self.config()
        self.groups['service'] = {601, 610, 611, 80}
        with self.assertRaises(ValueError): self.config()

    def test_service_login_refused(self):
        self.service.pw_shell = '/bin/zsh'
        with self.assertRaises(ValueError): self.config()

    def test_shared_socket_group_refused(self):
        self.management.gr_gid = self.sign.gr_gid
        with self.assertRaises(ValueError): self.config()


class ChildCredentials(unittest.TestCase):
    def test_primary_group_survives_darwin_egid_replacement(self):
        spec = importlib.util.spec_from_file_location('runtime_checks', Path(__file__).with_name('test-runtime.py'))
        runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runtime)
        config = {'service_uid': 600, 'admin_uids': [501], 'agent_gid': 602, 'admin_gid': 603}
        for uid, primary, required in [(600, 600, {602, 603}), (501, 20, {603}), (601, 601, {602}), (70, 70, {602})]:
            user = NS(pw_uid=uid, pw_gid=primary)
            result = runtime.child_credentials(user, config)
            self.assertEqual(result['extra_groups'][0], primary)
            # BSD setregid replaces group slot 0 after setgroups. Socket groups
            # must survive that documented kernel transition.
            after_setregid = [primary, *result['extra_groups'][1:]]
            self.assertTrue(required <= set(after_setregid))
            if uid in (601, 70):
                self.assertNotIn(603, after_setregid)
        agent = NS(pw_uid=601, pw_gid=601)
        elevated_transport = runtime.child_credentials(agent, config, extra_admin_group=True)
        self.assertEqual(elevated_transport['user'], 601)
        self.assertIn(603, elevated_transport['extra_groups'][1:])


class UpdateWrites(unittest.TestCase):
    def test_backup_and_stage_are_exclusive_and_ignore_restrictive_umask(self):
        import os
        import tempfile
        spec = importlib.util.spec_from_file_location('local_update', Path(__file__).with_name('update-local.py'))
        update = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(update)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            mask = os.umask(0o077)
            try:
                update.write_new(path, b'reviewed-binary')
            finally:
                os.umask(mask)
            self.assertEqual(path.read_bytes(), b'reviewed-binary')
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            with self.assertRaises(FileExistsError):
                update.write_new(path, b'overwrite')
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(FileExistsError):
                update.write_new(alias, b'follow-link')
            self.assertEqual(path.read_bytes(), b'reviewed-binary')


if __name__ == '__main__':
    unittest.main()
