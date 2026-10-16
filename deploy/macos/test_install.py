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


if __name__ == '__main__':
    unittest.main()
