"""U3 release gate regression; no signatures, hardware or system files changed."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('se_preflight', Path(__file__).with_name('se-preflight.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseGate(unittest.TestCase):
    def setUp(self):
        self.team = 'ABCDEFGHIJ'
        self.app = self.team + '.org.anp.keyd'
        self.metadata = {'TeamIdentifier': self.team, 'Authority': 'Apple Root CA',
                         'authorities': ['Developer ID Application',
                                         'Developer ID Certification Authority',
                                         'Apple Root CA'],
                         'flags': 'runtime'}
        self.entitlements = {'com.apple.application-identifier': self.app,
                             'com.apple.developer.team-identifier': self.team,
                             'keychain-access-groups': [self.app]}

    def evaluate(self, context='user-session'):
        return gate.policy(context, self.team, self.app, self.metadata, self.entitlements)

    def test_signed_system_daemon_still_refused(self):
        self.assertEqual(self.evaluate(), [])
        self.assertTrue(any('LaunchDaemon' in reason for reason in self.evaluate('system-daemon')))

    def test_untrusted_or_wrong_team_signature_refused(self):
        for field, value in [('TeamIdentifier', 'OTHERTEAM0'), ('Authority', ''), ('Signature', 'adhoc'), ('flags', '')]:
            with self.subTest(field=field):
                with patch.dict(self.metadata, {field: value}):
                    self.assertTrue(self.evaluate())

    def test_widened_keychain_and_debug_entitlements_refused(self):
        for changes in [{'keychain-access-groups': [self.app, 'OTHER.shared']},
                        {'keychain-access-groups': [self.team + '.*']},
                        {'com.apple.security.application-groups': ['group.shared']},
                        {'application-identifier': 'OTHER.app'},
                        {'com.apple.security.get-task-allow': True},
                        {'com.apple.security.cs.disable-library-validation': True},
                        {'com.apple.application-identifier': 'OTHER.app'},
                        {'com.apple.developer.team-identifier': 'OTHERTEAM0'}]:
            with self.subTest(changes=changes), patch.dict(self.entitlements, changes):
                self.assertTrue(self.evaluate())

    def test_wildcard_application_refused(self):
        self.app = self.team + '.*'
        self.assertTrue(self.evaluate())

    def test_digest_mismatch_does_not_inspect_or_execute_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'candidate'
            binary.write_bytes(b'not executable')
            with patch.object(gate.sys, 'platform', 'darwin'), patch.object(gate, 'command') as command:
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    gate.inspect(binary, '0' * 64, 'user-session', self.team, self.app)
                command.assert_not_called()

    def test_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'candidate'
            binary.write_bytes(b'candidate')
            alias = Path(directory) / 'alias'
            alias.symlink_to(binary)
            with patch.object(gate.sys, 'platform', 'darwin'), patch.object(gate, 'command') as command:
                with self.assertRaisesRegex(ValueError, 'symlink'):
                    gate.inspect(alias, '0' * 64, 'user-session', self.team, self.app)
                command.assert_not_called()

    def test_signature_precheck_never_claims_hardware_acceptance(self):
        from types import SimpleNamespace as NS
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'candidate'
            binary.write_bytes(b'candidate')
            digest = gate.hashlib.sha256(binary.read_bytes()).hexdigest()
            responses = [NS(stdout=b'', stderr=b''),
                         NS(stdout=b'', stderr=(f'TeamIdentifier={self.team}\nAuthority=Developer ID Application\n'
                                                'Authority=Developer ID Certification Authority\n'
                                                'Authority=Apple Root CA\n'
                                                'CodeDirectory v=20500 flags=0x10000(runtime)\n').encode()),
                         NS(stdout=gate.plistlib.dumps(self.entitlements), stderr=b'')]
            with patch.object(gate.sys, 'platform', 'darwin'), patch.object(gate, 'command', side_effect=responses) as command:
                report = gate.inspect(binary, digest, 'user-session', self.team, self.app)
            self.assertTrue(report['signature_prerequisites_passed'])
            self.assertFalse(report['hardware_acceptance_complete'])
            self.assertFalse(report['protected_supported'])
            self.assertTrue(report['pending'])
            for call in command.call_args_list:
                self.assertEqual(call.args[0][0], '/usr/bin/codesign')


if __name__ == '__main__':
    unittest.main()
