"""U3 SE persistence harness regressions; no SE, keychain or signatures involved."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


harness = load('se_persistence', 'se-persistence.py')
TEAM = 'ABCDEFGHIJ'
APP = TEAM + '.org.anp.keyd.helper'

FAKE = '''#!/usr/bin/env python3
import json, os, stat, sys
command = sys.argv[1]
if command == 'create':
    state, tag = sys.argv[2], sys.argv[3]
    body = {"schema": 1, "tag_hint": tag,
            "root": {"kind": "secure_enclave", "tag": "anp-keyd/" + tag},
            "ciphertext_b64": "", "hs_sha256": "00"}
    with open(state, 'x') as handle:
        handle.write(json.dumps(body))
    os.chmod(state, 0o600)
    print('CREATED ' + tag)
elif command == 'open':
    state = sys.argv[2]
    body = json.load(open(state))
    if os.path.exists(state + '.deleted'):
        print('this envelope cannot use it: no key with that label', file=sys.stderr)
        sys.exit(1)
    print('PASS ' + body['tag_hint'])
elif command == 'delete':
    state = sys.argv[2]
    body = json.load(open(state))
    open(state + '.deleted', 'w').close()
    print('DELETED ' + body['tag_hint'])
else:
    sys.exit(2)
'''

UNSIGNED = '''#!/usr/bin/env python3
import sys
print('this binary is not allowed to save a Secure Enclave key '
      '(errSecMissingEntitlement, -34018)', file=sys.stderr)
sys.exit(1)
'''


def script(directory, name, body):
    path = Path(directory) / name
    path.write_text(body)
    path.chmod(0o755)
    return path


def digest(path):
    return harness.hashlib.sha256(Path(path).read_bytes()).hexdigest()


class PersistenceHarness(unittest.TestCase):
    def args(self, binary, unsigned=None):
        return SimpleNamespace(binary=Path(binary), sha256=digest(binary),
                               unsigned_binary=Path(unsigned) if unsigned else None,
                               unsigned_sha256=digest(unsigned) if unsigned else None,
                               team_id=TEAM, application_id=APP, other_uid=None,
                               timeout=30)

    def test_create_open_delete_and_post_delete_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            with patch.object(harness, 'verify_binary', return_value={'signature_prerequisites_passed': True}):
                report = harness.accept(self.args(binary))
        self.assertTrue(report['persistence_across_processes'])
        self.assertTrue(report['deleted_key_rejected'])
        self.assertEqual(report['phases']['create'], 'ok')
        self.assertEqual(report['phases']['open_new_process'], 'ok')
        self.assertEqual(report['phases']['delete'], 'ok')
        self.assertEqual(report['phases']['open_after_delete_rejected'], 'ok')
        self.assertFalse(report['hardware_acceptance_complete'])
        self.assertFalse(report['lifecycle_acceptance_complete'])
        self.assertFalse(report['acceptance_scope_complete'])

    def test_unsigned_binary_cannot_create_a_persistent_key(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            unsigned = script(directory, 'unsigned', UNSIGNED)
            with patch.object(harness, 'verify_binary', return_value={'signature_prerequisites_passed': True}):
                report = harness.accept(self.args(binary, unsigned))
        self.assertTrue(report['unsigned_persistent_creation_refused'])
        self.assertEqual(report['phases']['unsigned_create_refused'], 'ok')

    def test_state_file_must_be_private_and_well_formed(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state.json'
            body = {'schema': 1, 'tag_hint': 'acceptance-x',
                    'root': {'kind': 'secure_enclave', 'tag': 'anp-keyd/acceptance-x'},
                    'ciphertext_b64': '', 'hs_sha256': '00'}
            state.write_text(json.dumps(body))
            os.chmod(state, 0o644)
            with self.assertRaisesRegex(harness.AcceptanceError, 'private regular file'):
                harness.read_state(state)
            os.chmod(state, 0o600)
            body['schema'] = 2
            state.write_text(json.dumps(body))
            with self.assertRaisesRegex(harness.AcceptanceError, 'schema'):
                harness.read_state(state)

    def test_digest_mismatch_is_refused_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.sha256 = '0' * 64
            with self.assertRaisesRegex(harness.AcceptanceError, 'digest mismatch'):
                harness.verify_binary(Path(binary), args.sha256, TEAM, APP)

    def test_second_uid_requires_root(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = script(directory, 'se-persistence', FAKE)
            args = self.args(binary)
            args.other_uid = 501
            with patch.object(harness.os, 'geteuid', return_value=501):
                with self.assertRaisesRegex(harness.AcceptanceError, 'root'):
                    harness.accept(args)


if __name__ == '__main__':
    unittest.main()
