"""Privileged bundle-copy guards; these tests make no hardware claims."""
from pathlib import Path
import tempfile
import unittest
import hashlib
from types import SimpleNamespace
from unittest.mock import patch

from acceptance_se import validate_bundle
import acceptance_signing


class BundleChecks(unittest.TestCase):
    def test_prepare_preserves_bundle_from_executable_path(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            macos = bundle / 'Contents/MacOS'
            macos.mkdir()
            binary = macos / 'anp-keyd'
            binary.write_bytes(b'fixture-executable')
            base = Path(root) / 'runtime'
            base.mkdir()
            args = SimpleNamespace(signing_helper=binary,
                helper_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                se_login_bundle=bundle)
            class ReachedGeneration(Exception):
                pass
            def run(admin, helper, mode, source):
                self.assertEqual(helper, base / 'Fixture.app/Contents/MacOS/anp-keyd')
                self.assertEqual(mode, 'generate-se')
                self.assertEqual(helper.read_bytes(), binary.read_bytes())
                self.assertTrue((base / 'Fixture.app/Contents/embedded.provisionprofile').is_file())
                raise ReachedGeneration()
            with patch.object(acceptance_signing.os, 'chown'):
                with self.assertRaises(ReachedGeneration):
                    acceptance_signing.prepare(base, {}, args,
                        SimpleNamespace(pw_uid=501, pw_gid=20), None, run)

    def fixture(self, root):
        bundle = Path(root) / 'Fixture.app'
        contents = bundle / 'Contents'
        contents.mkdir(parents=True)
        (contents / 'embedded.provisionprofile').write_bytes(b'test-profile')
        return bundle

    def test_profile_required(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            validate_bundle(bundle)
            (bundle / 'Contents/embedded.provisionprofile').unlink()
            with self.assertRaises(ValueError):
                validate_bundle(bundle)

    def test_links_refused_before_privileged_copy(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            (bundle / 'Contents/link').symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                validate_bundle(bundle)

    def test_entry_bound(self):
        with tempfile.TemporaryDirectory() as root:
            bundle = self.fixture(root)
            for index in range(257):
                (bundle / str(index)).touch()
            with self.assertRaises(ValueError):
                validate_bundle(bundle)
