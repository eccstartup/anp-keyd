"""Real SE joint acceptance; invoked only inside test-runtime's disposable service.
The public fixture password is not a production secret. No automatic UI consent.
"""
import hashlib
import json
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time

import acceptance_signing


def validate_bundle(bundle):
    """Bound a privileged copy and refuse links, including the bundle itself."""
    if bundle.suffix != '.app' or bundle.is_symlink():
        raise ValueError('expected a real app bundle')
    total = 0
    paths = [bundle, *bundle.rglob('*')]
    if len(paths) > 256:
        raise ValueError('bundle has too many entries')
    for path in paths:
        mode = path.lstat().st_mode
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError('bundle contains a link or special file')
        total += path.stat().st_size
    if total > 160 * 1024 * 1024:
        raise ValueError('bundle exceeds acceptance size bound')
    if not (bundle / 'Contents/embedded.provisionprofile').is_file():
        raise ValueError('bundle lacks an embedded profile')


class Checks(acceptance_signing.Checks):
    def exercise_signing(self):
        manifest = self.fixture['manifest']
        assert manifest.get('fixture_only') is True
        assert manifest['hot_kid'] == self.key['kid']
        hardware = manifest['hot_hardware']
        assert hardware['kind'] == 'secure_enclave', hardware
        # Keep the tag even if later UI/service checks fail: no claim that
        # removing the disposable filesystem also removes a keychain key.
        print('SE temporary wrapping-key locator: ' + json.dumps(hardware), flush=True)
        bundle = self.args.se_login_bundle
        validate_bundle(bundle)
        source = bundle / 'Contents/MacOS/anp-keyd'
        assert hashlib.sha256(source.read_bytes()).hexdigest() == self.args.se_login_sha256
        destination = self.base / 'LoginHelper.app'
        shutil.copytree(bundle, destination)
        binary = destination / 'Contents/MacOS/anp-keyd'
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == self.args.se_login_sha256
        info = subprocess.run([str(binary), 'build-info'], capture_output=True, text=True, timeout=15, **self.credentials(self.admin), env=self.env, cwd='/')
        assert info.returncode == 0, info.stderr
        flags = json.loads(info.stdout)
        assert flags['release'] and flags['hardware_se'] and not flags['hardware_software']
        assert not flags['seed_export'] and not flags['protected_supported']
        command = [str(binary), 'admin', '--config', str(self.path), 'se-session',
                   '--vault-id', self.fixture['vault_id'], '--did', self.key['did'], '--kid', self.key['kid']]
        denied = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                **self.credentials(self.agent), env=self.env, cwd='/')
        assert denied.returncode != 0 and 'ADMIN_REQUIRED' in denied.stderr, denied.stderr
        print('UI: check the temporary exact key and enter ONLY the public test password: '
              + acceptance_signing.PASSWORD, flush=True)
        log = self.base / 'se-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                      **self.credentials(self.admin), env=self.env, cwd='/')
            try:
                deadline = time.monotonic() + 145
                while time.monotonic() < deadline:
                    if helper.poll() is not None:
                        raise ValueError('signed helper exited: ' + log.read_text())
                    if 'SE session active for exact key' in log.read_text():
                        break
                    time.sleep(.2)
                else:
                    raise ValueError('signed helper did not establish a real SE session')
                request = self.signing()
                reply = self.request_as(self.agent, request)
                assert reply['code'] == 'OK' and reply['data']['state'] == 'completed', reply
                public = {'document': manifest['document'], **reply['data']['result']}
                verified = subprocess.run([str(self.fixture['helper']), 'verify'], input=json.dumps(public),
                    capture_output=True, text=True, timeout=15, **self.credentials(self.admin), env=self.env, cwd='/')
                assert verified.returncode == 0 and verified.stdout.strip() == 'VERIFIED', verified.stderr
                changed = {**public, 'url': 'https://example.com/other'}
                rejected = subprocess.run([str(self.fixture['helper']), 'verify'], input=json.dumps(changed),
                    capture_output=True, text=True, timeout=15, **self.credentials(self.admin), env=self.env, cwd='/')
                assert rejected.returncode != 0
                assert self.request_as(self.agent, request)['data'] == reply['data']
                helper.send_signal(signal.SIGKILL)
                helper.wait(timeout=10)
                # Allow the documented observation deadline; then require both
                # cached-result suppression and no authorized keys.
                deadline = time.monotonic() + 10
                while True:
                    replay = self.request_as(self.agent, request)
                    if replay['code'] != 'OK' or 'result' not in replay.get('data', {}):
                        break
                    if time.monotonic() >= deadline:
                        raise ValueError('helper death did not suppress cached signature')
                    time.sleep(.2)
                keys = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                assert keys['code'] == 'OK' and keys['data']['keys'] == [], keys
                fresh = self.grant()
                self.expect_locked(fresh)
                print('PASS independently verified SE hot-key signature, retry, changed-target refusal, helper SIGKILL, cache suppression, revocation and locked key', flush=True)
            finally:
                if helper.poll() is None:
                    helper.kill()
                    helper.wait(timeout=10)
                print('SE helper log: ' + log.read_text(), flush=True)
                print('Temporary SE wrapping key requires explicit keychain cleanup; locator above. Host lifecycle and raw OS isolation remain unaccepted.', flush=True)
