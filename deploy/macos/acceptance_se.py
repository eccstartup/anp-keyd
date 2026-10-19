"""Real SE joint acceptance; invoked only inside test-runtime's disposable service.
The public fixture password is not a production secret. No automatic UI consent.
"""
import hashlib
import json
import re
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import time

import acceptance_signing


def sleep_times(output):
    values = {}
    for name in ('sleeptime', 'waketime'):
        match = re.search(r'^kern\.' + name + r': \{ sec = (\d+), usec = (\d+) \}', output, re.M)
        if not match:
            raise ValueError('missing kernel sleep/wake evidence: ' + name)
        seconds, micros = map(int, match.groups())
        if not 0 <= micros < 1_000_000:
            raise ValueError('invalid kernel timestamp')
        values[name] = seconds + micros / 1_000_000
    return values


def kernel_sleep_times():
    result = subprocess.run(['/usr/sbin/sysctl', 'kern.sleeptime', 'kern.waketime'],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise ValueError('kernel sleep evidence unavailable: ' + result.stderr)
    return sleep_times(result.stdout)


def verify_sleep_transition(before, after, started, finished, long_sleep=False):
    sleep, wake = after['sleeptime'], after['waketime']
    if sleep <= before['sleeptime'] or wake <= before['waketime']:
        raise ValueError('no new kernel sleep/wake pair')
    if not started <= sleep < wake <= finished:
        raise ValueError('sleep/wake pair outside acceptance interval')
    if long_sleep:
        if wake - sleep <= 900:
            raise ValueError('long sleep must cross the original 900-second session limit')
        if finished - started > 2100:
            raise ValueError('long sleep exceeded the 2100-second acceptance window')
        return
    if wake - sleep < 6:
        raise ValueError('sleep must exceed the five-second heartbeat window')
    if finished - started > 90:
        raise ValueError('transition exceeded short acceptance window; approval expiry could confound evidence')


def wait_for_sleep_transition(before, started, read_times=None, clock=None, pause=None,
                              long_sleep=False, observe=None):
    read_times = read_times or kernel_sleep_times
    clock = clock or time.time
    pause = pause or time.sleep
    last_pair = None
    while True:
        after = read_times()
        finished = clock()
        if finished < started:
            raise ValueError('wall clock moved backwards during sleep acceptance')
        limit = 2100 if long_sleep else 90
        if finished - started > limit:
            raise ValueError(f'no valid sleep/wake pair within {limit} seconds')
        if after['sleeptime'] > before['sleeptime'] and after['waketime'] > before['waketime']:
            pair = (after['sleeptime'], after['waketime'])
            if pair != last_pair:
                if observe:
                    observe(after, finished)
                last_pair = pair
            if long_sleep and after['waketime'] - after['sleeptime'] <= 900:
                if not started <= after['sleeptime'] < after['waketime'] <= finished:
                    raise ValueError('sleep/wake pair outside acceptance interval')
                # Maintenance wakes can expose short pairs before the operator
                # wakes the display. Keep observing; never sum separate sleeps.
                pause(.5)
                continue
            verify_sleep_transition(before, after, started, finished, long_sleep=long_sleep)
            return after, finished
        pause(.5)


def operator_sleep_transition(long_sleep=False):
    before = kernel_sleep_times()
    started = time.time()
    timing = ('leave asleep for 16 minutes, then wake within 35 minutes. '
              if long_sleep else 'wait at least 6 seconds, then wake within 90 seconds. ')
    print('READY FOR MANUAL SLEEP: use Apple menu Sleep now; ' + timing +
          'Wake detection is automatic; DO NOT press Enter. '
          'This script does not trigger sleep.', flush=True)
    def observe(after, finished):
        print('KERNEL_SLEEP_EVIDENCE ' + json.dumps({'before': before, 'after': after,
              'started': started, 'finished': finished,
              'sleep_seconds': after['waketime'] - after['sleeptime']}), flush=True)
        if long_sleep and after['waketime'] - after['sleeptime'] <= 900:
            print('WAIT short sleep/wake pair; possibly a maintenance wake. '
                  'Still require one kernel sleep longer than 900 seconds within 35 minutes; '
                  'separate sleeps are not added together.', flush=True)
    wait_for_sleep_transition(before, started, long_sleep=long_sleep, observe=observe)


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
        helper_credentials = self.credentials(self.admin)
        if self.args.se_ending == 'logout':
            import acceptance_graphical
            old_session = acceptance_graphical.session(self.admin, self.path)
            print('OLD_GRAPHICAL_AUDIT_SESSION ' + str(old_session), flush=True)
            command = acceptance_graphical.command(self.admin, self.path, command)
            helper_credentials = {}
        log = self.base / 'se-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
                                      **helper_credentials, env=self.env, cwd='/')
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
                # Prepare an approval before lease loss; it must not recreate
                # authority after teardown advances the management epoch.
                change = self.base / 'stale-grant.json'
                change.write_text(json.dumps({'kind': 'Grant', 'change': {'action': 'Create',
                    'principal_id': self.config['principals'][0]['principal_id'],
                    'key_id': self.key['key_id'], 'policy_id': self.policy_id,
                    'policy_version': 1, 'expiry': int(time.time()) + 240, 'max_uses': 1}}))
                change.chmod(0o644)
                prepared = self.cli(self.admin, 'prepare', '--file', change)
                assert prepared.returncode == 0, prepared.stderr
                pending = json.loads(prepared.stdout)['prepared']
                ending = getattr(self.args, 'se_ending', 'kill')
                if ending in ('restart', 'crash'):
                    self.restart_service(ending == 'crash')
                elif ending in ('sleep', 'long-sleep'):
                    operator_sleep_transition(long_sleep=ending == 'long-sleep')
                elif ending == 'user-switch':
                    from acceptance_console import operator_user_switch
                    def check_away():
                        cached = self.request_as(self.agent, request)
                        assert cached['code'] != 'OK' or 'result' not in cached.get('data', {}), cached
                        listed = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                        assert listed['code'] == 'OK' and listed['data']['keys'] == [], listed
                        print('PASS cached signature suppressed and authorized keys empty while other user owns console', flush=True)
                    operator_user_switch(self.admin.pw_uid, check_away)
                elif ending == 'logout':
                    from acceptance_console import operator_logout
                    def check_logged_out():
                        cached = self.request_as(self.agent, request)
                        assert cached['code'] != 'OK' or 'result' not in cached.get('data', {}), cached
                        listed = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                        assert listed['code'] == 'OK' and listed['data']['keys'] == [], listed
                        print('PASS old cache suppressed and authorized keys empty at login window', flush=True)
                    operator_logout(self.admin.pw_uid, old_session, check_logged_out,
                        lambda: acceptance_graphical.relogin_session(self.admin))
                else:
                    helper.send_signal(signal.SIGSTOP if ending == 'hang' else signal.SIGKILL)
                if ending == 'kill':
                    helper.wait(timeout=10)
                # Allow the documented observation deadline; then require both
                # cached-result suppression and no authorized keys.
                deadline = time.monotonic() + 10
                while True:
                    replay = self.request_as(self.agent, request)
                    if replay['code'] != 'OK' or 'result' not in replay.get('data', {}):
                        break
                    if time.monotonic() >= deadline:
                        raise ValueError('SE session loss did not suppress cached signature')
                    time.sleep(.2)
                keys = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                assert keys['code'] == 'OK' and keys['data']['keys'] == [], keys
                if ending != 'long-sleep':
                    assert time.time() + 5 < pending['expires_at'], 'approval expired before teardown check'
                else:
                    assert time.time() > pending['expires_at'], 'long-sleep approval should have expired'
                    print('NOTE old approval and original grant naturally expire during long sleep; '
                          'their rejection alone does not prove session-loss revocation.', flush=True)
                stale = self.cli(self.admin, 'commit', '--operation-id', pending['operation_id'],
                                 '--digest', pending['digest'])
                assert stale.returncode != 0, 'old approval survived SE session loss'
                if ending == 'hang':
                    assert helper.poll() is None, 'hang test requires a live stopped helper'
                    helper.send_signal(signal.SIGCONT)
                    helper.wait(timeout=10)
                    replay = self.request_as(self.agent, request)
                    assert replay['code'] != 'OK' or 'result' not in replay.get('data', {}), replay
                if ending in ('sleep', 'long-sleep', 'user-switch', 'logout', 'restart', 'crash'):
                    helper.wait(timeout=10)
                fresh = self.grant()
                self.expect_locked(fresh)
                authority = ('expired authority remains unusable' if ending == 'long-sleep'
                             else 'revocation and stale-approval refusal')
                print(f'PASS independently verified SE hot-key signature, retry, changed-target refusal, helper {ending}, cache suppression, {authority} and fresh-grant locked key', flush=True)
            finally:
                if helper.poll() is None:
                    helper.kill()
                    helper.wait(timeout=10)
                print('SE helper log: ' + log.read_text(), flush=True)
                print('Temporary SE wrapping key requires explicit keychain cleanup; locator above. Host lifecycle and raw OS isolation remain unaccepted.', flush=True)
