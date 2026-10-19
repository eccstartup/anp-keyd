"""Real SE joint acceptance; invoked only inside test-runtime's disposable service.
The public fixture password is not a production secret. No automatic UI consent.
"""
import hashlib
import json
import os
import plistlib
import re
from pathlib import Path
import shutil
import shlex
import signal
import stat
import subprocess
import sys
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


def probe_result(label, action, timeout):
    started = time.monotonic()
    try:
        result = action()
        elapsed = time.monotonic() - started
        ok = result.returncode == 0
        print(f'{"PASS" if ok else "FAIL"} post-relogin probe {label} '
              f'elapsed={elapsed:.3f}s exit={result.returncode} '
              f'stdout={(result.stdout or "").strip()[:120]!r} '
              f'stderr={(result.stderr or "").strip()[:240]!r}', flush=True)
        return ok
    except subprocess.TimeoutExpired:
        print(f'FAIL post-relogin probe {label} timeout={timeout}s '
              f'elapsed={time.monotonic() - started:.3f}s', flush=True)
    except Exception as error:
        print(f'FAIL post-relogin probe {label} elapsed={time.monotonic() - started:.3f}s '
              f'{type(error).__name__}: {error}', flush=True)
    return False


def fresh_job_probe(base):
    """One-shot launchd job created after relogin; never authority or retries."""
    label = 'org.anp-keyd.logout-check.probe.' + str(os.getpid())
    marker = base / 'post-relogin-probe.marker'
    spec_path = base / 'post-relogin-probe.plist'
    try:
        marker.unlink()
    except FileNotFoundError:
        pass
    spec = {'Label': label, 'ProgramArguments': ['/bin/sh', '-c', 'echo fresh-job-ok > ' + str(marker)],
            'RunAtLoad': True, 'KeepAlive': False, 'LaunchOnlyOnce': True, 'SessionCreate': True,
            'ProcessType': 'Background', 'WorkingDirectory': '/',
            'StandardOutPath': str(base / 'post-relogin-probe.log'),
            'StandardErrorPath': str(base / 'post-relogin-probe.log')}
    spec_path.write_bytes(plistlib.dumps(spec))
    spec_path.chmod(0o644)
    try:
        bootstrap = subprocess.run(['/bin/launchctl', 'bootstrap', 'system', str(spec_path)],
                                   capture_output=True, text=True, timeout=6, cwd='/')
        if bootstrap.returncode:
            return bootstrap
        deadline = time.monotonic() + 6
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(.1)
        text = marker.read_text() if marker.exists() else ''
        return subprocess.CompletedProcess([], 0 if text.strip() == 'fresh-job-ok' else 1, text, '')
    finally:
        try:
            subprocess.run(['/bin/launchctl', 'bootout', 'system/' + label],
                           capture_output=True, text=True, timeout=6, cwd='/')
        except subprocess.SubprocessError:
            pass


def log_post_relogin_probes(checks):
    """Bounded layer probes after relogin. Evidence only; never unlocks or signs."""
    python = str(Path(sys.executable).resolve())
    survivor = lambda *command: subprocess.run(list(command), capture_output=True, text=True,
                                               timeout=6, env=checks.env, cwd='/')
    probe_result('survivor-true', lambda: survivor('/usr/bin/true'), 5)
    probe_result('survivor-python', lambda: survivor(python, '-I', '-c', 'print("probe-ok")'), 5)
    broker = getattr(checks.args, 'process_broker', None)
    if not broker:
        return
    # After any broker timeout the late reply stays in the pipe; later broker
    # requests would read stale replies and produce bogus fast results, so stop
    # the broker layer there. The launchd layer does not use the broker.
    broker_ok = probe_result('broker-root-true', lambda: broker.run(['/usr/bin/true'], {}, checks.env, timeout=2), 2)
    if broker_ok:
        for name, user in (('admin', checks.admin), ('agent', checks.agent)):
            if not probe_result('broker-' + name + '-python', lambda user=user: broker.run(
                    [python, '-I', '-c', 'print("probe-ok")'],
                    checks.credentials(user), checks.env, timeout=4), 4):
                break
    probe_result('launchd-fresh-job', lambda: fresh_job_probe(checks.base), 20)


POST_RELOGIN_LAUNCHER = Path('/Library/ANPKeydLogoutChecks-post-relogin.sh')


def write_post_relogin_state(checks, request, pending):
    """Serialize only what the new-session checker needs; root-owned, 0600."""
    base = checks.base
    result = base / 'post-relogin-result.json'
    try:
        result.unlink()
    except FileNotFoundError:
        pass
    state = {
        'config': checks.config,
        'path': str(checks.path),
        'base': str(base),
        'binary': str(Path(checks.args.binary).resolve()),
        'admin_uid': checks.admin.pw_uid,
        'agent_uid': checks.agent.pw_uid,
        'key': checks.key,
        'policy_id': checks.policy_id,
        'request': request,
        'pending': pending,
        'env': checks.env,
        'admin_credentials': checks.credentials(checks.admin),
        'agent_credentials': checks.credentials(checks.agent),
    }
    state_path = base / 'post-relogin-state.json'
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    return state_path


def write_post_relogin_launcher(state_path):
    """Fixed root-only entry point so the operator does not type stage paths."""
    launcher = POST_RELOGIN_LAUNCHER
    if launcher.is_symlink() or launcher.exists():
        meta = launcher.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0:
            raise ValueError('refusing to replace untrusted post-relogin launcher')
    # The state lives in the temporary service directory; the checker script
    # lives beside this module in the retained stage directory.
    module = Path(__file__).resolve().parent / 'post-relogin.py'
    script = ('#!/bin/sh\n'
              'state=' + shlex.quote(str(state_path)) + '\n'
              'if [ ! -f "$state" ]; then\n'
              '  echo "no pending logout acceptance at $state; start a new run" >&2\n'
              '  exit 1\n'
              'fi\n'
              'exec /usr/bin/python3 ' + shlex.quote(str(module)) + ' "$state"\n')
    launcher.write_text(script)
    launcher.chmod(0o700)
    return launcher


def wait_for_post_relogin_result(base, timeout=600):
    result_path = base / 'post-relogin-result.json'
    deadline = time.monotonic() + timeout
    while not result_path.exists():
        if time.monotonic() >= deadline:
            raise ValueError('post-relogin checker did not run within '
                             f'{timeout} seconds; run: sudo sh {POST_RELOGIN_LAUNCHER}')
        time.sleep(.5)
    meta = result_path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('post-relogin result is not a root-owned regular file')
    outcome = json.loads(result_path.read_text())
    if not outcome.get('ok'):
        raise ValueError('post-relogin checker failed: ' + str(outcome.get('error')))
    return outcome


POST_REBOOT_LAUNCHER = Path('/Library/ANPKeydRebootChecks-post-reboot.sh')


def host_boottime():
    """Seconds since the epoch at which the running kernel booted."""
    result = subprocess.run(['/usr/sbin/sysctl', '-n', 'kern.boottime'],
                            capture_output=True, text=True, timeout=10)
    match = re.search(r'sec = (\d+), usec = (\d+)', result.stdout)
    if result.returncode or not match:
        raise ValueError('kernel boot time unavailable: ' + result.stderr)
    seconds, micros = map(int, match.groups())
    if not 0 <= micros < 1_000_000:
        raise ValueError('invalid kernel boot timestamp')
    return seconds + micros / 1_000_000


def write_post_reboot_state(checks, request, pending):
    """Serialize only what the fresh-boot checker needs; root-owned, 0600."""
    base = checks.base
    result = base / 'post-reboot-result.json'
    try:
        result.unlink()
    except FileNotFoundError:
        pass
    status = checks.cli(checks.admin, 'status')
    if status.returncode != 0:
        raise ValueError('pre-reboot status failed: ' + status.stderr)
    current = json.loads(status.stdout)
    if current['instance_id'] != checks.config['instance_id']:
        raise ValueError('pre-reboot instance mismatch')
    state = {
        'config': checks.config,
        'path': str(checks.path),
        'base': str(base),
        'binary': str(Path(checks.args.binary).resolve()),
        'admin_uid': checks.admin.pw_uid,
        'agent_uid': checks.agent.pw_uid,
        'key': checks.key,
        'policy_id': checks.policy_id,
        'request': request,
        'pending': pending,
        'env': checks.env,
        'admin_credentials': checks.credentials(checks.admin),
        'agent_credentials': checks.credentials(checks.agent),
        'pre_boottime': host_boottime(),
        'pre_boot_epoch': current['boot_epoch'],
        'instance_id': current['instance_id'],
        'fixture': {'document': checks.fixture['manifest']['document'],
                    'helper': str(checks.fixture['helper']),
                    'vault_id': checks.fixture['vault_id']},
        'helper': str(base / 'LoginHelper.app/Contents/MacOS/anp-keyd'),
        'helper_sha256': str(checks.args.se_login_sha256),
        'hardware': checks.fixture['manifest']['hot_hardware'],
    }
    state_path = base / 'post-reboot-state.json'
    state_path.write_text(json.dumps(state))
    state_path.chmod(0o600)
    return state_path


def write_post_reboot_launcher(state_path):
    """Fixed root-only entry point so the operator does not type stage paths."""
    launcher = POST_REBOOT_LAUNCHER
    if launcher.is_symlink() or launcher.exists():
        meta = launcher.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0:
            raise ValueError('refusing to replace untrusted post-reboot launcher')
    module = Path(__file__).resolve().parent / 'post-reboot.py'
    script = ('#!/bin/sh\n'
              'state=' + shlex.quote(str(state_path)) + '\n'
              'if [ ! -f "$state" ]; then\n'
              '  echo "no pending reboot acceptance at $state; start a new run" >&2\n'
              '  exit 1\n'
              'fi\n'
              'exec /usr/bin/python3 ' + shlex.quote(str(module)) + ' "$state"\n')
    launcher.write_text(script)
    launcher.chmod(0o700)
    return launcher


def wait_for_manual_reboot(timeout=1800):
    """Hold the runner open until the machine reboots and kills this process."""
    print('READY FOR MANUAL REBOOT: save work and restart the Mac now. '
          'This script does not restart the machine. '
          'After logging in again, run the post-reboot command printed above.', flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(1)
    raise ValueError('machine did not reboot within '
                     f'{timeout} seconds; the prepared approval is abandoned')


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
    def approval_seconds(self, ending):
        # The fixture policy's duration bound and the approval expiry must come
        # from one source; a longer approval is refused as ADMIN_OPERATION_INVALID.
        return self.grant_limit() if ending in ('logout', 'reboot') else 240

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
        if self.args.se_ending in ('logout', 'reboot'):
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
                ending = getattr(self.args, 'se_ending', 'kill')
                change = self.base / 'stale-grant.json'
                change.write_text(json.dumps({'kind': 'Grant', 'change': {'action': 'Create',
                    'principal_id': self.config['principals'][0]['principal_id'],
                    'key_id': self.key['key_id'], 'policy_id': self.policy_id,
                    'policy_version': 1,
                    # Logout covers operator time away and back; other endings
                    # keep the short window that bounds the check itself.
                    'expiry': int(time.time()) + self.approval_seconds(ending),
                    'max_uses': 1}}))
                change.chmod(0o644)
                prepared = self.cli(self.admin, 'prepare', '--file', change)
                assert prepared.returncode == 0, prepared.stderr
                pending = json.loads(prepared.stdout)['prepared']
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
                    # Serialization must happen before logout; the surviving
                    # runner cannot start Python after relogin.
                    state_path = write_post_relogin_state(self, request, pending)
                    launcher = write_post_relogin_launcher(state_path)
                    print('ACTION REQUIRED after you log back in: sudo sh ' + str(launcher), flush=True)
                    def check_logged_out():
                        cached = self.request_as(self.agent, request)
                        assert cached['code'] != 'OK' or 'result' not in cached.get('data', {}), cached
                        listed = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
                        assert listed['code'] == 'OK' and listed['data']['keys'] == [], listed
                        print('PASS old cache suppressed and authorized keys empty at login window', flush=True)
                    operator_logout(self.admin.pw_uid, old_session, check_logged_out,
                        lambda: acceptance_graphical.relogin_session(self.admin))
                    context = acceptance_graphical.require_runner_session(
                        acceptance_graphical.relogin_session(self.admin), self.args.runner_audit_context)
                    print('PASS unchanged independent system runner audit context ' + json.dumps(context), flush=True)
                    if getattr(self.args, 'post_relogin_probes', False):
                        started = time.monotonic()
                        log_post_relogin_probes(self)
                        print(f'POST_RELOGIN_PROBE_SECONDS {time.monotonic() - started:.3f}', flush=True)
                    outcome = wait_for_post_relogin_result(self.base)
                    print('PASS post-relogin fresh-session checker ' + json.dumps(outcome['result']), flush=True)
                    if helper.poll() is None:
                        print('SE_HELPER_STATE running_after_relogin; terminating by signal', flush=True)
                        helper.terminate()
                        try:
                            helper.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            helper.kill()
                            helper.wait(timeout=10)
                    else:
                        print('SE_HELPER_STATE exited_after_relogin', flush=True)
                elif ending == 'reboot':
                    # The runner is killed by the reboot; the fresh-boot checker
                    # runs from the operator's new login and writes the verdict.
                    state_path = write_post_reboot_state(self, request, pending)
                    launcher = write_post_reboot_launcher(state_path)
                    print('ACTION REQUIRED after you log in following the reboot: sudo sh '
                          + str(launcher), flush=True)
                    wait_for_manual_reboot()
                else:
                    helper.send_signal(signal.SIGSTOP if ending == 'hang' else signal.SIGKILL)
                if ending not in ('logout', 'reboot'):
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
                    if ending in ('sleep', 'long-sleep', 'user-switch', 'restart', 'crash'):
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
