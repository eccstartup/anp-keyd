#!/usr/bin/python3
"""Fresh-boot authority checks after a whole-machine reboot.

Run as root after logging back in. Reads only the root-owned state written
before the reboot, verifies the kernel boot time actually advanced, starts a
fresh temporary daemon from the retained configuration, performs the fixed
checks and writes a result. No retries, no widened authority, no interactive
secrets beyond the public temporary test password.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

import acceptance_graphical
import acceptance_se
import acceptance_signing

SCHEMA = {'config', 'path', 'base', 'binary', 'admin_uid', 'agent_uid', 'key',
          'policy_id', 'request', 'pending', 'env', 'admin_credentials',
          'agent_credentials', 'pre_boottime', 'pre_boot_epoch', 'instance_id',
          'fixture', 'helper', 'helper_sha256', 'hardware'}


def validate_state(state):
    if set(state) != SCHEMA:
        raise ValueError('unexpected state schema')
    for name in ('pending', 'key', 'config', 'fixture'):
        if not isinstance(state[name], dict):
            raise ValueError('unexpected state value type')
    if not isinstance(state['pre_boottime'], (int, float)):
        raise ValueError('unexpected boot time value')
    if not isinstance(state['pre_boot_epoch'], int):
        raise ValueError('unexpected boot epoch value')


def load_state(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('state must be a regular file')
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('state must be root-owned, regular and not group/world writable')
    parent = path.parent.resolve()
    meta = parent.stat()
    if meta.st_uid != 0 or meta.st_mode & 0o022:
        raise ValueError('state directory must be root-owned and not group/world writable')
    state = json.loads(path.read_text())
    validate_state(state)
    return state


def reboot_confirmed(before, current, now):
    if not before > 0:
        raise ValueError('stored boot time is invalid')
    if current <= before + 1:
        raise ValueError('kernel boot time did not advance; reboot was not observed')
    if current > now + 1:
        raise ValueError('kernel boot time is in the future')
    return {'pre_boottime': before, 'boottime': current}


def approval_state(pending, now):
    """Prepared admin operations carry a fixed 120-second preparation window.

    A whole-machine reboot plus login normally exceeds it, so both branches are
    valid post-reboot evidence: an unexpired approval must be refused by the
    boot-epoch binding, and an expired one must simply be unusable.
    """
    expires = pending.get('expires_at')
    if type(expires) is not int:
        raise ValueError('approval expiry missing')
    return 'unexpired' if now + 5 < expires else 'expired'


def credentials_for(state):
    by_uid = {state['admin_uid']: state['admin_credentials'],
              state['agent_uid']: state['agent_credentials']}

    def credentials(user, extra_admin_group=False):
        if extra_admin_group or user.pw_uid not in by_uid:
            raise ValueError('unexpected post-reboot credentials request')
        return by_uid[user.pw_uid]
    return credentials


def service_credentials(config):
    service = pwd.getpwuid(config['service_uid'])
    groups = [config['agent_gid'], config['admin_gid']]
    groups = [service.pw_gid, *sorted(set(groups) - {service.pw_gid})]
    return {'user': service.pw_uid, 'group': service.pw_gid, 'extra_groups': groups}


def start_daemon(state):
    base = Path(state['base'])
    log = base / 'post-reboot-daemon.log'
    with log.open('a') as output:
        proc = subprocess.Popen([state['binary'], 'serve-protected', '--config', state['path']],
                                **service_credentials(state['config']), env=state['env'],
                                cwd='/', stdout=output, stderr=output)
    return proc


def stop_daemon(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
        raise ValueError('fresh daemon graceful shutdown timed out')
    if proc.returncode != 0:
        raise ValueError('fresh daemon did not shut down normally')


def wait_ready(proc, status, instance_id, timeout=15):
    deadline = time.monotonic() + timeout
    last = 'no successful management response'
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise ValueError('fresh daemon failed to start')
        result = status()
        if result.returncode == 0:
            reply = json.loads(result.stdout)
            if reply.get('instance_id') != instance_id:
                raise ValueError('fresh daemon instance mismatch')
            return reply
        last = result.stderr.strip()
        time.sleep(.05)
    raise ValueError('fresh daemon startup timed out: ' + last)


def wait_helper(log, helper, marker, timeout=145):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if helper.poll() is not None:
            raise ValueError('signed helper exited: ' + log.read_text(errors='replace'))
        if marker in log.read_text(errors='replace'):
            return
        time.sleep(.2)
    raise ValueError('signed helper did not establish a real SE session')


def verify_signature(state, admin, credentials, public):
    helper = state['fixture']['helper']
    verified = subprocess.run([helper, 'verify'], input=json.dumps(public),
                              capture_output=True, text=True, timeout=15,
                              **credentials(admin), env=state['env'], cwd='/')
    if verified.returncode != 0 or verified.stdout.strip() != 'VERIFIED':
        raise ValueError('independent verification failed: ' + verified.stderr)
    changed = {**public, 'url': 'https://example.com/other'}
    rejected = subprocess.run([helper, 'verify'], input=json.dumps(changed),
                              capture_output=True, text=True, timeout=15,
                              **credentials(admin), env=state['env'], cwd='/')
    if rejected.returncode == 0:
        raise ValueError('independent verifier accepted a changed target')


def run_checks(state):
    if os.geteuid() != 0:
        raise ValueError('post-reboot checker requires root')
    admin = pwd.getpwuid(state['admin_uid'])
    agent = pwd.getpwuid(state['agent_uid'])
    now = time.time()
    boot = reboot_confirmed(state['pre_boottime'], acceptance_se.host_boottime(), now)
    session = acceptance_graphical.relogin_session(admin)
    config, path = state['config'], Path(state['path'])
    credentials = credentials_for(state)

    def cli(user, *command):
        return subprocess.run([state['binary'], 'admin', '--config', str(path), *command],
                              **credentials(user), env=state['env'], cwd='/',
                              capture_output=True, text=True, timeout=15)

    helper_path = Path(state['helper'])
    if not helper_path.is_file() or helper_path.is_symlink():
        raise ValueError('retained login helper is missing')
    if hashlib.sha256(helper_path.read_bytes()).hexdigest() != state['helper_sha256']:
        raise ValueError('retained login helper digest mismatch')

    process = start_daemon(state)
    try:
        status = wait_ready(process, lambda: cli(admin, 'status'), state['instance_id'])
        if status['boot_epoch'] <= state['pre_boot_epoch']:
            raise ValueError('service boot epoch did not advance across reboot')
        args = SimpleNamespace(binary=Path(state['binary']), process_broker=None,
                               logout_diagnostics=False, interactive_ui=False, se_ending='reboot')
        checks = acceptance_signing.Checks(Path(state['base']), config, path, args, None,
                                           admin, agent, credentials, state['env'], cli)
        checks.key, checks.policy_id = state['key'], state['policy_id']
        checks.request = state['request']
        request, pending = checks.request, state['pending']
        deadline = time.monotonic() + 10
        while True:
            replay = checks.request_as(agent, request)
            if replay['code'] != 'OK' or 'result' not in replay.get('data', {}):
                break
            if time.monotonic() >= deadline:
                raise ValueError('old cached signature survived the reboot')
            time.sleep(.2)
        keys = checks.request_as(agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
        if keys['code'] != 'OK' or keys['data']['keys'] != []:
            raise ValueError('authorized keys survived the reboot: ' + json.dumps(keys))
        approval = approval_state(pending, time.time())
        stale = cli(admin, 'commit', '--operation-id', pending['operation_id'],
                    '--digest', pending['digest'])
        if stale.returncode == 0:
            raise ValueError('old approval survived the reboot')
        if approval == 'expired':
            print('NOTE pre-reboot approval was already past its fixed 120-second '
                  'preparation window; it must be unusable regardless. The boot-epoch '
                  'refusal for an unexpired approval is covered by the isolated '
                  'restart/crash acceptance.', flush=True)
        fresh = checks.grant()
        checks.expect_locked(fresh)

        print('UI: check the temporary exact key and enter ONLY the public test password: '
              + acceptance_signing.PASSWORD, flush=True)
        command = [str(helper_path), 'admin', '--config', str(path), 'se-session',
                   '--vault-id', state['fixture']['vault_id'], '--did', state['key']['did'],
                   '--kid', state['key']['kid']]
        log = Path(state['base']) / 'post-reboot-helper.log'
        with log.open('w+') as output:
            helper = subprocess.Popen(acceptance_graphical.command(admin, path, command),
                                      stdin=subprocess.DEVNULL, stdout=output,
                                      stderr=output, cwd='/')
            try:
                wait_helper(log, helper, 'SE session active for exact key')
                request = checks.signing(fresh)
                signed = checks.request_as(agent, request)
                if signed['code'] != 'OK' or signed['data']['state'] != 'completed':
                    raise ValueError('fresh-boot signature failed: ' + json.dumps(signed))
                public = {'document': state['fixture']['document'], **signed['data']['result']}
                verify_signature(state, admin, credentials, public)
                if checks.request_as(agent, request)['data'] != signed['data']:
                    raise ValueError('fresh-boot retry returned a different result')
            finally:
                if helper.poll() is None:
                    helper.terminate()
                    try:
                        helper.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        helper.kill()
                        helper.wait(timeout=10)
                print('SE helper log: ' + log.read_text(errors='replace'), flush=True)
        # Session exit revokes every grant by design; only a new grant may
        # observe that the key is locked again.
        final = checks.grant()
        checks.expect_locked(final)
    finally:
        stop_daemon(process)
    return {'session': session,
            'boot': boot,
            'boot_epoch': status['boot_epoch'],
            'approval': approval,
            'approval_age_seconds': int(time.time() - (pending['expires_at'] - 120)),
            'checks': ['old cache suppressed', 'authorized keys empty',
                       'old approval unusable (' + approval + ')', 'fresh grant locked',
                       'SE key persisted and unlocked by a new login session',
                       'helper exit relocked the key']}


def main():
    if len(sys.argv) != 2:
        raise ValueError('usage: post-reboot.py <state.json>')
    state = load_state(sys.argv[1])
    result_path = Path(state['base']) / 'post-reboot-result.json'
    try:
        outcome = {'ok': True, 'result': run_checks(state)}
        print('PASS post-reboot checks ' + json.dumps(outcome['result']), flush=True)
    except Exception as error:
        outcome = {'ok': False, 'error': type(error).__name__ + ': ' + str(error)}
        print('FAIL post-reboot checks ' + outcome['error'], flush=True)
    temporary = result_path.with_name('post-reboot-result.tmp')
    temporary.write_text(json.dumps(outcome))
    temporary.chmod(0o600)
    os.replace(temporary, result_path)
    return 0 if outcome['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
