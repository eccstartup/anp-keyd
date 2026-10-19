#!/usr/bin/python3
"""Fixed post-relogin authority checks from the new graphical session.

Run as root after the logout acceptance prints ACTION REQUIRED. Reads only the
root-owned state written before logout, performs the remaining fixed checks and
writes a result. No retries, no widened authority, no interactive secrets.
"""
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
import acceptance_signing

SCHEMA = {'config', 'path', 'base', 'binary', 'admin_uid', 'agent_uid', 'key',
          'policy_id', 'request', 'pending', 'env', 'admin_credentials',
          'agent_credentials'}


def validate_state(state):
    if set(state) != SCHEMA:
        raise ValueError('unexpected state schema')
    if not isinstance(state['pending'], dict) or not isinstance(state['key'], dict):
        raise ValueError('unexpected state value type')


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


def credentials_for(state):
    by_uid = {state['admin_uid']: state['admin_credentials'],
              state['agent_uid']: state['agent_credentials']}

    def credentials(user, extra_admin_group=False):
        if extra_admin_group or user.pw_uid not in by_uid:
            raise ValueError('unexpected post-relogin credentials request')
        return by_uid[user.pw_uid]
    return credentials


def run_checks(state):
    if os.geteuid() != 0:
        raise ValueError('post-relogin checker requires root')
    admin = pwd.getpwuid(state['admin_uid'])
    agent = pwd.getpwuid(state['agent_uid'])
    session = acceptance_graphical.relogin_session(admin)
    config = state['config']
    path = Path(state['path'])
    credentials = credentials_for(state)

    def cli(user, *command):
        return subprocess.run([state['binary'], 'admin', '--config', str(path), *command],
                              **credentials(user), env=state['env'], cwd='/',
                              capture_output=True, text=True, timeout=15)
    args = SimpleNamespace(binary=Path(state['binary']), process_broker=None,
                           logout_diagnostics=False, interactive_ui=False, se_ending='logout')
    checks = acceptance_signing.Checks(Path(state['base']), config, path, args, None,
                                       admin, agent, credentials, state['env'], cli)
    checks.key = state['key']
    checks.policy_id = state['policy_id']
    checks.request = state['request']
    request, pending = checks.request, state['pending']
    deadline = time.monotonic() + 10
    while True:
        replay = checks.request_as(agent, request)
        if replay['code'] != 'OK' or 'result' not in replay.get('data', {}):
            break
        if time.monotonic() >= deadline:
            raise ValueError('SE session loss did not suppress cached signature')
        time.sleep(.2)
    keys = checks.request_as(agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
    if keys['code'] != 'OK' or keys['data']['keys'] != []:
        raise ValueError('authorized keys not empty: ' + json.dumps(keys))
    if not time.time() + 5 < pending['expires_at']:
        raise ValueError('approval expired before teardown check')
    stale = cli(admin, 'commit', '--operation-id', pending['operation_id'], '--digest', pending['digest'])
    if stale.returncode == 0:
        raise ValueError('old approval survived SE session loss')
    fresh = checks.grant()
    checks.expect_locked(fresh)
    return {'session': session,
            'checks': ['cache suppressed', 'authorized keys empty',
                       'stale approval refused', 'fresh grant locked']}


def main():
    if len(sys.argv) != 2:
        raise ValueError('usage: post-relogin.py <state.json>')
    state = load_state(sys.argv[1])
    result_path = Path(state['base']) / 'post-relogin-result.json'
    try:
        outcome = {'ok': True, 'result': run_checks(state)}
        print('PASS post-relogin checks ' + json.dumps(outcome['result']), flush=True)
    except Exception as error:
        outcome = {'ok': False, 'error': type(error).__name__ + ': ' + str(error)}
        print('FAIL post-relogin checks ' + outcome['error'], flush=True)
    temporary = result_path.with_name('post-relogin-result.tmp')
    temporary.write_text(json.dumps(outcome))
    temporary.chmod(0o600)
    os.replace(temporary, result_path)
    return 0 if outcome['ok'] else 1


if __name__ == '__main__':
    sys.exit(main())
