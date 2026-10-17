#!/usr/bin/env python3
"""U3 acceptance: a Secure Enclave key must survive a process boundary.

This drives `examples/se-persistence` twice, in separate processes:

    create  ->  open (new process)  ->  delete  ->  open (must fail)

It also checks, when given an explicit second UID, that another local user
cannot reopen the same key, and, when given an unsigned binary, that the
unsigned build cannot create a persistent SE key at all. It never writes key
material: only the public keychain label, the ECDH ciphertext and a SHA-256 of
the derived HS are stored, and all of them live in a temporary directory.

Passing this tool proves persistent create/open across processes. It does not
prove logout/relogin, user switching, sleep/wake, reboot, upgrade or recovery;
those remain operator-run lifecycle acceptance.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

PENDING = [
    'logout/relogin and user switching',
    'sleep/wake and wall-clock rollback',
    'whole-machine reboot',
    'upgrade with the same identity/profile',
    'SE unavailable, key loss, signature identity change and recovery',
    'distribution review of the macOS protection claim',
]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load('se_preflight', 'se-preflight.py')
RELEASE = load('se_release', 'se-release.py')


class AcceptanceError(Exception):
    pass


def run(binary, *arguments, uid=None, timeout=120):
    environment = os.environ.copy()
    preexec = None
    if uid is not None:
        try:
            account = pwd.getpwuid(uid)
        except KeyError as error:
            raise AcceptanceError(f'no such UID: {uid}') from error
        if account.pw_uid == 0:
            raise AcceptanceError('the second UID must be non-root')
        environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                       'HOME': account.pw_dir, 'USER': account.pw_name}

        def preexec():
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)

    try:
        return subprocess.run([str(binary), *map(str, arguments)], env=environment,
                              capture_output=True, timeout=timeout, preexec_fn=preexec)
    except (OSError, subprocess.SubprocessError) as error:
        raise AcceptanceError(f'{binary} failed to run: {error}') from error


def output(result):
    return (result.stdout + result.stderr).decode(errors='replace').strip()


def require_success(result, operation):
    if result.returncode:
        raise AcceptanceError(f'{operation} failed ({result.returncode}): {output(result)}')
    return output(result)


def read_state(path):
    meta = path.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
        raise AcceptanceError(f'state file is not a private regular file: {path}')
    state = json.loads(path.read_text())
    for key in ('schema', 'tag_hint', 'root', 'ciphertext_b64', 'hs_sha256'):
        if key not in state:
            raise AcceptanceError(f'state file has no {key!r}')
    if state['schema'] != 1:
        raise AcceptanceError(f"state schema is {state['schema']}, expected 1")
    return state


def verify_binary(binary, digest, team, application):
    if not binary.is_file() or binary.is_symlink():
        raise AcceptanceError(f'candidate must be a regular file: {binary}')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise AcceptanceError('candidate digest mismatch')
    report = PREFLIGHT.inspect(binary, digest, 'user-session', team, application)
    if not report['signature_prerequisites_passed']:
        raise AcceptanceError('signature prerequisites failed: ' + '; '.join(report['blockers']))
    return report


def accept(args):
    RELEASE.validate_identity_fields(args.team_id, args.application_id)
    if args.other_uid is not None and os.geteuid() != 0:
        raise AcceptanceError('--other-uid requires root (credential switching)')
    if args.unsigned_binary and not args.unsigned_sha256:
        raise AcceptanceError('--unsigned-binary requires its reviewed --unsigned-sha256')
    binary = args.binary.resolve(strict=True)
    signature = verify_binary(binary, args.sha256, args.team_id, args.application_id)
    work = Path(tempfile.mkdtemp(prefix='anp-se-acceptance-'))
    os.chmod(work, 0o700)
    public_directories = []
    state = work / 'state.json'
    tag = 'acceptance-' + uuid.uuid4().hex
    report = {
        'schema': 1,
        'candidate_sha256': args.sha256,
        'team_id': args.team_id,
        'application_identifier': args.application_id,
        'tag': tag,
        'signature': signature,
        'work_directory': str(work),
        'phases': {},
        'persistence_across_processes': False,
        'cross_uid_denial': None,
        'deleted_key_rejected': False,
        'unsigned_persistent_creation_refused': None,
        'hardware_acceptance_complete': False,
        'lifecycle_acceptance_complete': False,
        'pending': PENDING,
    }
    created = False
    try:
        # 1. Process A creates a persistent SE key and its envelope-side state.
        result = run(binary, 'create', state, tag, timeout=args.timeout)
        require_success(result, 'create')
        created = True
        state_data = read_state(state)
        if state_data['tag_hint'] != tag:
            raise AcceptanceError('created state names a different tag')
        report['phases']['create'] = 'ok'
        report['state_sha256'] = hashlib.sha256(state.read_bytes()).hexdigest()

        # 2. Process B reopens it. This is the actual claim.
        result = run(binary, 'open', state, timeout=args.timeout)
        text = require_success(result, 'open in a new process')
        if 'PASS ' + tag not in text:
            raise AcceptanceError(f'open did not report PASS for {tag}: {text}')
        report['phases']['open_new_process'] = 'ok'
        report['persistence_across_processes'] = True

        # 3. Another UID must not reopen the same key. The state file is public
        #    on purpose: the denial has to come from the keychain, not from
        #    file permissions on the state.
        if args.other_uid is not None:
            public = Path(tempfile.mkdtemp(prefix='anp-se-public-'))
            public_directories.append(public)
            os.chmod(public, 0o755)
            public_state = public / 'state.json'
            shutil.copyfile(state, public_state)
            os.chmod(public_state, 0o644)
            public_binary = public / 'se-persistence'
            shutil.copyfile(binary, public_binary)
            os.chmod(public_binary, 0o755)
            if hashlib.sha256(public_binary.read_bytes()).hexdigest() != args.sha256:
                raise AcceptanceError('copied acceptance binary changed bytes')
            denied = run(public_binary, 'open', public_state, uid=args.other_uid,
                         timeout=args.timeout)
            if denied.returncode == 0:
                raise AcceptanceError('another UID reopened the Secure Enclave key')
            detail = output(denied)
            if not any(marker in detail for marker in
                       ('cannot use it', 'no key with that label', 'not allowed',
                        'HardwareMissing', 'errSecItemNotFound')):
                raise AcceptanceError('second UID failed for an unexpected reason: ' + detail)
            report['phases']['cross_uid_denied'] = 'ok'
            report['cross_uid_denial'] = True
        else:
            report['phases']['cross_uid_denied'] = 'not tested (no --other-uid)'

        # 4. Remove the key and prove the old envelope can no longer open it.
        result = run(binary, 'delete', state, timeout=args.timeout)
        text = require_success(result, 'delete')
        if 'DELETED ' + tag not in text:
            raise AcceptanceError(f'delete did not report DELETED for {tag}: {text}')
        created = False
        report['phases']['delete'] = 'ok'
        gone = run(binary, 'open', state, timeout=args.timeout)
        if gone.returncode == 0:
            raise AcceptanceError('the envelope still opened after the SE key was deleted')
        detail = output(gone)
        if not any(marker in detail for marker in
                   ('cannot use it', 'no key with that label', 'HardwareMissing')):
            raise AcceptanceError('post-delete open failed for an unexpected reason: ' + detail)
        report['phases']['open_after_delete_rejected'] = 'ok'
        report['deleted_key_rejected'] = True

        # 5. An unsigned binary must not be able to create a persistent key.
        if args.unsigned_binary:
            unsigned = args.unsigned_binary.resolve(strict=True)
            if not unsigned.is_file() or unsigned.is_symlink():
                raise AcceptanceError(f'unsigned candidate must be a regular file: {unsigned}')
            if hashlib.sha256(unsigned.read_bytes()).hexdigest() != args.unsigned_sha256:
                raise AcceptanceError('unsigned candidate digest mismatch')
            if unsigned == binary:
                raise AcceptanceError('--unsigned-binary must differ from --binary')
            unsigned_state = work / 'unsigned-state.json'
            unsigned_tag = 'acceptance-' + uuid.uuid4().hex
            result = run(unsigned, 'create', unsigned_state, unsigned_tag, timeout=args.timeout)
            if result.returncode == 0:
                # Do not leave a key behind even when the expected refusal failed.
                if unsigned_state.exists():
                    run(binary, 'delete', unsigned_state, timeout=args.timeout)
                raise AcceptanceError('an unsigned binary created a persistent SE key')
            detail = output(result)
            if not any(marker in detail for marker in
                       ('errSecMissingEntitlement', 'not allowed to save', '-34018')):
                raise AcceptanceError('unsigned create failed for an unexpected reason: ' + detail)
            if unsigned_state.exists():
                raise AcceptanceError('unsigned create left a state file behind')
            report['phases']['unsigned_create_refused'] = 'ok'
            report['unsigned_persistent_creation_refused'] = True
        else:
            report['phases']['unsigned_create_refused'] = 'not tested (no --unsigned-binary)'
    finally:
        if created:
            try:
                cleanup = run(binary, 'delete', state, timeout=args.timeout)
                report['phases']['cleanup'] = 'ok' if cleanup.returncode == 0 else output(cleanup)
            except AcceptanceError as error:
                report['phases']['cleanup'] = str(error)
        shutil.rmtree(work, ignore_errors=True)
        for directory in public_directories:
            shutil.rmtree(directory, ignore_errors=True)
    report['passed'] = report['persistence_across_processes'] and report['deleted_key_rejected']
    report['acceptance_scope_complete'] = (
        report['passed']
        and report['cross_uid_denial'] is True
        and report['unsigned_persistent_creation_refused'] is True
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--binary', type=Path, required=True,
                        help='signed se-persistence example')
    parser.add_argument('--sha256', required=True,
                        help='reviewed lowercase SHA-256 of --binary')
    parser.add_argument('--team-id', required=True)
    parser.add_argument('--application-id', required=True)
    parser.add_argument('--other-uid', type=int,
                        help='second non-root UID that must be denied; requires root')
    parser.add_argument('--unsigned-binary', type=Path,
                        help='same example built and signed without the SE entitlement')
    parser.add_argument('--unsigned-sha256',
                        help='reviewed lowercase SHA-256 of --unsigned-binary')
    parser.add_argument('--timeout', type=int, default=120)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    try:
        if not args.sha256.islower() or len(args.sha256) != 64:
            raise AcceptanceError('expected a lowercase SHA-256')
        report = accept(args)
    except (AcceptanceError, ValueError, OSError) as error:
        report = {'schema': 1, 'passed': False, 'error': str(error),
                  'hardware_acceptance_complete': False,
                  'lifecycle_acceptance_complete': False}
        print(json.dumps(report, indent=2))
        return 1
    report['passed'] = report['persistence_across_processes'] and report['deleted_key_rejected']
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
