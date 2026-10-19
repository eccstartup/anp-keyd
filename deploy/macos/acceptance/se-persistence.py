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
    path = Path(filename)
    if not path.is_absolute():
        path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load('se_preflight', Path(__file__).resolve().parents[1] / 'se-preflight.py')
RELEASE = load('se_release', Path(__file__).resolve().parents[1] / 'se-release.py')


class AcceptanceError(Exception):
    pass


def run(binary, *arguments, uid=None, timeout=120, isolated_session=False):
    environment = os.environ.copy()
    if uid is not None and uid != os.geteuid():
        try:
            account = pwd.getpwuid(uid)
        except KeyError as error:
            raise AcceptanceError(f'no such UID: {uid}') from error
        if account.pw_uid == 0:
            raise AcceptanceError('the second UID must be non-root')
        # The primary process stays in the operator's login session: root has
        # no login data protection keychain. The denial probe only needs the
        # binary to run under the other account, so ask sudo for that one
        # process. A password prompt, if needed, appears on the operator's tty.
        command = ['/usr/bin/sudo', '-u', account.pw_name, '--',
                   str(binary), *map(str, arguments)]
        if isolated_session:
            command = ['/usr/bin/sudo', '--', '/usr/bin/python3',
                       str(Path(__file__).with_name('se-isolated-open.py').resolve()),
                       '--uid', str(uid), '--binary', str(binary),
                       '--sha256', hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                       '--', *map(str, arguments)]
        try:
            result = subprocess.run(command, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise AcceptanceError(f'could not run as {account.pw_name}: {error}') from error
        error = result.stderr.decode(errors='replace').strip()
        if result.returncode and error.startswith('sudo:'):
            raise AcceptanceError(f'could not switch to UID {uid}: {error}')
        return result

    try:
        return subprocess.run([str(binary), *map(str, arguments)], env=environment,
                              capture_output=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as error:
        raise AcceptanceError(f'{binary} failed to run: {error}') from error


def output(result):
    return b'\n'.join((result.stdout, result.stderr)).decode(errors='replace').strip()


def process_context(result):
    for line in output(result).splitlines():
        if line.startswith('SE_CONTEXT '):
            context = json.loads(line[len('SE_CONTEXT '):])
            if not isinstance(context, dict):
                raise AcceptanceError('probe context must be a dictionary')
            return context
    return None


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
    if os.geteuid() == 0:
        raise AcceptanceError(
            'run this from the login user\'s terminal; root has no login data protection '
            'keychain. Use --other-uid to have sudo run only the denial probe as a second user')
    if args.unsigned_binary and not args.unsigned_sha256:
        raise AcceptanceError('--unsigned-binary requires its reviewed --unsigned-sha256')
    if getattr(args, 'isolated_session', False) and args.other_uid is None:
        raise AcceptanceError('--isolated-session requires --other-uid')
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
        'cross_uid_scope': ('independent-security-session' if getattr(args, 'isolated_session', False)
                            else 'inherited-security-session'),
        'scope_limitations': ([
            'independent-session denial does not supersede demonstrated inherited-session access',
            'the deployed Agent launcher and full helper lifecycle require separate acceptance',
        ] if getattr(args, 'isolated_session', False) else []),
        'denial_layer': ('application-login-policy' if getattr(args, 'checked_open', False)
                         else 'raw-keychain'),
        'pending': PENDING,
    }
    if getattr(args, 'checked_open', False):
        report['scope_limitations'].append(
            'application-policy denial does not establish raw OS keychain separation')
    created = False
    try:
        # 1. Process A creates a persistent SE key and its envelope-side state.
        result = run(binary, 'create', state, tag, timeout=args.timeout)
        require_success(result, 'create')
        created = True
        report['creator_context'] = process_context(result)
        state_data = read_state(state)
        if state_data['tag_hint'] != tag:
            raise AcceptanceError('created state names a different tag')
        report['phases']['create'] = 'ok'
        report['state_sha256'] = hashlib.sha256(state.read_bytes()).hexdigest()

        # 2. Process B reopens it. This is the actual claim.
        open_command = 'open-checked' if getattr(args, 'checked_open', False) else 'open'
        result = run(binary, open_command, state, timeout=args.timeout)
        text = require_success(result, 'open in a new process')
        if 'PASS ' + tag not in text:
            raise AcceptanceError(f'open did not report PASS for {tag}: {text}')
        report['phases']['open_new_process'] = 'ok'
        report['persistence_across_processes'] = True

        # 3. Another UID must not reopen the same key. The state file is public
        #    on purpose: the denial has to come from the keychain, not from
        #    file permissions on the state.
        if args.other_uid is not None:
            # macOS TMPDIR has a user-only (0700) ancestor. Making its child
            # world-searchable cannot let another UID traverse that ancestor.
            # Only the public ciphertext/state and signed code go here; the
            # private work directory and key material remain separate.
            public = Path(tempfile.mkdtemp(prefix='anp-se-public-', dir='/private/tmp'))
            public_directories.append(public)
            os.chmod(public, 0o755)
            public_state = public / 'state.json'
            shutil.copyfile(state, public_state)
            os.chmod(public_state, 0o644)
            # Preserve the containing app/profile for development signatures;
            # a bare copied executable may be killed before keychain access.
            bundle = binary.parent.parent.parent
            if (binary.parent.name == 'MacOS' and bundle.suffix == '.app'
                    and (bundle / 'Contents' / 'embedded.provisionprofile').is_file()):
                copied_bundle = public / bundle.name
                shutil.copytree(bundle, copied_bundle)
                public_binary = copied_bundle / 'Contents' / 'MacOS' / binary.name
            else:
                public_binary = public / 'se-persistence'
                shutil.copyfile(binary, public_binary)
            os.chmod(public_binary, 0o755)
            if hashlib.sha256(public_binary.read_bytes()).hexdigest() != args.sha256:
                raise AcceptanceError('copied acceptance binary changed bytes')
            extra = {'isolated_session': True} if getattr(args, 'isolated_session', False) else {}
            denied = run(public_binary, open_command, public_state, uid=args.other_uid,
                         timeout=args.timeout, **extra)
            report['other_uid_probe'] = {
                'requested_uid': args.other_uid,
                'returncode': denied.returncode,
                'context': process_context(denied),
                'output': output(denied),
            }
            context = report['other_uid_probe']['context']
            if (context is None or context.get('uid') != args.other_uid
                    or context.get('euid') != args.other_uid):
                raise AcceptanceError('second UID kernel identity was not confirmed')
            if getattr(args, 'isolated_session', False):
                creator = report['creator_context']
                if (creator is None or context.get('audit_uid') != args.other_uid
                        or context.get('audit_session') in (None, 0, 0xffffffff,
                                                           creator.get('audit_session'))
                        or context.get('session_attributes', 0xffffffff) & 0x1011):
                    raise AcceptanceError('independent security session was not confirmed')
            if denied.returncode == 0:
                raise AcceptanceError('another UID reopened the Secure Enclave key')
            detail = output(denied)
            if getattr(args, 'checked_open', False):
                if 'SE_LOGIN_SESSION_REQUIRED' not in detail:
                    raise AcceptanceError('production login policy did not provide the expected refusal: ' + detail)
            elif not any(marker in detail for marker in
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
    except AcceptanceError as error:
        # Preserve the actual identities, partial phases and cleanup result on
        # failures too; a summary string alone loses the security evidence.
        error.report = report
        raise
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
                        help='second non-root UID that must be denied; run through sudo')
    parser.add_argument('--isolated-session', action='store_true',
                        help='test a fresh non-GUI audit/bootstrap session; does not supersede inherited-session findings')
    parser.add_argument('--checked-open', action='store_true',
                        help='test application login policy, separately from raw OS keychain access')
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
        report = getattr(error, 'report', {'schema': 1,
                  'hardware_acceptance_complete': False,
                  'lifecycle_acceptance_complete': False})
        report.update(passed=False, error=str(error))
        if args.out:
            args.out.write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(report, indent=2))
        return 1
    report['passed'] = report['persistence_across_processes'] and report['deleted_key_rejected']
    if args.out:
        args.out.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
