#!/usr/bin/env python3
"""Read-only U3 SE deployment gate. Never executes or signs the candidate.

Signature prerequisites are not hardware acceptance. A system LaunchDaemon
cannot use this backend's data protection keychain even with a valid signature.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import sys

REFERENCE = 'https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains'
ENV = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'}


def policy(context, team, application, metadata, entitlements):
    blockers = []
    if context == 'system-daemon':
        blockers.append('system LaunchDaemon has no user login data protection keychain; signing cannot fix this')
    if not re.fullmatch(r'[A-Z0-9]{10}', team):
        blockers.append('expected an explicit 10-character Apple Team ID')
    if not application.startswith(team + '.') or '*' in application or application == team + '.':
        blockers.append('expected an exact team-prefixed application identifier')
    if metadata.get('TeamIdentifier') != team or not metadata.get('Authority'):
        blockers.append('signature must have the expected team and a certificate authority chain')
    if not any(name.startswith('Apple Root CA')
               for name in metadata.get('authorities', [])):
        blockers.append('certificate chain does not anchor at an Apple root CA')
    if metadata.get('Signature') == 'adhoc':
        blockers.append('ad-hoc signatures are not accepted')
    if 'runtime' not in metadata.get('flags', '').split(','):
        blockers.append('hardened runtime is required for the release candidate')
    if entitlements.get('com.apple.application-identifier') != application:
        blockers.append('macOS application identifier entitlement differs from the approved identifier')
    if entitlements.get('com.apple.developer.team-identifier') != team:
        blockers.append('team entitlement differs from the approved team')
    # No additional app/group may share the wrapping keys in this initial profile.
    if entitlements.get('keychain-access-groups', [application]) != [application]:
        blockers.append('only the exact application keychain access group is allowed')
    if entitlements.get('com.apple.security.application-groups', []):
        blockers.append('application groups are outside the initial isolated keychain profile')
    if entitlements.get('application-identifier', application) != application:
        blockers.append('conflicting legacy application identifier')
    for name in ['com.apple.security.get-task-allow', 'get-task-allow',
                 'com.apple.security.cs.disable-library-validation',
                 'com.apple.security.cs.allow-dyld-environment-variables',
                 'com.apple.security.cs.allow-unsigned-executable-memory',
                 'com.apple.security.cs.allow-jit']:
        if entitlements.get(name, False) is not False:
            blockers.append('release entitlement forbidden: ' + name)
    return blockers


def command(arguments):
    result = subprocess.run(arguments, env=ENV, capture_output=True, timeout=30)
    if result.returncode:
        raise ValueError('code signature inspection/verification failed: ' + result.stderr.decode(errors='replace'))
    return result


def inspect(binary, digest, context, team, application):
    if sys.platform != 'darwin':
        raise ValueError('macOS only')
    if not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('expected lowercase SHA-256')
    meta = binary.lstat()
    if not stat.S_ISREG(meta.st_mode):
        raise ValueError('candidate must be a regular file, not a symlink')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError('candidate digest mismatch')
    command(['/usr/bin/codesign', '--verify', '--strict', '--verbose=2', str(binary)])
    details = command(['/usr/bin/codesign', '-d', '--verbose=4', str(binary)])
    metadata = {}
    authorities = []
    for line in details.stderr.decode().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            metadata[key] = value
            if key == 'Authority':
                authorities.append(value)
    metadata['authorities'] = authorities
    # codesign includes runtime in the parenthesized flag description.
    flags = re.search(r'flags=0x[0-9a-f]+\(([^)]*)\)', details.stderr.decode())
    metadata['flags'] = flags.group(1) if flags else ''
    # Current codesign defaults to a human-readable [Dict] representation.
    # The colon-prefixed destination serializes DER entitlements as a plist;
    # --xml alone can return nothing for a DER-only signature. Fail closed if
    # a future codesign removes this deprecated serialization interface.
    raw = command(['/usr/bin/codesign', '-d', '--entitlements', ':-', str(binary)]).stdout
    entitlements = plistlib.loads(raw) if raw else {}
    if not isinstance(entitlements, dict):
        raise ValueError('entitlements must be a dictionary')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
        raise ValueError('candidate changed during inspection')
    blockers = policy(context, team, application, metadata, entitlements)
    return {'schema': 1, 'candidate_sha256': digest, 'execution_context': context,
            'signature_prerequisites_passed': not blockers, 'blockers': blockers,
            'hardware_acceptance_complete': False, 'protected_supported': False,
            'pending': ['provisioning profile authorization and distribution assessment',
                        'persistent SE create/open across independent processes in the selected login context',
                        'cross-UID denial, reboot, upgrade and recovery with temporary identities'],
            'reference': REFERENCE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--execution-context', choices=['system-daemon', 'user-session'], required=True)
    parser.add_argument('--team-id', required=True)
    parser.add_argument('--application-id', required=True)
    args = parser.parse_args()
    report = inspect(args.binary.resolve(strict=True) if not args.binary.is_symlink() else args.binary,
                     args.sha256, args.execution_context, args.team_id, args.application_id)
    print(json.dumps(report, indent=2))
    return 0 if report['signature_prerequisites_passed'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
        print(json.dumps({'signature_prerequisites_passed': False,
                          'hardware_acceptance_complete': False, 'error': str(error)}))
        sys.exit(1)
