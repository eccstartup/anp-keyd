#!/usr/bin/env python3
"""Operator-run root wrapper for a single independent-session SE denial probe.

Only the child process changes session. The approved probe executes after all
root credentials and supplementary groups are dropped. No job is installed.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import pwd
import resource
import stat
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--uid', required=True, type=int)
    parser.add_argument('--binary', required=True, type=Path)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if sys.platform != 'darwin' or os.geteuid() != 0 or args.uid <= 0:
        raise ValueError('requires macOS root and a non-root target UID')
    arguments = args.arguments[1:] if args.arguments[:1] == ['--'] else args.arguments
    if len(arguments) != 2 or arguments[0] not in ('open', 'open-checked'):
        raise ValueError('only open/open-checked STATE is allowed')
    account = pwd.getpwuid(args.uid)
    binary = args.binary.resolve(strict=True)
    meta = binary.lstat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o022:
        raise ValueError('probe must be a regular non-group/world-writable file')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != args.sha256:
        raise ValueError('probe digest mismatch')
    spec = importlib.util.spec_from_file_location('probe_security_session',
        Path(__file__).with_name('security-session.py'))
    policy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(policy)
    policy.isolate(account.pw_uid)
    os.setgroups([account.pw_gid])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    if os.getuid() != account.pw_uid or os.geteuid() != account.pw_uid:
        raise ValueError('failed to drop root credentials')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.chdir('/private/tmp')
    os.closerange(3, resource.getrlimit(resource.RLIMIT_NOFILE)[0])
    environment = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': account.pw_dir,
                   'USER': account.pw_name, 'LOGNAME': account.pw_name,
                   'TMPDIR': '/private/tmp', 'LANG': 'en_US.UTF-8'}
    os.execve(binary, [str(binary), *arguments], environment)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as error:
        sys.exit(str(error))
