"""Root test runner bridges only disposable SE work into the GUI audit session."""
import ctypes
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import time


def command(user, config, argv):
    return ['/bin/launchctl', 'asuser', str(user.pw_uid), sys.executable, '-I',
            str(Path(__file__).resolve()), str(config), str(user.pw_uid), *map(str, argv)]


def current_session(requested=0xffffffff):
    lib = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
    lib.SessionGetInfo.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
                                   ctypes.POINTER(ctypes.c_uint32)]
    lib.SessionGetInfo.restype = ctypes.c_int32
    actual, attrs = ctypes.c_uint32(), ctypes.c_uint32()
    if lib.SessionGetInfo(requested, ctypes.byref(actual), ctypes.byref(attrs)) != 0:
        raise ValueError('graphical audit session unavailable')
    if actual.value in (0, 0xffffffff) or not attrs.value & 0x10 or attrs.value & 0x1001:
        raise ValueError('not an eligible graphical audit session')
    if requested != 0xffffffff and actual.value != requested:
        raise ValueError('graphical audit session mismatch')
    return actual.value


def domain_session(output, uid):
    context = re.search(r'^\s*security context = \{\s*uid = (\d+)\s*asid = (\d+)\s*\}', output, re.M)
    if not context or int(context[1]) != uid:
        raise ValueError('graphical bootstrap security context missing or wrong UID')
    value = int(context[2])
    if value in (0, 0xffffffff):
        raise ValueError('invalid graphical bootstrap audit session')
    return value


def relogin_session(user, timeout=20):
    """Read-only readiness probe; never enter a GUI context or restart a helper."""
    deadline = time.monotonic() + timeout
    last = 'graphical bootstrap not ready'
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(['/bin/launchctl', 'print', f'gui/{user.pw_uid}'],
                capture_output=True, text=True, timeout=min(3, max(.01, deadline - time.monotonic())))
            if result.returncode:
                raise ValueError('graphical bootstrap unavailable: ' + result.stderr)
            value = domain_session(result.stdout, user.pw_uid)
            return current_session(value)
        except (ValueError, subprocess.TimeoutExpired) as error:
            last = str(error)
            time.sleep(.2)
    raise ValueError('relogin graphical session readiness timed out: ' + last)


def session(user, config):
    result = subprocess.run(command(user, config, ['--audit-session']),
        capture_output=True, text=True, timeout=10, cwd='/')
    if result.returncode:
        raise ValueError('graphical audit session probe failed: ' + result.stderr)
    return int(result.stdout.strip())


def main():
    if os.geteuid() != 0:
        raise ValueError('graphical bridge requires root before credential drop')
    config_path, uid, *argv = sys.argv[1:]
    config = json.loads(Path(config_path).read_text())
    uid = int(uid)
    if uid == 0 or uid not in config['admin_uids']:
        raise ValueError('graphical bridge target must be a configured non-root administrator')
    user = pwd.getpwuid(uid)
    os.setgroups([user.pw_gid, *sorted({config['admin_gid']} - {user.pw_gid})])
    os.setgid(user.pw_gid)
    os.setuid(uid)
    current_session()  # No fallback to a system or inherited non-graphical session.
    if argv == ['--audit-session']:
        print(current_session(), flush=True)
    else:
        os.execv(argv[0], argv)


if __name__ == '__main__':
    main()
