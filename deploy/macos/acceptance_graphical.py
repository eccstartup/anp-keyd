"""Root test runner bridges only disposable SE work into the GUI audit session."""
import ctypes
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys


def command(user, config, argv):
    return ['/bin/launchctl', 'asuser', str(user.pw_uid), sys.executable, '-I',
            str(Path(__file__).resolve()), str(config), str(user.pw_uid), *map(str, argv)]


def current_session():
    lib = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
    lib.SessionGetInfo.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32),
                                   ctypes.POINTER(ctypes.c_uint32)]
    lib.SessionGetInfo.restype = ctypes.c_int32
    actual, attrs = ctypes.c_uint32(), ctypes.c_uint32()
    if lib.SessionGetInfo(0xffffffff, ctypes.byref(actual), ctypes.byref(attrs)) != 0:
        raise ValueError('graphical audit session unavailable')
    if actual.value in (0, 0xffffffff) or not attrs.value & 0x10 or attrs.value & 0x1001:
        raise ValueError('not an eligible graphical audit session')
    return actual.value


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
