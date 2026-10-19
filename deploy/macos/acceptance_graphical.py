"""Root test runner bridges only disposable SE work into the GUI audit session."""
import ctypes
import json
import os
from pathlib import Path
import pwd
import plistlib
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


def relogin_session(user, timeout=20):
    """Native read-only readiness probe; no subprocess or helper restart."""
    deadline = time.monotonic() + timeout
    last = 'graphical bootstrap not ready'
    while time.monotonic() < deadline:
        try:
            value = console_session_id(console_state(), user.pw_uid)
            return current_session(value)
        except (ValueError, subprocess.TimeoutExpired) as error:
            last = str(error)
            time.sleep(.2)
    raise ValueError('relogin graphical session readiness timed out: ' + last)


def console_session_id(state, uid):
    if state.get('UID') != uid:
        raise ValueError('console state UID does not match administrator')
    matches = [entry for entry in state.get('SessionInfo', [])
        if entry.get('kCGSSessionUserIDKey') == uid
        and entry.get('kCGSSessionOnConsoleKey') is True
        and entry.get('kCGSessionLoginDoneKey') is True]
    if len(matches) != 1:
        raise ValueError('exactly one completed on-console graphical session required')
    value = matches[0].get('kCGSSessionAuditIDKey')
    if type(value) is not int or not 0 < value < 0xffffffff or matches[0].get('kSCSecuritySessionID') != value:
        raise ValueError('console audit session fields missing or inconsistent')
    return value


def console_state():
    """Copy native SystemConfiguration state; no launchctl/scutil subprocess."""
    system = ctypes.CDLL('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')
    core = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    core.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
    core.CFStringCreateWithCString.restype = ctypes.c_void_p
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    system.SCDynamicStoreCopyValue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    system.SCDynamicStoreCopyValue.restype = ctypes.c_void_p
    core.CFPropertyListCreateData.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                            ctypes.c_long, ctypes.c_ulong, ctypes.c_void_p]
    core.CFPropertyListCreateData.restype = ctypes.c_void_p
    core.CFDataGetLength.argtypes = [ctypes.c_void_p]
    core.CFDataGetLength.restype = ctypes.c_long
    core.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
    core.CFDataGetBytePtr.restype = ctypes.c_void_p
    key = core.CFStringCreateWithCString(None, b'State:/Users/ConsoleUser', 0x08000100)
    value = data = None
    try:
        if not key:
            raise ValueError('console state key allocation failed')
        value = system.SCDynamicStoreCopyValue(None, key)
        if not value:
            raise ValueError('native console state unavailable')
        data = core.CFPropertyListCreateData(None, value, 100, 0, None)
        if not data:
            raise ValueError('native console state serialization failed')
        size = core.CFDataGetLength(data)
        if not 0 < size <= 1024 * 1024:
            raise ValueError('native console state exceeds bound')
        return plistlib.loads(ctypes.string_at(core.CFDataGetBytePtr(data), size))
    finally:
        for item in (data, value, key):
            if item:
                core.CFRelease(item)


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
