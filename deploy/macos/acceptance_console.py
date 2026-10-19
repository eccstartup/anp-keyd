"""Observe a real console UID round trip; never initiate a user transition."""
import ctypes
import json
import time


def console_uid():
    system = ctypes.CDLL('/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration')
    core = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
    system.SCDynamicStoreCopyConsoleUser.argtypes = [ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
    system.SCDynamicStoreCopyConsoleUser.restype = ctypes.c_void_p
    core.CFRelease.argtypes = [ctypes.c_void_p]
    core.CFRelease.restype = None
    uid, gid = ctypes.c_uint32(0xffffffff), ctypes.c_uint32(0xffffffff)
    name = system.SCDynamicStoreCopyConsoleUser(None, ctypes.byref(uid), ctypes.byref(gid))
    if not name:
        raise ValueError('console user unavailable')
    core.CFRelease(name)
    return uid.value


def wait_user_switch(actor, check_away, read_uid=console_uid, clock=time.time,
                     pause=time.sleep, observe=None):
    started = previous = clock()
    if read_uid() != actor:
        raise ValueError('administrator must initially own the graphical console')
    away_uid = None
    away_since = None
    checked = False
    last_uid = actor
    while True:
        now = clock()
        if now < previous:
            raise ValueError('wall clock moved backwards during user switch')
        previous = now
        if now - started > 90:
            raise ValueError('user switch and return must complete within 90 seconds')
        uid = read_uid()
        if uid != last_uid:
            if observe:
                observe({'uid': uid, 'wall': now, 'started': started})
            last_uid = uid
        if uid == actor:
            if away_uid is not None:
                if not checked:
                    raise ValueError('returned before six seconds and away-state checks')
                return away_uid
        elif uid not in (0, 0xffffffff):
            if away_uid is None:
                away_uid, away_since = uid, now
            elif uid != away_uid:
                raise ValueError('unexpected third console user')
            if not checked and now - away_since >= 6:
                check_away()
                checked = True
        elif away_uid is not None and not checked:
            # Login-window time does not count as logged into another user.
            away_since = now
        pause(.2)


def operator_user_switch(actor, check_away):
    from acceptance_se import kernel_sleep_times
    before = kernel_sleep_times()
    if console_uid() != actor:
        raise ValueError('administrator must initially own the graphical console')
    print('READY FOR MANUAL USER SWITCH: switch to another graphical account, '
          'leave its desktop active for at least 10 seconds, then switch back within '
          '90 seconds. Do not log out or sleep. Detection is automatic; no Enter.', flush=True)
    other = wait_user_switch(actor, check_away,
        observe=lambda evidence: print('CONSOLE_SWITCH_EVIDENCE ' + json.dumps(evidence), flush=True))
    if kernel_sleep_times() != before:
        raise ValueError('sleep occurred during user-switch test; evidence is confounded')
    print(f'PASS observed graphical console UID {actor} -> {other} -> {actor}; '
          'away-state checks ran; no kernel sleep transition', flush=True)
