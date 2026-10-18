"""Diagnostic creation of a fresh non-GUI security/bootstrap session.

Unix setuid alone can retain the human's keychain audit session. This module
changes only the calling process and its future children, not a login account.
It must run single-threaded. This transition has not prevented same-signed
cross-UID SE key access on the test host; it is not a keychain isolation fix
and is not used by the Agent launcher.
"""
import ctypes
import os


class SessionAPI:
    def __init__(self):
        self.security = ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        self.bsm = ctypes.CDLL('/usr/lib/libbsm.dylib', use_errno=True)
        self.security.SessionGetInfo.argtypes = [ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        self.security.SessionGetInfo.restype = ctypes.c_int32
        self.security.SessionCreate.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self.security.SessionCreate.restype = ctypes.c_int32
        for function in (self.bsm.getauid, self.bsm.setauid):
            function.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
            function.restype = ctypes.c_int

    def context(self):
        session, flags, auid = ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32()
        if self.security.SessionGetInfo(0xffffffff, ctypes.byref(session), ctypes.byref(flags)) != 0:
            raise ValueError('cannot read security session')
        if self.bsm.getauid(ctypes.byref(auid)) != 0:
            raise ValueError('cannot read audit UID')
        return {'audit_session': session.value, 'session_attributes': flags.value,
                'audit_uid': auid.value}

    def create(self):
        # No sessionKeepCurrentBootstrap: detach the bootstrap context too.
        status = self.security.SessionCreate(0, 0)
        if status != 0:
            raise ValueError(f'cannot create isolated security session: {status}')

    def set_audit_uid(self, uid):
        auid = ctypes.c_uint32(uid)
        if self.bsm.setauid(ctypes.byref(auid)) != 0:
            raise ValueError(f'cannot set isolated audit UID: errno {ctypes.get_errno()}')


def isolate(uid, api=None):
    if os.geteuid() != 0 or not 0 < uid < 0xffffffff:
        raise ValueError('security session isolation requires root and a non-root target UID')
    api = api if api is not None else SessionAPI()
    old = api.context()
    api.create()
    api.set_audit_uid(uid)
    new = api.context()
    if (new['audit_session'] in (0, 0xffffffff, old['audit_session'])
            or new['audit_uid'] != uid
            or new['session_attributes'] & 0x1011):
        raise ValueError('isolated security session identity or attributes are invalid')
    return new
