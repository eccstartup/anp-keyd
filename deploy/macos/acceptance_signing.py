"""Disposable signing acceptance. Fixed test password; never reads real vaults.
Called only by test-runtime.py in its new temporary service instance.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import time
import uuid

PASSWORD = 'temporary-boundary-test-secret'


def prepare(base, config, args, admin, service, run):
    if not args.helper_sha256 or len(args.helper_sha256) != 64:
        raise ValueError('full signing checks require --helper-sha256')
    with args.signing_helper.open('rb') as source:
        content = source.read(128 * 1024 * 1024 + 1)
    if len(content) > 128 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != args.helper_sha256:
        raise ValueError('fixture helper digest mismatch')
    helper = base / 'fixture-helper'
    with helper.open('xb') as target:
        target.write(content)
    helper.chmod(0o755)  # new root-owned copy in a root-owned directory
    work = base / 'fixture-work'
    work.mkdir(mode=0o700)
    os.chown(work, admin.pw_uid, admin.pw_gid)
    source = work / 'vault'
    made = run(admin, helper, 'generate', source)
    assert made.returncode == 0, made.stderr
    manifest = json.loads(made.stdout)
    vault_id = str(uuid.uuid4())
    parent = Path(config['state_dir']) / 'vaults'
    parent.mkdir(mode=0o700)
    os.chown(parent, service.pw_uid, service.pw_gid)
    vault = parent / vault_id
    # Helper output is trusted test data, but refuse links/special files and bound
    # the copy so a bad fixture can never redirect a privileged filesystem walk.
    count, size = 0, 0
    for path in [source, *source.rglob('*')]:
        meta = path.lstat()
        if not (stat.S_ISREG(meta.st_mode) or stat.S_ISDIR(meta.st_mode)):
            raise ValueError('fixture contains a link or special file')
        count += 1
        size += meta.st_size
    if count > 128 or size > 4 * 1024 * 1024:
        raise ValueError('fixture exceeds bound')
    shutil.copytree(source, vault)
    for path in [vault, *vault.rglob('*')]:
        os.chown(path, service.pw_uid, service.pw_gid)
        path.chmod(0o700 if path.is_dir() else 0o600)
    config['vault_ids'] = [vault_id]
    # A real second OS UID, with transport membership applied ONLY to the child
    # process. No Directory Services account/group changes are made.
    other = pwd.getpwnam('nobody')
    if other.pw_uid in {0, service.pw_uid, admin.pw_uid, *[p['uid'] for p in config['principals']]}:
        raise ValueError('second test subject overlaps configured identities')
    config['principals'] = [*config['principals'], {'principal_id': str(uuid.uuid4()),
                            'uid': other.pw_uid, 'generation': 1, 'enabled': True}]
    return {'helper': helper, 'manifest': manifest, 'vault_id': vault_id, 'other': other}


# Client authenticates kernel UID before sending the test-only binary password.
REQUEST = r'''import ctypes,json,socket,struct,sys
endpoint, expected_uid, wants_secret=sys.argv[1:]
request=sys.stdin.buffer.read(65537)
assert len(request)<=65536
s=socket.socket(socket.AF_UNIX);s.settimeout(15);s.connect(endpoint)
if sys.platform=='darwin':
 lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib');uid=ctypes.c_uint();gid=ctypes.c_uint()
 assert lib.getpeereid(s.fileno(),ctypes.byref(uid),ctypes.byref(gid))==0
 actual_uid=uid.value
else:
 _,actual_uid,_=struct.unpack('3i',s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
assert actual_uid==int(expected_uid), 'wrong daemon UID'
if wants_secret!='refuse': s.sendall(struct.pack('!I',len(request))+request)
if wants_secret=='yes':
 secret=b'temporary-boundary-test-secret'
 s.sendall(struct.pack('!I',len(secret))+secret)
def exact(n):
 out=b''
 while len(out)<n:
  part=s.recv(n-len(out))
  if not part: raise EOFError('incomplete reply')
  out+=part
 return out
length=struct.unpack('!I',exact(4))[0];assert length<=65536
print(exact(length).decode())
'''


class Checks:
    def __init__(self, base, config, path, args, fixture, admin, agent, identity, env, cli):
        self.base, self.config, self.path, self.args = base, config, path, args
        self.fixture, self.admin, self.agent = fixture, admin, agent
        self.identity, self.env, self.cli = identity, env, cli
        self.key = self.grant_id = self.request = self.signed = None

    def request_as(self, user, operation, management=False, secret=False, extra_admin_group=False):
        def drop():
            self.identity(user)()
        # setgroups must precede dropping UID. Only the second, disposable child
        # receives signing transport access, without changing account membership.
        if user == self.fixture['other']:
            def drop():
                os.setgroups([self.config['agent_gid']])
                os.setgid(user.pw_gid)
                os.setuid(user.pw_uid)
        if extra_admin_group:
            def drop():
                os.initgroups(user.pw_name, user.pw_gid)
                os.setgroups([*os.getgroups(), self.config['admin_gid']])
                os.setgid(user.pw_gid)
                os.setuid(user.pw_uid)
        endpoint = self.config['admin_socket' if management else 'sign_socket']
        result = subprocess.run(['/usr/bin/python3', '-I', '-c', REQUEST, endpoint,
                                 str(self.config['service_uid']), 'refuse' if extra_admin_group else ('yes' if secret else 'no')],
                                input=json.dumps({'version': 2, 'request': operation}),
                                capture_output=True, text=True, preexec_fn=drop,
                                env=self.env, cwd='/', timeout=20)
        assert result.returncode == 0, result.stderr
        reply = json.loads(result.stdout)
        if reply['code'] == 'OK':
            assert reply['instance_id'] == self.config['instance_id']
        return reply

    def change(self, change):
        path = self.base / 'change.json'
        path.write_text(json.dumps(change)); path.chmod(0o644)
        prepared = self.cli(self.admin, 'prepare', '--file', path)
        assert prepared.returncode == 0, prepared.stderr
        pending = json.loads(prepared.stdout)['prepared']
        committed = self.cli(self.admin, 'commit', '--operation-id', pending['operation_id'], '--digest', pending['digest'])
        assert committed.returncode == 0, committed.stderr
        return pending

    def unlock(self):
        result = self.request_as(self.admin, {'operation': 'UNLOCK_KEY',
            'vault_id': self.fixture['vault_id'], 'did': self.key['did'], 'kid': self.key['kid']}, True, True)
        assert result['code'] == 'OK', result

    def grant(self):
        pending = self.change({'kind': 'Grant', 'change': {'action': 'Create',
            'principal_id': self.config['principals'][0]['principal_id'], 'key_id': self.key['key_id'],
            'policy_id': self.policy_id, 'policy_version': 1, 'expiry': int(time.time()) + 240, 'max_uses': 20}})
        return pending['effect']['effect']['grant']['grant_id']

    def signing(self, grant=None):
        return {'operation': 'SIGN_HTTP', 'grant_id': grant or self.grant_id,
                'request_id': str(uuid.uuid4()), 'http': {'method': 'GET',
                'url': 'https://example.com/test', 'headers': {}, 'body': {'state': 'absent'}, 'nonce': None}}

    def expect_locked(self, grant=None):
        result = self.request_as(self.agent, self.signing(grant))
        assert result['code'] == 'KEY_LOCKED', result

    def before_restart(self):
        self.change({'kind': 'Catalog', 'change': {'action': 'EnrollVault', 'vault_id': self.fixture['vault_id']}})
        catalog = json.loads(self.cli(self.admin, 'catalog').stdout)['catalog']
        assert all(k['role'] == 'unclassified' for k in catalog['keys'])
        root = next(k for k in catalog['keys'] if k['kid'] == self.fixture['manifest']['kid'])
        path = self.base / 'change.json'
        path.write_text(json.dumps({'kind': 'Catalog', 'change': {'action': 'ConfirmRole', 'key_id': root['key_id'], 'role': 'hot'}}))
        path.chmod(0o644)
        refused = self.cli(self.admin, 'prepare', '--file', path)
        assert refused.returncode != 0, 'root was relabeled as hot'
        self.change({'kind': 'Catalog', 'change': {'action': 'ConfirmRole', 'key_id': root['key_id'], 'role': 'root'}})
        self.key = next(k for k in catalog['keys'] if k['kid'].endswith('#http-hot'))
        self.change({'kind': 'Catalog', 'change': {'action': 'ConfirmRole', 'key_id': self.key['key_id'], 'role': 'hot'}})
        self.policy_id = str(uuid.uuid4())
        self.change({'kind': 'Catalog', 'change': {'action': 'PublishPolicy', 'policy_id': self.policy_id, 'version': 1,
            'content': {'schema_version': 1, 'name': 'local-temporary-test', 'purpose': 'http-authentication',
            'origin': 'https://example.com', 'methods': ['GET'], 'paths': ['/test'],
            'query': {'mode': 'none'}, 'body': {'mode': 'empty', 'max_bytes': 0}, 'signature_profile': 'anp-http-v2',
            'grant_limits': {'max_duration_seconds': 300, 'max_uses': 20}}}})
        self.grant_id = self.grant()
        denied = self.request_as(self.agent, {'operation': 'GET_CAPABILITIES'}, True, extra_admin_group=True)
        assert denied['code'] == 'ADMIN_REQUIRED', denied
        for operation in [{'operation': 'SIGN_RAW'}, {'operation': 'UNLOCK_KEY', 'passphrase': PASSWORD}]:
            denied = self.request_as(self.agent, operation)
            assert denied['code'] == 'PROTOCOL_INVALID', denied
        print('PASS root cannot become hot; transport management-group membership cannot override Agent UID; data has no raw/unlock operations', flush=True)
        self.expect_locked()
        refused = self.cli(self.agent, 'unlock', '--native-ui', '--vault-id', self.fixture['vault_id'], '--did', self.key['did'], '--kid', self.key['kid'])
        assert refused.returncode != 0 and 'ADMIN_REQUIRED' in refused.stderr, refused.stderr
        self.unlock()
        self.request = self.signing()
        result = self.request_as(self.agent, self.request)
        assert result['code'] == 'OK' and result['data']['state'] == 'completed', result
        self.signed = result['data']
        public = {'document': self.fixture['manifest']['document'], **self.signed['result']}
        verified = subprocess.run([str(self.fixture['helper']), 'verify'], input=json.dumps(public),
                                  preexec_fn=self.identity(self.admin), env=self.env, cwd='/',
                                  capture_output=True, text=True, timeout=15)
        assert verified.returncode == 0 and verified.stdout.strip() == 'VERIFIED', verified.stderr
        tampered = {**public, 'url': 'https://example.com/other'}
        rejected = subprocess.run([str(self.fixture['helper']), 'verify'], input=json.dumps(tampered),
                                  preexec_fn=self.identity(self.admin), env=self.env, cwd='/',
                                  capture_output=True, text=True, timeout=15)
        assert rejected.returncode != 0, 'upstream verifier accepted changed target'
        assert self.request_as(self.agent, self.request)['data'] == self.signed
        changed = {**self.request, 'http': {**self.request['http'], 'nonce': 'changed'}}
        assert self.request_as(self.agent, changed)['code'] == 'REQUEST_ID_CONFLICT'
        forbidden = {**self.signing(), 'http': {**self.request['http'], 'url': 'https://evil.example/test'}}
        assert self.request_as(self.agent, forbidden)['code'] == 'POLICY_DENIED' 
        print('PASS actual temporary hot-key signature independently verified; stable-ID retry is identical', flush=True)
        for operation in [self.request, {'operation': 'GET_GRANT_STATUS', 'grant_id': self.grant_id},
                          {'operation': 'GET_DOCUMENT', 'key_id': self.key['key_id']}]:
            denied = self.request_as(self.fixture['other'], operation)
            assert denied['code'] == 'GRANT_INVALID', denied
        hidden = self.request_as(self.fixture['other'], {'operation': 'GET_REQUEST_STATUS', 'request_id': self.request['request_id']})
        assert hidden['code'] == 'REQUEST_NOT_FOUND', hidden
        print('PASS real second UID cannot use grant, obtain document or recover another principal result', flush=True)
        self.change({'kind': 'Grant', 'change': {'action': 'Revoke', 'grant_id': self.grant_id}})
        replay = self.request_as(self.agent, self.request)
        assert replay['code'] != 'OK' or 'result' not in replay.get('data', {}), replay
        self.grant_id = self.grant()
        self.unlock()  # management changes may lock keys
        self.request = self.signing()
        assert self.request_as(self.agent, self.request)['data']['state'] == 'completed'
        print('PASS revocation suppresses cached signature; fresh grant active before restart', flush=True)

    def arm_crash(self):
        self.unlock()
        self.request = self.signing()
        signed = self.request_as(self.agent, self.request)
        assert signed['code'] == 'OK' and signed['data']['state'] == 'completed', signed

    def after_restart(self, interactive=True):
        denied = self.request_as(self.agent, self.request)
        assert denied['code'] != 'OK' or 'result' not in denied.get('data', {}), denied
        keys = self.request_as(self.agent, {'operation': 'LIST_AUTHORIZED_KEYS'})
        assert keys['code'] == 'OK' and keys['data']['keys'] == [], keys
        fresh = self.grant()
        self.expect_locked(fresh)
        print('PASS restart invalidates real active grant/cached signature and leaves key locked with a fresh grant', flush=True)
        self.grant_id = fresh
        if self.args.interactive_ui and interactive:
            self.interactive()

    def interactive(self):
        command = [str(self.args.binary), 'admin', '--config', str(self.path), 'unlock', '--native-ui',
                   '--vault-id', self.fixture['vault_id'], '--did', self.key['did'], '--kid', self.key['kid']]
        def window(instruction):
            print(instruction, flush=True)
            started = time.monotonic()
            result = subprocess.run(command, preexec_fn=self.identity(self.admin), env=self.env,
                                    cwd='/', stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=150)
            return result, time.monotonic() - started
        cancelled, _ = window('UI 1/3: check exact instance/vault/DID/key in the window; click Cancel. Do not enter a real password.')
        assert cancelled.returncode != 0 and 'native unlock cancelled' in cancelled.stderr, cancelled.stderr
        self.expect_locked()
        expired, elapsed = window('UI 2/3: leave the window untouched for its full 120-second timeout.')
        assert expired.returncode != 0 and 'native unlock cancelled' in expired.stderr and elapsed >= 115, expired.stderr
        self.expect_locked()
        opened, _ = window('UI 3/3: enter ONLY the public temporary test password: ' + PASSWORD + '\nCheck that input is masked, then click Unlock (Cancel is the default).')
        assert opened.returncode == 0, opened.stderr
        if input('Did all windows show the correct exact key, and was password input masked? Type yes: ').strip() != 'yes':
            raise ValueError('native UI visual confirmation not accepted')
        signed = self.request_as(self.agent, self.signing())
        assert signed['code'] == 'OK' and signed['data']['state'] == 'completed', signed
        print('PASS native UI cancel/timeout keep key locked; masked human unlock enables actual Agent signing', flush=True)
