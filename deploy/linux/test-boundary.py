#!/usr/bin/env python3
"""Destructive to its container only. Root, Docker and explicit harness required."""
import argparse
import json
import os
from pathlib import Path
import pty
import pwd
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
import uuid

if sys.platform != 'linux' or os.geteuid() != 0 or not Path('/.dockerenv').exists():
    sys.exit('requires disposable root Linux Docker container')

os.umask(0o077)  # Installation must set modes explicitly, independent of caller umask.

parser = argparse.ArgumentParser()
parser.add_argument('--binary', required=True)
args = parser.parse_args()
for name in ['boundary-admin', 'boundary-agent-a', 'boundary-agent-b', 'boundary-stranger']:
    subprocess.run(['useradd', '--create-home', '--shell', '/bin/sh', name], check=True)
subprocess.run([sys.executable, 'deploy/linux/install.py', '--binary', args.binary,
                '--admin-user', 'boundary-admin', '--agent-user', 'boundary-agent-a', '--agent-user', 'boundary-agent-b'], check=True)
config_path = Path('/etc/anp-keyd/service.json')
config = json.loads(config_path.read_text())
fixture = json.loads(Path('/tmp/keyd-boundary-fixture-info.json').read_text())
vault_id = str(uuid.uuid4())
config['vault_ids'] = [vault_id]
config_path.write_text(json.dumps(config))
vault = Path(config['state_dir']) / 'vaults' / vault_id
shutil.copytree('/tmp/keyd-boundary-fixture', vault)
service = pwd.getpwnam('anp-keyd')
for path in [vault, *vault.rglob('*')]:
    os.chown(path, service.pw_uid, service.pw_gid)
binary = '/usr/local/libexec/anp-keyd'
passed = []


def identity(name):
    user = pwd.getpwnam(name)
    def change():
        os.initgroups(user.pw_name, user.pw_gid)
        os.setgid(user.pw_gid)
        os.setuid(user.pw_uid)
    return change


def command(name, *argv):
    return subprocess.run([binary, *argv], preexec_fn=identity(name), capture_output=True, text=True, timeout=12)


def check(condition, label):
    assert condition, label
    passed.append(label)
    print('PASS', label, flush=True)


def frame(value):
    payload = json.dumps(value).encode()
    return struct.pack('!I', len(payload)) + payload


def exact(sock, size):
    out = b''
    while len(out) < size:
        data = sock.recv(size - len(out))
        if not data:
            raise EOFError('connection closed')
        out += data
    return out


def reply(sock):
    return json.loads(exact(sock, struct.unpack('!I', exact(sock, 4))[0]))


def request(endpoint, value, secret=None):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(8)
        sock.connect(endpoint)
        sock.sendall(frame(value))
        if secret is not None:
            sock.sendall(struct.pack('!I', len(secret)) + secret)
        return reply(sock)


def start():
    process = subprocess.Popen([binary, 'serve-protected'], preexec_fn=identity('anp-keyd'), stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if process.poll() is not None:
            raise AssertionError(process.stderr.read())
        if Path(config['admin_socket']).exists():
            return process
        time.sleep(.05)
    raise AssertionError('service did not start')


def stop(process):
    process.terminate()
    process.wait(timeout=12)
    stderr = process.stderr.read()
    check('temporary-boundary-test-secret' not in stderr, 'service log has no password')
    check(not Path(config['sign_socket']).exists() and not Path(config['admin_socket']).exists(), 'shutdown cleans owned socket inodes')


def capabilities(endpoint):
    return request(endpoint, {'version': 2, 'request': {'operation': 'GET_CAPABILITIES'}})


process = start()
try:
    # Root uses explicit privilege drop so probes are real SO_PEERCRED identities.
    code = '''import json,socket,struct,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);data=json.dumps({'version':2,'request':{'operation':'GET_CAPABILITIES'}}).encode();s.sendall(struct.pack('!I',len(data))+data)
def exact(n):
 b=b''
 while len(b)<n:b+=s.recv(n-len(b))
 return b
print(exact(struct.unpack('!I',exact(4))[0]).decode())'''
    def as_agent(name):
        result = subprocess.run([sys.executable, '-c', code, config['sign_socket']], preexec_fn=identity(name), capture_output=True, text=True, timeout=8)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    a, b = as_agent('boundary-agent-a'), as_agent('boundary-agent-b')
    check(a['code'] == b['code'] == 'OK' and a['principal_id'] != b['principal_id'], 'same client maps A/B to distinct kernel principals')
    check(not a['signing_available'] and not a['protected_supported'], 'preview never reports protected signing support')
    check(command('boundary-admin', 'admin', 'status').returncode == 0, 'independent administrator authenticated')
    check(command('boundary-admin', 'probe', '--security').returncode != 0, 'probe refuses protected release claim')
    check(command('boundary-agent-a', 'admin', 'status').returncode != 0, 'Agent cannot invoke admin CLI')
    # A real controlling PTY does not grant administrative identity.
    pid, terminal = pty.fork()
    if pid == 0:
        identity('boundary-agent-a')()
        os.execv(binary, [binary, 'admin', 'unlock', '--vault-id', vault_id, '--did', fixture['did'], '--kid', fixture['kid']])
    output = b''
    while True:
        readable, _, _ = select.select([terminal], [], [], 5)
        assert readable, 'PTY admin denial timed out'
        try:
            chunk = os.read(terminal, 4096)
            if not chunk:
                break
            output += chunk
        except OSError:
            break
    _, status = os.waitpid(pid, 0)
    os.close(terminal)
    check(os.waitstatus_to_exitcode(status) != 0 and b'ADMIN_REQUIRED' in output and b'Passphrase:' not in output, 'PTY does not bypass admin UID or prompt for password')
    for protected_path in [config['sign_socket'], str(config_path)]:
        tamper = subprocess.run([sys.executable, '-c', 'import os,sys;os.unlink(sys.argv[1])', protected_path], preexec_fn=identity('boundary-agent-a'), capture_output=True)
        check(tamper.returncode != 0 and Path(protected_path).exists(), 'Agent cannot replace ' + protected_path)
    # Even giving Agent A the admin connection group cannot override the UID check.
    subprocess.run(['usermod', '-a', '-G', 'anp-keyd-admin', 'boundary-agent-a'], check=True)
    raw_admin = subprocess.run([sys.executable, '-c', code, config['admin_socket']], preexec_fn=identity('boundary-agent-a'), capture_output=True, text=True, timeout=8)
    check('ADMIN_REQUIRED' in raw_admin.stdout, 'admin socket group alone cannot authorize Agent')
    # Data protocol cannot parse old operations, even for an authorized Agent.
    data_probe = code.replace("{'operation':'GET_CAPABILITIES'}", "{'operation':'UNLOCK_KEY','passphrase':'temporary-boundary-test-secret'}")
    refused = subprocess.run([sys.executable, '-c', data_probe, config['sign_socket']], preexec_fn=identity('boundary-agent-a'), capture_output=True, text=True, timeout=8)
    check('PROTOCOL_INVALID' in refused.stdout and 'temporary-boundary-test-secret' not in refused.stdout, 'data socket has no password operation')
    # Unknown UID with connection-group membership is still denied.
    subprocess.run(['usermod', '-a', '-G', 'anp-keyd-agent', 'boundary-stranger'], check=True)
    check(as_agent('boundary-stranger')['code'] == 'PRINCIPAL_DISABLED', 'unregistered UID rejected despite socket group')
    # Admin mutation is unavailable to an Agent even with vault/did/kid knowledge.
    unlock = {'version': 2, 'request': {'operation': 'UNLOCK_KEY', 'vault_id': vault_id, **fixture}}
    secret = b'temporary-boundary-test-secret'
    # Root is not configured as admin in this deployment. Use a child client UID.
    admin_call = '''import socket,struct,json,sys
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);p=sys.argv[2].encode();secret=b'temporary-boundary-test-secret';s.sendall(struct.pack('!I',len(p))+p+struct.pack('!I',len(secret))+secret)
def exact(n):
 b=b''
 while len(b)<n:b+=s.recv(n-len(b))
 return b
print(exact(struct.unpack('!I',exact(4))[0]).decode())
assert s.recv(1)==b''
'''
    unlocked = subprocess.run([sys.executable, '-c', admin_call, config['admin_socket'], json.dumps(unlock)], preexec_fn=identity('boundary-admin'), capture_output=True, text=True, timeout=12)
    check(unlocked.returncode == 0 and json.loads(unlocked.stdout)['code'] == 'OK', 'authenticated admin unlocks temporary vault, connection closes: ' + unlocked.stdout + unlocked.stderr)
    check(command('boundary-admin', 'admin', 'lock-all').returncode == 0, 'independent management lock works')
    audit = ''.join(path.read_text() for path in (vault / 'audit').glob('*.jsonl'))
    check('temporary-boundary-test-secret' not in audit and '"dropped":1' in audit.replace(' ', ''), 'audit records actual management lock count without secrets')
    # The old data wire must fail, not downgrade. A known principal sends LIST_KEYS.
    legacy = code.replace("data=json.dumps({'version':2,'request':{'operation':'GET_CAPABILITIES'}}).encode()", "data=bytes([1])")
    refused = subprocess.run([sys.executable, '-c', legacy, config['sign_socket']], preexec_fn=identity('boundary-agent-b'), capture_output=True, text=True, timeout=8)
    check('PROTOCOL_INVALID' in refused.stdout, 'v1 cannot downgrade data endpoint')
    # Service-owned state is inaccessible even through the same public executable.
    read = subprocess.run(['cat', str(vault / 'device.secret')], preexec_fn=identity('boundary-agent-a'), capture_output=True)
    check(read.returncode != 0 and not read.stdout, 'Agent cannot read service vault material')
    # Stale config mutations and bad ownership are rejected at client side.
    original = config_path.read_text()
    config_path.chmod(0o666)
    check(command('boundary-admin', 'admin', 'status').returncode != 0, 'client rejects writable trust config')
    config_path.chmod(0o644)
    bad = dict(config, service_uid=pwd.getpwnam('boundary-stranger').pw_uid)
    config_path.write_text(json.dumps(bad))
    check(command('boundary-admin', 'admin', 'status').returncode != 0, 'client rejects mismatched service ownership')
    config_path.write_text(original)
    second = command('anp-keyd', 'serve-protected')
    check(second.returncode != 0 and 'state lock' in second.stderr, 'second daemon cannot replace sockets')
    # Slow partial data frames consume only bounded data slots, not admin slots.
    slow_code = """import socket,sys,time
sockets=[]
for _ in range(20):
 s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);sockets.append(s)
print('ready',flush=True)
sys.stdin.readline()
for s in sockets:s.close()
"""
    slow = subprocess.Popen([sys.executable, '-c', slow_code, config['sign_socket']], preexec_fn=identity('boundary-agent-b'), stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    assert slow.stdout.readline().strip() == 'ready'
    started = time.monotonic()
    check(command('boundary-admin', 'admin', 'lock-all').returncode == 0 and time.monotonic() - started < 3, 'authorized slow data clients do not starve management')
    slow.communicate('done\n', timeout=8)
finally:
    stop(process)

# Impersonation test: socket inode owner looks correct, actual server UID differs.
# Only root can manufacture this setup; the client must still check SO_PEERCRED.
fake_path = config['admin_socket']
fake_code = '''import socket,sys,time
s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen();print('ready',flush=True);c,_=s.accept();c.settimeout(3)
try:data=c.recv(100)
except Exception:data=b''
print(len(data),flush=True)
'''
fake = subprocess.Popen([sys.executable, '-c', fake_code, fake_path], stdout=subprocess.PIPE, text=True)
assert fake.stdout.readline().strip() == 'ready'
os.chown(fake_path, service.pw_uid, config['admin_gid'])
os.chmod(fake_path, 0o660)
result = command('boundary-admin', 'admin', 'unlock', '--vault-id', vault_id, '--did', fixture['did'], '--kid', fixture['kid'])
check('SERVER_IDENTITY_MISMATCH' in result.stderr, 'kernel peer credentials reject fake daemon before TTY/password')
check(fake.stdout.readline().strip() == '0', 'fake daemon receives zero credential bytes')
fake.wait(timeout=5)
Path(fake_path).unlink()
# Refuse a regular file occupying a socket location; never unlink it.
Path(config['sign_socket']).write_text('keep me')
os.chown(config['sign_socket'], service.pw_uid, config['agent_gid'])
os.chmod(config['sign_socket'], 0o660)
result = command('anp-keyd', 'serve-protected')
check(result.returncode != 0 and Path(config['sign_socket']).read_text() == 'keep me', 'stale cleanup preserves regular files')
Path(config['sign_socket']).unlink()
# Symlinks are never treated as stale sockets.
marker = Path('/tmp/keyd-boundary-marker')
marker.write_text('preserve symlink target')
Path(config['sign_socket']).symlink_to(marker)
result = command('anp-keyd', 'serve-protected')
check(result.returncode != 0 and Path(config['sign_socket']).is_symlink() and marker.read_text() == 'preserve symlink target', 'stale cleanup preserves symlinks and targets')
Path(config['sign_socket']).unlink()
# A real abandoned service-owned socket is safely removed under the state lock.
with socket.socket(socket.AF_UNIX) as abandoned:
    abandoned.bind(config['sign_socket'])
os.chown(config['sign_socket'], service.pw_uid, config['agent_gid'])
os.chmod(config['sign_socket'], 0o660)
process = start()
check(command('boundary-admin', 'admin', 'status').returncode == 0, 'verified stale socket is recovered')
stop(process)
# Disabling a bootstrap principal is effective after the documented restart.
config['principals'][1]['enabled'] = False
config_path.write_text(json.dumps(config))
process = start()
try:
    check(as_agent('boundary-agent-b')['code'] == 'PRINCIPAL_DISABLED', 'disabled principal denied after reload')
    check(as_agent('boundary-agent-a')['code'] == 'OK', 'other principal continues after disable')
finally:
    stop(process)
print(json.dumps({'passed': len(passed), 'protected_supported': False}), flush=True)
