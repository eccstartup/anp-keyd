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
import sqlite3
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
# Test-only staging under root while the service is stopped; not a migration API.
with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
    database.execute("INSERT INTO vaults VALUES(?,?,'active')", (vault_id, 'vaults/' + vault_id))
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
    check(a['signing_available'] and not a['protected_supported'], 'transaction executor available while protected release remains pending')
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
    def prepare_change(change):
        source = Path('/tmp/keyd-management-change.json')
        source.write_text(json.dumps(change))
        source.chmod(0o644)
        result = command('boundary-admin', 'admin', 'prepare', '--file', str(source))
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)['prepared']

    def commit_change(change):
        prepared = prepare_change(change)
        result = command('boundary-admin', 'admin', 'commit', '--operation-id', prepared['operation_id'], '--digest', prepared['digest'])
        assert result.returncode == 0, result.stderr
        return prepared

    commit_change({'kind': 'Catalog', 'change': {'action': 'EnrollVault', 'vault_id': vault_id}})
    listed = command('boundary-admin', 'admin', 'catalog')
    catalog = json.loads(listed.stdout)['catalog']
    check(all(k['role'] == 'unclassified' for k in catalog['keys']), 'vault enrollment never infers key roles from fragments')
    refused = subprocess.run([sys.executable, '-c', admin_call, config['admin_socket'], json.dumps(unlock)], preexec_fn=identity('boundary-admin'), capture_output=True, text=True, timeout=12)
    check(json.loads(refused.stdout)['code'] == 'KEY_ROLE_FORBIDDEN', 'unclassified key cannot be unlocked')
    root_key = next(k for k in catalog['keys'] if k['kid'] == fixture['kid'])
    change = {'kind':'Catalog','change':{'action':'ConfirmRole','key_id':root_key['key_id'],'role':'hot'}}
    source = Path('/tmp/keyd-management-change.json'); source.write_text(json.dumps(change)); source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode != 0, 'root cannot be relabeled as a hot signing key')
    commit_change({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':root_key['key_id'],'role':'root'}})
    check(command('boundary-agent-a','admin','catalog').returncode != 0, 'Agent cannot inspect or mutate managed key roles')
    for local_command in [('keygen','--spec','/tmp/unused-spec.json'),('publish','--did',fixture['did']),('serve',)]:
        result = command('anp-keyd','--root',str(vault),*local_command)
        check(result.returncode != 0 and 'managed vault requires' in result.stderr, 'service UID cannot use legacy local ' + local_command[0])
    relative = subprocess.run([binary,'--root','new-untracked-vault','keygen','--spec','/tmp/unused-spec.json'],cwd=str(vault),preexec_fn=identity('anp-keyd'),capture_output=True,text=True,timeout=12)
    check(relative.returncode != 0 and 'managed vault requires' in relative.stderr, 'relative nonexistent root cannot bypass managed directory guard')
    alias=Path('/tmp/keyd-managed-vault-alias');alias.symlink_to(vault)
    check(command('anp-keyd','--root',str(alias),'status').returncode != 0, 'symlink root cannot bypass managed directory guard')
    alias.unlink()
    policy_id = str(uuid.uuid4())
    policy = {'schema_version':1,'name':'read-only','purpose':'http-authentication','origin':'https://example.com','methods':['GET'],'paths':['/test'],'query':{'mode':'none'},'body':{'mode':'empty','max_bytes':0},'signature_profile':'anp-http-v2','grant_limits':{'max_duration_seconds':60,'max_uses':2}}
    commit_change({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':policy_id,'version':1,'content':policy}})
    # M3 uses actual OS subjects, signed root/hot documents and typed v2 frames.
    hot_key = next(k for k in catalog['keys'] if k['kid'].endswith('#http-hot'))
    commit_change({'kind':'Catalog','change':{'action':'ConfirmRole','key_id':hot_key['key_id'],'role':'hot'}})
    def data_as(name, operation):
        script = admin_call.replace("secret=b'temporary-boundary-test-secret';", "secret=b'';").replace("+struct.pack('!I',len(secret))+secret", "")
        result = subprocess.run([sys.executable,'-c',script,config['sign_socket'],json.dumps({'version':2,'request':operation})],preexec_fn=identity(name),capture_output=True,text=True,timeout=12)
        assert result.returncode == 0, result.stderr
        return json.loads(result.stdout)
    check(data_as('boundary-agent-a',{'operation':'LIST_AUTHORIZED_KEYS'})['data']['keys'] == [], 'unlocked or enrolled keys alone give no data authorization')
    principal_a=a['principal_id']; principal_b=b['principal_id']
    create_grant={'action':'Create','principal_id':principal_a,'key_id':hot_key['key_id'],'policy_id':policy_id,'policy_version':1,'expiry':int(time.time())+55,'max_uses':2}
    granted=commit_change({'kind':'Grant','change':create_grant})['effect']['effect']['grant']
    grant_id=granted['grant_id']
    check(len(grant_id)==64, 'grant references contain 256 random bits')
    keys=data_as('boundary-agent-a',{'operation':'LIST_AUTHORIZED_KEYS'})['data']['keys']
    check(len(keys)==1 and keys[0]['kid']==hot_key['kid'], 'Agent A sees exact granted hot key only')
    check(data_as('boundary-agent-b',{'operation':'LIST_AUTHORIZED_KEYS'})['data']['keys']==[], 'Agent B cannot list Agent A keys')
    check(data_as('boundary-agent-b',{'operation':'GET_GRANT_STATUS','grant_id':grant_id})['code']=='GRANT_INVALID', 'cross-principal grant lookup uniformly refused')
    check(data_as('boundary-agent-b',{'operation':'GET_DOCUMENT','key_id':hot_key['key_id']})['code']=='GRANT_INVALID', 'cross-principal document handle refused')
    check(data_as('boundary-agent-a',{'operation':'GET_DOCUMENT','key_id':hot_key['key_id']})['data']['document']['id']==fixture['did'], 'authorized public document returned')
    http={'method':'GET','url':'https://EXAMPLE.com:443/test','headers':{},'body':{'state':'absent'},'nonce':None}
    signing={'operation':'SIGN_HTTP','grant_id':grant_id,'request_id':str(uuid.uuid4()),'http':http}
    def unlock_hot():
        op={'version':2,'request':{'operation':'UNLOCK_KEY','vault_id':vault_id,'did':fixture['did'],'kid':hot_key['kid']}}
        result=subprocess.run([sys.executable,'-c',admin_call,config['admin_socket'],json.dumps(op)],preexec_fn=identity('boundary-admin'),capture_output=True,text=True,timeout=12)
        assert result.returncode==0 and json.loads(result.stdout)['code']=='OK', result.stdout+result.stderr
    unlock_hot()
    first=data_as('boundary-agent-a',signing)
    check(first['code']=='OK' and first['data']['state']=='completed' and first['data']['result']['url']=='https://example.com/test', 'M4 signs canonical target after durable reservation and result commit')
    check(data_as('boundary-agent-a',signing)['data']==first['data'], 'same ID returns identical cached signature without a second use')
    check(data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':signing['request_id']})['data']==first['data'], 'lost response can be recovered by request status')
    check(data_as('boundary-agent-b',{'operation':'GET_REQUEST_STATUS','request_id':signing['request_id']})['code']=='REQUEST_NOT_FOUND', 'request results remain scoped to principal')
    check(data_as('boundary-agent-a',{**signing,'http':{**http,'nonce':'different'}})['code']=='REQUEST_ID_CONFLICT', 'request ID cannot be rebound to another payload')
    check(data_as('boundary-agent-b',signing)['code']=='GRANT_INVALID', 'cross-principal signing refused')
    for target in ['https://evil.com/test','https://example.com/other','https://example.com/%74est','https://example.com/a/../test','https://example.com//test','https://example.com/test?a=1&a=2']:
        denied={**signing,'request_id':str(uuid.uuid4()),'http':{**http,'url':target}}
        check(data_as('boundary-agent-a',denied)['code']=='POLICY_DENIED', 'policy and canonical target reject '+target)
    check(data_as('boundary-agent-a',{**signing,'did':fixture['did']})['code']=='PROTOCOL_INVALID', 'data caller cannot override exact grant key')
    for operation in ['SIGN_RAW','SIGN_CHALLENGE','LOCK_ALL']:
        check(data_as('boundary-agent-a',{'operation':operation})['code']=='PROTOCOL_INVALID','v2 excludes '+operation)
    root_grant={**create_grant,'key_id':root_key['key_id']}
    source.write_text(json.dumps({'kind':'Grant','change':root_grant}));source.chmod(0o644)
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode!=0, 'root role cannot enter an Agent grant')
    check(data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':grant_id})['data']['used_uses']==1,'retries and policy denials do not consume extra quota')
    # Revoke A while a separate grant to B remains usable.
    second=commit_change({'kind':'Grant','change':{**create_grant,'principal_id':principal_b}})['effect']['effect']['grant']['grant_id']
    commit_change({'kind':'Grant','change':{'action':'Revoke','grant_id':grant_id}})
    check('result' not in data_as('boundary-agent-a',signing)['data'],'revocation suppresses cached signature delivery')
    check(data_as('boundary-agent-b',{**signing,'grant_id':second})['data']['state']=='completed','revoking A leaves B signing usable without unlocking again')
    source.write_text(json.dumps({'operation':'LIST_AUTHORIZED_KEYS'}));source.chmod(0o644)
    check(command('boundary-agent-b','data','--file',str(source)).returncode==0,'v2 CLI authenticates fixed configured endpoint')
    check(command('boundary-agent-b','data','--socket','/tmp/evil','--file',str(source)).returncode!=0,'v2 CLI has no socket override')
    if command('boundary-agent-b','mcp','--help').returncode == 0:
        child=subprocess.Popen([binary,'mcp','--config',str(config_path)],preexec_fn=identity('boundary-agent-b'),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        def rpc(value):
            child.stdin.write(json.dumps(value)+'\n');child.stdin.flush()
            assert select.select([child.stdout],[],[],10)[0], 'MCP reply timed out'
            return json.loads(child.stdout.readline())
        try:
            init=rpc({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'boundary-test','version':'1'}}})
            check('result' in init,'protected MCP initializes with clean JSON stdout')
            child.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\n');child.stdin.flush()
            tools=rpc({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})['result']['tools']
            check(len(tools)==5 and all(t['name'] not in ['unlock','lock_all','sign_raw','sign_challenge'] for t in tools),'protected MCP exposes only five authorized v2 tools')
            listed=rpc({'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'list_my_keys','arguments':{}}})
            result=json.loads(listed['result']['content'][0]['text'])
            check(result['data']['keys'][0]['key_id']==hot_key['key_id'],'protected MCP lists only caller-authorized hot key')
            signed=rpc({'jsonrpc':'2.0','id':4,'method':'tools/call','params':{'name':'sign_request','arguments':{'grant_id':second,'request_id':str(uuid.uuid4()),'http':http}}})
            check('Signature-Input' in json.dumps(signed),'protected MCP completes durable v2 signature without legacy fallback')
        finally:
            child.terminate();child.wait(timeout=10)
    # Last remaining use: many distinct requests contend for one durable slot.
    from concurrent.futures import ThreadPoolExecutor
    one=commit_change({'kind':'Grant','change':{**create_grant,'max_uses':1}})['effect']['effect']['grant']['grant_id']
    calls=[{**signing,'grant_id':one,'request_id':str(uuid.uuid4())} for _ in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes=list(pool.map(lambda op:data_as('boundary-agent-a',op),calls))
    check(sum(r['code']=='OK' and r['data'].get('result') is not None for r in outcomes)==1, 'eight concurrent final-use requests yield exactly one signature')
    winner=next(op for op,r in zip(calls,outcomes) if r['code']=='OK')
    cached=data_as('boundary-agent-a',winner)
    check(cached['data']['result'] is not None,'last completed signature remains retrievable after exhaustion')
    # A response lost on the socket still leaves a single completed result.
    lost=commit_change({'kind':'Grant','change':{**create_grant,'max_uses':1}})['effect']['effect']['grant']['grant_id']
    lostop={**signing,'grant_id':lost,'request_id':str(uuid.uuid4())}
    drop_script="import socket,struct,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);p=sys.argv[2].encode();s.sendall(struct.pack('!I',len(p))+p);s.close()"
    subprocess.run([sys.executable,'-c',drop_script,config['sign_socket'],json.dumps({'version':2,'request':lostop})],preexec_fn=identity('boundary-agent-a'),check=True)
    for _ in range(50):
        recovered=data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':lostop['request_id']})
        if recovered['code']=='OK':break
        time.sleep(.02)
    check(recovered['data']['state']=='completed' and recovered['data'].get('result') is not None,'disconnect after send preserves completed result for explicit recovery')
    stop(process); process=start()
    check(data_as('boundary-agent-a',{'operation':'GET_GRANT_STATUS','grant_id':lost})['data']['state'] in ['revoked_restart','exhausted'],'restart never revives consumed grants')
    check('result' not in data_as('boundary-agent-a',{'operation':'GET_REQUEST_STATUS','request_id':lostop['request_id']})['data'],'restart suppresses old completed signature')
    check(data_as('boundary-agent-a',{**signing,'grant_id':lost,'request_id':str(uuid.uuid4())})['code'] in ['GRANT_INVALID','GRANT_EXHAUSTED'],'restart refuses old grant for new signing')
    with sqlite3.connect(Path(config['state_dir'])/'state.sqlite') as database:
        check(database.execute("SELECT count(*) FROM audit_events WHERE CAST(event_data AS TEXT) LIKE '%LEGACY_AUDIT_LINKED%'").fetchone()[0]>=1,'SQLite history links verified legacy audit without rewriting it')
    policy['unexpected'] = True
    source.write_text(json.dumps({'kind':'Catalog','change':{'action':'PublishPolicy','policy_id':policy_id,'version':2,'content':policy}}))
    check(command('boundary-admin','admin','prepare','--file',str(source)).returncode != 0, 'policy schema rejects unknown fields')
    doc = json.loads(next((vault / 'dids').glob('*.json')).read_text())
    commit_change({'kind':'Catalog','change':{'action':'InstallDocument','vault_id':vault_id,'document':doc}})
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        check(database.execute("SELECT count(*) FROM file_operations WHERE state='complete'").fetchone()[0] == 1, 'managed document install completes durable file journal')
    unlocked = subprocess.run([sys.executable, '-c', admin_call, config['admin_socket'], json.dumps(unlock)], preexec_fn=identity('boundary-admin'), capture_output=True, text=True, timeout=12)
    check(unlocked.returncode == 0 and json.loads(unlocked.stdout)['code'] == 'OK', 'authenticated admin unlocks temporary vault, connection closes: ' + unlocked.stdout + unlocked.stderr)
    check(command('boundary-admin', 'admin', 'lock-all').returncode == 0, 'independent management lock works')
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        audit = ''.join(row[0].decode() for row in database.execute('SELECT event_data FROM audit_events'))
    check('temporary-boundary-test-secret' not in audit and '"dropped":1' in audit.replace(' ', ''), 'transactional audit records management lock count without secrets')
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
# Two-phase persistent management: no config edit can re-enable old principals.
process = start()
try:
    prepared = command('boundary-admin', 'admin', 'prepare-disable-principal', '--principal-id', b['principal_id'])
    assert prepared.returncode == 0, prepared.stderr
    operation = json.loads(prepared.stdout)['prepared']
    wrong = command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', 'wrong')
    check(wrong.returncode != 0 and as_agent('boundary-agent-b')['code'] == 'OK', 'digest substitution does not disable principal')
    committed = command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', operation['digest'])
    check(committed.returncode == 0 and as_agent('boundary-agent-b')['code'] == 'PRINCIPAL_DISABLED', 'principal disable is durable and immediate')
    check(command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', operation['digest']).returncode != 0, 'admin commit cannot replay')
    check(as_agent('boundary-agent-a')['code'] == 'OK', 'other principal continues after disable')
finally:
    stop(process)
process = start()
try:
    check(config['principals'][1]['enabled'] and as_agent('boundary-agent-b')['code'] == 'PRINCIPAL_DISABLED', 'restart never resurrects principal from bootstrap config')
    prepared = command('boundary-admin', 'admin', 'prepare-register-principal', '--uid', str(pwd.getpwnam('boundary-agent-b').pw_uid))
    operation = json.loads(prepared.stdout)['prepared']
    committed = command('boundary-admin', 'admin', 'commit', '--operation-id', operation['operation_id'], '--digest', operation['digest'])
    check(committed.returncode == 0 and as_agent('boundary-agent-b')['principal_id'] != b['principal_id'], 'reused UID receives a new principal identity')
    listed = command('boundary-admin', 'admin', 'list-principals')
    principals = json.loads(listed.stdout)['principals']
    check(len([p for p in principals if p['uid'] == pwd.getpwnam('boundary-agent-b').pw_uid]) == 2, 'administrator sees retired and replacement principal generations')
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        database.execute("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    check(command('boundary-admin', 'admin', 'lock-all').returncode != 0 and as_agent('boundary-agent-a')['code'] == 'AUDIT_UNAVAILABLE', 'audit persistence failure latches emergency stop')
    with sqlite3.connect(Path(config['state_dir']) / 'state.sqlite') as database:
        database.execute('DROP TRIGGER fail_audit')
    check(as_agent('boundary-agent-a')['code'] == 'AUDIT_UNAVAILABLE', 'repair alone cannot clear emergency stop without restart')
finally:
    stop(process)
state_path = Path(config['state_dir']) / 'state.sqlite'
check(b'temporary-boundary-test-secret' not in state_path.read_bytes(), 'SQLite contains no unlock password')
check(command('anp-keyd', 'init-protected-state').returncode != 0, 'explicit initialization refuses an existing database')
saved = state_path.with_suffix('.saved')
state_path.rename(saved)
try:
    result = command('anp-keyd', 'serve-protected')
    check(result.returncode != 0 and not state_path.exists(), 'missing database stops startup without implicit recreation')
finally:
    saved.rename(state_path)
state_path.rename(saved)
try:
    state_path.symlink_to(saved)
    check(command('anp-keyd', 'serve-protected').returncode != 0, 'symlink database rejected')
    state_path.unlink()
    os.link(saved, state_path)
    check(command('anp-keyd', 'serve-protected').returncode != 0, 'multiply linked database rejected')
    state_path.unlink()
finally:
    saved.rename(state_path)
with sqlite3.connect(state_path) as database:
    database.execute('PRAGMA user_version=4')
check(command('anp-keyd', 'serve-protected').returncode != 0, 'newer schema stops startup')
with sqlite3.connect(state_path) as database:
    database.execute('PRAGMA user_version=3')
    database.execute("UPDATE audit_events SET event_data=x'00' WHERE seq=1")
check(command('anp-keyd', 'serve-protected').returncode != 0, 'corrupt audit stops startup')
print(json.dumps({'passed': len(passed), 'protected_supported': False}), flush=True)
