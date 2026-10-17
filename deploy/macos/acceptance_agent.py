"""Real Claude Code process + tools, disposable HTTPS receiver and API fixture.
Run only inside test-runtime.py's isolated temporary service. No real identities,
model credentials, inference, or remote business service is involved.
"""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shlex
import ssl
import stat
import subprocess
import threading
import uuid

import claude_fixture


class Framework:
    def __init__(self, checks):
        self.checks = checks
        self.base = checks.base / 'framework'
        self.base.mkdir(mode=0o755)
        self.base.chmod(0o755)
        binary = checks.args.claude_binary
        meta = binary.lstat()
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError('framework input must be a regular binary, not a symlink')
        with binary.open('rb') as source:
            content = source.read(256 * 1024 * 1024 + 1)
        if len(content) > 256 * 1024 * 1024 or hashlib.sha256(content).hexdigest() != checks.args.claude_sha256:
            raise ValueError('framework binary digest mismatch')
        self.binary = self.base / 'claude'
        with self.binary.open('xb') as target:
            target.write(content)
        self.binary.chmod(0o755)  # root-owned, outside writable HOME/workspace
        self.step = self.base / 'agent-step.py'
        self.step.write_bytes(Path(__file__).with_name('agent-step.py').read_bytes())
        self.step.chmod(0o644)
        self.home = self.base / 'home'
        self.work = self.base / 'work'
        for path in [self.home, self.work]:
            path.mkdir(mode=0o700)
            os.chown(path, checks.agent.pw_uid, checks.agent.pw_gid)
        (self.home / 'tmp').mkdir(mode=0o700)
        os.chown(self.home / 'tmp', checks.agent.pw_uid, checks.agent.pw_gid)
        self.spec = self.base / 'public-spec.json'
        self.received = []
        self.failures = []
        self.server = self.thread = None

    def audit_access(self):
        checks = self.checks
        human = Path(checks.admin.pw_dir)
        sensitive = [str(human / name) for name in ('.ssh', '.aws', '.codex', '.claude', '.config')]
        protected = [checks.config['state_dir'], checks.config['admin_socket'],
                     '/var/run/docker.sock', str(human / '.colima/default/docker.sock'),
                     str(human / '.docker/run/docker.sock')]
        script = """import json,os,sys
paths=json.loads(sys.argv[1])
report={p:os.access(p,os.R_OK|os.W_OK) or os.access(p,os.R_OK) for p in paths}
print(json.dumps(report))
assert not any(report.values()), 'Agent can access a credential directory or host-control endpoint'
"""
        result = subprocess.run(['/usr/bin/python3', '-I', '-c', script, json.dumps(sensitive + protected)],
            **checks.credentials(checks.agent), env=checks.env, cwd=self.work,
            capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stdout + result.stderr
        if os.uname().sysname == 'Darwin':
            sudo = subprocess.run(['/usr/bin/sudo', '-n', '-l', '-U', checks.agent.pw_name],
                capture_output=True, env=checks.env, timeout=15)
            assert sudo.returncode == 1, 'Agent sudo rights found or sudo audit failed'
        print('PASS Agent cannot read known human credential directories, protected state/admin socket or known host Docker endpoints; dedicated HOME/workspace and only primary/signing groups', flush=True)

    def start_receiver(self):
        cert_config = self.base / 'tls.conf'
        cert_config.write_text('[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\n')
        key, cert = self.base / 'receiver.key', self.base / 'receiver.crt'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-days', '1', '-config', str(cert_config), '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True, timeout=30)
        key.chmod(0o600)
        cert.chmod(0o644)
        owner = self
        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                try:
                    assert self.path == '/test', 'unexpected receiver path'
                    headers = {k.lower(): v for k, v in self.headers.items()}
                    # Rebuild target from the receiver's actual authority/path,
                    # never take an asserted URL from the Agent's JSON output.
                    url = owner.origin + self.path
                    public = {'document': owner.checks.fixture['manifest']['document'],
                              'url': url, 'headers': headers}
                    result = subprocess.run([str(owner.checks.fixture['helper']), 'verify'],
                        input=json.dumps(public), capture_output=True, text=True, cwd='/',
                        env=owner.checks.env, **owner.checks.credentials(owner.checks.admin), timeout=20)
                    assert result.returncode == 0 and result.stdout.strip() == 'VERIFIED', result.stderr
                    signature = headers.get('signature')
                    assert signature and signature not in owner.received, 'receiver replay'
                    owner.received.append(signature)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'VERIFIED')
                except Exception as error:
                    owner.failures.append(str(error))
                    self.send_error(403)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        self.server.daemon_threads = True
        self.origin = 'https://localhost:' + str(self.server.server_port)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.ca = cert

    def invoke(self, action):
        checks = self.checks
        command = shlex.join(['/usr/bin/python3', str(self.step), str(self.spec), action])
        tool_results = []
        with claude_fixture.messages_api(command, tool_results) as endpoint:
            env = claude_fixture.environment(self.home, checks.agent.pw_name, endpoint)
            result = subprocess.run(claude_fixture.arguments(self.binary), env=env,
                cwd=self.work, **checks.credentials(checks.agent),
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, 'Claude Code failed: ' + result.stderr[-2000:]
        evidence_path = self.work / ('evidence-' + action + '.json')
        assert evidence_path.exists(), 'framework tool did not produce evidence: ' + result.stdout[-4000:] + result.stderr[-2000:] + json.dumps(tool_results)[-4000:]
        assert evidence_path.stat().st_uid == checks.agent.pw_uid
        evidence = json.loads(evidence_path.read_text())
        assert evidence['uid'] == evidence['euid'] == checks.agent.pw_uid, evidence
        assert set(evidence['groups']) <= {checks.agent.pw_gid, checks.config['agent_gid']}, evidence
        assert evidence['home'] == str(self.home), evidence
        print('PASS actual Claude Code and Bash/tool child run as independent Agent UID: ' + json.dumps(evidence), flush=True)

    def run(self):
        checks = self.checks
        try:
            self.audit_access()
            self.start_receiver()
            policy_id = str(uuid.uuid4())
            checks.change({'kind': 'Catalog', 'change': {'action': 'PublishPolicy', 'policy_id': policy_id, 'version': 1,
                'content': {'schema_version': 1, 'name': 'claude-loopback-temporary', 'purpose': 'http-authentication',
                'origin': self.origin, 'methods': ['GET'], 'paths': ['/test'],
                'query': {'mode': 'none'}, 'body': {'mode': 'empty', 'max_bytes': 0}, 'signature_profile': 'anp-http-v2',
                'grant_limits': {'max_duration_seconds': 300, 'max_uses': 20}}}})
            previous_policy = checks.policy_id
            checks.policy_id = policy_id
            try:
                grant = checks.grant()
            finally:
                checks.policy_id = previous_policy
            checks.unlock()
            sign = {**checks.signing(grant), 'http': {**checks.signing(grant)['http'], 'url': self.origin + '/test'}}
            self.spec.write_text(json.dumps({'binary': str(checks.args.binary), 'config': str(checks.path),
                'sign': sign, 'origin': self.origin, 'ca': str(self.ca)}))
            self.spec.chmod(0o644)
            self.invoke('sign')
            assert len(self.received) == 1 and not self.failures, self.failures
            other = checks.request_as(checks.fixture['other'], sign)
            assert other['code'] == 'GRANT_INVALID', other
            hidden = checks.request_as(checks.fixture['other'], {'operation': 'GET_REQUEST_STATUS', 'request_id': sign['request_id']})
            assert hidden['code'] == 'REQUEST_NOT_FOUND', hidden
            checks.change({'kind': 'Grant', 'change': {'action': 'Revoke', 'grant_id': grant}})
            self.invoke('revoked')
            assert len(self.received) == 1 and not self.failures, self.failures
            print('PASS framework stable-ID/status/conflict/unknown-ID, exact HTTPS send, independent upstream verification, cross-UID denial and revocation; API fixture, no live model inference', flush=True)
        finally:
            if self.server:
                self.server.shutdown()
                self.server.server_close()
                self.thread.join(timeout=5)
