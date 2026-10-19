"""Pipe-only test subprocess broker, started before the parent loads native APIs.

No listener, persistent state, secret store, retries, or authorization decisions.
Child credentials are exactly those already chosen by the acceptance runner.
"""
import atexit
import json
import os
from pathlib import Path
import select
import subprocess
import sys


def native_stack(pid):
    try:
        captured = subprocess.run(['/usr/bin/sample', str(pid), '1', '-file', '/dev/stdout'],
            capture_output=True, text=True, timeout=5, close_fds=False)
        return (captured.stdout + captured.stderr)[-24576:]
    except (OSError, subprocess.SubprocessError) as error:
        return 'native stack unavailable: ' + str(type(error).__name__)


def child_command(request):
    if not request['credentials']:
        return request['argv']
    return [str(Path(sys.executable).resolve()), '-I', str(Path(__file__).resolve()),
            '--exec', json.dumps(request['credentials']), *request['argv']]


def credential_exec(credentials, argv):
    if os.geteuid() != 0 or set(credentials) != {'user', 'group', 'extra_groups'}:
        raise ValueError('expected root and exact acceptance child credentials')
    def stage(value):
        print('CREDENTIAL_STAGE ' + value, file=sys.stderr, flush=True)
    stage('wrapper-started')
    os.setgroups(credentials['extra_groups'])
    stage('groups-set')
    os.setregid(credentials['group'], credentials['group'])
    stage('gid-set')
    os.setreuid(credentials['user'], credentials['user'])
    stage('uid-set')
    if os.getuid() != credentials['user'] or os.getgid() != credentials['group']:
        raise ValueError('credential drop did not match requested identity')
    stage('exec-client')
    os.execve(argv[0], argv, dict(os.environ))


def execute(request, sample=True):
    # No cwd or uid/gid subprocess options: CPython can use posix_spawn rather
    # than fork with credential changes before exec. The broker already runs /.
    with subprocess.Popen(child_command(request), env=request['env'], close_fds=False,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as child:
        try:
            out, err = child.communicate(request.get('input'), timeout=request['timeout'])
            return {'returncode':child.returncode, 'stdout':out, 'stderr':err}
        except subprocess.TimeoutExpired:
            stack = 'sampling disabled'
            if sample and sys.platform == 'darwin':
                stack = native_stack(child.pid)
            child.kill()
            out, err = child.communicate(timeout=5)
            return {'timeout':True, 'pid':child.pid, 'stdout':out, 'stderr':err, 'stack':stack}


class Broker:
    def __init__(self):
        self.process = subprocess.Popen([str(Path(sys.executable).resolve()), '-I', str(Path(__file__).resolve())],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1, cwd='/')
        atexit.register(self.close)
        ready = self.run([str(Path(sys.executable).resolve()), '-I', '-c', 'print("broker-ready")'], {},
                         {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}, timeout=5)
        if ready.returncode != 0 or ready.stdout.strip() != 'broker-ready':
            raise ValueError('subprocess broker self-check failed')
        print(f'PASS native-free subprocess broker ready pid={self.process.pid}', flush=True)

    def run(self, argv, credentials, env, input=None, timeout=20):
        request = {'argv':list(map(str,argv)), 'credentials':credentials,
                   'env':env, 'input':input, 'timeout':timeout}
        self.process.stdin.write(json.dumps(request) + '\n')
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], timeout + 12)[0]:
            if sys.platform == 'darwin':
                print(f'BROKER_TIMEOUT_STACK pid={self.process.pid}\n' + native_stack(self.process.pid), flush=True)
            raise ValueError('subprocess broker response timed out; no retry attempted')
        line = self.process.stdout.readline(4 * 1024 * 1024 + 1)
        if not line or len(line) > 4 * 1024 * 1024:
            raise ValueError('subprocess broker missing or oversized reply')
        reply = json.loads(line)
        if 'error' in reply:
            raise ValueError('subprocess broker failed: ' + reply['error'])
        if reply.get('timeout'):
            print(f'CLIENT_TIMEOUT_STACK pid={reply["pid"]}\n{reply["stack"]}', flush=True)
            raise subprocess.TimeoutExpired(['broker-child'], timeout,
                output=reply['stdout'], stderr=reply['stderr'])
        return subprocess.CompletedProcess(argv, reply['returncode'], reply['stdout'], reply['stderr'])

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.process.stdout.close()


def main():
    if os.geteuid() != 0:
        raise ValueError('test subprocess broker requires root')
    os.chdir('/')
    for line in sys.stdin:
        try:
            reply = execute(json.loads(line))
        except Exception as error:
            reply = {'error':type(error).__name__}
        print(json.dumps(reply), flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--exec']:
        credential_exec(json.loads(sys.argv[2]), sys.argv[3:])
    else:
        main()
