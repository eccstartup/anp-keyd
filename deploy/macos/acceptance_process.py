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


def execute(request, sample=True):
    with subprocess.Popen(request['argv'], **request['credentials'], env=request['env'],
                          cwd='/', stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True) as child:
        try:
            out, err = child.communicate(request.get('input'), timeout=request['timeout'])
            return {'returncode':child.returncode, 'stdout':out, 'stderr':err}
        except subprocess.TimeoutExpired:
            stack = 'sampling disabled'
            if sample and sys.platform == 'darwin':
                try:
                    captured = subprocess.run(['/usr/bin/sample', str(child.pid), '1', '-file', '/dev/stdout'],
                        capture_output=True, text=True, timeout=5)
                    stack = (captured.stdout + captured.stderr)[-24576:]
                except (OSError, subprocess.SubprocessError) as error:
                    stack = 'native stack unavailable: ' + str(type(error).__name__)
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
    for line in sys.stdin:
        try:
            reply = execute(json.loads(line))
        except Exception as error:
            reply = {'error':type(error).__name__}
        print(json.dumps(reply), flush=True)


if __name__ == '__main__':
    main()
