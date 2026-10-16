#!/usr/bin/env python3
"""Bounded local runtime checks in a separate temporary service instance.
Requires the explicitly provisioned accounts and root. Never touches the running
installation's state, keys, configuration or launchd job. No new accounts created.
"""
import argparse
import json
import os
from pathlib import Path
import pwd
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/Library/ANPKeyd/service.json'))
    parser.add_argument('--binary', type=Path, default=Path('/Library/ANPKeyd/bin/anp-keyd'))
    parser.add_argument('--signing-helper', type=Path, help='digest-pinned local-preview-fixture example; enables full temporary signing checks')
    parser.add_argument('--helper-sha256')
    parser.add_argument('--interactive-ui', action='store_true', help='human window checks: cancel, 120-second timeout, masked temporary-password unlock')
    parser.add_argument('--container-regression', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    args.config = args.config.absolute()
    args.binary = args.binary.absolute()
    if args.signing_helper:
        args.signing_helper = args.signing_helper.absolute()
    elif args.interactive_ui or args.helper_sha256:
        raise ValueError('UI/digest options require --signing-helper')
    portable = args.container_regression
    if os.geteuid() != 0:
        raise ValueError('requires root; run in the human terminal')
    if portable:
        if sys.platform != 'linux' or not Path('/.dockerenv').exists() or args.interactive_ui:
            raise ValueError('container regression requires disposable root Linux Docker without UI')
    elif sys.platform != 'darwin':
        raise ValueError('requires macOS')
    installed = json.loads(args.config.read_text())
    expected_mode = 'linux-boundary-preview' if portable else 'macos-boundary-preview'
    if installed['mode'] != expected_mode or not installed['principals']:
        raise ValueError('requires a configured macOS preview with an Agent')
    service = pwd.getpwuid(installed['service_uid'])
    admin = pwd.getpwuid(installed['admin_uids'][0])
    agent = pwd.getpwuid(installed['principals'][0]['uid'])
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'RUST_LOG': 'info'}
    def credentials(user, extra_admin_group=False):
        # Use subprocess's native credential switch, not Python after fork.
        # Explicit minimal child groups avoid Darwin getgroups/initgroups cache
        # differences and NGROUPS_MAX; account membership itself is not changed.
        groups = [installed['agent_gid']]
        if user.pw_uid == service.pw_uid:
            groups.append(installed['admin_gid'])
        elif user.pw_uid == admin.pw_uid:
            groups = [installed['admin_gid']]
        if extra_admin_group:
            groups.append(installed['admin_gid'])
        return {'user': user.pw_uid, 'group': user.pw_gid,
                'extra_groups': sorted(set(groups))}
    def run(user, *command):
        return subprocess.run(list(map(str, command)), **credentials(user),
                              env=env, capture_output=True, text=True, timeout=15, cwd="/")
    parent = '/tmp' if portable else '/Library'
    if portable:
        parent = '/keyd-checks'
        Path(parent).mkdir(mode=0o755, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ANPKeydChecks-', dir=parent) as directory:
        base = Path(directory)
        base.chmod(0o755)
        config = {**installed, 'instance_id': str(uuid.uuid4()), 'vault_ids': [],
                  'state_dir': str(base / 'state'), 'sign_socket': str(base / 'sign/sign.sock'),
                  'admin_socket': str(base / 'admin/admin.sock')}
        for name, gid, mode in [('state', service.pw_gid, 0o700),
                                ('sign', config['agent_gid'], 0o750),
                                ('admin', config['admin_gid'], 0o750)]:
            path = base / name
            path.mkdir()
            os.chown(path, service.pw_uid, gid)
            path.chmod(mode)
        fixture = None
        if args.signing_helper:
            import acceptance_signing
            fixture = acceptance_signing.prepare(base, config, args, admin, service, run)
        path = base / 'service.json'
        path.write_text(json.dumps(config))
        path.chmod(0o644)
        def cli(user, *command):
            return run(user, args.binary, 'admin', '--config', path, *command)
        result = run(service, args.binary, 'init-protected-state', '--config', path)
        assert result.returncode == 0, result.stderr
        process = None
        def start():
            proc = subprocess.Popen([str(args.binary), 'serve-protected', '--config', str(path)],
                                    **credentials(service), env=env, cwd="/",
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(100):
                if proc.poll() is not None:
                    raise ValueError('temporary service failed to start')
                if Path(config['admin_socket']).exists():
                    return proc
                time.sleep(0.05)
            proc.terminate()
            proc.wait(timeout=10)
            raise ValueError('temporary service startup timed out')
        def stop(proc):
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                raise ValueError('temporary service graceful shutdown timed out')
            assert proc.returncode == 0, 'temporary service did not shut down normally'
        try:
            process = start()
            result = cli(admin, 'status')
            assert result.returncode == 0, result.stderr
            first = json.loads(result.stdout)
            assert first['instance_id'] == config['instance_id'] and not first['protected_supported']
            checks = None
            if fixture:
                checks = acceptance_signing.Checks(base, config, path, args, fixture, admin, agent, credentials, env, cli)
                checks.before_restart()
            # task_for_pid queries a task port, never attaches a debugger or reads
            # memory. Root performs only the UID switch; the Agent makes the call.
            script = '''import ctypes,sys
lib=ctypes.CDLL('/usr/lib/libSystem.B.dylib')
lib.task_for_pid.argtypes=[ctypes.c_uint,ctypes.c_int,ctypes.POINTER(ctypes.c_uint)]
port=ctypes.c_uint()
self_task=ctypes.c_uint.in_dll(lib,'mach_task_self_').value
status=lib.task_for_pid(self_task,int(sys.argv[1]),ctypes.byref(port))
if status == 0:
 lib.mach_port_deallocate(self_task,port)
 sys.exit('Agent obtained daemon task port')
print('task_for_pid denied')
'''
            if not portable:
                result = run(agent, '/usr/bin/python3', '-I', '-c', script, process.pid)
                assert result.returncode == 0 and 'task_for_pid denied' in result.stdout, result.stderr
                print('PASS independent Agent UID cannot obtain daemon task port', flush=True)
            else:
                print('SKIP macOS task-port probe in Linux container regression', flush=True)
            stop(process)
            process = None
            assert not Path(config['admin_socket']).exists()
            process = start()
            second = json.loads(cli(admin, 'status').stdout)
            assert second['boot_epoch'] > first['boot_epoch']
            print('PASS graceful shutdown cleans sockets; restart advances boot epoch', flush=True)
            if checks:
                checks.after_restart()
                checks.arm_crash()
                process.kill()
                process.wait(timeout=10)
                process = None
                process = start()
                checks.after_restart(interactive=False)
                print('PASS abrupt process death also revokes active grants, suppresses cached results and locks keys', flush=True)
            stop(process)
            process = None
            # Forge the expected filesystem UID/group/mode, but keep the listener
            # running as root. Kernel peer identity must still reject this server
            # BEFORE a native dialog or credential frame could be sent.
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(config['admin_socket'])
                os.chown(config['admin_socket'], service.pw_uid, config['admin_gid'])
                os.chmod(config['admin_socket'], 0o660)
                listener.listen(1)
                listener.settimeout(15)
                received = []
                def accept():
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            connection.settimeout(10)
                            received.append(connection.recv(1))
                    except OSError as error:
                        received.append(str(error))
                thread = threading.Thread(target=accept)
                thread.start()
                result = cli(admin, 'unlock', '--native-ui', '--vault-id', str(uuid.uuid4()),
                             '--did', 'did:wba:example.com:temporary', '--kid', 'temporary')
                thread.join(timeout=16)
                assert not thread.is_alive(), 'fake-server check timed out'
                assert result.returncode != 0 and 'SERVER_IDENTITY_MISMATCH' in result.stderr, result.stderr
                assert received == [b''], 'client sent bytes before authenticating server'
                print('PASS forged socket owner/mode cannot impersonate daemon; no request/secret sent', flush=True)
            print('PASS temporary runtime checks; installed launchd instance was not modified', flush=True)
        finally:
            if process is not None and process.poll() is None:
                stop(process)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, AssertionError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
