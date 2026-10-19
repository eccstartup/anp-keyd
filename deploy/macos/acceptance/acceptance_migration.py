"""Exercise the supported offline migrator with ONLY this run's public fixture.
Password injection here is test-only; the production migrator always uses tty.
"""
import errno
import json
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import time


def install(base, config, path, args, fixture):
    source = fixture['source']
    # Freeze this newly generated disposable source and its immediate parent.
    # Never takes a caller-supplied real identity or changes any installed vault.
    for node in [*source.rglob('*'), source, source.parent]:
        os.chown(node, 0, 0, follow_symlinks=False)
        node.chmod(0o700 if node.is_dir() else 0o600)
    migration = Path(__file__).parents[2] / ('linux' if args.container_regression else 'macos') / 'migrate-vault.py'
    recovery = base / 'recovery'
    command = [sys.executable, str(migration), '--source', str(source), '--config', str(path), '--binary', str(args.binary)]
    before = path.read_bytes()
    dry = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert dry.returncode == 0 and json.loads(dry.stdout.splitlines()[-1])['dry_run'], dry.stderr
    assert path.read_bytes() == before and not recovery.exists(), 'dry run mutated state'

    def apply():
        pid, terminal = pty.fork()
        if pid == 0:
            os.execv(sys.executable, [*command, '--apply', '--recovery-dir', str(recovery)])
        output, sent = b'', 0
        deadline = time.monotonic() + 60
        reaped = False
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([terminal], [], [], remaining)[0]:
                    raise ValueError('disposable recovery verification timed out')
                try:
                    chunk = os.read(terminal, 8192)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break
                if not chunk:
                    break
                output += chunk
                if len(output) > 256 * 1024:
                    raise ValueError('migration output exceeds bound')
                prompts = len(re.findall(rb'Verify recovery of [^\r\n]*: ', output))
                while sent < prompts:
                    os.write(terminal, b'temporary-boundary-test-secret\n')
                    sent += 1
            _, status = os.waitpid(pid, 0)
            reaped = True
            assert os.waitstatus_to_exitcode(status) == 0 and sent == 3, output.decode(errors='replace')
        finally:
            if not reaped:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            os.close(terminal)
        return json.loads((recovery / 'migration.json').read_text())

    first = apply()
    assert first['phase'] == 'installed_locked_unclassified'
    again = apply()
    assert again == first, 'resume changed inventory or vault identity'
    config.update(json.loads(path.read_text()))
    fixture['vault_id'] = first['vault_id']
    assert config['vault_ids'] == [first['vault_id']]
    # Tampered completed recovery material is preserved and refused before tty.
    key = next((recovery / 'vault/keys').glob('*.json'))
    saved = key.read_bytes()
    key.write_bytes(b'unknown recovery bytes')
    refused = subprocess.run([*command, '--apply', '--recovery-dir', str(recovery)], capture_output=True, text=True, timeout=20)
    assert refused.returncode != 0 and key.read_bytes() == b'unknown recovery bytes'
    assert 'unknown bytes' in refused.stderr or 'backup changed' in refused.stderr, refused.stderr
    key.write_bytes(saved)  # only this test-created backup, retain verified fixture
    print('PASS supported offline migration: read-only plan, every backup key recovered, same-ID resume, changed backup refused; managed catalog still unclassified and locked', flush=True)
