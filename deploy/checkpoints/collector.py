#!/usr/bin/env python3
"""Independent checkpoint keeper. Standard library only; no signing permissions.

The pinned SSH source validates chain extension. The collector serializes source
requests with a durable SQLite transaction, retaining immutable checkpoint rows.
The host running this process and its storage must be outside the service domain.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import time

APP_ID = 0x414E5043
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
CONFIG_KEYS = {"version", "instance_id", "host", "port", "user", "identity_file",
               "known_hosts_file", "timeout_seconds", "max_age_seconds"}


class Rejected(Exception):
    pass


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Rejected("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def check(condition, reason):
    if not condition:
        raise Rejected(reason)


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def secure_path(path, directory=False):
    """Reject links and writable ancestors, including before SQLite follows paths."""
    path = Path(path)
    check(path.is_absolute() and str(path) == os.path.normpath(path), "absolute path required")
    for part in [*reversed(path.parents), path]:
        meta = part.lstat()
        check(meta.st_uid in (0, os.geteuid()) and not meta.st_mode & 0o022,
              "untrusted path owner or permissions")
        check(stat.S_ISDIR(meta.st_mode) if part != path or directory else stat.S_ISREG(meta.st_mode),
              "unexpected path type")
    return path


def private_directory(path):
    path = secure_path(path, directory=True)
    meta = path.stat()
    check(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o700,
          "store directory must be owned by collector with mode 0700")
    return path


def read_config(path):
    path = secure_path(path)
    with path.open('rb') as file:
        data = file.read(8193)
    check(len(data) <= 8192, "oversized config")
    config = strict_json(data)
    check(type(config) is dict and set(config) == CONFIG_KEYS, "unknown config schema")
    check(type(config['version']) is int and config['version'] == 1, "unsupported config")
    check(type(config['instance_id']) is str and UUID.fullmatch(config['instance_id']), "invalid instance")
    check(type(config['host']) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", config['host']), "invalid host")
    check(type(config['user']) is str and re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", config['user']), "invalid user")
    check(integer(config['port'], 1, 65535), "invalid port")
    check(integer(config['timeout_seconds'], 1, 120), "invalid timeout")
    check(integer(config['max_age_seconds'], 1, 86400), "invalid observation budget")
    for name in ('identity_file', 'known_hosts_file'):
        check(type(config[name]) is str and not any(c in config[name] for c in '\n\r\x00'), "invalid credential path")
        secure_path(config[name])
    meta = Path(config['identity_file']).stat()
    check(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o600,
          "collector identity must have mode 0600")
    return config


def binding(config):
    # Bind the source identity and trust material; rotation is an explicit migration,
    # never an automatic reset. Operational timeout/budget can change independently.
    identity = {k: v for k, v in config.items() if k not in ('timeout_seconds', 'max_age_seconds')}
    for name in ('identity_file', 'known_hosts_file'):
        with open(config[name], 'rb') as file:
            data = file.read(65537)
        check(len(data) <= 65536, "oversized credential file")
        identity[name + '_sha256'] = hashlib.sha256(data).hexdigest()
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def validate_checkpoint(cp, instance):
    check(type(cp) is dict and set(cp) == {'version', 'instance_id', 'sequence', 'digest'}, "invalid checkpoint schema")
    check(type(cp['version']) is int and cp['version'] == 1 and cp['instance_id'] == instance,
          "wrong checkpoint instance/version")
    check(integer(cp['sequence'], 1, 2**63-1) and type(cp['digest']) is str
          and re.fullmatch('[0-9a-f]{64}', cp['digest']), "invalid checkpoint position")
    return cp


def ssh_request(config, previous):
    # No user SSH config, agent, proxy, forwarding, TOFU, shell-built arguments,
    # or password prompts. The server forces audit-source with fixed paths.
    command = ['/usr/bin/ssh', '-F', '/dev/null', '-T', '-p', str(config['port']),
               '-i', config['identity_file']]
    options = ['BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none',
               'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null',
               'UserKnownHostsFile=' + config['known_hosts_file'], 'UpdateHostKeys=no',
               'HostKeyAlgorithms=ssh-ed25519', 'PasswordAuthentication=no',
               'KbdInteractiveAuthentication=no', 'ClearAllForwardings=yes',
               'PermitLocalCommand=no', 'ConnectionAttempts=1',
               'ConnectTimeout=' + str(config['timeout_seconds']),
               'ServerAliveInterval=5', 'ServerAliveCountMax=1']
    for option in options:
        command += ['-o', option]
    command += ['-l', config['user'], '--', config['host'], 'audit-source-v1']
    payload = json.dumps({'version': 1, 'enroll': previous is None, 'previous': previous}).encode()
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        process.stdin.write(payload)
        process.stdin.close()
        output = bytearray()
        deadline = time.monotonic() + config['timeout_seconds']
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                check(time.monotonic() < deadline, "source timeout")
                for key, _ in selector.select(min(.1, max(0, deadline-time.monotonic()))):
                    chunk = os.read(key.fd, 4097)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    output.extend(chunk)
                    check(len(output) <= 4096, "oversized source response")
        process.wait(timeout=max(.001, deadline-time.monotonic()))
        check(process.returncode == 0, "authenticated source unavailable or rejected history")
        response = strict_json(output)
        check(type(response) is dict and set(response) == {'version', 'previous', 'checkpoint'}
              and type(response['version']) is int and response['version'] == 1,
              "invalid source response")
        check(response['previous'] == previous, "source responded to a different checkpoint")
        candidate = validate_checkpoint(response['checkpoint'], config['instance_id'])
        if previous:
            check(candidate['sequence'] >= previous['sequence'], "checkpoint rollback")
            if candidate['sequence'] == previous['sequence']:
                check(candidate == previous, "checkpoint fork")
        return candidate
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()


SCHEMA = '''
CREATE TABLE keeper(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 instance_id TEXT NOT NULL, source_binding TEXT NOT NULL,
 last_success INTEGER, latest_seq INTEGER REFERENCES checkpoints(sequence)) STRICT;
CREATE TABLE checkpoints(sequence INTEGER PRIMARY KEY CHECK(sequence>0),
 digest TEXT NOT NULL CHECK(length(digest)=64), retained_at INTEGER NOT NULL) STRICT;
CREATE TRIGGER immutable_update BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER immutable_delete BEFORE DELETE ON checkpoints BEGIN SELECT RAISE(ABORT,'immutable'); END;
'''


def open_store(directory, config, enroll):
    directory = private_directory(directory)
    path = directory / 'checkpoints.sqlite'
    if not path.exists():
        check(enroll, "checkpoint store missing; explicit enrollment required")
        # Exclusive creation; an interrupted initialization leaves a maintenance
        # artifact. Never replace unknown/corrupt state with an empty store.
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.fsync(fd)
        os.close(fd)
        init = True
    else:
        init = False
    secure_path(path)
    meta = path.stat()
    check(meta.st_uid == os.geteuid() and stat.S_IMODE(meta.st_mode) == 0o600 and meta.st_nlink == 1,
          "unsafe checkpoint store")
    # mode=rw prevents a missing store from being silently re-created.
    connection = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True, timeout=.5, isolation_level=None)
    try:
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA foreign_keys=ON')
        if not init:
            check(connection.execute('PRAGMA application_id').fetchone()[0] == APP_ID
                  and connection.execute('PRAGMA user_version').fetchone()[0] == 1,
                  'unknown checkpoint store schema')
        check(connection.execute('PRAGMA journal_mode=DELETE' if init else 'PRAGMA journal_mode').fetchone()[0] == 'delete', "unsafe journal mode")
        connection.execute('PRAGMA synchronous=EXTRA')
        if init:
            connection.executescript('BEGIN IMMEDIATE;'+SCHEMA)
            connection.execute('INSERT INTO keeper VALUES(1,?,?,NULL,NULL)',
                               (config['instance_id'], binding(config)))
            connection.execute(f'PRAGMA application_id={APP_ID}')
            connection.execute('PRAGMA user_version=1')
            connection.commit()
            fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        check(connection.execute('PRAGMA application_id').fetchone()[0] == APP_ID
              and connection.execute('PRAGMA user_version').fetchone()[0] == 1,
              "unknown checkpoint store schema")
        check(connection.execute('PRAGMA integrity_check(1)').fetchone()[0] == 'ok'
              and not connection.execute('PRAGMA foreign_key_check').fetchall(), "corrupt checkpoint store")
        return connection
    except BaseException:
        connection.close()
        raise


def current(connection, config):
    row = connection.execute('SELECT instance_id,source_binding,last_success,latest_seq FROM keeper WHERE singleton=1').fetchone()
    check(row is not None and row[:2] == (config['instance_id'], binding(config)), "source binding changed")
    _, _, last_success, sequence = row
    maximum = connection.execute('SELECT MAX(sequence) FROM checkpoints').fetchone()[0]
    check(maximum == sequence and (sequence is None) == (last_success is None), "inconsistent checkpoint store")
    previous = None
    if sequence is not None:
        digest, retained_at = connection.execute('SELECT digest,retained_at FROM checkpoints WHERE sequence=?', (sequence,)).fetchone()
        check(integer(last_success, 0, 2**63-1) and retained_at <= last_success, "invalid retention time")
        previous = validate_checkpoint({'version': 1, 'instance_id': config['instance_id'],
                                        'sequence': sequence, 'digest': digest}, config['instance_id'])
    return previous, last_success


def report(config, cp, last_success, now, state):
    check(last_success is None or now >= last_success, "collector clock regression")
    age = None if last_success is None else now-last_success
    return {'version': 1, 'instance_id': config['instance_id'], 'state': state,
            'checkpoint': cp, 'last_success': last_success, 'age_seconds': age,
            'max_age_seconds': config['max_age_seconds'],
            'deadline_exceeded': age is None or age > config['max_age_seconds'],
            'signing_policy': 'continue_local_audit', 'unobserved_tail': 'unknown'}


def collect(directory, config, enroll=False, transport=ssh_request, clock=time.time, before_commit=None):
    with contextlib.closing(open_store(directory, config, enroll)) as connection:
        # Hold the independent-store write lease across fetch and commit. A late
        # result cannot overwrite a newer checkpoint from another collector.
        connection.execute('BEGIN IMMEDIATE')
        try:
            previous, last_success = current(connection, config)
            check((previous is None) == enroll, "explicit initial enrollment required; re-enrollment forbidden")
            start = int(clock())
            prior = report(config, previous, last_success, start, 'collecting')
            candidate = validate_checkpoint(transport(config, previous), config['instance_id'])
            if previous:
                check(candidate['sequence'] >= previous['sequence'], "checkpoint rollback")
                check(candidate['sequence'] != previous['sequence'] or candidate == previous, "checkpoint fork")
            completed = int(clock())
            check(completed >= start, "collector clock regression")
            if previous != candidate:
                connection.execute('INSERT INTO checkpoints VALUES(?,?,?)',
                                   (candidate['sequence'], candidate['digest'], completed))
            connection.execute('UPDATE keeper SET last_success=?,latest_seq=? WHERE singleton=1',
                               (completed, candidate['sequence']))
            if before_commit:
                before_commit(connection)
            connection.commit()
            result = report(config, candidate, completed, completed, 'retained')
            result['previous_observation_age_seconds'] = prior['age_seconds']
            result['observation_deadline_missed'] = (last_success is not None and
                                                    completed-last_success > config['max_age_seconds'])
            return result
        except BaseException:
            connection.rollback()
            raise


def status(directory, config, clock=time.time):
    with contextlib.closing(open_store(directory, config, False)) as connection:
        connection.execute('BEGIN')
        cp, last_success = current(connection, config)
        return report(config, cp, last_success, int(clock()), 'observed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['collect', 'enroll', 'status'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--store', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config = None
    try:
        config = read_config(args.config)
        result = (status(args.store, config) if args.action == 'status' else
                  collect(args.store, config, enroll=args.action == 'enroll'))
        print(json.dumps(result, sort_keys=True))
        return 2 if args.action == 'status' and result['deadline_exceeded'] else 0
    except (Rejected, OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        result = {'version': 1, 'state': 'unavailable', 'signing_policy': 'continue_local_audit',
                  'reason': str(error) if isinstance(error, Rejected) else 'storage_or_transport_error'}
        if config:
            try:
                result.update(status(args.store, config))
                result['state'] = 'unavailable'
            except (Rejected, OSError, ValueError, sqlite3.Error):
                pass
        print(json.dumps(result, sort_keys=True))
        # Never echo paths, private identity material, remote stderr or bodies.
        print('checkpoint collection/status failed; retained evidence was not reset', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
