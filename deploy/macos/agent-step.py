#!/usr/bin/env python3
"""Public temporary-identity tool executed by the complete Claude Code process.
No secrets. Its output is checked independently by the parent and HTTPS receiver.
"""
import ctypes
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import uuid


def kernel_groups():
    # macOS os.getgroups() reports the account's configured groups, not the
    # kernel credential list, so ask libc getgroups(2) directly. Linux agrees
    # either way.
    lib = ctypes.CDLL(None, use_errno=True)
    count = lib.getgroups(0, None)
    if count < 0:
        raise OSError(ctypes.get_errno(), 'getgroups')
    groups = (ctypes.c_uint * count)()
    if lib.getgroups(count, groups) < 0:
        raise OSError(ctypes.get_errno(), 'getgroups')
    return list(groups)


def run(spec, action):
    def request(value, expect='OK'):
        path = Path('request.json')
        path.write_text(json.dumps(value))
        result = subprocess.run([spec['binary'], 'data', '--config', spec['config'], '--file', str(path)],
                                capture_output=True, text=True, timeout=20)
        if expect != 'OK':
            assert result.returncode != 0 and expect in result.stderr, result.stderr
            return None
        assert result.returncode == 0, result.stderr
        reply = json.loads(result.stdout)
        assert reply['code'] == 'OK', reply
        return reply['data']
    sign = spec['sign']
    evidence = {'uid': os.getuid(), 'euid': os.geteuid(), 'kernel_groups': kernel_groups(),
                'home': os.environ['HOME'], 'action': action}
    if action == 'revoked':
        cached = request(sign)
        assert not cached.get('result'), cached
        request({**sign, 'request_id': str(uuid.uuid4())}, 'GRANT_INVALID')
        # No completed signature may be recovered after revocation.
        result = request({'operation': 'GET_REQUEST_STATUS', 'request_id': sign['request_id']})
        assert not result.get('result'), result
    else:
        status = request(sign)
        assert status['state'] == 'completed' and status['result'], status
        assert request(sign) == status, 'stable ID changed result'
        assert request({'operation': 'GET_REQUEST_STATUS', 'request_id': sign['request_id']}) == status
        request({'operation': 'GET_REQUEST_STATUS', 'request_id': str(uuid.uuid4())}, 'REQUEST_NOT_FOUND')
        changed = {**sign, 'http': {**sign['http'], 'nonce': 'conflicting-payload'}}
        request(changed, 'REQUEST_ID_CONFLICT')
        forbidden = {**sign, 'request_id': str(uuid.uuid4()),
                     'http': {**sign['http'], 'url': spec['origin'] + '/forbidden'}}
        request(forbidden, 'POLICY_DENIED')
        signed = status['result']
        assert signed['url'] == sign['http']['url'], 'signed target differs'
        # No redirect handler or URL rewrite: exactly the signed GET path and
        # daemon-produced headers, over TLS with only this receiver's test CA.
        from urllib.parse import urlsplit
        target = urlsplit(signed['url'])
        assert target.scheme == 'https' and not target.query and not target.fragment
        context = ssl.create_default_context(cafile=spec['ca'])
        connection = http.client.HTTPSConnection(target.hostname, target.port, context=context, timeout=20)
        try:
            connection.request('GET', target.path, headers=signed['headers'])
            response = connection.getresponse()
            body = response.read(4096)
            assert response.status == 200 and body == b'VERIFIED', (response.status, body)
        finally:
            connection.close()
        evidence['receiver'] = 'VERIFIED'
    Path('evidence-' + action + '.json').write_text(json.dumps(evidence))
    print(json.dumps(evidence), flush=True)


if __name__ == '__main__':
    run(json.loads(Path(sys.argv[1]).read_text()), sys.argv[2])
