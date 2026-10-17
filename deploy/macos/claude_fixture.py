"""Deterministic loopback Messages API for real Claude Code tool-runner checks.

No model inference or external credentials. This tests framework execution and
UID inheritance, not model quality or live-provider compatibility.
"""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading


@contextmanager
def messages_api(command, tool_results=None):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 4 * 1024 * 1024:
                self.send_error(413)
                return
            request = json.loads(self.rfile.read(length))
            if self.path.split('?')[0].endswith('/count_tokens'):
                self.send_json({'input_tokens': 100})
                return
            if self.path.split('?')[0] != '/v1/messages':
                self.send_error(404)
                return
            results = [block for message in request.get('messages', [])
                       if isinstance(message.get('content'), list)
                       for block in message['content'] if block.get('type') == 'tool_result']
            if results:
                if tool_results is not None:
                    tool_results.extend(results)
                content = [{'type': 'text', 'text': 'Local framework tool step finished.'}]
                reason = 'end_turn'
            else:
                if not any(tool['name'] == 'Bash' for tool in request.get('tools', [])):
                    self.send_error(400, 'Bash tool required')
                    return
                content = [{'type': 'tool_use', 'id': 'toolu_keyd_fixture', 'name': 'Bash',
                            'input': {'command': command, 'description': 'Run disposable keyd acceptance tool', 'timeout': 60000}}]
                reason = 'tool_use'
            message = {'id': 'msg_keyd_fixture', 'type': 'message', 'role': 'assistant',
                       'model': request.get('model', 'claude-sonnet-4-6'), 'content': content,
                       'stop_reason': reason, 'stop_sequence': None,
                       'usage': {'input_tokens': 100, 'output_tokens': 20}}
            if not request.get('stream'):
                self.send_json(message)
                return
            events = [{'type': 'message_start', 'message': {**message, 'content': [], 'stop_reason': None}}]
            for i, block in enumerate(content):
                initial = {**block, 'input': {}} if block['type'] == 'tool_use' else {'type': 'text', 'text': ''}
                delta = ({'type': 'input_json_delta', 'partial_json': json.dumps(block['input'])}
                         if block['type'] == 'tool_use' else {'type': 'text_delta', 'text': block['text']})
                events += [{'type': 'content_block_start', 'index': i, 'content_block': initial},
                           {'type': 'content_block_delta', 'index': i, 'delta': delta},
                           {'type': 'content_block_stop', 'index': i}]
            events += [{'type': 'message_delta', 'delta': {'stop_reason': reason, 'stop_sequence': None},
                        'usage': {'output_tokens': 20}}, {'type': 'message_stop'}]
            data = ''.join('event: ' + event['type'] + '\ndata: ' + json.dumps(event) + '\n\n' for event in events).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, message):
            data = json.dumps(message).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def arguments(binary):
    return [str(binary), '--bare', '--print', '--no-session-persistence',
            '--setting-sources', '', '--strict-mcp-config', '--mcp-config', '{"mcpServers":{}}',
            '--tools', 'Bash', '--allowedTools', 'Bash', '--permission-mode', 'dontAsk',
            '--model', 'claude-sonnet-4-6', '--output-format', 'json',
            '--system-prompt', 'Run the requested disposable local acceptance tool once.',
            'Execute the supplied local test tool. Do not access other files or services.']


def environment(home, user, endpoint):
    return {'HOME': str(home), 'USER': user, 'LOGNAME': user,
            'TMPDIR': str(home / 'tmp'), 'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
            'LANG': 'en_US.UTF-8', 'RUST_LOG': 'info',
            'ANTHROPIC_BASE_URL': endpoint, 'ANTHROPIC_API_KEY': 'public-local-fixture-only',
            'DISABLE_NONESSENTIAL_TRAFFIC': '1', 'CLAUDE_CODE_DISABLE_AUTO_MEMORY': '1'}
