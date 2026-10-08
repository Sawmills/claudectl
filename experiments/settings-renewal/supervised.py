"""End-to-end synthetic launcher test. Requires the isolation in linux.py/mac-settings-base.py.

`claudectl server run` keeps the host Claude config and passes only the server token. Run 1: a
real Claude process runs one Bash tool on server token A while the HOME holds a host login
(token H). Run 2: a relaunch with --resume continues the same session after the account server
moved to token B. Checks: the host token is never sent, the host credentials file and identity
are unchanged, the tool ran once, and no private session state survives exit.
"""
import importlib.util
import http.server
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

spec = importlib.util.spec_from_file_location('base', Path(__file__).with_name('mac-settings-base.py' if sys.platform == 'darwin' else 'linux.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
LAUNCHER = os.environ['CLAUDECTL_PROBE_LAUNCHER']
ACCOUNT = 'a' * 64
IDENTITY = {'account_uuid': 'synthetic-account', 'organization_uuid': 'synthetic-org'}
HOST = 'synthetic-host-login-generation-h'


def run_case(root, case, inference):
    run = root / 'supervised'
    run.mkdir(mode=0o700)
    marker = run / 'tool-count'
    temporary = run / 'tmp'
    temporary.mkdir(mode=0o700)
    home = run / 'home'
    home.mkdir(mode=0o700)
    state = {'generation': 1, 'expect': 'A', 'requests': [], 'other_requests': [],
             'expires_at': int(time.time()*1000)+8*3600000}
    host = home / '.claude'
    host.mkdir(mode=0o700)
    base.atomic_json(host / '.credentials.json', {'claudeAiOauth': {
        'accessToken': HOST, 'refreshToken': 'synthetic-host-refresh',
        'expiresAt': int(time.time()*1000)+3600000, 'scopes': ['user:inference', 'user:profile']}})
    base.atomic_json(home / '.claude.json', {
        'oauthAccount': {'accountUuid': 'host-account', 'organizationUuid': 'host-org'},
        'hasCompletedOnboarding': True, 'projects': {str(run): {'hasTrustDialogAccepted': True}}})
    host_before = (host / '.credentials.json').read_bytes()
    inference.state = state

    class AccountServer(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, value):
            data = json.dumps(value).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            assert self.headers.get('Authorization') == 'Bearer synthetic-machine'
            if self.path == '/v2/anthropic/accounts':
                self.reply([{'provider': 'anthropic', 'account_id': ACCOUNT, 'alias': 'work',
                             'identity': IDENTITY, 'available': True}])
            elif self.path.startswith('/v2/anthropic/usage?'):
                self.reply({'data': None, 'observed_at': None, 'next_retry_at': 0,
                            'stale': True, 'error': None})
            else:
                raise AssertionError(self.path)

        def do_POST(self):
            assert self.path == '/v2/anthropic/token', self.path
            assert self.headers.get('Authorization') == 'Bearer synthetic-machine'
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            assert request['account_id'] == ACCOUNT
            n = state['generation']
            self.reply({'provider': 'anthropic', 'account_id': ACCOUNT, 'user_id': 'person',
                        'identity': IDENTITY, 'access_token': base.A if n == 1 else base.B,
                        'expires_at': state['expires_at'],
                        'scopes': ['user:inference', 'user:profile'],
                        'generation': n, 'revision': 'revision-' + str(n)})

    broker = http.server.ThreadingHTTPServer(('127.0.0.1', 0), AccountServer)
    threading.Thread(target=broker.serve_forever, daemon=True).start()
    client = home / '.claudectl/server'
    client.mkdir(mode=0o700, parents=True)
    base.atomic_json(client / 'machine.json', 'synthetic-machine')
    qualify = os.environ.get('CLAUDECTL_PROBE_QUALIFY_SHA256')
    if qualify:
        # `claudectl server qualify`: allow only the candidate build, only in this throwaway HOME.
        base.atomic_json(client / 'qualified-builds.json', [{
            'sha256': qualify, 'platform': 'macos' if sys.platform == 'darwin' else 'linux',
            'qualified_at': 'candidate'}])
    base.atomic_json(client / 'connection.json', {
        'server': 'http://127.0.0.1:' + str(broker.server_port), 'user_id': 'person',
        'token_file': str(client / 'machine.json')})

    def messages(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or '{}')
        if not self.path.startswith('/v1/messages') or 'count_tokens' in self.path:
            self.reply_json(404, {'error': {'type': 'not_found_error'}})
            return
        auth = self.headers.get('Authorization')
        generation = 'A' if auth == 'Bearer ' + base.A else 'B' if auth == 'Bearer ' + base.B else 'H' if auth == 'Bearer ' + HOST else 'other'
        state['requests'].append({'generation': generation, 'probe': True}) if generation not in ['A', 'B'] else None
        assert generation in ['A', 'B'] and not self.headers.get('X-Api-Key'), generation
        tool_results = [block for message in body.get('messages', [])
                        for block in message.get('content', []) if isinstance(block, dict)
                        and block.get('type') == 'tool_result']
        state['requests'].append({'generation': generation, 'tool_result': bool(tool_results)})
        tool = not tool_results
        if tool:
            assert len(state['requests']) == 1, 'tool action would be replayed'
            content = {'type': 'tool_use', 'id': 'tool_synthetic', 'name': 'Bash',
                       'input': {'command': 'sleep 8; printf x >> ' + str(marker) + '; printf complete',
                                 'description': 'Synthetic tool continuity check', 'timeout': 15000}}
        else:
            assert generation == state['expect'], 'the session did not use the server token it was launched with'
            assert marker.exists(), json.dumps(tool_results)
            assert marker.read_text() == 'x', 'tool did not run exactly once'
            content = {'type': 'text', 'text': 'OK'}
        message = {'id': 'msg_synthetic', 'type': 'message', 'role': 'assistant',
                   'model': body.get('model'), 'content': [], 'stop_reason': None,
                   'stop_sequence': None, 'usage': {'input_tokens': 10, 'output_tokens': 0}}
        events = [('message_start', {'type': 'message_start', 'message': message}),
                  ('content_block_start', {'type': 'content_block_start', 'index': 0,
                    'content_block': dict(content, input={}) if tool else {'type': 'text', 'text': ''}}),
                  ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                    'delta': {'type': 'input_json_delta', 'partial_json': json.dumps(content['input'])} if tool
                        else {'type': 'text_delta', 'text': 'OK'}}),
                  ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                  ('message_delta', {'type': 'message_delta',
                    'delta': {'stop_reason': 'tool_use' if tool else 'end_turn', 'stop_sequence': None},
                    'usage': {'output_tokens': 5}}),
                  ('message_stop', {'type': 'message_stop'})]
        payload = ''.join('event: ' + event + '\ndata: ' + json.dumps(data) + '\n\n' for event, data in events).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    base.Handler.do_POST = messages
    env = {'HOME': str(home), 'PATH': '/usr/local/bin:/usr/bin:/bin',
           'SHELL': '/bin/bash', 'TMPDIR': str(temporary), 'NODE_EXTRA_CA_CERTS': str(root / 'cert.pem'), 'CLAUDECTL_ALLOW_INSECURE_LOOPBACK': '1',
           'DISABLE_TELEMETRY': '1', 'DISABLE_ERROR_REPORTING': '1', 'DISABLE_GROWTHBOOK': '1',
           'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'API_TIMEOUT_MS': '8000'}
    command = [LAUNCHER, 'server', 'run', 'work', '--claude', base.BINARY, '--',
               '-p', '--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose',
               '--model', 'claude-sonnet-4-6', '--tools', 'Bash', '--allowedTools', 'Bash',
               '--strict-mcp-config']
    tool_directory = None
    if sys.platform == 'darwin':
        # Claude uses a per-project directory under /tmp/claude-UID even with TMPDIR.
        # Permit only this fresh fixture's directory; never broaden the Keychain/network rules.
        tool_directory = Path('/private/tmp') / ('claude-' + str(os.getuid())) / re.sub(r'[^A-Za-z0-9]', '-', str(run))
        tool_directory.mkdir(parents=True, exist_ok=False)
        sandbox = root / 'sandbox.sb'
        with sandbox.open('a') as policy:
            policy.write('(allow file-write* (subpath ' + json.dumps(str(tool_directory)) + '))\n')
        env['HTTPS_PROXY'] = base.PROXY_URL
        env['HTTP_PROXY'] = base.PROXY_URL
        command = ['/usr/bin/sandbox-exec', '-f', str(root / 'sandbox.sb')] + command
    def launch(extra, prompt):
        child = subprocess.Popen(command + extra, env=env, cwd=run, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
        output = queue.Queue()
        threading.Thread(target=lambda: [output.put(line) for line in child.stdout], daemon=True).start()
        child.stdin.write(json.dumps({'type': 'user', 'message': {'role': 'user', 'content': prompt}}) + '\n')
        child.stdin.flush()
        result = None
        events_seen = []
        deadline = time.monotonic() + 120
        try:
            while time.monotonic() < deadline:
                event = json.loads(output.get(timeout=max(0.1, deadline - time.monotonic())))
                events_seen.append(event)
                if event.get('type') == 'result':
                    result = event
                    break
            assert result and not result.get('is_error'), result
            assert child.poll() is None
        finally:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=15)
            if not result:
                print(json.dumps({'failed_state': state, 'child_errors': child.stderr.read(),
                                  'events': events_seen, 'tool_marker_exists': marker.exists()}), flush=True)
        assert not child.stderr.read().strip(), 'launcher wrote errors'
        return result

    try:
        first = launch([], 'Run the synthetic Bash check once, then say OK.')
        assert marker.read_text() == 'x'
        assert [r['generation'] for r in state['requests']] == ['A', 'A'], state
        # The account server moves on; a relaunch resumes the same session with the new token.
        state.update(generation=2, expect='B')
        second = launch(['--resume', first['session_id']], 'Say OK again.')
        assert second['session_id'] == first['session_id'], (first, second)
        assert [r['generation'] for r in state['requests']] == ['A', 'A', 'B'], state
        assert marker.read_text() == 'x', 'tool ran again'
        assert (host / '.credentials.json').read_bytes() == host_before, 'host credentials changed'
        identity = json.loads((home / '.claude.json').read_text()).get('oauthAccount')
        assert identity == {'accountUuid': 'host-account', 'organizationUuid': 'host-org'}, identity
    finally:
        broker.shutdown()
        if tool_directory is not None:
            shutil.rmtree(tool_directory)
    assert not list((client / 'sessions').iterdir()), 'private credentials survived exit'
    print(json.dumps({'case': 'supervised_host_config', 'checks': 'passed',
                      'requests': state['requests'], 'tool_executions': 1,
                      'resumed_same_session': True, 'private_sessions_after_exit': 0}), flush=True)


if __name__ == '__main__':
    base.run_case = run_case
    sys.argv = [sys.argv[0], 'file_proactive' if sys.platform == 'darwin' else 'supervised']
    base.main()
