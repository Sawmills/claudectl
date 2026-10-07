"""Throwaway synthetic-only Claude credential-reload experiment; not product code.

macOS variant: every Claude child runs under a network/credential-store sandbox.
No real credential value is read or logged. Report only synthetic generation labels.
"""
import fcntl
import hashlib
import http.server
import json
import os
import pty
from pathlib import Path
import queue
import re
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

BINARY = os.environ.get('CLAUDECTL_PROBE_BINARY', '/Users/amirjakoby/.local/share/claude/versions/2.1.288')
A = 'synthetic-invalid-generation-a'
B = 'synthetic-invalid-generation-b'


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f)
    os.replace(tmp, path)


def process_start():
    stat = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()
    boot = next(int(x.split()[1]) for x in Path('/proc/stat').read_text().splitlines()
                if x.startswith('btime '))
    return boot * 1000 + int(stat[19]) / os.sysconf('SC_CLK_TCK') * 1000


def run_case(root, case, server):
    run = root / case
    run.mkdir(mode=0o700)
    config = run / 'config'
    config.mkdir(mode=0o700)
    creds = config / 'settings.json'
    host = run / 'host.json'
    helper_token = run / 'helper-input'
    env = {
        'HTTPS_PROXY': PROXY_URL, 'HTTP_PROXY': PROXY_URL,
        'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': os.environ['HOME'],
        'CLAUDE_CONFIG_DIR': str(config), 'DISABLE_AUTOUPDATER': '1',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1',
        'DISABLE_ERROR_REPORTING': '1', 'DISABLE_GROWTHBOOK': '1',
        'ANTHROPIC_BASE_URL': 'https://api.anthropic.com',
        'NODE_EXTRA_CA_CERTS': str(root / 'cert.pem'),
        'CLAUDE_CODE_MAX_OUTPUT_TOKENS': '128', 'API_TIMEOUT_MS': '8000',
    }
    settings = {'alwaysThinkingEnabled': False, 'disableAllHooks': True}
    fds = ()
    initial_expiry = int(time.time() * 1000) + 5000

    def write_generation(token):
        if case.startswith('file'):
            atomic_json(creds, {'env': {'CLAUDE_CODE_OAUTH_TOKEN': token}})
        elif case.startswith('host'):
            key = 'CLAUDE_CODE_OAUTH_TOKEN' if case == 'host_oauth' else 'ANTHROPIC_AUTH_TOKEN'
            atomic_json(host, {'env': {key: token}, 'pid': os.getpid(),
                              'procStart': process_start(),
                              'expiresAt': int(time.time() * 1000) + 3600000})
        elif case == 'helper':
            helper_token.write_text(token)
            helper_token.chmod(0o600)
        elif case == 'settings_env':
            atomic_json(config / 'settings.json', {'env': {'CLAUDE_CODE_OAUTH_TOKEN': token}})

    write_generation(A)
    if case == 'env':
        env['CLAUDE_CODE_OAUTH_TOKEN'] = A
    elif case == 'fd':
        r, w = os.pipe()
        os.write(w, A.encode())
        os.close(w)
        env['CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR'] = str(r)
        fds = (r,)
    elif case.startswith('host'):
        env['CLAUDE_CODE_HOST_CREDS_FILE'] = str(host)
        env['CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST'] = '1'
        if case == 'host_oauth':
            env['CLAUDE_CODE_HOST_AUTH_ENV_VAR'] = 'CLAUDE_CODE_OAUTH_TOKEN'
    elif case == 'helper':
        settings['apiKeyHelper'] = '/bin/cat ' + str(helper_token)
        env['CLAUDE_CODE_API_KEY_HELPER_TTL_MS'] = '600000'

    state = {'case': case, 'turn': 1, 'requests': [], 'other_requests': [],
             'rotate_on_401': case in ['file_401', 'host_oauth', 'host_bearer', 'helper'],
             'rotate': lambda: write_generation(B), 'rotated': False}
    server.state = state
    command = ['/usr/bin/sandbox-exec', '-f', str(root / 'sandbox.sb'), BINARY, '-p', '--input-format', 'stream-json', '--output-format',
               'stream-json', '--verbose', '--model', 'claude-sonnet-4-6',
               '--tools', '', '--strict-mcp-config', '--setting-sources', 'user',
               '--settings', json.dumps(settings), '--no-session-persistence']
    p = subprocess.Popen(command, env=env, cwd=run, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, pass_fds=fds, start_new_session=True)
    for fd in fds:
        os.close(fd)
    out = queue.Queue()
    errors = []

    def read_stdout():
        for line in p.stdout:
            try:
                out.put(json.loads(line))
            except ValueError:
                out.put({'type': 'unparsed'})
        out.put({'type': 'eof'})

    def read_stderr():
        for line in p.stderr:
            # All inputs are synthetic; retain errors in memory for diagnosis only.
            errors.append(line.replace(A, '<generation A>').replace(B, '<generation B>'))

    threading.Thread(target=read_stdout, daemon=True).start()
    threading.Thread(target=read_stderr, daemon=True).start()
    results = []
    events = []
    try:
        for turn in ([1, 2, 3] if case == 'file_outage' else [1, 2]):
            state['turn'] = turn
            if turn == 2 and case in ['file_expired', 'file_outage']:
                time.sleep(max(0, (initial_expiry + 200) / 1000 - time.time()))
            if turn == 3:
                write_generation(B)
                time.sleep(1.1)
            if turn == 2 and not state['rotate_on_401']:
                if case != 'file_outage':
                    write_generation(B)
                if case == 'file_missing':
                    creds.unlink()
                if case == 'file_malformed':
                    creds.write_text('{broken')
                time.sleep(1.1)
            p.stdin.write(json.dumps({'type': 'user', 'message': {
                'role': 'user', 'content': 'Reply OK only. Turn ' + str(turn)}}) + '\n')
            p.stdin.flush()
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                try:
                    event = out.get(timeout=max(0.1, deadline - time.monotonic()))
                except queue.Empty:
                    results.append({'turn': turn, 'timeout': True})
                    break
                events.append(event.get('type'))
                if event.get('type') == 'result':
                    results.append({'turn': turn, 'is_error': event.get('is_error'),
                                    'subtype': event.get('subtype'),
                                    'result': event.get('result', '')[:300],
                                    'session_id': event.get('session_id')})
                    break
                if event.get('type') == 'eof':
                    results.append({'turn': turn, 'eof': True})
                    break
            if results[-1].get('timeout') or results[-1].get('eof'):
                break
    except BrokenPipeError:
        results.append({'broken_pipe': True})
    finally:
        alive = p.poll() is None
        os.killpg(p.pid, signal.SIGTERM) if alive else None
        try:
            p.wait(timeout=4)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait()
    summary = {k: v for k, v in state.items() if k not in ['rotate']}
    summary.update(pid=p.pid, same_process_alive_after_turns=alive, results=results,
                   event_types=events, stderr=''.join(errors)[-1500:])
    print(json.dumps(summary), flush=True)


class Proxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_CONNECT(self):
        if self.path not in ['api.anthropic.com:443', 'console.anthropic.com:443',
                             'platform.claude.com:443', 'claude.ai:443']:
            self.send_error(403, 'Synthetic proxy refuses this destination')
            return
        self.send_response(200, 'Connection established')
        self.end_headers()
        try:
            connection = self.server.tls_context.wrap_socket(self.connection, server_side=True)
            Handler(connection, self.client_address, self.server)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        self.close_connection = True


def main():
    global PROXY_URL
    if sys.platform != 'darwin':
        raise SystemExit('This variant requires macOS sandbox-exec')
    supported = {'file_proactive', 'file_401', 'file_expired', 'file_outage',
                 'file_missing', 'file_malformed', 'env', 'fd', 'helper',
                 'settings_env', 'file_tui'}
    cases = sys.argv[1:] or ['file_proactive', 'file_401', 'file_expired', 'file_outage',
                             'file_missing', 'file_malformed', 'env', 'fd', 'file_tui']
    if not set(cases) <= supported:
        raise SystemExit('Unsupported macOS test case')
    with tempfile.TemporaryDirectory(prefix='claudectl-mac-isolated-') as scratch:
        root = Path(scratch).resolve()
        (root / 'sandbox-denied').write_text('synthetic sandbox check')
        home = Path(os.environ['HOME'])
        forbidden = [home / '.claude', home / '.claudectl', home / '.config/anthropic',
                     home / 'Library/Keychains', root / 'sandbox-denied']
        profile = '''(version 1)
(allow default)
(deny network*)
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (remote ip "localhost:*"))
(deny mach-lookup (global-name "com.apple.securityd")
                  (global-name "com.apple.securityd.xpc")
                  (global-name "com.apple.SecurityServer"))
(deny file-write*)
'''
        profile += '(allow file-write* (subpath ' + json.dumps(str(root)) + ') (subpath "/dev"))\n'
        for location in forbidden:
            profile += '(deny file-read* file-write* (subpath ' + json.dumps(str(location)) + '))\n'
        profile += '(deny file-read* file-write* (literal ' + json.dumps(str(home / '.claude.json')) + '))\n'
        (root / 'sandbox.sb').write_text(profile)
        validation = '''import socket,sys
try:
 open(sys.argv[1]).read()
 raise SystemExit('FAIL: protected fixture readable')
except PermissionError: pass
s=socket.socket(); s.settimeout(2)
try:
 s.connect(('1.1.1.1',443))
 raise SystemExit('FAIL: external network allowed')
except PermissionError: pass
print('PASS: fixture reads and external connections denied')
'''
        checked = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(root / 'sandbox.sb'),
                                  sys.executable, '-c', validation, str(root / 'sandbox-denied')],
                                 text=True, capture_output=True, timeout=10)
        if checked.returncode:
            raise SystemExit('Sandbox validation failed: ' + checked.stderr + checked.stdout)
        print(checked.stdout.strip(), flush=True)
        subprocess.run(['/opt/homebrew/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=api.anthropic.com',
                        '-addext', 'subjectAltName=DNS:api.anthropic.com,DNS:console.anthropic.com,DNS:platform.claude.com,DNS:claude.ai'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        server.rotation_lock = threading.Lock()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        server.tls_context = ctx
        PROXY_URL = 'http://127.0.0.1:' + str(server.server_port)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(json.dumps({'binary_sha256': hashlib.sha256(Path(BINARY).read_bytes()).hexdigest(),
                          'network': 'sandboxed Claude children; local synthetic HTTPS CONNECT proxy',
                          'keychain': 'securityd access and Keychain files denied'}), flush=True)
        for case in cases:
            if case == 'file_tui':
                run_tui_case(root, server)
            else:
                run_case(root, case, server)
        server.shutdown()


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply_json(self, status, data):
        payload = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.server.state['other_requests'].append(['GET', self.path])
        self.reply_json(404, {'error': {'type': 'not_found_error', 'message': 'mock only'}})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or '{}')
        state = self.server.state
        if not self.path.startswith('/v1/messages') or 'count_tokens' in self.path:
            state['other_requests'].append(['POST', self.path])
            self.reply_json(404, {'error': {'type': 'not_found_error', 'message': 'mock only'}})
            return
        auth = self.headers.get('Authorization', '')
        key = self.headers.get('X-Api-Key', '')
        generation = 'A' if auth == 'Bearer ' + A or key == A else 'B' if auth == 'Bearer ' + B or key == B else 'none'
        status = 401 if state['turn'] >= 2 and generation != 'B' else 200
        state['requests'].append({'turn': state['turn'], 'generation': generation,
                                  'status': status, 'oauth_beta': 'oauth-2025-04-20' in self.headers.get('anthropic-beta', ''),
                                  'api_key_header': bool(key)})
        if status == 401:
            with self.server.rotation_lock:
                if state['rotate_on_401'] and not state['rotated']:
                    state['rotate']()
                    state['rotated'] = True
            self.reply_json(401, {'type': 'error', 'error': {'type': 'authentication_error',
                                                           'message': 'Synthetic old credential expired'}})
            return
        message = {'id': 'msg_synthetic', 'type': 'message', 'role': 'assistant',
                   'model': body.get('model'), 'content': [], 'stop_reason': None,
                   'stop_sequence': None, 'usage': {'input_tokens': 10, 'output_tokens': 0}}
        events = [('message_start', {'type': 'message_start', 'message': message}),
                  ('content_block_start', {'type': 'content_block_start', 'index': 0,
                                           'content_block': {'type': 'text', 'text': ''}}),
                  ('content_block_delta', {'type': 'content_block_delta', 'index': 0,
                                           'delta': {'type': 'text_delta', 'text': 'OK'}}),
                  ('content_block_stop', {'type': 'content_block_stop', 'index': 0}),
                  ('message_delta', {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn',
                                     'stop_sequence': None}, 'usage': {'output_tokens': 1}}),
                  ('message_stop', {'type': 'message_stop'})]
        payload = ''.join('event: ' + name + '\ndata: ' + json.dumps(data) + '\n\n'
                          for name, data in events).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def run_tui_case(root, server):
    run = root / 'tui'
    run.mkdir(mode=0o700)
    config = run / 'config'
    config.mkdir(mode=0o700)
    creds = config / 'settings.json'
    def rotate(token):
        atomic_json(creds, {'env': {'CLAUDE_CODE_OAUTH_TOKEN': token}})
    rotate(A)
    atomic_json(config / '.claude.json', {'hasCompletedOnboarding': True,
                'lastOnboardingVersion': '2.1.288', 'theme': 'dark',
                'projects': {str(run): {'hasTrustDialogAccepted': True}}})
    state = {'case': 'file_tui', 'turn': 1, 'requests': [], 'other_requests': [],
             'rotate_on_401': True, 'rotated': False, 'rotate': lambda: rotate(B)}
    server.state = state
    env = {'HTTPS_PROXY': PROXY_URL, 'HTTP_PROXY': PROXY_URL, 'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': os.environ['HOME'],
           'CLAUDE_CONFIG_DIR': str(config), 'DISABLE_AUTOUPDATER': '1',
           'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1',
           'DISABLE_ERROR_REPORTING': '1', 'DISABLE_GROWTHBOOK': '1',
           'ANTHROPIC_BASE_URL': 'https://api.anthropic.com',
           'NODE_EXTRA_CA_CERTS': str(root / 'cert.pem'),
           'CLAUDE_CODE_MAX_OUTPUT_TOKENS': '128', 'API_TIMEOUT_MS': '8000',
           'TERM': 'xterm-256color', 'COLORTERM': 'truecolor'}
    master, slave = pty.openpty()
    fcntl.ioctl(slave, 0x80087467, struct.pack('HHHH', 40, 120, 0, 0))
    command = ['/usr/bin/sandbox-exec', '-f', str(root / 'sandbox.sb'), BINARY, '--model', 'claude-sonnet-4-6', '--tools', '',
               '--strict-mcp-config', '--setting-sources', 'user', '--settings',
               json.dumps({'alwaysThinkingEnabled': False, 'disableAllHooks': True})]
    child = subprocess.Popen(command, env=env, cwd=run, stdin=slave, stdout=slave,
                             stderr=slave, start_new_session=True)
    os.close(slave)
    screen = []
    def reader():
        try:
            while True:
                data = os.read(master, 65536)
                if not data:
                    return
                screen.append(data.decode('utf8', 'replace'))
        except OSError:
            pass
    threading.Thread(target=reader, daemon=True).start()
    def text_screen():
        return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', ''.join(screen))
    time.sleep(2)
    os.write(master, b'Reply OK only. Turn 1\r')
    results = []
    try:
        for turn in [1, 2]:
            if turn == 2:
                state['turn'] = 2
                os.write(master, b'Reply OK only. Turn 2\r')
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if any(x['turn'] == turn and x['status'] == 200 for x in state['requests']):
                    time.sleep(1)
                    results.append({'turn': turn, 'request_succeeded': True})
                    break
                if child.poll() is not None:
                    break
                time.sleep(0.1)
            else:
                results.append({'turn': turn, 'timeout': True})
            if not results or results[-1].get('timeout'):
                break
    finally:
        alive = child.poll() is None
        if alive:
            os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        os.close(master)
    summary = {k: v for k, v in state.items() if k != 'rotate'}
    summary.update(pid=child.pid, same_process_alive_after_turns=alive, results=results,
                   terminal_excerpt=text_screen()[-2500:].replace(A, '<A>').replace(B, '<B>'))
    print(json.dumps(summary), flush=True)

if __name__ == '__main__':
    main()
