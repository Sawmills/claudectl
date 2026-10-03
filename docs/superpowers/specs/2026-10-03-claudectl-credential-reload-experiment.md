# Claude Code credential reload experiment

2026-10-03. Question: can a running Claude Code session receive a replacement
subscription access token without restarting or holding a refresh token?

## Result

**Yes, in the tested Linux client with a synthetic API.** Claude Code 2.1.280
reloaded an access-only `.credentials.json` file, sent the replacement bearer,
and continued in the same process. This worked in streaming command mode and in
the interactive terminal. Recovery also worked when the replacement file appeared
only after a simulated HTTP 401.

This supports choosing an access-only file, updated by a local account-server
client, for the [account-server design](2026-10-02-claudectl-central-design.md).
The account server would retain refresh ownership. A fixed OAuth environment
value or a one-time inherited pipe did not recover in this test.

This is a client-behavior result, not a live Anthropic interoperability result.
No real login, token exchange, or provider request occurred. macOS, genuine plan
entitlement, real rotation timing, and account identity still need acceptance.

## Test boundary

- Unmodified installed Linux binary: Claude Code `2.1.280`.
- Binary SHA-256: `92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2`.
- A new network namespace contained only loopback. A new mount namespace hid
  existing `~/.claude`, `~/.claudectl`, `~/.config/anthropic`, and `~/.claude.json`
  where present, without reading their contents. `HOME` remained unchanged.
- A temporary hosts file mapped the normal API hostname and known OAuth hosts to
  loopback. A temporary certificate, trusted only by the test child, allowed the
  mock to serve HTTPS at `https://api.anthropic.com`. Thus the normal first-party
  hostname was retained without permitting external network access.
- Every case used a fresh private `CLAUDE_CONFIG_DIR` and working directory, an
  allowlisted environment, no tools/MCP servers/hooks, and disabled updates and
  nonessential traffic. All temporary state was removed after the run.
- Credentials were two deliberately invalid strings, referred to below as A and
  B. Neither was a real token. No refresh token was supplied in any file or
  environment input. Results record generation labels, not authorization headers.
- The access-only file contained `claudeAiOauth.accessToken`, `expiresAt`,
  `scopes: ["user:inference", "user:profile"]`, and synthetic
  `subscriptionType: "max"`. The Max label is supplied fixture data, not evidence
  of a verified subscription. Writes used a 0600 temporary file and atomic rename
  inside a 0700 directory.
- The mock returned a small valid Messages SSE response. It recorded bearer
  generation, OAuth beta presence, API-key-header presence, request status, and
  other endpoint paths. Profile reads returned 404. Identity lookup was therefore
  deliberately outside the success claim.

## Procedure and observations

Each streaming case kept one `claude -p --input-format stream-json
--output-format stream-json` process alive. The first prompt succeeded with A.
For the second prompt the mock accepted B and rejected A with HTTP 401. The
controller either replaced the credential beforehand or atomically published B
immediately before returning that first 401. No restart occurred between prompts.

The inherited-pipe case closed its writer after sending A; it tests the existing
one-time descriptor approach, not an invented reusable pipe protocol. The plain
environment case tests the fixed launch input; a separate settings case tests
rewriting the on-disk `env` setting. Host-file cases used the PID/start-time/expiry
shape observed in this binary, including its managed-host flag and, for OAuth,
`CLAUDE_CODE_HOST_AUTH_ENV_VAR=CLAUDE_CODE_OAUTH_TOKEN`.

`A/200` below means a request using synthetic generation A received HTTP 200.
Successful streaming prompts returned `is_error: false`, `result: "OK"`, and the
same session ID. Error outcomes were checked using `is_error`; this binary still
reported `subtype: "success"` for some authentication errors.

| Case                                                                 | Observed request sequence         | Outcome                                                                              |
| -------------------------------------------------------------------- | --------------------------------- | ------------------------------------------------------------------------------------ |
| File replaced before second prompt                                   | A/200 → B/200                     | Same process and session continued.                                                  |
| File replaced while returning second prompt's first 401              | A/200 → A/401 → B/200             | Retry used B; second prompt succeeded.                                               |
| File A's `expiresAt` elapsed before publishing B                     | A/200 → B/200                     | Same session continued with the successor.                                           |
| File A expired, successor unavailable; publish B before third prompt | A/200 → A/401 → A/401 → B/200     | Second prompt reported authentication failure; third succeeded in the same session.  |
| Credential file removed before second prompt                         | A/200; no second Messages request | `Not logged in`; process remained alive.                                             |
| Credential file malformed before second prompt                       | A/200; no second Messages request | `Not logged in`; process remained alive.                                             |
| Fixed `CLAUDE_CODE_OAUTH_TOKEN`                                      | A/200 → A/401 → A/401             | Retained A; second prompt failed.                                                    |
| One-time OAuth descriptor                                            | A/200 → A/401 → A/401             | Retained A; second prompt failed.                                                    |
| Host credential file supplying OAuth, replaced on 401                | A/200 → A/401 → A/401             | Retained A; second prompt failed.                                                    |
| Host credential file supplying generic bearer, replaced on 401       | A/200 → A/401 → B/200             | Reload worked, but requests lacked the OAuth beta header.                            |
| `apiKeyHelper` output replaced on 401                                | A/200 → A/401 → B/200             | Reload worked, but requests used an API-key header and lacked the OAuth beta header. |
| `settings.json` OAuth `env` value replaced before second prompt      | A/200 → B/200                     | This build reloaded the setting; not a reason to prefer secrets in general settings. |
| Interactive terminal, credential file replaced on 401                | A/200 ×2 → A/401 ×2 → B/200 ×2    | Same terminal process continued and displayed `OK` for the second prompt.            |

All 13 outcomes matched these expectations. Every child was still running when
the controller completed its case. Each streaming case kept one session ID
across its prompts. The terminal case used a single pseudo-terminal process and
displayed an API-retry notice followed by the successful reply. It made multiple
model requests; do not infer one HTTP request per interactive prompt.

The file, environment, descriptor, and OAuth-settings requests included
`anthropic-beta: oauth-2025-04-20` and no API-key header. The file tests observed
only a profile GET outside the Messages requests, with no OAuth-token endpoint
requests. This is stronger evidence of the intended client auth path than the
earlier `auth status` checks, while still proving nothing about real entitlements.

## Design consequences

1. Prefer a dedicated private access-only credential file for continuous sessions.
   Do not also inject an OAuth environment value or descriptor that would override it.
2. The local writer acquires access tokens from the account server and atomically
   replaces the file before expiry. It never receives a refresh token.
3. A server outage can still cause a failed prompt. Preserve the session and allow
   a later retry after credentials arrive; do not promise zero visible auth errors
   or automatically replay work with side effects.
4. Retain the version/hash compatibility boundary. The test does not turn the
   internal credential-file schema into an official external-writer API.
5. Next acceptance work is real Anthropic behavior and macOS file/Keychain
   selection, followed by multiple machines and repeated rotation. This experiment
   did not use real accounts, implement a server, or change product code.

## Reproduce

The following is a throwaway experiment harness, not a product component. It needs
Linux user/network/mount namespaces, Python 3, OpenSSL, `mount`, and the Claude
binary. Save the Python block below to a temporary `probe.py`, then run:

```bash
CLAUDECTL_PROBE_BINARY=/absolute/path/to/claude \
CLAUDECTL_PROBE_PARENT_NET="$(readlink /proc/self/ns/net)" \
CLAUDECTL_PROBE_PARENT_MNT="$(readlink /proc/self/ns/mnt)" \
unshare -Urnm python3 /tmp/probe.py > /tmp/claudectl-reload-results.jsonl
```

The namespace arguments are required: the harness refuses to run without them,
or with any non-loopback network interface. It prints one JSON summary per case.
For a narrower run, append case names such as `file_401 file_tui`. The complete
matrix above was run using the final harness, with the real stores hidden.

<details>
<summary>Complete synthetic experiment harness</summary>

```python
"""Throwaway synthetic-only Claude credential-reload experiment; not product code.

Run under unshare -Urnm so the process has no external network and its own mounts.
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

BINARY = os.environ.get('CLAUDECTL_PROBE_BINARY', '/home/amir/.local/bin/claude')
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
    creds = config / '.credentials.json'
    host = run / 'host.json'
    helper_token = run / 'helper-input'
    env = {
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
            atomic_json(creds, {'claudeAiOauth': {
                'accessToken': token,
                'expiresAt': initial_expiry if case in ['file_expired', 'file_outage'] and token == A
                             else int(time.time() * 1000) + 3600000,
                'scopes': ['user:inference', 'user:profile'], 'subscriptionType': 'max',
            }})
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
    command = [BINARY, '-p', '--input-format', 'stream-json', '--output-format',
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
    creds = config / '.credentials.json'
    def rotate(token):
        atomic_json(creds, {'claudeAiOauth': {'accessToken': token,
                    'expiresAt': int(time.time() * 1000) + 3600000,
                    'scopes': ['user:inference', 'user:profile'], 'subscriptionType': 'max'}})
    rotate(A)
    atomic_json(config / '.claude.json', {'hasCompletedOnboarding': True,
                'lastOnboardingVersion': '2.1.280', 'theme': 'dark',
                'projects': {str(run): {'hasTrustDialogAccepted': True}}})
    state = {'case': 'file_tui', 'turn': 1, 'requests': [], 'other_requests': [],
             'rotate_on_401': True, 'rotated': False, 'rotate': lambda: rotate(B)}
    server.state = state
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': os.environ['HOME'],
           'CLAUDE_CONFIG_DIR': str(config), 'DISABLE_AUTOUPDATER': '1',
           'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1',
           'DISABLE_ERROR_REPORTING': '1', 'DISABLE_GROWTHBOOK': '1',
           'ANTHROPIC_BASE_URL': 'https://api.anthropic.com',
           'NODE_EXTRA_CA_CERTS': str(root / 'cert.pem'),
           'CLAUDE_CODE_MAX_OUTPUT_TOKENS': '128', 'API_TIMEOUT_MS': '8000',
           'TERM': 'xterm-256color', 'COLORTERM': 'truecolor'}
    master, slave = pty.openpty()
    fcntl.ioctl(slave, 0x5414, struct.pack('HHHH', 40, 120, 0, 0))
    command = [BINARY, '--model', 'claude-sonnet-4-6', '--tools', '',
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


def main():
    for kind in ['net', 'mnt']:
        parent_namespace = os.environ.get('CLAUDECTL_PROBE_PARENT_' + kind.upper())
        if not parent_namespace or os.readlink('/proc/self/ns/' + kind) == parent_namespace:
            raise SystemExit('Run with unshare -Urnm: separate network and mount namespaces required')
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise SystemExit('Refusing a network namespace with any non-loopback interface')
    with tempfile.TemporaryDirectory(prefix='claudectl-renewal-isolated-') as scratch:
        root = Path(scratch)
        # Hide real credential stores in this private mount namespace, without reading them.
        for number, relative in enumerate(['.claude', '.claudectl', '.config/anthropic']):
            original = Path(os.environ['HOME']) / relative
            if original.is_dir():
                empty = root / ('empty-store-' + str(number))
                empty.mkdir(mode=0o700)
                subprocess.run(['mount', '--bind', str(empty), str(original)], check=True)
        original_json = Path(os.environ['HOME']) / '.claude.json'
        if original_json.is_file():
            empty_json = root / 'empty-user.json'
            empty_json.write_text('{}')
            subprocess.run(['mount', '--bind', str(empty_json), str(original_json)], check=True)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fcntl.ioctl(sock, 0x8914, struct.pack('16sh', b'lo', 0x1 | 0x40))
        sock.close()
        (root / 'hosts').write_text('127.0.0.1 localhost api.anthropic.com console.anthropic.com platform.claude.com claude.ai\n')
        subprocess.run(['mount', '--bind', str(root / 'hosts'), '/etc/hosts'], check=True)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=api.anthropic.com',
                        '-addext', 'subjectAltName=DNS:api.anthropic.com,DNS:console.anthropic.com,DNS:platform.claude.com,DNS:claude.ai'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 443), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(json.dumps({'binary_sha256': hashlib.sha256(Path(BINARY).read_bytes()).hexdigest(),
                          'network': 'isolated namespace; only loopback; synthetic TLS endpoint'}), flush=True)
        for case in sys.argv[1:] or ['file_proactive', 'file_401', 'env', 'fd', 'host_oauth',
                                   'host_bearer', 'helper', 'settings_env', 'file_expired',
                                   'file_outage', 'file_missing', 'file_malformed', 'file_tui']:
            if case == 'file_tui':
                run_tui_case(root, server)
            else:
                run_case(root, case, server)
        server.shutdown()


if __name__ == '__main__':
    main()
```

</details>
