"""SAW-12555 experiment: a server token through a --settings file over the HOST config dir.

Synthetic only. Run like linux.py, under `unshare -Urnm`, from experiments/settings-renewal.
The config dir stands in for the real ~/.claude: it holds a host login (.credentials.json with
token H and a refresh token) and the host identity in .claude.json. The server token travels
only in a separate settings file passed with --settings. Checks per case: the host token is
never sent, no refresh or other POST goes out, and the host credentials file and identity are
byte-identical afterwards.
"""
import hashlib
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import linux  # noqa: E402  (shared isolation, fake TLS provider and helpers)

A, B = linux.A, linux.B
H = 'synthetic-host-login-generation-h'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_config(run):
    config = run / 'host-config'
    config.mkdir(mode=0o700)
    linux.atomic_json(config / '.credentials.json', {'claudeAiOauth': {
        'accessToken': H, 'refreshToken': 'synthetic-host-refresh',
        'expiresAt': int(time.time() * 1000) + 3600000,
        'scopes': ['user:inference', 'user:profile']}})
    linux.atomic_json(config / '.claude.json', {
        'oauthAccount': {'accountUuid': 'host-account', 'organizationUuid': 'host-org',
                         'emailAddress': 'host@example.invalid'},
        'hasCompletedOnboarding': True,
        'projects': {str(run): {'hasTrustDialogAccepted': True}}})
    linux.atomic_json(config / 'settings.json', {'alwaysThinkingEnabled': False})
    return config


def launch(run, config, flag_file, case, resume=None):
    env = {
        'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': os.environ['HOME'],
        'CLAUDE_CONFIG_DIR': str(config), 'DISABLE_AUTOUPDATER': '1',
        'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC': '1', 'DISABLE_TELEMETRY': '1',
        'DISABLE_ERROR_REPORTING': '1', 'DISABLE_GROWTHBOOK': '1',
        'ANTHROPIC_BASE_URL': 'https://api.anthropic.com',
        'NODE_EXTRA_CA_CERTS': str(run.parent / 'cert.pem'),
        'CLAUDE_CODE_MAX_OUTPUT_TOKENS': '128', 'API_TIMEOUT_MS': '8000',
    }
    command = [linux.BINARY, '-p', '--input-format', 'stream-json', '--output-format',
               'stream-json', '--verbose', '--model', 'claude-sonnet-4-6', '--tools', '',
               '--strict-mcp-config']
    if case == 'env_only':
        env['CLAUDE_CODE_OAUTH_TOKEN'] = A
    elif case.startswith('hostfile'):
        # Host-managed credentials: a private per-process file the wrapper rewrites.
        env['CLAUDE_CODE_HOST_CREDS_FILE'] = str(flag_file)
        env['CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST'] = '1'
        env['CLAUDE_CODE_HOST_AUTH_ENV_VAR'] = 'CLAUDE_CODE_OAUTH_TOKEN'
    else:
        # The process value is a fixed invalid fallback; the flag file must outrank it.
        env['CLAUDE_CODE_OAUTH_TOKEN'] = 'claudectl-unavailable-access-token'
        command += ['--settings', str(flag_file)]
    if resume:
        command += ['--resume', resume]
    return subprocess.Popen(command, env=env, cwd=run, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            start_new_session=True)


def turns(p, server, numbers, before_turn):
    out = queue.Queue()
    threading.Thread(target=lambda: [out.put(l) for l in p.stdout] + [out.put(None)],
                     daemon=True).start()
    threading.Thread(target=lambda: [None for _ in p.stderr], daemon=True).start()
    results = []
    for turn in numbers:
        server.state['turn'] = turn
        before_turn(turn)
        p.stdin.write(json.dumps({'type': 'user', 'message': {
            'role': 'user', 'content': 'Reply OK only. Turn ' + str(turn)}}) + '\n')
        p.stdin.flush()
        deadline = time.monotonic() + 25
        result = {'turn': turn, 'timeout': True}
        while time.monotonic() < deadline:
            try:
                line = out.get(timeout=max(0.1, deadline - time.monotonic()))
            except queue.Empty:
                break
            if line is None:
                result = {'turn': turn, 'eof': True}
                break
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if event.get('type') == 'result':
                result = {'turn': turn, 'is_error': event.get('is_error'),
                          'session_id': event.get('session_id')}
                break
        results.append(result)
        if result.get('timeout') or result.get('eof'):
            break
    if p.poll() is None:
        os.killpg(p.pid, signal.SIGTERM)
    p.wait(timeout=5)
    return results


def run_case(root, case, server):
    run = root / case
    run.mkdir(mode=0o700)
    config = host_config(run)
    flag_file = run / 'claudectl-token-settings.json'

    def write(token):
        value = {'env': {'CLAUDE_CODE_OAUTH_TOKEN': token}}
        if case.startswith('hostfile'):
            value.update(pid=os.getpid(), procStart=linux.process_start(),
                         expiresAt=int(time.time() * 1000) + 3600000)
        linux.atomic_json(flag_file, value)

    write(A)
    before = {'credentials': sha(config / '.credentials.json'),
              'identity': json.loads((config / '.claude.json').read_text())['oauthAccount']}
    rotate = lambda: write(B)
    server.state = {'case': case, 'turn': 1, 'requests': [], 'other_requests': [],
                    'rotate_on_401': case in ('flag_401', 'hostfile_401'), 'rotate': rotate, 'rotated': False}

    def before_turn(turn):
        if turn == 2 and case in ('flag_proactive', 'hostfile_proactive'):
            rotate()
            time.sleep(1.1)

    p = launch(run, config, flag_file, case)
    results = turns(p, server, [1, 2], before_turn)
    session = next((r.get('session_id') for r in results if r.get('session_id')), None)
    resumed = None
    if case == 'flag_proactive' and session:
        # A new process resumes the same session from the host config, with the B token.
        server.state.update(turn=2)
        p = launch(run, config, flag_file, case, resume=session)
        resumed = turns(p, server, [3], lambda turn: None)
    state = server.state
    summary = {'case': case, 'results': results, 'resumed': resumed,
               'sequence': [(r['generation'], r['status']) for r in state['requests']],
               'other_requests': state['other_requests'],
               'host_token_sent': any(r['generation'] == 'none' for r in state['requests']),
               'credentials_unchanged': sha(config / '.credentials.json') == before['credentials'],
               'identity_unchanged': json.loads((config / '.claude.json').read_text())
               .get('oauthAccount') == before['identity']}
    print(json.dumps(summary), flush=True)
    assert summary['credentials_unchanged'] and summary['identity_unchanged'], summary
    assert not any(m == 'POST' for m, _ in summary['other_requests']), summary
    assert not summary['host_token_sent'], summary
    expected = {'flag_proactive': ('A', 'B'), 'flag_401': ('A', 'B'), 'env_only': ('A', 'A'),
                'hostfile_proactive': ('A', 'B'), 'hostfile_401': ('A', 'B')}
    first, last = summary['sequence'][0], summary['sequence'][-1]
    assert first == (expected[case][0], 200), summary
    in_process = [x for x in summary['sequence']][:len(state['requests'])]
    renewed_in_process = any(g == 'B' and st == 200 for g, st in summary['sequence']
                             if not resumed) or (resumed is not None and results[-1].get('is_error') is False)
    print(json.dumps({'case': case, 'safety_checks': 'passed',
                      'turn2_in_same_process_ok': results[-1].get('is_error') is False,
                      'resume_new_process_ok': None if resumed is None else
                      (not resumed[-1].get('is_error') and resumed[-1].get('session_id') == session)}),
          flush=True)


if __name__ == '__main__':
    linux.run_case = run_case
    sys.argv = sys.argv[:1] + (sys.argv[1:] or ['flag_proactive', 'flag_401', 'env_only',
                                                'hostfile_proactive', 'hostfile_401'])
    linux.main()
