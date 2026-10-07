"""Synthetic Keychain command-boundary experiment, never a real Keychain read.

Run beside mac-settings-base.py. No product code or live login.
"""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('base', Path(__file__).with_name('mac-settings-base.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

K = 'synthetic-invalid-keychain-k'
original_popen = subprocess.Popen
original_case = base.run_case
original_post = base.Handler.do_POST
active = None

STUB = r'''#!PYTHON
import json, os, sys, time
from pathlib import Path
config = Path(os.environ['CLAUDE_CONFIG_DIR'])
run = config.parent
fixture = json.loads((run / 'keychain-fixture.json').read_text())
args = sys.argv[1:]
operation = args[0] if args else 'none'
service = args[args.index('-s') + 1] if '-s' in args else ''
credential = '-credentials' in service
selected = credential and (fixture['scope'] == 'scoped' or service == 'Claude Code-credentials')
if fixture['scope'] == 'late':
    try:
        selected = credential and json.loads((config / 'settings.json').read_text())['env']['CLAUDE_CODE_OAUTH_TOKEN'] == 'synthetic-invalid-generation-b'
    except (OSError, ValueError, KeyError):
        selected = False
record = {'operation': operation, 'service': service,
          'returned': 'K' if operation == 'find-generic-password' and selected else 'absent'}
fd = os.open(run / 'keychain-calls.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, (json.dumps(record) + '\n').encode())
os.close(fd)
if operation == 'find-generic-password' and selected:
    print(json.dumps({'claudeAiOauth': {'accessToken': 'synthetic-invalid-keychain-k',
          'refreshToken': 'synthetic-invalid-keychain-refresh',
          'expiresAt': int(time.time() * 1000) - 3600000,
          'scopes': ['user:inference', 'user:profile'], 'subscriptionType': 'max'}}))
    sys.exit(0)
if operation == 'show-keychain-info':
    sys.exit(0)
# No delegation to real security, and no synthetic mutation support.
sys.exit(44 if operation == 'find-generic-password' else 1)
'''


def intercepted_popen(command, *args, **kwargs):
    if isinstance(command, list) and base.BINARY in command:
        env = kwargs['env']
        config = Path(env['CLAUDE_CONFIG_DIR'])
        run = config.parent
        root = run.parent
        stub_dir = root / 'synthetic-bin'
        stub_dir.mkdir(mode=0o700, exist_ok=True)
        stub = stub_dir / 'security'
        stub.write_text(STUB.replace('#!PYTHON', '#!' + sys.executable, 1))
        stub.chmod(0o700)
        base.atomic_json(run / 'keychain-fixture.json', {'scope': active['scope']})
        if active.get('no_file'):
            (config / '.credentials.json').unlink()
        # Block the real command as well as the original securityd/file denies.
        profile = root / 'sandbox.sb'
        text = profile.read_text()
        extra = '(deny process-exec (literal "/usr/bin/security"))\n'
        if extra not in text:
            profile.write_text(text + extra)
        env['PATH'] = str(stub_dir) + ':' + env['PATH']
        env['CLAUDE_CODE_OAUTH_TOKEN'] = 'claudectl-unavailable-access-token'
        if active.get('securestorage_override'):
            env['CLAUDE_SECURESTORAGE_CONFIG_DIR'] = ''
        checked = subprocess.run(['/usr/bin/sandbox-exec', '-f', str(profile),
                                  '/usr/bin/security', 'help'],
                                 capture_output=True, timeout=5)
        if checked.returncode == 0:
            raise RuntimeError('Real security command was not blocked')
    return original_popen(command, *args, **kwargs)


def labelled_post(self):
    keychain = self.headers.get('Authorization') == 'Bearer ' + K
    original_post(self)
    # Base mock treats unknown generations as invalid on turn 2; retain this
    # behavior, but distinguish our synthetic Keychain value in the evidence.
    if keychain:
        for request in self.server.state['requests']:
            if request['generation'] == 'none':
                request['generation'] = 'K'


CASES = [
    {'name': 'proactive', 'scope': 'scoped', 'base': 'file_proactive'},
    {'name': 'retry_401', 'scope': 'scoped', 'base': 'file_401'},
    {'name': 'expired', 'scope': 'scoped', 'base': 'file_expired'},
    {'name': 'outage', 'scope': 'scoped', 'base': 'file_outage'},
    {'name': 'missing', 'scope': 'scoped', 'base': 'file_missing'},
    {'name': 'malformed', 'scope': 'scoped', 'base': 'file_malformed'},
    {'name': 'late', 'scope': 'late', 'base': 'file_proactive'},
    {'name': 'terminal', 'scope': 'scoped', 'base': 'file_tui'},
]



def run_cases(root, ignored_case, server):
    global active
    for fixture in CASES:
        active = fixture
        case_root = root / fixture['name']
        case_root.mkdir(mode=0o700)
        # The base case expects sandbox.sb and certificate under its root.
        for filename in ['sandbox.sb', 'cert.pem']:
            (case_root / filename).write_bytes((root / filename).read_bytes())
        print(json.dumps({'fixture': fixture['name'], 'scope': fixture['scope']}), flush=True)
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            if fixture['base'] == 'file_tui':
                base.run_tui_case(case_root, server)
            else:
                original_case(case_root, fixture['base'], server)
        result = json.loads(captured.getvalue())
        print(json.dumps(result), flush=True)
        run = case_root / ('tui' if fixture['base'] == 'file_tui' else fixture['base'])
        calls = [json.loads(line) for line in (run / 'keychain-calls.jsonl').read_text().splitlines()] if (run / 'keychain-calls.jsonl').exists() else []
        summary = {'fixture': fixture['name'], 'keychain_calls': calls,
                   'real_security_execution': 'denied'}
        print(json.dumps(summary), flush=True)
        if any(c['operation'] not in ['find-generic-password', 'show-keychain-info'] for c in calls):
            raise RuntimeError('Unexpected Keychain mutation attempted')
        if not result['same_process_alive_after_turns'] or result.get('stderr'):
            raise RuntimeError('Child exit or stderr')
        if any(r['generation'] not in ['A', 'B'] or not r['oauth_beta'] or r['api_key_header'] for r in result['requests']):
            raise RuntimeError('Credential source switched')
        if any(method == 'POST' for method, path in result['other_requests']):
            raise RuntimeError('Unexpected refresh attempt')
        print(json.dumps({'fixture': fixture['name'], 'sequences': [(r['generation'], r['status']) for r in result['requests']]}), flush=True)
        sequence = [(r['generation'], r['status']) for r in result['requests']]
        expected = {
            'proactive': [('A', 200), ('B', 200)],
            'expired': [('A', 200), ('B', 200)],
            'late': [('A', 200), ('B', 200)],
            'missing': [('A', 200), ('A', 401), ('A', 401)],
            'malformed': [('A', 200), ('A', 401), ('A', 401)],
            'outage': [('A', 200), ('A', 401), ('A', 401), ('B', 200)],
        }
        if fixture['name'] in expected:
            assert sequence == expected[fixture['name']], result
        else:
            assert sequence[0] == ('A', 200) and sequence[-1] == ('B', 200), result
        print(json.dumps({'fixture': fixture['name'], 'checks': 'passed'}), flush=True)


if __name__ == '__main__':
    subprocess.Popen = intercepted_popen
    base.Handler.do_POST = labelled_post
    base.run_case = run_cases
    sys.argv = [sys.argv[0], 'file_proactive']
    base.main()
