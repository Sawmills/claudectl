# macOS Keychain credential-selection experiment

2026-10-03. Follow-up to the [Mac reload experiment](2026-10-03-claudectl-macos-credential-reload-experiment.md).
Question: can a Keychain credential override a private access-only credential file?

## Result

**Yes.** In unmodified macOS Claude Code 2.1.288, a synthetic response from the
Keychain lookup for the selected config overrides `.credentials.json`. Replacing
the file before a request or during a simulated 401 does not override that Keychain
response. A matching entry appearing after launch also takes over the session.

Without a storage override, each private config requested service names shaped
like `Claude Code-credentials-<suffix>` and `Claude Code-<suffix>`. The suffix
differed across fresh configs. It did not request the ordinary
`Claude Code-credentials` service, even when the private file went missing or
became malformed. However, setting `CLAUDE_SECURESTORAGE_CONFIG_DIR` to the empty
string caused the private-config child to request the ordinary service and use
its synthetic credential. Treat that setting as a credential-source override.

All ten expected outcomes passed the harness checks. This establishes selection
at the `security` command boundary. It does **not** establish native Keychain ACL,
unlock, or unsandboxed behavior: every response was a fixture, and real Keychain
access remained blocked. No real account or token was used.

## Method and protection

- Same Mac mini, macOS 27.0/arm64, and unmodified Claude Code 2.1.288 as the prior
  experiment. Binary SHA-256:
  `bbe93063f7a0879a1021b2891e5c9354e5b3b98433e32efe6750f7710afed750`.
- The companion harness imports the previously published Mac harness, preserving
  its loopback-only sandbox, local synthetic TLS proxy, isolated config, real
  credential-file denials, and securityd/Keychain-file denials. `HOME` is unchanged.
- The installed binary's readable code identified lookup through `security` on
  `PATH`, and the storage override. Those observations guided the experiment;
  recorded child-process requests, rather than strings alone, establish selection.
- A fixture-only executable named `security` is prepended to the Claude child's
  `PATH`. It returns synthetic OAuth JSON or item-not-found (44); it never delegates
  to the real command. The sandbox additionally denies execution of
  `/usr/bin/security`, and the harness checks that denial before every child starts.
- The global fixture returns K only for the exact ordinary OAuth service name.
  The scoped fixture returns K for the requested OAuth service in the private
  namespace. API-key lookups return absent. The late fixture returns absent until
  the controller publishes file generation B, then returns K. Thus late appearance
  is a controlled input at the command boundary, not an actual Keychain mutation.
- Only operation, service name, and synthetic result label are logged for lookups.
  No account-name argument or credential output is retained in lookup evidence.
  Mutations are refused and cause the controller to fail if attempted. No Keychain
  password, login flow, native Keychain item, or system setting is involved.
- A/B are file generations and K is a different, deliberately invalid Keychain
  value. No fixture contains a refresh token. The endpoint accepts any generation
  for turn 1 and accepts only B for turn 2; K's first success demonstrates selection,
  not real entitlement or identity.
- Each streaming case uses two prompts in one process/session. Fixture directories,
  certificates, and children are cleaned by the base harness. Remote copies of the
  harness were removed after the run. The final run had no fixture or child stderr.

## Observed outcomes

| Fixture                                          | Messages sequence        | Meaning                                                          |
| ------------------------------------------------ | ------------------------ | ---------------------------------------------------------------- |
| Ordinary OAuth item only; private file replaced  | A/200 → B/200            | Private namespace did not select the ordinary item.              |
| Ordinary item only; private file removed         | A/200; no second request | Failed with `Not logged in`; no ordinary-item fallback.          |
| Ordinary item only; private file malformed       | A/200; no second request | Failed with `Not logged in`; no ordinary-item fallback.          |
| Matching item; private file replaced             | K/200 → K/401 → K/401    | Keychain response won over both file generations.                |
| Matching item; private file removed              | K/200 → K/401 → K/401    | File removal did not remove the selected credential.             |
| Matching item; private file malformed            | K/200 → K/401 → K/401    | File corruption did not prevent Keychain selection.              |
| Matching item; file replaced during 401          | K/200 → K/401 → K/401    | Retry retained K even after B was published.                     |
| Matching item; file initially absent, then B     | K/200 → K/401 → K/401    | Positive control: fixture alone supplied authentication.         |
| Matching item appears after first prompt         | A/200 → K/401 → K/401    | Startup absence did not prevent later source switching.          |
| Ordinary item plus empty secure-storage override | K/200 → K/401 → K/401    | Private config did not isolate the overridden storage namespace. |

Every Messages request carried the OAuth beta header and no API-key header.
No OAuth exchange or other non-Messages POST was observed. All children remained
alive and returned both results with unchanged session IDs. Global service names
were requested only in the explicit override case. All observed Keychain operations
were reads; no write/delete attempt was recorded.

These are **expected test outcomes, including deliberately failed prompts**.
They do not mean the proposed production launcher has passed isolation acceptance.
The earlier missing/malformed-file result was conditional on Keychain being blocked.

## Design consequence and remaining checks

The [account-server design](2026-10-02-claudectl-central-design.md) must not claim
that an access-only file always wins on macOS. Prefer a fresh private namespace,
reject storage/credential overrides from both environment and settings, and verify
isolation for the whole session. A startup-only presence check cannot prevent
late Keychain selection. Session identity must remain pinned to the chosen server
account. Do not overwrite or delete an unrelated Keychain item to fix a conflict.

The [implementation plan](../plans/2026-10-03-claudectl-central-implementation.md)
therefore starts with a macOS isolation milestone. The research sandbox already
demonstrates continuous file reload with Keychain denied, but a production boundary
must preserve required tool behavior and normal network access. The fake `security`
executable is test instrumentation, not a proposed production workaround.

Still unproved: actual Keychain ACL/unlock behavior; the final launcher's refusal
of settings-based overrides; tool behavior under production isolation; terminal
behavior with conflicting Keychain responses; other Claude versions; and real
Anthropic identity, entitlement, expiry, refresh, and multi-machine operation.
An account-server implementation and explicit admission of a dedicated live account
are required for the later live pilot. No product code changed in this experiment.

## Reproduce

Save the Python block from the [previous Mac report](2026-10-03-claudectl-macos-credential-reload-experiment.md)
as `mac-probe.py`, and this report's block as `mac-keychain-probe.py` beside it.
Use Python 3, Homebrew OpenSSL, `sandbox-exec`, and the explicit Claude binary path:

```bash
CLAUDECTL_PROBE_BINARY=/absolute/path/to/claude \
/opt/homebrew/bin/python3 /tmp/mac-keychain-probe.py > /tmp/keychain-results.jsonl
```

The companion monkey-patches only its own imported test harness and subprocess
environment; it does not modify the Claude binary, shell profile, or system PATH.
The global override case remains safe because the fixture intercepts lookup while
native Keychain and real credential paths stay denied. Keep those restrictions.
Ten `"checks": "passed"` records and a zero exit status constitute the recorded
matrix result. The base report documents the local TLS/mock response limitations.

<details>
<summary>Complete companion harness</summary>

```python
"""Synthetic Keychain command-boundary experiment, never a real Keychain read.

Run beside the previously published mac-probe.py. No product code or live login.
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

spec = importlib.util.spec_from_file_location('base', Path(__file__).with_name('mac-probe.py'))
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
        selected = credential and json.loads((config / '.credentials.json').read_text())['claudeAiOauth']['accessToken'] == 'synthetic-invalid-generation-b'
    except (OSError, ValueError, KeyError):
        selected = False
record = {'operation': operation, 'service': service,
          'returned': 'K' if operation == 'find-generic-password' and selected else 'absent'}
fd = os.open(run / 'keychain-calls.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
os.write(fd, (json.dumps(record) + '\n').encode())
os.close(fd)
if operation == 'find-generic-password' and selected:
    print(json.dumps({'claudeAiOauth': {'accessToken': 'synthetic-invalid-keychain-k',
          'expiresAt': int(time.time() * 1000) + 3600000,
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
    {'name': 'global_item', 'scope': 'global', 'base': 'file_proactive'},
    {'name': 'global_missing', 'scope': 'global', 'base': 'file_missing'},
    {'name': 'global_malformed', 'scope': 'global', 'base': 'file_malformed'},
    {'name': 'scoped_conflict', 'scope': 'scoped', 'base': 'file_proactive'},
    {'name': 'scoped_missing', 'scope': 'scoped', 'base': 'file_missing'},
    {'name': 'scoped_malformed', 'scope': 'scoped', 'base': 'file_malformed'},
    {'name': 'scoped_401', 'scope': 'scoped', 'base': 'file_401'},
    {'name': 'scoped_only', 'scope': 'scoped', 'base': 'file_proactive', 'no_file': True},
    {'name': 'scoped_late', 'scope': 'late', 'base': 'file_proactive'},
    {'name': 'global_override', 'scope': 'global', 'base': 'file_proactive', 'securestorage_override': True},
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
            original_case(case_root, fixture['base'], server)
        result = json.loads(captured.getvalue())
        print(json.dumps(result), flush=True)
        run = case_root / fixture['base']
        calls = [json.loads(line) for line in (run / 'keychain-calls.jsonl').read_text().splitlines()]
        summary = {'fixture': fixture['name'], 'keychain_calls': calls,
                   'real_security_execution': 'denied'}
        print(json.dumps(summary), flush=True)
        if not any(c['operation'] == 'find-generic-password' for c in calls):
            raise RuntimeError('No Keychain lookup intercepted')
        if any(c['operation'] not in ['find-generic-password', 'show-keychain-info'] for c in calls):
            raise RuntimeError('Unexpected Keychain mutation attempted')
        if not result['same_process_alive_after_turns'] or result['stderr']:
            raise RuntimeError('Unexpected child exit or stderr')
        if len(result['results']) != 2 or len({r.get('session_id') for r in result['results']}) != 1:
            raise RuntimeError('Session continuity failed')
        if any(not r['oauth_beta'] or r['api_key_header'] for r in result['requests']):
            raise RuntimeError('Unexpected authentication headers')
        if any(method == 'POST' for method, path in result['other_requests']):
            raise RuntimeError('Unexpected non-Messages POST')
        global_lookup = any(c['service'] in ['Claude Code', 'Claude Code-credentials'] for c in calls)
        if global_lookup != bool(fixture.get('securestorage_override')):
            raise RuntimeError('Unexpected Keychain namespace')
        requests = [(r['generation'], r['status']) for r in result['requests']]
        if fixture.get('securestorage_override'):
            expected = [('K', 200), ('K', 401), ('K', 401)]
        elif fixture['scope'] == 'global':
            expected = [('A', 200), ('B', 200)] if fixture['base'] == 'file_proactive' else [('A', 200)]
        elif fixture['scope'] == 'scoped':
            expected = [('K', 200), ('K', 401), ('K', 401)]
        else:
            expected = [('A', 200), ('K', 401), ('K', 401)]
        if requests != expected:
            raise RuntimeError('Unexpected credential selection: ' + repr(requests))
        print(json.dumps({'fixture': fixture['name'], 'checks': 'passed'}), flush=True)


if __name__ == '__main__':
    subprocess.Popen = intercepted_popen
    base.Handler.do_POST = labelled_post
    base.run_case = run_cases
    sys.argv = [sys.argv[0], 'file_proactive']
    base.main()
```

</details>
