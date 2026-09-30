# Design: per-process saved-account execution (`claudectl exec`)

Status: accepted with required changes (Architect HQ, 2026-09-30); implemented on branch `amiri/claudectl-account-exec`. Ticket: SAW-11554 (tooling dependency).

## Accepted changes to the first proposal

1. `exec` refuses the active alias and any saved grant shared with the live login. It starts no child and refreshes nothing. It never refreshes any token; a non-active profile is refreshed with `claudectl status <alias>`.
2. `--min-valid` defaults to 30 minutes, which covers a 900 s review. A shorter lifetime is refused; the value is never lowered.
3. Each run gets a fresh private 0700 config dir under `~/.claudectl/run/<alias>/`, removed after the run.
4. The receipt separates `prepared` from `started`. The PID appears only after a successful spawn; a failed spawn writes `spawn_failed`. It names the executable path and SHA-256 and claudectl's path, SHA-256 and version. No `--version` subprocess runs. A failed receipt write before the spawn starts no child; after the spawn it stops the child.
5. Tests compare token bytes in memory and print no credential. The identity lookup is a trait; tests inject a fake through the library only, and the binary always uses the production endpoint.
6. README gains one section. AGENTS.md is unchanged.
7. The fd and config-dir names are hypotheses from the binary until a real-binary smoke run proves them. That run needs Architect HQ admission of the exact non-active alias, accountUuid, pinned binary, command and duration.

## Problem

`claudectl use` changes the global active profile. Every Claude Code process on the machine then uses that account. Some callers need one process to run on a named saved account while all other processes keep the global login. For example, autoreview needs a `--claude-bin` launcher pinned to one account. No claudectl command does this today.

## Goals

- Run one child process on a named saved profile.
- Leave the global login untouched: Keychain entry, `~/.claude/.credentials.json`, `~/.claude.json`, and `~/.claudectl/active`.
- Keep refresh ownership. claudectl never refreshes the active profile's grant, or a saved grant that the live login shares.
- Refuse to run when the profile's identity is missing or does not match.
- Keep concurrent runs on different accounts isolated from each other.
- Never write a credential to stdout, stderr, logs, argv, or the environment.
- Emit a receipt that names the pinned executable and the account identity.

## Non-goals

- No change to `use`, `switch`, `status`, or `login` behavior.
- No automatic refresh of the child's token during its run.
- No Windows support in this change.

## Mechanism

Claude Code 2.1.x reads an OAuth access token from an inherited file descriptor when `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR` is set. `CLAUDE_CONFIG_DIR` also moves its config, and so its stored login, away from `~/.claude`. Both names appear in the shipped binary, 2.1.285. Step 1 of the plan confirms the behavior with a fake-free, non-active test profile.

`claudectl exec` does this:

1. Resolve the alias with `get_profile_from`, then read the saved credentials.
2. Take `lock_auth_state` only for the token step:
   - If the profile is not active, does not share the live grant, and its token expires within `--min-valid` (default 30 minutes), refresh it with the same rules as `status`. Then persist the rotated grant with `persist_rotated_grant`.
   - If the profile is active or shares the live grant, never refresh. If its token expires within `--min-valid`, exit with an error.
   - Release the lock before the child starts.
3. Identity check, fail closed:
   - Call `fetch_oauth_account` with the token.
   - The returned `accountUuid` must equal `account.json`'s `account_uuid`, and `--expect-account <uuid>` when that flag is given.
   - On any mismatch, missing field, or HTTP failure, exit 3 and start no child.
4. Executable pin:
   - Resolve the child program to its real path and hash it with SHA-256.
   - If `--expect-sha256` is given and does not match, exit 4.
5. Start the child:
   - Write the access token into a pipe. The child inherits the read end as fd N.
   - Set `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=N` and `CLAUDE_CONFIG_DIR=~/.claudectl/run/<alias>/config`, a private directory with mode 0700.
   - Remove `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` from the child's environment, so no other credential can win.
   - Forward stdin, stdout and stderr. Exit with the child's exit code.
6. Receipt:
   - Before the child starts, write one JSON line to `--receipt <path>`, or to stderr when no path is given.
   - It holds `alias`, `account_uuid`, `email`, `executable`, `sha256`, `claude_version` (from `--version` when the program is Claude), `token_expires_at`, `refreshed`, `config_dir`, `pid` and `started_at`.
   - It never holds a token.

`claudectl launcher --profile <alias> --claude <path> --out <file>` writes a two-line executable script for `--claude-bin`. The script calls `claudectl exec --profile <alias> --expect-account <uuid> --expect-sha256 <sha> -- <path> "$@"`. The account and hash are pinned when the script is written, so a later profile or binary change fails closed.

## Config directory

The child uses a per-alias `CLAUDE_CONFIG_DIR` so it neither reads nor writes the global `~/.claude.json` identity or the global Keychain login. The directory starts empty. `--inherit-settings` symlinks `settings.json`, `CLAUDE.md`, `agents/`, `commands/` and `skills/` from `~/.claude` into it; the default is off. Step 1 must confirm that a fresh config dir with an fd token runs `claude -p` without an onboarding prompt.

## Concurrency

- Runs on different aliases share no writable state: each has its own config dir and pipe.
- Two runs on the same alias share the config dir, the way two terminals share `~/.claude`.
- The auth lock covers only refresh and persist. Refresh follows `status`: one refresh per grant.

## Tests

- **Fake Claude:** a test binary reads fd N and prints `sha256(token)`, its config dir, and whether the forbidden env vars are set. Assert the right token hash, the right dir, no token in env or argv, and exit-code pass-through.
- **Identity:** a local HTTP fake behind a URL override. Assert that a mismatched `accountUuid`, a missing field and HTTP 500 each exit 3 with no child started, and that the receipt has no token.
- **Refresh ownership:** reuse the `status` fixtures. The active alias and a shared live grant never refresh; a near-expiry active token exits with an error.
- **Concurrency:** start two runs on two aliases together, and assert each child sees only its own token hash and config dir.
- **Global state:** snapshot the Keychain stub, `.credentials.json`, `.claude.json` and `active` before and after `exec`, and assert they are unchanged.

## Plan

1. Verify the mechanism on the real binary with a non-active saved profile after this design is accepted: the fd token, a fresh config dir, and the global login unchanged.
2. Add `exec` and `launcher` with URL overrides for tests.
3. Add the tests above.
4. Update the README and AGENTS.md map.
5. Review, CI, then a release through the existing tap.

## Open questions

- Should `exec` refuse the active alias entirely? Plain `claude` already covers it. The current proposal allows it with no refresh.
- Is `--min-valid` of 30 minutes right for autoreview runs?
