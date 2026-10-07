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

Claude Code 2.1.x reads an OAuth access token from an inherited file descriptor when `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR` is set. `CLAUDE_CONFIG_DIR` also moves its config, and so its stored login, away from `~/.claude`. Both names appear in the shipped binary, 2.1.285. A real-binary smoke run confirms them only after admission (accepted change 7).

`claudectl exec --profile <alias> [--expect-account <uuid>] [--expect-sha256 <sha>] [--min-valid 30m] [--receipt <file>] -- <program> [args]` does this:

1. Prepare, under the auth lock:
   - Refuse the active alias, compared by directory identity.
   - Refuse a saved grant that the live login or the active profile's saved credentials share. If either is unreadable, refuse.
   - Refuse the live login's account: the active profile's account plus the `accountUuid` in `~/.claude.json`. If live credentials exist but that uuid is missing, refuse.
   - Refuse a token that has expired or expires within `--min-valid`. `exec` never refreshes any token.
2. Identity check, fail closed:
   - Look up the account of the profile's token. The result must equal the saved `accountUuid`, and `--expect-account` when given. Otherwise exit 3.
   - Look up the account of the live login's token. If it is the profile's account, or the lookup fails, refuse (exit 5).
3. Executable pin:
   - Resolve the program on `PATH` to its real path and hash it with SHA-256. If `--expect-sha256` does not match, exit 4.
   - Copy the program into the run's private directory, hash the copy again, and run the copy with `argv[0]` set to the original path.
   - Bind claudectl's own path and SHA-256 to the running image: `/proc/self/exe` on Linux, image device, inode and build UUID on macOS.
4. Start the child:
   - Create a fresh private 0700 config directory under `~/.claudectl/run/<alias>/`.
   - Write the access token into a pipe. The parent keeps close-on-exec on it; only the child's pre-exec step maps it to fd 3. Set `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR=3` and `CLAUDE_CONFIG_DIR`.
   - Remove from the child's environment every `ANTHROPIC_*` and `CLAUDE_CODE_*` variable that selects a provider (`CLAUDE_CODE_USE_*`) or ends in `_API_KEY`, `_TOKEN`, `_FILE_DESCRIPTOR`, `_BASE_URL`, `_HOST`, `_HEADERS` or `_HELPER`. Name rules, not a fixed list, so a new variable with the same shape is covered.
   - Refuse when a project, local or managed settings file in the working directory or a parent (not `~/.claude` below home, which is user scope) sets such a variable in `env`, sets a credential helper (`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`), or cannot be parsed. The private config dir removes user settings only.
   - Under the auth lock, check ownership and the settings files again, and check that the live token did not change since step 2. Then spawn.
5. Run and tear down:
   - The child leads its own process group. `SIGTERM`, `SIGINT` and `SIGHUP` reach the group once. A signal inherited as ignored stays ignored, and the child inherits that.
   - When the child exits, claudectl waits without reaping it, sends `SIGTERM` and then `SIGKILL` to descendants left in the group, then reaps it and removes the config directory.
   - Exit with the child's exit code, or 8 when cleanup fails.
6. Receipt:
   - JSON lines go to `--receipt <file>`, or to stderr.
   - `prepared` comes before the spawn; `started` names the PID; `exited` names the exit code, signal and descendant teardown. Failures write `refused`, `spawn_failed` or `cleanup_failed`.
   - Each record names the alias, account, email, executable path and SHA-256, the executed snapshot, the token expiry, the config directory, and claudectl's path, SHA-256 and version. It never holds a token.

`claudectl launcher --profile <alias> --claude <path> --out <file>` writes a script for `--claude-bin`. It pins the alias, the account, the executable's SHA-256 and `--min-valid`. It keeps a private 0500 copy of claudectl in `<file>.claudectl/`, checks that copy's SHA-256, and runs it. A later profile, binary or claudectl change fails closed.

## Config directory

Each run gets a new private directory, so the child neither reads nor writes the global `~/.claude.json` identity or the global Keychain login. Nothing is linked into it, and only one file is copied in: a `.claude.json` built from an allowlist, so that the child starts at its prompt (SAW-12468).

- Top-level keys: `hasCompletedOnboarding` and `lastOnboardingVersion`.
- Folder trust: the closest directory, from the current directory up, with `hasTrustDialogAccepted: true`, copied under its own key. Claude Code 2.1.292 trusts a directory under any trusted ancestor, also when a nearer entry is `false`, and it writes `false` entries on its own for directories it opens (checked live). The seed grants the same trust the user's Claude grants, no more.
- For the current directory only: `hasClaudeMdExternalIncludesApproved` and `hasClaudeMdExternalIncludesWarningShown`, copied only when true.
- Claude rewrites `~/.claude.json` while it runs, so a parse error gets one retry, then a warning on stderr and no seed. A malformed file is refused earlier, by the live identity check.
- Never copied: `oauthAccount` and any other identity, tokens, approved API keys, allowed tools, MCP servers, other projects, and settings files.
- Without a readable `~/.claude.json`, nothing is copied and Claude shows its first-run screens.

## Concurrency

- Each run has its own config directory and pipe, so runs share no writable state, also on the same alias.
- The auth lock covers the ownership checks and the spawn. It is not held while the child runs.
- One process runs one `exec` at a time; an overlapping run in the same process is refused.

## Tests

- **Fake child:** a script reads fd 3 and records the token, its config directory, leaked environment names and extra pipe descriptors. Tests compare token bytes in memory and print no credential.
- **Identity:** a fake identity source through the library. Mismatched, missing and failed lookups exit 3 with no child; the live login's account is refused.
- **Refresh ownership:** the active alias, a shared grant, the live login's account and a near-expiry token are refused, and nothing is refreshed.
- **Concurrency:** two helper processes run two aliases together and each sees only its own token and directory.
- **Global state:** the Keychain stub, `.credentials.json`, `.claude.json` and `active` are unchanged after a run.
- **Settings:** project, local, parent-directory and managed settings that set a credential, provider, endpoint or helper are refused, and an unparsable file fails closed. A helper process started in such a project starts no child.
- **Signals and teardown:** forwarding once per signal, signals that arrive before the child registers, an inherited ignored `SIGCHLD` and `SIGHUP`, and descendant teardown.

## Plan

1. Implement `exec` and `launcher` with the tests above. Done on the branch.
2. Review, CI, then a release through the existing tap.
3. Run the real-binary smoke run after admission (accepted change 7).
