# Claude accounts on a company account server

Implementation preview; do not deploy real refresh grants until the remaining
pilot checks below pass. The design research is in
[the central design](superpowers/specs/2026-10-02-claudectl-central-design.md).

A company server holds Claude refresh credentials. Each enrolled machine receives
only access tokens. Claude-only users install `claudectl` and Claude Code; they do
not need Codex or an OpenAI account. The server is the `claudectl-server` binary in
this repository, built with `--features server`. It serves only the company emails
given with `--allow-user`; the staging deployment allows one person.

## Commands

```sh
claudectl server connect https://accounts.example.com --name laptop
claudectl server accounts
claudectl server login work
claudectl server run work --claude /absolute/path/to/claude
claudectl server run work -- --resume SESSION_ID
claudectl server status work
claudectl server status work --cached
claudectl server qualify --claude /absolute/path/to/claude
claudectl server devices
claudectl server migrate --all --exclusive-owner
claudectl server migrate --abort work
claudectl server revoke MACHINE_ID
claudectl server remove work
claudectl server disconnect
```

`accounts`, `status` and `devices` print tables; add `--json` for the raw JSON.
`claudectl status` (without `server`) shows local and server accounts in one table.

`connect` opens company SSO; `--no-browser` prints the URL for another browser.
`login` opens Claude sign-in, but the server exchanges the authorization code and
retains the refresh grant. `renew` performs sign-in again for an existing alias and
refuses a different Claude account or organization. If identity verification fails
after token exchange, the server retains the acquired response. The failure shows
`complete-login ID --resume`, which retries verification without exchanging the
code again. An uncertain exchange with no retained response requires a new login.

`migrate --all --exclusive-owner` moves every saved account on this machine in one run;
without `--exclusive-owner` it refuses and fences nothing. It first refuses
the whole run while any Claude process runs (with or without `--exclusive-owner`),
when the host's Claude build is not qualified, or when the server is unreachable;
then nothing is fenced. Expired inactive profiles are refreshed locally before their
fence. Inactive accounts migrate first. The host's live login migrates last, from its
Keychain grant. claudectl never deletes the live login: `security(1)` cannot delete
conditionally and Claude Code takes no lock, so a delete could erase a newer login.
After the server verifies the rotation, the live login holds a retired grant; the row
reads `migrated (log out the live login)` and the command prints the step to run:
`claude auth logout`, then `claudectl server run <alias>`. If the live login changed
since the fence, the row says so and nothing is touched. A server outage or 5xx stops the
run; other accounts continue past a per-account refusal. The summary shows one row per
account (`migrated`, `already`, `refused:…`, `unrotated`, `superseded`, `gone`,
`lost-reply`, `failed:fenced`, `not-attempted`) with the next command; the exit code is
1 unless every row is `migrated` or `already`. A rerun resumes fenced accounts through the
receipt lookup.

`migrate --abort ALIAS` first asks the server to cancel the migration ID. The server
records the cancel under the alias lock (a cancelled tombstone when nothing arrived yet),
so a delayed import with that ID is rejected (`409 migration_cancelled`). Only after the
server confirms the cancel does abort restore the local grant, into the profile only. Abort
never writes the live login, so a login made after any check is never replaced; for a live
migration the profile gets the fenced live grant, and abort prints `claudectl use <alias>`
to make it live again. `claudectl remove` refuses a profile with an open fence, so abort
always has its profile directory. Once the admission committed, the cancel is refused
(`409 migration_admitted`) and abort reports the state; for a superseded or deleted server
account it drops the fence without keeping a copy.

The company user, provider, account UUID, organization UUID, and monotonically
increasing generation are checked before replacing the session credential. Only
this Claude binary hash is built in, with synthetic evidence for the host-config launch model:

| Platform    | Claude version | SHA-256                                                            |
| ----------- | -------------- | ------------------------------------------------------------------ |
| Linux ARM64 | 2.1.280        | `92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2` |

`server run` copies the build once, before any server call, and hashes that copy; the
same copy is checked, recorded and run. A build that is not built in or qualified is
checked on first use: `server run` prints `qualifying Claude build <digest> (first use,
about 15 s)`, and only on a pass does it ask the server for a token. One check runs at a
time per machine (`~/.claudectl/server/qualify.lock`); another launch waits up to 90 s and
prints `waiting for qualification (pid N)`. One check is limited to 75 s. A failed check
is recorded in `qualify-failures.json` (same key as a pass; a damaged file refuses), and
launches of that build are refused for one hour without a new check.
`claudectl server qualify --claude PATH` always runs the check and clears a failure on a
pass. The check runs the full-launcher check `supervised_host_config` from
`experiments/settings-renewal/supervised.py` against a private snapshot of the build:
a fake API and a host login in the HOME, one Bash tool call on server token A, then a
`--resume` relaunch on server token B. The host token must never be sent and the host files
must not change. Only on a pass is the hash recorded, with the check name, in
`~/.claudectl/server/qualified-host-config-builds.json`. Builds qualified by the earlier
renewal check (in `qualified-builds.json`, before the host-config model) are not
qualified for this client: run `server qualify` again after the upgrade. Older clients keep
reading the old file, so both versions work on one machine during the upgrade. A damaged list refuses every build. It needs `python3` (and
`unshare` on Linux, Homebrew OpenSSL on macOS). Claude 2.1.280 on Linux ARM64 on the devbox
passed on 2026-10-07. The operator procedure is in [the runbook](account-server-runbook.md).

## Plain `claude` through the server (shim)

`claudectl shim install --account work` writes `~/.local/claudectl/bin/claude`
(without `--account`, the account is `amir@sawmills.ai` for now). That
small sh script runs `claudectl server run work --claude <real Claude> -- <your args>`,
so plain `claude` in a terminal, a script, or a lane uses the server account. Put the
directory first on PATH; install prints the line and never edits shell files:

```sh
claudectl shim install --account work
export PATH="$HOME/.local/claudectl/bin:$PATH"
claudectl shim status
```

- Install records the real Claude (the first `claude` on PATH that is not a shim, or
  `--claude`) as found, so the native installer's `~/.local/bin/claude` link keeps
  following updates. It records claudectl the same way. Run install again to change the
  account.
- The shim passes the real Claude by path, so `server run` never finds the shim on PATH.
  `server run --claude <shim>` is refused before any server call.
- `CLAUDECTL_SHIM=off claude ...` runs the real Claude. `-v`, `--version`, `-h`,
  `--help`, `update`, `doctor`, and `install` as the first argument also run it directly,
  without a server token.
- `server run` sets `CLAUDECTL_SERVER_RUN` in its Claude to its session directory and
  records the SHA-256 of the token it hands out there. A nested `server run` (a `claude`
  started inside that session) accepts the inherited `CLAUDE_CODE_OAUTH_TOKEN` only when
  the marker names a session under `~/.claudectl/server/sessions`, that session still
  holds its lease, and the digest matches. Any other inherited credential is refused, so
  a hand-set marker cannot pass a hand-set token. The shim passes the environment
  through unchanged on that path. Its direct branches (`CLAUDECTL_SHIM=off` and the
  token-free first arguments) drop the session's token and marker when the marker is
  set, so a direct Claude never runs on the server account.
- Install refuses an account that is not on the server, a real Claude that is a shim,
  and an existing `claude` file in the directory that it did not write. `claudectl shim
uninstall` removes only its own file.

## Session behavior

`claudectl server run <alias> -- <claude args>` keeps the host Claude config: the same
`~/.claude` (or the inherited default) with its conversations, skills, hooks, memory and
folder trust, so `--resume <session>` finds a conversation started on the host login. The
child receives only the server access token, in `CLAUDE_CODE_OAUTH_TOKEN`; credential and
routing overrides (`ANTHROPIC_API_KEY` and the like) are removed from its environment, and
the client never holds a refresh token. Existing project and managed credential overrides
are refused at startup, and user-supplied `--settings`, `--setting-sources` and `--bare` are
refused.

The synthetic check `experiments/settings-renewal/host-config.py` (Claude 2.1.280, Linux)
shows, with a host login present in the config dir: the server token is used, the host token
is never sent, nothing calls a refresh or other POST endpoint, and the host credentials file
and the host identity in `.claude.json` stay byte-identical. It also shows that Claude does
not reload a changed token inside a running process (a `--settings` file, a host-managed
credentials file and the process environment all behave the same), while a new process with
`--resume <session>` continues the same session.

Token lifetime is therefore the session limit. A provider refresh revokes the access token
issued before it, and every `server run` of an account shares that token, so a launch never
forces a refresh: it takes the current token, and the server refreshes on demand near expiry.
`claudectl server refresh-access` forces one and ends every running session of that account
(relaunch each with `--resume`).

`server run` follows the account's token revision (SAW-12610). It registers its own Claude
hooks (`--settings <session dir>/hooks.json`, run by a private copy of claudectl) for
`SessionStart`, `UserPromptSubmit`, `Stop`, `StopFailure` and the `idle_prompt` notification, which record
only the event, the session id and the time in `<session dir>/events`. It asks the server
for the current token only while Claude passes every idle gate below, at most every 30 min
(every 5 min in the token's last hour), retrying 30 s after a failed request. The request
observes (`"observe": true`): the server never refreshes an unexpired token for it, so it
cannot revoke the token another session's turn uses, and a revision that another session's
refresh superseded early shows at once. After expiry the server refreshes as usual; the held
token is dead for every session then. One case remains: while a migration's rotation is
pending (between its admission and its first refresh), the server refreshes for any request;
do not migrate an account while `server run` sessions use it. When the
revision changed (a refresh revoked the held token), it restarts Claude with
`--resume <latest session>` on the new token, in the same folder and terminal, from the same
checked build, and prints `claudectl: server token renewed; resuming session <id>`. It
restarts only when all hold: the new token outlives the held one, the last turn ended at
least 60 s ago with no prompt since (a turn that failed, for example on a revoked token,
ends with `StopFailure` and counts too), no terminal input for 5 min (the terminal device's
access time), and fewer than 3 restarts in the last hour. Extra processes in Claude's group
(an LSP, `caffeinate`, a background shell) do not hold a restart back: the held token is
already superseded or expired, so it is dead for every holder; work still running in
Claude's group ends with the restart. A turn in progress is never cut; a draft typed earlier
than the input gate is lost on restart. Relaunch happens only after claudectl's own
SIGTERM; any other exit ends `server run` with Claude's exit code. A `-p`/`--print` run is
never restarted. If Claude sends no hook event within 30 s, or a hook could not record an event (the
`hook-error` marker), renewal is off for that session.
`session.json` (alias, account, `expires_at`, pid, `renewal`: `on`, `off: <reason>` or
`renewing`; no token) is updated on every renewal; a supervisor leaves expiry to
`server run` and skips a renewing session. A per-session lock protects live session
directories; a later launch removes abandoned ones after their recorded expiry.

This is not an OS sandbox. Tools inherit the access token environment and can
access files available to the same OS user. The Mac experiment's fake `security`
command and OS sandbox are **test fixtures only**. They are never installed by the
launcher. Managed policy changes during a session and native Keychain ACL behavior
remain acceptance gaps; a startup scan does not prove lifetime policy isolation.
The same holds for the host user settings and the project settings of the cwd: the child
loads them like any host Claude session, and Claude applies settings changes while it runs.
An edit made after the startup check (for example `env.ANTHROPIC_BASE_URL` or
`apiKeyHelper` in `.claude/settings.json`) can route the server token, exactly as it would
route the host login token in a normal session. Run server sessions only in folders you
trust as much as your host login.

Conversations that a `server run` before this model stored in
`~/.claudectl/server/conversations/<account_id>` are not migrated. To resume one, copy its
`<project>/<session>.jsonl` into `~/.claude/projects/<project>/`; otherwise delete the
directory.

While Claude runs, the client reads usage every five minutes. It never changes the token of
the running process; it asks for the current token only while Claude is idle, and that
request never refreshes an unexpired token (above).
Another session's request can still trigger the refresh; a busy session then fails its next
request and restarts at its next idle point. After an early provider 401, wait for the
renewal or use `server refresh-access work` (it ends every running session of the account).
The client never replays tools. On server outage, the token of a running session stays
valid until provider expiry or rejection. Revocation
stops new acquisitions; it cannot revoke an access token already delivered.

`status --cached` and `statusline ACCOUNT_ID` read local files only. Native Claude
status-line fields remain available, but the wrapper does not overwrite a user's
existing status-line configuration. The server caches usage for up to five minutes,
polls at least one second apart, and shares 429 cooldowns across accounts.

## Migration

Migration is separate from `use`; local switching remains network-free.

1. Inventory **every** grant holder: saved aliases, active Keychain/file state,
   other machines, custom configs, old binaries, running sessions, jobs and backups.
2. Stop other owners and retire their copies. An uncertain inventory is not an
   exclusive-owner declaration. The current command refuses active profiles,
   shared live grants, unreadable ownership state and duplicate saved identities.
3. Run `claudectl server migrate ALIAS --exclusive-owner` only when that declaration
   is true. The access token must still be usable; the client never refreshes it.
   After admission the server refreshes once. Refresh tokens are single use, so
   the refresh makes every copy left elsewhere stale.
4. If interrupted, repeat the same command against the same server/company user.
   It retrieves the receipt before retrying admission.

The client persists a fence outside the profile, then moves credentials out of the
normal profile path before contacting the server. The server authenticates the
access token, stores the grant encrypted and returns a durable receipt. Only after
that receipt is saved does the client delete its retained refresh copy. A failed or
uncertain transfer stays fenced. Profile removal, another alias, and ordinary local
login/save cannot restore the migrated grant. Fences retain account metadata and
one-way token digests, never usable tokens after retirement.

The client cannot stop unknown old binaries or erase external backup copies. Do not
restore a copied refresh grant to undo a migration. Recover on the server through
verification or identity-pinned login renewal.

## Running the server

```sh
cargo build --release --features server --bin claudectl-server
# PostgreSQL, several replicas (staging):
DATABASE_URL='postgres://migrator@db/claudectl?sslmode=require' claudectl-server migrate
DATABASE_URL='postgres://claudectl@db/claudectl?sslmode=require' claudectl-server serve \
  --key-file /keys/vault-key --listen 0.0.0.0:8787 --public-url https://claudectl.example.com \
  --sso-config /configuration/sso.json --metrics-token-file /keys/metrics-token \
  --allow-user person@example.com
# One machine, file store:
claudectl-server setup --state /data/state --key-file /keys/vault-key --if-absent
claudectl-server serve --state /data/state --key-file /keys/vault-key --public-url http://127.0.0.1:8787/ --allow-user person@example.com
# Operator commands take --database-url (or DATABASE_URL) or --state, plus --key-file:
claudectl-server users --key-file /keys/vault-key
claudectl-server revoke --key-file /keys/vault-key --machine MACHINE_ID
claudectl-server audit --key-file /keys/vault-key
```

- **Storage.** PostgreSQL for several replicas, or one sealed file for one process. Every
  payload is sealed with AES-256-GCM under the vault key before it reaches the store; the
  key never does. A lost vault key loses every grant.
- **Schema.** Only `migrate` changes the schema; the staging Argo CD app runs it as a PreSync
  Job with the migrator role. `serve` refuses a schema older than it needs, or one that needs
  a newer server.
- **One refresh owner.** Each account has a database lease (120 s, epoch-fenced). Only its
  holder refreshes, and every write a refresh makes checks the lease. Another replica waits
  up to 35 s for the new token and then answers 503 `refresh_in_progress`; machines retry.
  A provider response is kept before it is parsed, so a stop never forces a replay.
- **Access.** A request needs an enrolled machine token, an enabled company user, and an
  email on the allow list. A network listener needs an HTTPS origin and company SSO. With
  the Google issuer, the signed `hd` claim must match `allowed_hosted_domains` (default:
  `allowed_domains`), and `email_verified` must be true. Users key on issuer and subject.
  Enrollment state lives in the store and is consumed once, so any replica can serve it.
- **Refresh.** The server refreshes when a machine reports the current revision as rejected,
  or when less than five minutes remain. A usage read never refreshes.
- **Revoke.** `server revoke` stops a machine, also during a refresh in progress.
  `server remove` deletes the account, its grant, and every pending login or admission for
  its alias in one step; later token requests get HTTP 410, and work that started before the
  delete cannot recreate it. Neither recalls an access token already delivered, so the
  exposure after a revoke is at most one access-token lifetime.
- **Shutdown.** On SIGTERM readiness fails, new connections stop, and in-flight refreshes
  and verifications finish and persist before the process exits (grace period 120 s).
- **Audit.** Every migrate, issue, refresh, and revoke writes one line to stderr and one
  sealed row to the store: operation, machine, account digest, result, and for a refresh
  whether the provider rotated the refresh token. No line holds a token.
- **Metrics.** `/metrics` (scrape token or machine token) exports
  `claudectl_server_failed_requests_total{reason}` and
  `claudectl_server_last_failure_timestamp_seconds{reason}`. The staging overlay in
  `deploy/k8s` alerts on both through the existing alert routing.

## Validation and remaining release gates

The executable experiments are in [experiments/settings-renewal](../experiments/settings-renewal).
They use synthetic tokens and block external networking/real credential reads.
The Linux and Mac lifecycle matrices cover proactive replacement, 401 retry,
delayed replacement, outage/recovery, missing/malformed settings and terminal
continuity. The Linux and Mac full-launcher checks also renew access during an eight-second
Bash operation, observe the successor on the next model request, prove the tool
ran once, and check credential cleanup. Mac also covers a late-appearing conflicting Keychain credential.
“Delayed replacement” is a simulated rejection; settings tokens contain no expiry
metadata and this experiment does not establish real OAuth lifetime.

A limited live check on one inactive Team account returned a successful inference
through this access-only client. The [validation report](account-server-validation.md)
distinguishes that check from a complete server migration and billing validation.
The implementation is not release-approved. Outstanding acceptance includes live
subscription entitlement/billing, actual expiry and repeated rotation on both
machines, a complete ownership inventory, native Mac Keychain isolation, runtime
managed-policy changes, and broader resume/tool/signal coverage.
The current pilot account has not been migrated: SSH cannot read its authoritative
Keychain credential even after a successful native unlock.
