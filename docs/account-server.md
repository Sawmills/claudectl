# Claude accounts on a company account server

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

### Shared credential for unattended jobs

An administrator can issue one shared machine credential for an existing enabled
company user. Find its ID with `claudectl-server users`, then run:

```sh
claudectl-server service-account issue COMPANY_USER_ID \
  --database-url DATABASE_URL --key-file KEY_FILE --allow-user COMPANY_EMAIL
```

Pass the same `--allow-user` list as `serve` (repeat the flag for more addresses).
Issuance requires both an enabled company user and an email allowed by that list,
using the same case-insensitive rule as `/v1/me`. A refusal prints no credential
and leaves the current shared credential valid.

The command prints the credential once to stdout after the write commits. Deliver
it directly to the job's secret store; do not send it to logs. The server stores
only its hash. Repeating the command rotates the single shared credential: the
old one is refused on every replica, and other enrolled machines keep working.
For file storage, use `--state STATE` instead of `--database-url` and stop the
file-mode server during administration, as its ordinary store lock requires.

Inject `CLAUDECTL_SERVICE_TOKEN` and the nonsecret `CLAUDECTL_SERVER_URL` (an HTTPS
origin) into the job. With those variables set, no `server connect`, saved profile,
machine file or human login is needed:

```sh
claudectl run -- --print 'Perform the scheduled task.'
claudectl run work -- --print 'Perform the scheduled task.'
claudectl status --json
```

The unnamed run uses the existing account picker. Both forms require current
included capacity, with extra usage explicitly off, before executing any Claude
build. Missing configuration, rejected credentials, stale usage and unavailable
capacity refuse the job; they never fall back to a human machine credential.
Service status requires a live connection, so omit `--cached`. One-shot `--print`
runs keep the existing rule: no renewal or failover replay after the child starts.

This is an ordinary machine bearer, shared by trusted jobs, with the same account
authority as that machine, including machine revocation, account removal and
`refresh-access`. The environment remains visible to Claude and its
tools; keep task code trusted and never echo the credential. This adds no pools,
leases, scopes, billing permission or automatic reset redemption.
`server disconnect` refuses in service mode so it cannot delete a human machine's
saved connection. Unset both service variables before disconnecting that machine.

The server's existing usage read requests optional limit-reset offers. When present,
`claudectl status` (including `--details` and `--json`) and the `/accounts` dashboard
show the remaining count, affected limits and expiry. Paused offers, future starts
and offers that cannot currently be used are labeled. Empty offers are hidden;
unknown expiry is labeled, and old observations remain marked as old data. The
dashboard uses cached usage and makes no additional provider request. These are
read-only hints by default: use `/limit-reset` in Claude Code or Settings > Usage on
claude.ai to apply a reset. The browser dashboard Apply reset action is an explicit
staging opt-in (`CLAUDECTL_CENTRAL_BROWSER_RESETS=1`). It requires a recent company
sign-in, the dashboard session and form token, and the exact configured Origin. It
only enables for a fresh exhausted window and keeps the provider request ID sealed in
the account record so a timeout retry reuses it. The provider call is outside the
store transaction, and the action writes an `account_reset` audit row without tokens.

Mixed server versions are unsupported during this rollout. Enable the browser action only
after every staging replica runs this release and the image rollout and replica readiness
check are complete. Do not apply a reset during the roughly one-minute rollout. Verify the
synthetic timeout replay on the new image before any live staging use.

On the first successful usage poll for each account in a server process, the
`limit_reset_offers` log records only `present` (the provider returned an offer
block) and `count` (remaining unexpired resets), without account or
grant identifiers. Optional offer metadata can be absent or malformed without
failing the ordinary usage read.

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

For human machine credentials, `server run` copies the build before any server call.
Service jobs authenticate and check included capacity first. The launcher hashes
the single copy; that same copy is checked, recorded and run. A build that is not built in or qualified is
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
are refused at startup. Explicit `--settings <JSON-or-file>` values are checked with the
same rules, then merged in argument order into the private session settings file. Objects
merge recursively, later non-hook values win, and hook arrays append to claudectl's hooks.
Claude receives exactly one `--settings`; unreadable files or invalid JSON stop the launch.
`--setting-sources` and `--bare` remain refused.

This merge checks JSON syntax, credential/routing isolation and hook-array structure; it
is not a full Claude settings-schema validator. On Claude 2.1.302, a schema error such as
`"model": 5` makes the whole merged file inactive, including the generated supervision
hooks. Token renewal and account failover then lack their hook events. Supply settings
valid for the installed Claude version and fix its startup warnings before using the
session. The valid A2A settings `crossSessionInbound: "accept"` and
`isolatePeerMachines: true` retain the hooks. No native validation subprocess is added.

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

**Current limitation:** hook-only sessions no longer automatically restart at idle, for
renewal or account failover. Claude's command hooks cannot acknowledge that all prompt
sources are closed and every submitted prompt is safe to hand over. A missing acknowledgement
is `evidence_unknown`, so the wrapper keeps the existing child and token instead of sending
SIGTERM. It does not collect, store or replay prompts to work around that limit.

`server run` registers Claude hooks for `SessionStart`, `UserPromptSubmit`, `Stop`,
`StopFailure`, `SessionEnd` and the `idle_prompt` notification. They record only the event,
session ID and time in `<session dir>/events`. Workload evidence still distinguishes running
turns, background tasks and holds, but a clear workload sample is not input-admission proof.
Every deferred session is checked each monitor tick, even before hooks arrive, during a
running turn, or when no server revision has changed. Five minutes before token expiry its
status and structured alert change to `warn`; expiry or an authentication failure changes
them to `blocked`. The child and its work stay alive, without a forced timeout. The held
token can stop working before you can safely end and relaunch the session.

The retained restart and cron-recovery path described below is not reached by current
hook-only sessions. It has no input-admission override. Existing sessions must be ended
explicitly by their owner after the work and cleanup are complete; installing a new CLI
does not upgrade a running wrapper.

For a Fleet Operator, `HERDR_TAB_ID` selects the matching `operator_tab` in
`~/Code/.fleet/*/operator.md`. Its `cron_prompts` entries (a prompt file and five schedule
fields, separated by semicolons) are the source of truth, even when the resumed session's
CronList is empty. Cards without saved jobs do not participate in discovery. When one tab
owns several populated cards, their jobs are merged: the same resolved prompt file and
schedule is created once, with its new ID recorded on every owning card. Different schedules
for the same file across cards skip recovery with a conflict reason; a single card can
still schedule one file at several times. The renewal prompt names every
participating card, file and schedule, asks Claude to read
each prompt verbatim, delete only matching card-owned IDs from `cron_ids` while preserving
other session jobs, create the recurring jobs, run CronList again, and update
each card's `cron_ids` and `claude_session_file`. claudectl reads that final inventory from the
renewed session transcript, matched to its tool call and renewal prompt. It prints
`cron recovery verified: N/N saved jobs`, `missing cron: <file> (<schedule>)`, or an explicit
unverified notice if evidence is absent or unreadable. Prompt contents are not printed.
Extra copies of saved jobs prevent a verified result; unrelated jobs are preserved and are
outside the saved-job count.
The transcript read is limited to 8 MiB after the previous recorded position. An ambiguous
card, an unreadable saved prompt, a malformed entry, or a recovery-arm failure prints
`cron recovery skipped: <reason>` and falls back to the existing renewal note. Optional
cron recovery never aborts token renewal. Sessions with no matching card keep the existing note; first
launches, manual resumes, and account failovers do not use this recovery.
Cards with no saved crons also keep the existing note. Unreadable unrelated cards produce a
discovery warning and do not stop ordinary renewal. Saved paths support absolute paths,
paths relative to the card, `~/`, `$HOME/`, and `${HOME}/`; other variables and `~user`
are refused with an explicit unsupported-path error.
If the resumed conversation is missing, the existing `No conversation found` fallback
starts a fresh session without this cron-restoration prompt. The failed resume reports
unverified recovery; restore its jobs from the card in the fresh session. This limitation
does not change the normal renewal-resume path.

This remains a best-effort workaround for Claude Code's resume behavior, with these limits:

- Missed one-shot crons and exact jitter are outside this workaround; a non-idempotent job can replay up to once per renewal.
- Every listed job is reset on each renewal resume, not only a silent one: neither claudectl nor
  the session can tell a silent job from a live one.
- A reset can shift a job's fire time. Claude Code delays each recurring fire by an offset it
  derives from the job ID, and a re-created job gets a new ID, so the same cron expression can
  fire at a different minute ([how late a recurring task runs](https://code.claude.com/docs/en/scheduled-tasks#how-late-a-recurring-task-runs)).
  A watchdog that looks for a silent job must use the re-created job's timing, not the old
  job's fire times.
- Without an Operator card, claudectl does not check that each `CronDelete` and `CronCreate` succeeded; the session's
  transcript shows the result. If a call fails, a job stays as the resume left it (listed, and
  maybe silent), or is gone.
  The session decides whether fires were missed from the schedule and its last turn;
  claudectl does not verify that judgment or the catch-up run.
- Recovery: run `CronList` in the tab and create a missing job again by hand. Fleet Operators
  keep their own watchdog for a silent cron.
- The defect belongs to Claude Code; an upstream report waits on the owner's decision. Remove
  the note once Claude Code fires restored jobs reliably.

Automatic restart always requires both input-admission proof and fresh workload evidence.
Foreground turns, live background tasks and explicit production holds prevent renewal and
failover, even after token expiry. The task check reads live descendants' stdout/stderr:
a Claude task file under `<tmp>/claude-<uid>/.../tasks/*.output` holds admission. MCP/LSP
servers and `caffeinate` without task-output descriptors do not add a workload blocker.
They do not remove the missing input-admission proof.

Current command hooks provide no supported close-and-drain acknowledgement, so even an
idle session defers with `evidence_unknown`. No failover reservation or restart budget is
consumed. The final signal path independently checks admission before waiting on hook
locks or publishing `renewal=renewing`. Any explicit child exit ends `server run` with that
child's exit code. A `-p`/`--print` run is never automatically restarted either.
`session.json` records the alias, account, held `expires_at`, pid and renewal state without
the token. The run's deferred status identifies warnings and blocked sessions for Operators.

### Production Holds and Deferred Restarts

Inside a server-run child, hold a production step explicitly:

```sh
claudectl hold start --reason "SAW-12345 production migration"
# Complete or abort the step, including its cleanup, before ending the hold.
claudectl hold end
```

The command uses the inherited `CLAUDECTL_SERVER_RUN` identity. One hold belongs to one run;
starting a different reason while a hold exists fails. Check the command's exit status before
starting the production step. Lane skill/runbook adoption is a separate rollout.

When the lane exports `HERDR_TAB_ID` (or `HERDR_PANE_ID`), the monitor consumes that lane's
`[starting]`/`STARTING NOW` and matching `[done]`/`DONE` markers from the optional goal file
(`LANE_GOAL_FILE` or `SAW_GOAL_FILE`) and fleet voice outboxes. Outbox markers are checked
even when no goal file is configured. An open marker defers admission even when Claude has
no local task-output child. Missing or unreadable marker evidence is reported as
`evidence_unknown` and keeps admission closed. Restoring workload evidence does not provide
the missing input-admission proof; explicit holds remain the preferred production boundary.
An older running wrapper cannot enforce a hold. The command checks the wrapper's recorded
gate capability and refuses the start if it is absent; installing a new CLI alone does not
upgrade a wrapper that is already running.

Holds stay in `~/.claudectl/server/holds/<run-id>.json`, outside temporary session cleanup.
A hold whose owner exits remains blocked and reports attention. It never clears by age or
token expiry. After the wrapper exits, explicitly clear its recorded hold with
`claudectl hold end --run <run-id>` after the production step and its cleanup are complete.

`claudectl status` and the inherited session's status line show
`restart deferred: <reason>`. `status --json` adds a `sessions` list with the run, reason,
stage and deferred counter. At five minutes before token expiry the wrapper warns; expiry
or an authentication failure changes the stage to blocked. It keeps the child and its
background work alive until admission is safe, with no forced timeout. API use can fail
while the held token is expired or revoked; another session can revoke it before its
recorded expiry.

`~/.claudectl/server/restart-decisions.jsonl` records one `restart_deferred` event per
session and severity stage. Its `claudectl_restart_deferred_total` metric has only cause,
reason and stage labels. Routine workload or cause changes update current status without
adding journal rows or counts; entering warning or blocked status emits a new event. The current run's `restart-status.json` holds its status
and counter. Records contain no tokens or prompt contents. A diagnostic write failure
closes automatic admission for that child and reports attention instead of restarting it.

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

While Claude runs, the client reads usage every five minutes. It never changes the token
of the running process. Hook-only sessions defer before token observations, account
reservations and automatic restart; they do not refresh or replace the held token. Another
client can still rotate the account's token, so a deferred session may lose API access.
Plan an owner-controlled exit and relaunch only after its work and cleanup are complete.
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
  --sso-config /configuration/sso.json \
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
  or when less than five minutes remain. A fresh usage read refreshes only an expired token
  of a Ready account (that token is dead for every holder). It never refreshes a token that
  sessions still use, so an idle account does not report `login_required` while its refresh
  grant is good. If that refresh fails, or its audit row cannot be stored, the read fails.
  A cached usage read never contacts the provider.
- **Revoke.** `server revoke` stops a machine, also during a refresh in progress.
  `server remove` deletes the account, its grant, and every pending login or admission for
  its alias in one step; later token requests get HTTP 410, and work that started before the
  delete cannot recreate it. Neither recalls an access token already delivered, so the
  exposure after a revoke is at most one access-token lifetime.
- **Shutdown.** On SIGTERM readiness fails, new connections stop, and in-flight refreshes
  and verifications finish and persist before the process exits (grace period 120 s).
- **Audit.** Every migrate, issue, refresh, revoke, finished login (`login`), and finished
  login renewal (`renew`) writes one line to stderr and one
  sealed row to the store: operation, machine, account digest, result, and for a refresh
  whether the provider rotated the refresh token. No line holds a token. A login retry that
  returns the kept receipt writes one more `login` or `renew` line with `reason: retry`, so a
  first line lost to an audit failure is recovered.
  Dashboard actions (`account_remove`, `machine_revoke`, `account_reset`) and every Google sign-in that the
  provider answered (`dashboard_sign_in`, `enroll_sign_in`) also write one line, with the
  person as `actor` (`dashboard:<email>` or `enrollment:<email>`; a refusal names the person
  only once the email is a verified company email, as for `user_not_allowed`) and, for a refused
  sign-in, the bounded `reason` (`sso_denied`, `company_identity_required`,
  `user_not_allowed`, `user_unavailable`, or `persistence_failed` when the user row could not
  be written). A bad or expired sign-in state, another browser's callback, or a provider
  that cannot be reached (`sso_unavailable`) is not audited (metric and log only). An audit write
  failure fails the operation.
- **Metrics.** `/metrics` accepts scrapes without a bearer and exports
  `claudectl_server_failed_requests_total{reason}` and
  `claudectl_server_last_failure_timestamp_seconds{reason}`. The staging overlay in
  `deploy/k8s` alerts on both through the existing alert routing. Account and machine
  routes still require their existing authentication. Omit `--metrics-token-file`
  when starting the server. The legacy option remains accepted for compatibility
  and reads the supplied file, but does not protect `/metrics`.
  [PR #118](https://github.com/Sawmills/claudectl/pull/118) removes the old staging
  metrics-file and scrape-authorization wiring. Operator rollout and per-replica
  scrape readback remain separate gates. Existing SSM parameter deletion needs
  separate approval; this documentation change does not deploy an image or change
  network exposure.

## Validation history

The account server is in production use. The reports below record earlier
experiments and their limits; they are historical evidence, not release gates.

The executable experiments are in [experiments/settings-renewal](../experiments/settings-renewal).
They use synthetic tokens and block external networking and real credential reads.
The Linux and Mac lifecycle matrices cover proactive replacement, 401 retry,
delayed replacement, outage and recovery, missing or malformed settings, and
terminal continuity. The full launcher checks also renew access during an
eight-second Bash operation, observe the successor on the next model request,
prove the tool ran once, and check credential cleanup. Mac also covers a
late-appearing conflicting Keychain credential. Delayed replacement is a simulated
rejection; these settings tokens contain no expiry metadata, so this experiment
does not establish real OAuth lifetime.

An early live check on one inactive Team account returned a successful inference
through the access-only client. The [reduced live report](../experiments/settings-renewal/live-access-result.json)
records that result. It does not establish billing behavior, credential rotation,
or SSO deployment readiness. For current deployment and operations procedures, use
the [server runbook](account-server-runbook.md).
