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
claudectl server revoke MACHINE_ID
claudectl server remove work
claudectl server disconnect
```

`connect` opens company SSO; `--no-browser` prints the URL for another browser.
`login` opens Claude sign-in, but the server exchanges the authorization code and
retains the refresh grant. `renew` performs sign-in again for an existing alias and
refuses a different Claude account or organization. If identity verification fails
after token exchange, the server retains the acquired response. The failure shows
`complete-login ID --resume`, which retries verification without exchanging the
code again. An uncertain exchange with no retained response requires a new login.

The company user, provider, account UUID, organization UUID, and monotonically
increasing generation are checked before replacing the session credential. Only
these Claude binary hashes have synthetic compatibility evidence:

| Platform    | Claude version | SHA-256                                                            |
| ----------- | -------------- | ------------------------------------------------------------------ |
| Linux ARM64 | 2.1.280        | `92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2` |
| macOS ARM64 | 2.1.288        | `bbe93063f7a0879a1021b2891e5c9354e5b3b98433e32efe6750f7710afed750` |

The launcher hashes a private executable snapshot before running it. Any other
build is refused until `claudectl server qualify --claude PATH` passes on that
machine. The command runs the full-launcher renewal check from
`experiments/settings-renewal/supervised.py` against a private snapshot of the build:
a fake API, an invalid process token, and one settings token change during a Bash
tool call. Only on a pass does it record the hash in
`~/.claudectl/server/qualified-builds.json`. A damaged list refuses every build. It
needs `python3` (and `unshare` on Linux, Homebrew OpenSSL on macOS). On 2026-10-06,
Claude 2.1.292 on macOS ARM64 (`97a01e5bc74a199e67189435d0331ea3a24eac2e07db4b76d9148c5b0386138f`)
and Claude 2.1.280 on Linux ARM64 on the devbox
(`92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2`) passed. The operator
procedure is in [the runbook](account-server-runbook.md).

## Session behavior

The credential writer atomically replaces a private `settings.json` containing
`env.CLAUDE_CODE_OAUTH_TOKEN`. The child starts with an invalid fallback token.
The tested builds reload the settings token, including with conflicting synthetic
Keychain responses. Missing/malformed settings retain the last selected token;
they do not immediately stop network requests. The client has no refresh token.

Each session gets a private config directory. A per-session lock protects live
sessions from cleanup. A later launch removes abandoned directories only after
their recorded access expiry; ordinary exit removes them immediately. Its `projects` directory points at
persistent conversation storage for the server account. The launcher forces
`--setting-sources user`, so project/local settings do not override its credential
while the process runs. Existing project and managed credential overrides are
refused at startup. User-supplied `--settings`, `--setting-sources`, and `--bare`
are refused. Normal project instructions and tool operation still need separate
compatibility checks; settings-based permissions and hooks are not copied from the
user's ordinary Claude config.

This is not an OS sandbox. Tools inherit the access token environment and can
access files available to the same OS user. The Mac experiment's fake `security`
command and OS sandbox are **test fixtures only**. They are never installed by the
launcher. Managed policy changes during a session and native Keychain ACL behavior
remain acceptance gaps; a startup scan does not prove lifetime policy isolation.

The writer polls the server every five seconds and publishes a changed generation.
The server refreshes before expiry. An early provider 401 does not automatically
notify the writer: use `server refresh-access work`, wait for publication, then
retry the failed prompt. It never automatically replays tools. On server outage,
the last access token remains available until provider expiry/rejection. Revocation
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
