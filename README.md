# claudectl

Manage multiple Claude Code accounts. Switch profiles, check rate limits across all
accounts, and tab-complete profile names. Sibling of
[codexctl](https://github.com/Sawmills/codexctl).

## Install

```bash
cargo install --git https://github.com/Sawmills/claudectl
```

## Usage

### Save accounts

Save the account you're currently logged into:

```bash
claudectl save                 # alias defaults to the account email
claudectl save work-main       # custom alias
```

Add more accounts without touching the live login:

```bash
claudectl login amir+2@example.com
```

`claudectl login` runs its own OAuth flow (browser opens, you paste the code back) and
saves the tokens straight into a profile — it never runs the `claude` binary and never
overwrites another account's session. If the flow is ever rejected, fall back to
logging in with `claude /login` and running `claudectl save <alias>`.

If activation fails after the OAuth flow completed, the profile is still saved. Fix the
reported problem and run `claudectl use <alias>` — there is no need to log in again.

### macOS Keychain preflight

On macOS, claudectl writes live credentials to the Keychain already containing the
`Claude Code-credentials` item, or to the default Keychain when that item does not
exist. Every command that writes live credentials (`login`, `use`, `switch`) checks
that target Keychain is unlocked **first** — for `login` that means before the browser
opens and before any token is exchanged; for `switch`, the check runs immediately
after you pick a profile.

- **Unlocked** — nothing happens, the command proceeds.
- **Locked, running in a terminal** — claudectl runs `security unlock-keychain` with the
  terminal handed straight to `security(1)`, so macOS prompts you for the password
  itself. claudectl never accepts, passes, stores, or logs your Keychain password.
  Unlock status is re-checked after the prompt.
- **Locked, no terminal** (CI, a pipe, a non-interactive shell) — the command fails
  immediately and tells you exactly what to run:

  ```bash
  security unlock-keychain '/path/reported/by/claudectl'
  ```

The unlock check cannot prove that an existing item's access controls will authorize
claudectl to update it. If macOS denies that write after OAuth, the profile is already
saved; resolve the reported Keychain access problem and run `claudectl use <alias>`
without logging in again.

### Check usage and capacity

```bash
claudectl status                  # all profiles; reuse data for up to five minutes
claudectl status work-main        # one profile
claudectl status --cached         # no network requests or token refresh
claudectl status --refresh        # request fresh data; obey saved cooldowns
claudectl status --details        # token expiry, old usage, and fetch diagnostics
claudectl status --json           # machine-readable report (version 1)
```

`status --json` prints `{"version": 1, "accounts": [...]}`, sorted by alias. Each
account has `alias`, `label`, `active`, `plan`, `billing_class`, `exhausted`,
`windows` (`five_hour`, `seven_day`, `seven_day_opus`, `seven_day_sonnet` with
`used_percent` and `resets_at`; `fable_weekly` with `used_percent`),
`extra_usage`, `token_expires_in_seconds`, `usage_age_seconds`, `usage_stale`
and `error`. `billing_class` is `usage_based` when extra usage is on (running past
a plan window bills credits), `rate_limited` for a subscription plan with usage
windows and extra usage reported off, and `unknown` otherwise (missing or null
extra-usage data counts as unknown). `exhausted` is true when any window, including
Opus, Sonnet and Fable, is at 100%. It combines with `--cached` and `--refresh`.

The default table shows each account's status and next step:

- `Login needed`: the login is missing or authentication was rejected. Follow the
  command in `Next step`.
- `Check live login`: claudectl cannot confirm which login owns token refresh.
  Check Keychain access and the Claude Code login before logging into saved accounts.
- `Let Claude refresh`: the expired token belongs to the live Claude Code login.
  Open Claude Code. Log in again only if Claude cannot refresh it.
- `Usage check throttled`: wait until the next check. HTTP 429 limits usage checks;
  it does not prove that the account has exhausted its allowance.
- `Refresh throttled`: wait until the next check. The token refresh service limited
  requests before claudectl could check usage.
- `Profile save failed`: check file permissions. Token refresh succeeded, but
  claudectl could not save the new tokens. A saved account may need a fresh login.
- `5-hour limit reached` or `Weekly limit reached`: wait for the displayed reset
  or use another account.
- `Within usage limits`: recent data shows available general usage. A model request
  can still fail or have a separate limit.

Other statuses also include a next step. `Access denied` asks you to check account
permissions. `Cannot read login` asks you to check Claude Code and Keychain access.
`Cannot read saved login` asks you to check the saved profile's file permissions,
then repair it with `claudectl save <alias>` from the correct live account or
`claudectl login <alias>`.
`Check failed` points to `--details` for the error. `Usage unknown` asks you to run
another check or verify model access. A model limit, such as `Fable limit reached`,
asks you to use another model or account.

`Usage used` shows percentages only when recent data is available and the latest
check succeeded. Old data and failed checks show `Unknown`. The `Data` column
shows whether saved data is old or recent. `*` marks the active account.
In a terminal, the active account and headers are cyan. Green status means usage
is within limits. Red status means a reached limit, a required login, denied
access, or a profile save failure. Other checks that need attention are yellow.
Usage color follows the highest reported percentage:
green below 50%, yellow from 50%, and red from 80%. Colors are disabled when
output is redirected or `NO_COLOR` has a nonempty value.
An expired access token alone does not mean you must log in again.

Use `--details` to see the full table, including old percentages, model limits,
token expiry, exact fetch errors, and retry times. Recent cached data can lag by
five minutes. Both views use the same data and refresh rules.

All commands share a cache and an operating-system lock under `~/.claudectl/usage/`.
Requests run one at a time, with a one-second gap. A concurrent command stops with
an explicit message instead of starting another batch. Cache files contain usage
data and token digests, never credential values. Token changes isolate the cache
from an old login. Entries unused for a day are removed on the next cache update.
A corrupt or unwritable cache produces an error.

HTTP 429 pauses usage checks for all profiles on this machine. The delay is at
least five minutes and at least the server's `Retry-After` value. Repeated 429s
increase the local delay up to one hour. A longer server delay still applies.
Other HTTP errors on usage fetches or token refreshes delay retries for that token.
Network errors, timeouts, and invalid responses add no per-token retry delay.
These controls reduce requests; they do not guarantee that Anthropic will accept
the next request. Other clients
and older claudectl versions do not share these controls.

`--refresh` bypasses recent successful data, but never bypasses a cooldown.
`--cached` and `--refresh` cannot be combined. A general usage window reset ends
its cache validity early. Non-active expired tokens refresh only when a network
check is due. Claude Code remains the sole owner of refresh for the active profile.
Aliases with the same refresh token share one refresh result per check.
They also share saved refresh cooldowns across separate checks.
Selection and display recheck cache expiry after the batch completes. An alias
that shares the live login's refresh token also leaves refresh to Claude Code.
If the authoritative live credentials are unavailable, status does not refresh
saved tokens. On macOS, a file fallback cannot prove Keychain token ownership.
Account changes and token refresh share a separate lock. Status reads ownership
under that lock and releases it before usage requests. A busy account update
returns an error that asks you to retry after the other command finishes.

### Switch accounts

```bash
claudectl use amir+2@example.com   # direct
claudectl use                      # auto-select the most available account
claudectl switch                   # interactive fuzzy picker
```

Explicit switching is a local operation (Keychain + files), with cached usage
and no requests to Anthropic. Automatic selection checks usage once and reuses
that result after the switch. If the cached display fails after an explicit switch,
the command reports the completed switch and a separate warning.
It runs the same [Keychain preflight](#macos-keychain-preflight) before touching the
live auth. On macOS it updates the `Claude Code-credentials` Keychain entry,
`~/.claude/.credentials.json`, and the `oauthAccount` identity in `~/.claude.json` —
so Claude Code shows the right account immediately.

Auto-select uses only fresh, successful results with known five-hour and weekly
usage below 100%. It picks the lowest `max(5h, 7d)` utilization and breaks near-ties
toward the soonest weekly reset. Model-specific limits remain visible in the table;
automatic selection does not choose for a particular model.

### Run one command on a saved account

```bash
claudectl exec --profile amir+2@example.com -- claude -p "review this diff"
claudectl launcher --profile amir+2@example.com --claude "$(command -v claude)" --out ./claude-amir2
```

`exec` runs one command on a saved profile and leaves the live login alone.
The child gets the saved access token through an inherited pipe
(`CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`) and a fresh private
`CLAUDE_CONFIG_DIR` that is removed when the run ends. So that the child
starts at its prompt, that directory gets a `.claude.json` with only your
onboarding state (`hasCompletedOnboarding`, `lastOnboardingVersion`) and the
start-up approvals that cover the current directory (folder trust, also when
it comes from a parent directory, and external CLAUDE.md imports). Accounts, tokens, allowed tools and MCP servers are never
copied. The child runs
in its own process group: `SIGTERM`, `SIGINT` and `SIGHUP` sent to claudectl
reach the whole group once, and descendants left after the child exits get
`SIGTERM`, then `SIGKILL`. `SIGCONT` follows each of these signals, so a
stopped process acts on them.

`exec` also runs an interactive child such as the Claude Code TUI. When
claudectl owns the terminal foreground, the child's group takes it, as a shell
job does: the terminal sends Ctrl-C and window size changes to the child
directly. Ctrl-Z stops the child and claudectl together, and `fg` resumes both.
claudectl takes the foreground back when the child exits, unless the shell
owns it (after `bg`). Known limit: a Ctrl-Z in the few microseconds between
the terminal handoff and the start of the child can leave the child stopped
while `fg` cannot resume claudectl. Run `kill -CONT <child pid>` to recover;
Ctrl-C does not help in that state. If the terminal hangs
up (for example, the pane closes), the child gets `SIGHUP` from the terminal,
and the private directory is still removed after it exits. `exec` runs a
private copy of the executable, so use it for a single-file program such as the
Claude Code native binary; a program that loads files next to its own path does
not find them. The Keychain entry,
`~/.claude/.credentials.json`, `~/.claude.json` and the active marker are not
written.

The child's environment drops other credentials and routing settings: every
`ANTHROPIC_*` or `CLAUDE_CODE_*` variable that selects a provider
(`CLAUDE_CODE_USE_*`) or whose name ends in `_API_KEY`, `_TOKEN`,
`_FILE_DESCRIPTOR`, `_BASE_URL`, `_HOST`, `_HEADERS` or `_HELPER`, for example
`ANTHROPIC_API_KEY`, `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR` and
`ANTHROPIC_BASE_URL`. Other variables, such as `ANTHROPIC_MODEL`, pass
through. A signal that claudectl inherits as ignored, for example `SIGHUP`
under `nohup`, stays ignored for the child.

Claude Code also reads project, local and managed settings files, which can
set the same variables. `exec` checks `.claude/settings.json` and
`.claude/settings.local.json` in the working directory and every parent
directory (except `~/.claude` below home, which is user scope and replaced by
the private config dir), and the managed settings (`managed-settings.json` and
`managed-settings.d/`). If one sets such a variable in `env`, sets
`CLAUDE_CONFIG_DIR` or `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR` in `env`
(they would replace the private directory or the token descriptor), or sets
`apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport` or `gcpAuthRefresh`,
`exec` refuses; run it from another directory. Arguments after `--` are passed
as given, so do not pass `--settings` with such values.

`exec` never refreshes a token. It refuses, and starts no child, when:

- the profile is the active profile, shares its refresh grant with the live login, or is the same account as the live login (exit 5);
- claudectl cannot tell which account the live login uses, or the live login changes while `exec` prepares the run (exit 5);
- the saved credentials are unreadable, have no access token, or change while `exec` prepares the run (exit 5);
- a settings file Claude Code would load sets a credential, provider or endpoint, sets `CLAUDE_CONFIG_DIR` or the token descriptor variable, or cannot be read or parsed (exit 5);
- the token has expired (run `claudectl status <alias>` to refresh it), or expires within `--min-valid` (default `30m`). claudectl refreshes a saved token only after it expires, so retry after it expires and run `claudectl status <alias>`. `claudectl login <alias>` also gives a fresh token, but it makes that profile active; switch back with `claudectl use` before running `exec` (exit 5);
- another `exec` run is active in the same process, or the auth state stays locked (exit 5);
- the profile has no saved `accountUuid`, the token's account differs from it or from `--expect-account`, or the account lookup fails (exit 3);
- the executable's SHA-256 differs from `--expect-sha256`, the executable changes after it is hashed, or the running claudectl does not match its own path (exit 4);
- a receipt record cannot be written (exit 6);
- the token pipe, the private config directory or the child process cannot be created (exit 7).

A run that started but whose private config directory could not be removed, or whose descendant processes survived `SIGKILL`, exits 8 and names the child's exit code.

Otherwise it exits with the child's exit code. `exec` writes JSON receipt
records to stderr, or appends them to `--receipt <file>`: `prepared`,
`started` (with the child PID), `exited` (with the exit code, signal and
descendant teardown result), or `refused`, `spawn_failed` and
`cleanup_failed`. Each names the profile, account, executable path and
SHA-256, and the claudectl path, SHA-256 and version. Receipts never contain
tokens.

`launcher` writes a script for tools that take a `--claude-bin` path. The script
pins the profile's account and the executable's SHA-256. It also keeps a private
copy of claudectl in `<launcher>.claudectl/`, checks that copy's SHA-256 and runs
it, so a later claudectl upgrade does not change what the launcher runs.

### Lanes: one session across accounts

```bash
claudectl claude --lane review -- --dangerously-skip-permissions
claudectl claude --lane review --account amir+2@example.com
```

`claudectl claude` runs Claude Code through `exec` on a saved account, with
`CLAUDE_CONFIG_DIR` set to the lane's directory, `~/.claudectl/lanes/<lane>/config`.
Only `projects/` (session transcripts) and the start-up decisions you made in
the lane (folder trust, external CLAUDE.md imports) carry from one run to the
next. Everything else, the `.claude.json` account state included, is rebuilt
at every launch, so nothing moves from one account to another. One launcher at
a time holds a lane.

When Claude records a rate-limit error in the lane's transcript and one usage
read confirms the account is at 100% of a window, claudectl ends the run
(Claude gets `SIGTERM` and saves its session), picks the rate-limited account
with the most room that this launch has not tried, and starts it with
`--resume <session> "<recovery prompt>"`. It never picks an account that may
bill credits (`usage_based` or `unknown` in `status --json`) and stops after 3
recoveries in an hour, or when no account has room; the session stays in the
lane. An explicit `--account` that may bill credits needs a yes on the terminal
or `--allow-billing`. Without `--account`, it starts on the rate-limited
account with the most room. `--lane` names the lane; `accounts.jsonl` in the
lane records which account ran when, and `receipts.jsonl` holds the `exec`
receipts.

### Statusline

```bash
claudectl statusline   # e.g. "team 62% wk · 6d22h · 90% 5h"
```

`statusline` prints the active account's weekly room, the time to its weekly
reset and, while a 5-hour window is open, its 5-hour room. The name is the
account's label, or the alias before the `@`, cleaned to letters, digits, space,
`.`, `_` and `-` and capped at 20 characters. It only reads a small sample that
`status`, `use` and `switch` write for the active account
(`~/.claudectl/statusline.json`, no credentials), so it never touches the
network or the Keychain. It prints nothing, and exits 0, when the sample is
missing, older than 5 minutes, for another account (alias, profile or live
login account UUID),
past its weekly reset, or slow to read (150 ms). Use it as
Claude Code's status line in `~/.claude/settings.json`:

```json
{ "statusLine": { "type": "command", "command": "claudectl statusline" } }
```

### Housekeeping

```bash
claudectl list      # saved profiles, * marks active
claudectl whoami    # active profile
claudectl remove <alias>
claudectl label <alias> "Team seat"   # display label; omit the text to clear
```

A label is a display name only: `list` shows it in brackets, and `status` adds a
Label column when any account has one. It is at most 40 characters and need
not be unique. Saving the alias again keeps it.

### Shell completions

```bash
# zsh (~/.zshrc)
source <(claudectl completions zsh)

# bash (~/.bashrc)
source <(claudectl completions bash)

# fish
claudectl completions fish > ~/.config/fish/completions/claudectl.fish
```

## How it works

Profiles live under `~/.claudectl/profiles/<alias>/` as a `credentials.json`
(exactly the shape Claude Code stores) plus an `account.json` identity snapshot.
`~/.claudectl/active` tracks the profile claudectl last activated.

Two safety rules are baked in:

- **Switching captures rotated tokens first.** Claude Code refreshes tokens while it
  runs, so before overwriting the live auth, claudectl folds the live tokens back into
  the outgoing profile (only when the live identity still matches it).
- **The active profile is never auto-refreshed.** Claude Code owns the active refresh
  token; rotating it underneath Claude Code would log you out. Only non-active
  profiles with a different refresh token from the live login can be refreshed.

If `status --details` shows an expired token, follow the default view's `Next step`.
Claude Code refreshes the active login. Status can refresh saved accounts when
refresh ownership is known. Log in again when the login is missing or rejected.

## Company account server (implementation preview)

`claudectl server` connects to a private company account server and runs Claude with
access-only credentials. Claude-only users do not need Codex. See the
[commands, migration contract, and remaining pilot gates](docs/account-server.md).
