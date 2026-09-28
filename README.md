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
```

The table separates usage data from the result of the fetch:

- `5h`, `7d`, and model columns show the percentage of capacity used.
- `Account capacity` shows a general or model limit, or `below reported limits`.
  Missing or stale data gives an unknown capacity. A successful fetch does not
  prove that a model request will succeed.
- `Usage fetch` shows `live`, `cached`, `failed`, or `cooldown`. HTTP 429 means that
  Anthropic limited requests for usage data. A cooldown skips the request.
  Neither state proves exhausted capacity.
- `Data age` shows the age of the last successful result. After a failed fetch,
  the table retains old percentages and marks their age as stale.
- `Next fetch` shows when another check can contact the endpoint. It is separate
  from the account's five-hour and weekly reset times.
- `Token expiry` shows the stored token expiry, independently of fetch errors.
  `*` marks the active profile. Model columns appear when the endpoint reports them.

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
Aliases with the same refresh token share one refresh result per check. An alias
that shares the live login's refresh token also leaves refresh to Claude Code.

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

### Housekeeping

```bash
claudectl list      # saved profiles, * marks active
claudectl whoami    # active profile
claudectl remove <alias>
```

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

If a profile shows `expired` in `status`, just `claudectl use` it (or wait for the
auto-refresh) before reaching for a fresh `claude /login`.
