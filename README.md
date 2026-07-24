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

### Check rate limits

```bash
claudectl status
```

```
Live status fetched at Tue Jun 09 20:02:47

┌─────────────────────┬─────┬───────────┬────┬─────────────────────────────┬─────────┬───────────┬────────┐
│ Account             ┆ 5h  ┆ 5h Reset  ┆ 7d ┆ 7d Reset                    ┆ Opus 7d ┆ Sonnet 7d ┆ Token  │
╞═════════════════════╪═════╪═══════════╪════╪═════════════════════════════╪═════════╪═══════════╪════════╡
│ * amir2@sawmills.ai ┆ 22% ┆ in 4h 27m ┆ 3% ┆ in 4d 3h (Sun Jun 14 00:00) ┆ -       ┆ 0%        ┆ 7h 29m │
└─────────────────────┴─────┴───────────┴────┴─────────────────────────────┴─────────┴───────────┴────────┘
```

All accounts are fetched live in parallel and sorted most-available first. `*` marks
the active account. The `Token` column shows how long the stored access token lasts;
non-active profiles with an expired token are refreshed automatically during `status`.

### Switch accounts

```bash
claudectl use amir+2@example.com   # direct
claudectl use                      # auto-select the most available account
claudectl switch                   # interactive fuzzy picker
```

Switching is a pure local operation (Keychain + files); it never contacts Anthropic.
It runs the same [Keychain preflight](#macos-keychain-preflight) before touching the
live auth. On macOS it updates the `Claude Code-credentials` Keychain entry,
`~/.claude/.credentials.json`, and the `oauthAccount` identity in `~/.claude.json` —
so Claude Code shows the right account immediately.

Auto-select picks the profile with the lowest `max(5h, 7d)` utilization, breaking
near-ties toward the soonest 7d reset.

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
  profiles are refreshed, and claudectl is the only holder of those tokens.

If a profile shows `expired` in `status`, just `claudectl use` it (or wait for the
auto-refresh) before reaching for a fresh `claude /login`.
