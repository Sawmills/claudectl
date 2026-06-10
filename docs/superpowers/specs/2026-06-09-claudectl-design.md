# claudectl — design

2026-06-09. Approved by amir.

## Purpose

Manage multiple Claude Code accounts: save them as named profiles, switch the live
Claude Code auth between them, and see rate-limit status across all accounts at once.
Sibling tool to [codexctl](https://github.com/Sawmills/codexctl), which does the same
for OpenAI Codex.

v1 scope is **switch + status only**. No PTY wrapper / rate-limit failover launcher
(codexctl's `codexctl codex` equivalent) — possible later.

## Verified facts (probed 2026-06-09 on macOS)

- Claude Code stores OAuth credentials in **two places on macOS**: the login Keychain
  (generic password, service `Claude Code-credentials`, account = `$USER`) and
  `~/.claude/.credentials.json` (mode 600). They can diverge; the Keychain copy is the
  newer/authoritative one. On Linux only the file exists.
- Credential shape: `{"claudeAiOauth": {"accessToken": "sk-ant-oat01-...",
  "refreshToken": "sk-ant-ort01-...", "expiresAt": <ms epoch>, "scopes": [...],
  "subscriptionType": "team", "rateLimitTier": "..."}}`. Tokens are opaque, not JWTs —
  expiry comes from `expiresAt`, identity does NOT come from the token.
- Identity/metadata lives in `~/.claude.json` top-level key `oauthAccount`:
  `emailAddress`, `accountUuid`, `organizationUuid`, `organizationName`,
  `subscriptionCreatedAt`, `seatTier`, rate-limit tiers, etc. Claude Code displays
  identity from here, so a switch must swap this blob too.
- Usage endpoint: `GET https://api.anthropic.com/api/oauth/usage` with headers
  `Authorization: Bearer <accessToken>` and `anthropic-beta: oauth-2025-04-20`.
  Returns (verified live):

  ```json
  {
    "five_hour":  {"utilization": 6.0, "resets_at": "2026-06-10T07:30:00Z"},
    "seven_day":  {"utilization": 1.0, "resets_at": "2026-06-14T07:00:00Z"},
    "seven_day_opus":   null,
    "seven_day_sonnet": {"utilization": 0.0, "resets_at": null},
    "extra_usage": {"is_enabled": true, "monthly_limit": null,
                    "used_credits": 0.0, "utilization": null, "currency": "USD"}
  }
  ```

  (plus other nullable experiment fields — parser must tolerate unknown/null keys).
- Claude Code refreshes/rotates tokens on its own while running, so a profile snapshot
  goes stale while it is the active account. Same problem codexctl solves with
  capture-before-switch.

## Architecture

New Rust crate at `~/Code/claudectl`, binary `claudectl`. Structure mirrors codexctl:

```
src/
  main.rs            clap CLI, subcommand routing
  lib.rs             module re-exports
  config.rs          Paths struct (~/.claudectl layout), injectable for tests
  profile.rs         Profile CRUD, switch logic (capture + write-through)
  auth_store.rs      live-auth read/write abstraction (Keychain + files)
  api.rs             usage fetch, token refresh, response types
  oauth.rs           PKCE login flow
  commands/          one file per subcommand (login, save, use, switch, status,
                     list, remove, whoami, completions)
```

Dependencies (same set codexctl uses, minus PTY): `clap` + `clap_complete`,
`serde`/`serde_json`, `reqwest` (blocking + async), `tokio`, `dialoguer`,
`comfy-table`, `chrono`, `dirs`, `anyhow`, `sha2` + `base64` + `rand` (PKCE),
`open` (browser launch). No keychain crate — shell out to `security(1)`.

## Storage layout

```
~/.claudectl/
├── profiles/
│   └── <alias>/
│       ├── credentials.json   # {"claudeAiOauth": {...}} — same shape Claude Code uses
│       └── account.json       # {"alias", "saved_at", "oauthAccount": {...}}
└── active                     # plain-text alias of the profile claudectl last activated
```

Alias rules as in codexctl: trimmed, non-empty, no path separators; default alias is
the account email.

## auth_store module

Single seam for "the live Claude Code auth". Trait with two impls:

- **macOS (real)**: read = Keychain first (`security find-generic-password -s
  "Claude Code-credentials" -w`), fall back to `~/.claude/.credentials.json`.
  Write = both Keychain (`security add-generic-password -U`) and the file, atomically
  (temp file + rename, mode 600). Also reads/writes the `oauthAccount` key inside
  `~/.claude.json` (preserving all other keys in that file).
- **Linux (real)**: file + `~/.claude.json` only.
- **Test fake**: file-backed in a tempdir.

`~/.claude.json` edit must be surgical: parse as `serde_json::Value`, replace only
`oauthAccount`, write back. Never reshape the rest of the file.

## Commands

### `login <alias>`
Own OAuth 2.0 PKCE flow — never runs the `claude` binary, never risks clobbering
another seat:

1. Generate PKCE verifier/challenge (S256) and state.
2. Open browser to `https://claude.ai/oauth/authorize` with the Claude Code public
   client ID (`9d1c250a-e61b-44d9-88ed-5944d1962f5e`), `code=true`,
   `redirect_uri=https://console.anthropic.com/oauth/code/callback`, requested scopes.
3. User pastes the displayed `code#state` string back into the terminal.
4. Exchange at `POST https://console.anthropic.com/v1/oauth/token`
   (`grant_type=authorization_code`, code, state, client_id, redirect_uri,
   code_verifier). Response: access/refresh tokens + `expires_in`.
5. Fetch identity for `account.json` (profile endpoint or usage probe; verified
   during implementation).
6. Save profile, then activate it via the same path as `use`.

**Known risk**: the community-known scope set for this flow
(`org:create_api_key user:profile user:inference`) differs from the scopes Claude
Code currently requests (`user:sessions:claude_code`, etc.). During implementation,
verify a token from this flow (a) answers the usage endpoint and (b) is accepted by
Claude Code when written to the Keychain. Fallback: request Claude Code's exact scope
list in the authorize URL. If the flow is rejected entirely, degrade `login` to
printed instructions: "run `claude /login`, then `claudectl save <alias>`" — the rest
of the tool is unaffected.

### `save [alias]`
Snapshot live auth (via auth_store) + `oauthAccount` into a profile. Default alias =
`oauthAccount.emailAddress`. Errors if no live auth found.

### `use [alias]`
1. **Capture**: if `~/.claudectl/active` names a managed profile, read live auth and
   write it back into that profile (picks up tokens Claude Code rotated). Skip capture
   if the live account's `accountUuid`/email no longer matches the profile (user
   logged in manually over it) — leave the profile untouched and warn.
2. **Write**: target profile's credentials → Keychain + `~/.claude/.credentials.json`;
   profile's `oauthAccount` → `~/.claude.json`; update `active`.

Pure local file/Keychain operation — never contacts Anthropic.

Bare `claudectl use` auto-selects: same refresh-then-fetch path as `status` (expired
non-active profiles get a token refresh first), skip profiles that still fail, pick
lowest `max(five_hour, seven_day)` utilization; tie-break on soonest 7d reset. Prints
what it picked and why.

### `switch`
`dialoguer` fuzzy picker over profiles → `use <picked>`.

### `status`
Fetch usage for all profiles in parallel (tokio). Before fetching, auto-refresh any
**non-active** profile whose access token is expired (see Token refresh). Table
(comfy-table, UTF8_FULL_CONDENSED), sorted most-available first:

| Account | 5h | 5h Reset | 7d | 7d Reset | Opus 7d | Sonnet 7d | Token |
|---------|----|----------|----|----------|---------|-----------|-------|

- Account: alias, `*` prefix on active.
- Percent columns colored: <50 green, <80 yellow, ≥80 red. Opus/Sonnet columns shown
  only if any account has non-null data.
- Reset columns: relative (`in 3h 54m`) + absolute for the 7d window, codexctl style.
- Token: time until `expiresAt` (green days / yellow hours / red <1h), `expired` red.
- Fetch failure for one account: show `error` row, don't fail the whole table.

### `list`, `whoami`, `remove <alias>`, `completions <shell>`
As in codexctl: enumerate profiles; print active alias; delete profile dir (refuses
nothing — but warns if removing the active profile and clears `active`); clap_complete
for zsh/bash/fish.

## Token refresh

`POST https://console.anthropic.com/v1/oauth/token` with
`grant_type=refresh_token`, refresh token, client ID. Persist the rotated token pair
back into the profile immediately.

**Rule: never auto-refresh the active profile.** Claude Code owns that refresh token;
rotating it out from under Claude Code would invalidate its stored refresh token and
log the user out. The active profile is always read fresh from the live auth store
instead. Non-active profiles are safe to refresh because claudectl's copy is the only
holder of that refresh token.

## Error handling

`anyhow` with context strings, as in codexctl. Specific cases:
- No Keychain entry and no credentials file → "no live Claude Code login found".
- `security` binary errors (locked keychain, denied) surfaced verbatim with a hint.
- Usage endpoint 401 → render as `expired/invalid` in status rather than aborting.
- Malformed `~/.claude.json` → abort the switch before writing anything (no partial
  switches: credentials and identity must move together).

## Testing

- codexctl style: `Paths` injected, tempdir-based unit tests for profile CRUD,
  capture-on-switch, active tracking.
- auth_store behind a trait; tests use the file-backed fake (no Keychain in CI).
- Fixture tests for usage-response parsing (including null experiment fields) and
  for `~/.claude.json` surgical editing (other keys preserved byte-for-byte where
  JSON allows).
- Selection scoring unit tests (auto-select ordering, expired-token skip).

## Release

After the tool works locally: copy codexctl's tag-driven GitHub release workflow
(macOS arm64/x86_64 + Linux x86_64 prebuilts) and the Sawmills Homebrew-tap PR flow.
Not part of v1 implementation.

## Out of scope (v1)

- `claudectl claude` failover wrapper (PTY watch + auto-switch + resume).
- Console/API-key accounts (only claude.ai OAuth subscription accounts).
- Windows.
