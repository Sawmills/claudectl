# claudectl v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** CLI to manage multiple Claude Code accounts — save profiles, switch live auth (Keychain + files), show rate-limit status across all accounts.

**Architecture:** Rust crate mirroring codexctl (`~/Code/codexctl` is the reference implementation — same module layout, same testable-`Paths` pattern). New pieces vs codexctl: a `auth_store` seam because macOS Claude Code keeps credentials in the login Keychain _and_ `~/.claude/.credentials.json` plus identity in `~/.claude.json#oauthAccount`; an `oauth` module implementing the Anthropic PKCE login flow; opaque tokens (no JWT decoding — expiry is `expiresAt` ms in the credential blob).

**Tech Stack:** clap 4 + clap_complete, serde/serde_json, reqwest (blocking+async, rustls), tokio, futures, dialoguer (fuzzy-select), comfy-table, chrono, dirs, anyhow, sha2 + base64 + rand (PKCE), tempfile (dev).

**Spec:** `docs/superpowers/specs/2026-06-09-claudectl-design.md`. Read it first — especially "Verified facts" (real credential/usage JSON shapes) and the never-refresh-active-profile rule.

**Constants (used across tasks):**

```rust
pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
pub const TOKEN_URL: &str = "https://console.anthropic.com/v1/oauth/token";
pub const REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";
pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const OAUTH_BETA_HEADER: (&str, &str) = ("anthropic-beta", "oauth-2025-04-20");
pub const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";
```

---

### Task 1: Scaffold crate + CLI skeleton

**Files:**

- Create: `Cargo.toml`, `rustfmt.toml`, `.gitignore`, `src/main.rs`, `src/lib.rs`, and empty module files `src/{config,api,auth_store,oauth,profile}.rs`, `src/commands/mod.rs`

- [ ] **Step 1: Cargo.toml** — codexctl's minus PTY deps (`portable-pty`, `vt100`, `crossterm`, `libc`), plus `sha2 = "0.10"`, `rand = "0.9"`, `open = "5"`, `urlencoding = "2"`. Package name `claudectl`, version `0.1.0`, edition 2024, description "Manage multiple Claude Code accounts", license Apache-2.0. Copy `rustfmt.toml` from codexctl. `.gitignore`: `/target`.
- [ ] **Step 2: CLI skeleton in `src/main.rs`** — clap derive, mirroring codexctl `main.rs` minus `Codex`/filter flags:

```rust
mod api; mod auth_store; mod commands; mod config; mod oauth; mod profile;

use clap::{Parser, Subcommand};
use clap_complete::Shell;

#[derive(Parser)]
#[command(name = "claudectl", about = "Manage multiple Claude Code accounts")]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show rate limit status for all accounts
    Status,
    /// Log into a Claude account via OAuth and save it as a profile
    Login { alias: String },
    /// Save the current live Claude Code login as a profile
    Save { alias: Option<String> },
    /// Switch to a profile by alias (or most available if omitted)
    Use { alias: Option<String> },
    /// Interactive fuzzy picker to switch accounts
    Switch,
    /// List saved profiles
    List,
    /// Remove a saved profile
    Remove { alias: String },
    /// Show current active account
    Whoami,
    /// Generate shell completions
    Completions { shell: Shell },
}
```

`main()` identical shape to codexctl's: `config::ensure_dirs()` then match → `commands::<cmd>::run(...)`, `eprintln!("error: {e:#}")` + exit 1 on Err. Stub each command module with `pub fn run(...) -> anyhow::Result<()> { anyhow::bail!("not implemented") }`.

- [ ] **Step 3: Verify** — `cargo build` then `cargo run -- --help` lists all 9 subcommands.
- [ ] **Step 4: Commit** — `feat: scaffold claudectl CLI skeleton`

### Task 2: config.rs — Paths

**Files:** Create: `src/config.rs` (tests inline)

- [ ] **Step 1: Failing tests** — `paths_layout()` asserting, for `Paths::from_home("/h")`: `claudectl_dir()=/h/.claudectl`, `profiles_dir()=/h/.claudectl/profiles`, `active_file()=/h/.claudectl/active`, `claude_credentials_file()=/h/.claude/.credentials.json`, `claude_json()=/h/.claude.json`. And `ensure_dirs_creates_profiles_dir()` with `tempfile::tempdir()`.
- [ ] **Step 2: Implement** — copy codexctl `src/config.rs` structure: `Paths { home }`, the five methods above, `ensure_dirs()` (creates `profiles_dir`), `default_paths()` via `dirs::home_dir()`. No login-homes dir (claudectl has none). Keep the thin `default_paths()` delegating helpers only as needed by later tasks.
- [ ] **Step 3: `cargo test`** → PASS. **Commit** — `feat: add Paths config with claude file locations`

### Task 3: api.rs — credential + usage types (parsing only)

**Files:** Create: `src/api.rs` (tests inline with real-shape fixtures from the spec)

- [ ] **Step 1: Failing tests**
  - `credentials_round_trip_preserves_unknown_fields`: parse `{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":1781087528419,"scopes":["user:inference"],"subscriptionType":"team","rateLimitTier":"t","futureField":7}}`, serialize back, assert `futureField` survives and `accessToken` field name is camelCase in output.
  - `usage_parses_real_response`: the exact JSON from the spec's Verified facts (including nulls and unknown experiment keys) parses; `five_hour.utilization == Some(6.0)`; `seven_day_opus.is_none()`; `reset_timestamp()` of `five_hour` equals the RFC3339 instant.
  - `expired_detection`: `OauthCreds::is_expired()` true when `expires_at` (ms) < now, false when in future or None.
- [ ] **Step 2: Implement types**

```rust
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct OauthCreds {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>, // ms epoch
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    pub subscription_type: Option<String>,
    pub rate_limit_tier: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CredentialsFile {
    #[serde(rename = "claudeAiOauth")]
    pub claude_ai_oauth: OauthCreds,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Clone)]
pub struct UsageWindow { pub utilization: Option<f64>, pub resets_at: Option<String> }

#[derive(Deserialize, Clone, Default)]
pub struct UsageResponse {
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
    pub seven_day_opus: Option<UsageWindow>,
    pub seven_day_sonnet: Option<UsageWindow>,
    pub extra_usage: Option<ExtraUsage>,
}

#[derive(Deserialize, Clone)]
pub struct ExtraUsage { pub is_enabled: Option<bool>, pub used_credits: Option<f64> }
```

`UsageWindow::reset_timestamp() -> Option<i64>` parses `resets_at` RFC3339 → unix secs. `OauthCreds::is_expired()` compares `expires_at` ms to `chrono::Utc::now().timestamp_millis()`; `expiry_secs() -> Option<i64>` = `expires_at / 1000`. Skip-serializing nones: add `#[serde(skip_serializing_if = "Option::is_none")]` on optional fields so round-trips don't inject nulls Claude Code never wrote.

- [ ] **Step 3: `cargo test`** → PASS. **Commit** — `feat: credential and usage response types`

### Task 4: auth_store.rs — live auth read/write seam

**Files:** Create: `src/auth_store.rs` (tests inline, tempdir-based, keychain disabled)

Design: one struct, keychain optionally enabled — tests run file-only, the real store enables keychain on macOS.

```rust
pub struct AuthStore { paths: Paths, keychain: bool }

impl AuthStore {
    pub fn real(paths: Paths) -> Self { Self { keychain: cfg!(target_os = "macos"), paths } }
    pub fn file_only(paths: Paths) -> Self { Self { keychain: false, paths } }

    pub fn read_credentials(&self) -> Result<CredentialsFile>;   // keychain first, file fallback
    pub fn write_credentials(&self, creds: &CredentialsFile) -> Result<()>; // both targets
    pub fn read_oauth_account(&self) -> Result<Option<serde_json::Value>>;  // ~/.claude.json#oauthAccount
    pub fn write_oauth_account(&self, account: &serde_json::Value) -> Result<()>; // surgical
}
```

- Keychain read: `security find-generic-password -s "Claude Code-credentials" -w` via `std::process::Command`; non-zero exit → fall through to file. Keychain write: `security add-generic-password -U -a $USER -s "Claude Code-credentials" -w <json>`; failure → hard error with hint ("keychain locked?").
- File writes are atomic: write `<path>.tmp`, set mode 600 (`std::os::unix::fs::PermissionsExt`), `fs::rename`. Create parent dirs.
- `write_oauth_account`: parse `~/.claude.json` as `serde_json::Value` (error if malformed — abort, per spec "no partial switches"), set `obj["oauthAccount"]`, write back pretty + atomic. Missing file → create `{"oauthAccount": ...}`.

- [ ] **Step 1: Failing tests** (all with `AuthStore::file_only` + tempdir): `write_then_read_credentials_round_trips`; `write_credentials_sets_0600`; `write_oauth_account_preserves_other_keys` (seed claude.json with `{"oauthAccount": {"emailAddress":"old@x"}, "numStartups": 5, "projects": {"/a": {}}}`, write new account, assert `numStartups`/`projects` intact and email updated); `read_credentials_missing_everything_errors` (message contains "no live Claude Code login"); `write_oauth_account_rejects_malformed_claude_json`.
- [ ] **Step 2: Implement** per design above.
- [ ] **Step 3: `cargo test`** → PASS. **Commit** — `feat: auth store for keychain + file credential storage`

### Task 5: profile.rs — CRUD, active, switch with capture

**Files:** Create: `src/profile.rs` (tests inline)

Storage per spec: `profiles/<alias>/credentials.json` (CredentialsFile shape) + `profiles/<alias>/account.json`:

```rust
#[derive(Serialize, Deserialize, Clone)]
pub struct AccountMeta {
    pub alias: String,
    pub saved_at: String,
    /// oauthAccount blob from ~/.claude.json (None when login couldn't fetch identity)
    pub oauth_account: Option<serde_json::Value>,
}
impl AccountMeta {
    pub fn email(&self) -> Option<&str> { self.oauth_account.as_ref()?.get("emailAddress")?.as_str() }
    pub fn account_uuid(&self) -> Option<&str> { self.oauth_account.as_ref()?.get("accountUuid")?.as_str() }
}
pub struct Profile { pub meta: AccountMeta, pub dir: PathBuf }
impl Profile {
    pub fn credentials_path(&self) -> PathBuf { self.dir.join("credentials.json") }
    pub fn read_credentials(&self) -> Result<CredentialsFile>;
    pub fn write_credentials(&self, creds: &CredentialsFile) -> Result<()>;
}
```

Functions (all `_from(paths: &Paths, ...)` + thin default wrappers, codexctl style): `list_profiles_from`, `get_profile_from`, `save_profile_to(paths, alias, creds, oauth_account)`, `delete_profile_from`, `get_active_from`/`set_active_from` (+ `clear_active_from`), and the core:

```rust
/// Switch live auth to `alias`. Returns the profile's email for display.
pub fn switch_to(store: &AuthStore, paths: &Paths, alias: &str) -> Result<String> {
    let profile = get_profile_from(paths, alias)?;
    let creds = profile.read_credentials()?;
    capture_outgoing(store, paths); // best-effort, warns on stderr, never blocks
    store.write_credentials(&creds)?;
    if let Some(account) = &profile.meta.oauth_account {
        store.write_oauth_account(account)?;
    }
    set_active_from(paths, alias)?;
    Ok(profile.meta.email().unwrap_or("unknown").to_string())
}

/// Fold Claude-Code-rotated tokens back into the outgoing profile, but only when
/// the live identity still matches the profile (guard: accountUuid, falling back
/// to emailAddress, from live ~/.claude.json vs the profile's account.json).
fn capture_outgoing(store: &AuthStore, paths: &Paths) { ... }
```

`capture_outgoing` logic: `get_active_from` → `get_profile_from` → live `store.read_oauth_account()` → compare `accountUuid` (or email when either uuid missing) → match: `profile.write_credentials(&store.read_credentials()?)` and refresh `oauth_account` in account.json; mismatch: `eprintln!("warning: live login ({live}) does not match active profile '{alias}' ({prof}); skipping token capture")`. Any read error → silently skip (nothing to capture).

- [ ] **Step 1: Failing tests** (tempdir + `AuthStore::file_only`): `save_list_get_delete_round_trip`; `active_tracking` (none → set → get → clear); `switch_writes_credentials_and_oauth_account` (live files updated, active set); `switch_captures_rotated_tokens_into_outgoing_profile` (save profile A, activate, mutate live credentials' accessToken to simulate Claude Code rotation, switch to B → profile A's stored credentials now hold the rotated token); `switch_skips_capture_when_live_identity_differs` (live oauthAccount has different accountUuid → profile A untouched); `switch_fails_before_writing_when_target_missing`.
- [ ] **Step 2: Implement.** Alias validation helper `commands/alias.rs` comes in Task 7 — here only `validate_alias(s: &str) -> Result<&str>` (trimmed, non-empty, no `/`), used by save.
- [ ] **Step 3: `cargo test`** → PASS. **Commit** — `feat: profile CRUD and switch with rotated-token capture`

### Task 6: api.rs — network calls (usage, refresh, profile identity)

**Files:** Modify: `src/api.rs`

- [ ] **Step 1: Implement** (no unit tests beyond Task 3's parsers — these are thin HTTP wrappers, verified manually in Task 12):

```rust
pub async fn fetch_usage_async(client: &reqwest::Client, access_token: &str) -> Result<UsageResponse> {
    let resp = client.get(USAGE_URL)
        .bearer_auth(access_token)
        .header(OAUTH_BETA_HEADER.0, OAUTH_BETA_HEADER.1)
        .send().await.context("failed to reach usage API")?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        anyhow::bail!("expired");
    }
    if !status.is_success() { anyhow::bail!("API returned {status}"); }
    resp.json().await.context("failed to parse usage response")
}

/// Refresh-token grant. Returns new creds preserving metadata from `old`.
/// CALLER CONTRACT: never call for the active profile (spec: Claude Code owns
/// that refresh token; rotating it logs the user out).
pub fn refresh_credentials(old: &OauthCreds) -> Result<OauthCreds>;
// blocking POST TOKEN_URL json {"grant_type":"refresh_token","refresh_token":..,"client_id":CLIENT_ID}
// → {"access_token","refresh_token","expires_in"} ; expires_at = now_ms + expires_in*1000
// carry over scopes/subscription_type/rate_limit_tier/extra from `old`.
// Also: async twin refresh_credentials_async(client, old) for status path.

/// GET PROFILE_URL → map to an oauthAccount-shaped Value:
/// {accountUuid: account.uuid, emailAddress: account.email_address,
///  organizationUuid: organization.uuid, organizationName: organization.name}
/// Returns Ok(None) on any non-success (identity is best-effort for login).
pub fn fetch_oauth_account(access_token: &str) -> Result<Option<serde_json::Value>>;
```

- [ ] **Step 2: `cargo build` + `cargo test`** still green. **Commit** — `feat: usage fetch, token refresh, identity lookup`

### Task 7: simple commands — alias, save, list, whoami, remove

**Files:** Create: `src/commands/{alias,save,list,whoami,remove}.rs`; Modify: `src/commands/mod.rs`, `src/main.rs` (wire real impls)

- [ ] **Step 1: Failing tests** — in `profile.rs`-level terms these are covered; command-level tests only for pure logic: `alias::normalize` (trims; rejects empty, `/`); `save::default_alias_from_account` (oauthAccount → emailAddress; None → error "no email found; pass an alias").
- [ ] **Step 2: Implement**
  - `save::run(alias: Option<&str>)`: `store.read_credentials()?` + `store.read_oauth_account()?`; alias = given or `emailAddress`; `profile::save_profile_to`; if no active is set and live identity matches the just-saved profile, also `set_active`; print `saved profile '<alias>' (<email>)`.
  - `list::run()`: rows `alias  email  saved_at` (plain println, codexctl list style), `*` on active.
  - `whoami::run()`: print active alias + email, or "no active profile".
  - `remove::run(alias)`: delete; if it was active, `clear_active` + warn.
- [ ] **Step 3: `cargo test`**; manual smoke: `cargo run -- save` (against the real machine — expect it to snapshot the live login), `cargo run -- list`, `cargo run -- whoami`. **Commit** — `feat: save, list, whoami, remove commands`

### Task 8: status command

**Files:** Create: `src/commands/status.rs`; Modify: `src/main.rs`

Single account table (no usage-based split — all claude.ai accounts are subscription):

```
Account | 5h | 5h Reset | 7d | 7d Reset | Opus 7d | Sonnet 7d | Token
```

Struct + scoring (tests target these):

```rust
struct AccountStatus {
    alias: String,
    h5_pct: Option<f64>, d7_pct: Option<f64>,
    h5_reset: String, d7_reset: String,
    opus_pct: Option<f64>, sonnet_pct: Option<f64>,
    token_expiry_secs: Option<i64>,
    is_active: bool, is_error: bool, error_msg: String,
}
impl AccountStatus {
    fn availability_score(&self) -> f64 { /* codexctl semantics:
        error → 1000; both ≥100 → 900; d7 ≥100 → 700+h5; h5 ≥100 → 500+d7; else h5*2+d7 */ }
}
```

Flow in `run()`: list profiles → tokio runtime → per profile in parallel: creds = live store read when active else profile file; if **non-active && is_expired && refresh_token present** → `refresh_credentials_async`, persist to profile (each task writes its own dir — no contention), then `fetch_usage_async`. Map errors: "expired" → red `expired` token cell; other → `error` row. Sort by `availability_score`. Render with comfy-table `UTF8_FULL_CONDENSED`; reuse codexctl's `format_window_reset`/`format_duration`/`colorize_usage` (copy them — they're free functions; adjust `reset_timestamp` source to `UsageWindow`). Opus/Sonnet columns included only when any row has data (`Table::set_header` chosen dynamically; cells `-` when absent). Token cell: from `expiry_secs` — green ≥1d, yellow ≥1h, red <1h, red `expired` when past.

- [ ] **Step 1: Failing tests** — `availability_score_orders_correctly` (fresh < busy < h5-exhausted < d7-exhausted < both < error); `render_row_column_count` (8 cols with opus/sonnet shown, 6 without); `format_duration` cases (`3d 4h`, `2h 05m`, `9m`); `colorize_usage` boundaries (49→green, 50/79→yellow, 80→red).
- [ ] **Step 2: Implement.** **Step 3: `cargo test`** → PASS; manual: `cargo run -- status` against the real saved profile shows live percentages. **Commit** — `feat: status command with parallel usage fetch`

### Task 9: use + switch commands (auto-select)

**Files:** Create: `src/commands/{use_profile,switch}.rs`; Modify: `src/main.rs`

- [ ] **Step 1: Failing tests** — selection is pure:

```rust
struct Candidate { alias: String, score: f64, d7_reset_ts: i64 } // score = max(h5, d7) utilization; errors → f64::MAX
fn select_most_available(c: &[Candidate]) -> Option<&str>
// lowest score; tie (|a-b| < 0.5) → soonest d7_reset_ts; all MAX → None
```

Tests: picks lowest max-utilization; tie broken by soonest 7d reset; skips errored (MAX) candidates entirely; returns None when all errored.

- [ ] **Step 2: Implement**
  - `use_profile::run(alias: Option<&str>)`: Some → `profile::switch_to`, print `switched to <alias> (<email>)`. None → refresh-then-fetch usages for all profiles (same path as status — extract a shared `fetch_all_usages` helper in `status.rs`), score, select, switch, print `auto-selected most available: <alias> (<email>)`. After either, print the selected account's fresh status row (reuse status rendering on the already-fetched data for auto-select; re-fetch single for direct).
  - `switch::run()`: `dialoguer::FuzzySelect` over `alias (email)` items, default at active, then delegate to `use_profile::run(Some(picked))`. Non-tty → error "no TTY; use 'claudectl use <alias>'".
- [ ] **Step 3: `cargo test`** → PASS; manual: `cargo run -- use <real-alias>` then `claude` shows the right account; switch back. **Commit** — `feat: use and switch commands with auto-select`

### Task 10: oauth.rs + login command

**Files:** Create: `src/oauth.rs`, `src/commands/login.rs`; Modify: `src/main.rs`

- [ ] **Step 1: Failing tests** (pure parts):
  - `pkce_challenge_matches_rfc7636_vector`: verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` → challenge `E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM`.
  - `authorize_url_contains_required_params`: built URL has `code=true`, `client_id`, `response_type=code`, `redirect_uri`, `code_challenge`, `code_challenge_method=S256`, `state`, `scope`.
  - `parse_pasted_code_splits_code_and_state`: `"abc#xyz"` → `("abc","xyz")`; missing `#` → code only, state falls back to our generated state.
- [ ] **Step 2: Implement `oauth.rs`**

```rust
pub struct PkcePair { pub verifier: String, pub challenge: String }
pub fn generate_pkce() -> PkcePair  // 64 random bytes → base64url-no-pad verifier; challenge = b64url(sha256(verifier))
pub fn build_authorize_url(challenge: &str, state: &str) -> String
// scopes: "org:create_api_key user:profile user:inference" (space-separated, urlencoded)
pub fn exchange_code(code: &str, state: &str, verifier: &str) -> Result<OauthCreds>
// blocking POST TOKEN_URL json {"grant_type":"authorization_code","code","state","client_id","redirect_uri","code_verifier"}
// → access_token, refresh_token, expires_in (→ expires_at ms), scopes if present
```

- [ ] **Step 3: Implement `login::run(alias)`** — generate pkce + random state; `open::that(url)` (and print the URL for manual copy); prompt "Paste the authorization code: " (read stdin line); `exchange_code`; `api::fetch_oauth_account(&creds.access_token)` (best-effort identity); `profile::save_profile_to`; activate via `profile::switch_to`; print confirmation. If the exchange returns 4xx, error message must mention the spec fallback: "login flow rejected — log in with 'claude /login' then run 'claudectl save <alias>'".
- [ ] **Step 4: `cargo test`** → PASS. Manual verification deferred to Task 12 (needs a real second account). **Commit** — `feat: OAuth PKCE login command`

### Task 11: completions + README

**Files:** Create: `src/commands/completions.rs`, `README.md`

- [ ] **Step 1:** completions — copy codexctl's (clap_complete `generate` to stdout, `Cli::command()`).
- [ ] **Step 2:** README modeled on codexctl's: install, save/login, status (sample table), use/switch, the two safety rules users must know (switch = pure local operation; don't re-login when a profile merely shows expired — `use` first, claudectl/Claude Code refresh on demand), completions setup.
- [ ] **Step 3:** `cargo run -- completions zsh | head` sanity. **Commit** — `feat: shell completions; docs: README`

### Task 12: gate + live verification

- [ ] **Step 1:** `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` — all green (fix anything).
- [ ] **Step 2: Live round-trip on this machine** (real account, reversible):
  1. `claudectl save` → profile for amir2@sawmills.ai appears; `list`/`whoami` agree.
  2. `claudectl status` → live 5h/7d percentages match `claude` `/usage`.
  3. `claudectl use <alias>` (same account) → keychain + `.credentials.json` + `oauthAccount` all updated; `claude` still authenticated afterwards (launch + `/status`).
  4. `claudectl login <test-alias>` with a second account if available; otherwise verify the flow up to the browser URL opening and document the scope-acceptance result in the README (spec's known risk).
- [ ] **Step 3:** `git status` clean, scratch files removed. **Commit** — final fixes as needed.

---

## Self-review notes

- Spec coverage: storage layout (T5), auth_store incl. surgical claude.json (T4), all 9 commands (T1,7–11), refresh rules incl. never-refresh-active (T6 contract + T8 flow), auto-select shared refresh-then-fetch (T9 reuses T8 helper), error handling cases (T4/T8), testing strategy (each task), release workflow explicitly out of v1 (spec: "after the tool works locally").
- Types used consistently: `OauthCreds`/`CredentialsFile` (T3) consumed by T4/T5/T6/T10; `UsageResponse`/`UsageWindow` (T3) by T8/T9; `AccountMeta.oauth_account` is `serde_json::Value` everywhere.
- No placeholder steps: thin HTTP wrappers (T6) intentionally have no unit tests — verified live in T12; noted inline.
