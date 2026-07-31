READ ${CODE_ROOT:-$HOME/Code}/agent-scripts/AGENTS.md BEFORE ANYTHING (skip if missing). If missing, also try: $HOME/repos/agent-scripts/AGENTS.md

# AGENTS.md

## Project

- `claudectl` manages multiple Claude Code accounts.
- It saves profiles, switches accounts, checks rate limits, and generates shell completions.
- The package uses Rust edition 2024.
- The package is licensed under Apache-2.0.

## Map

- `src/main.rs` contains the binary entry point.
- `src/lib.rs` contains the library entry point.
- `src/commands/` contains CLI command implementations.
- `src/api.rs` contains API code.
- `src/auth_store.rs` contains credential storage code.
- `src/oauth.rs` contains OAuth code.
- `src/config.rs`, `src/profile.rs`, and `src/shell.rs` contain configuration, profile, and shell code.
- `tests/cli_test.rs` contains CLI tests.
- `README.md` documents installation, usage, and credential behavior.
- `docs/superpowers/specs/2026-06-09-claudectl-design.md` contains the design.
- `docs/superpowers/plans/2026-06-09-claudectl-v1.md` contains the existing implementation plan.

## Commands

- Format check: `cargo fmt --all -- --check`
- Lint: `cargo clippy --all-targets`
- Test: `cargo test --all-targets`
- Release build: `cargo build --release`
- Locked target release build: `cargo build --release --locked --target ${{ matrix.target }}`
- Install from Git: `cargo install --git https://github.com/Sawmills/claudectl`

## Rules

- Keep profiles under `~/.claudectl/profiles/<alias>/`.
- Store each profile as `credentials.json` plus `account.json`.
- Keep the active profile marker in `~/.claudectl/active`.
- Capture rotated live tokens into the outgoing profile before switching, but only when the live identity matches.
- Never auto-refresh the active profile. Claude Code owns its refresh token.
- Refresh only non-active profiles during status checks.
- Keep switching local. It must not contact Anthropic.
- On macOS, update the `Claude Code-credentials` Keychain entry, `~/.claude/.credentials.json`, and the `oauthAccount` identity in `~/.claude.json`.
- Run the Keychain unlock preflight before commands write live credentials.
- For `login`, run the preflight before the browser opens and before token exchange.
- Never accept, pass, store, or log a Keychain password.
- Preserve a saved profile when activation fails after OAuth.
