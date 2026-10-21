# claudectl

Run Claude Code with accounts held by a company account server. claudectl checks
usage, selects an eligible account, and can resume a conversation on another
account at a usage limit. The server holds refresh credentials; connected machines
receive access tokens only.

## Install

Install [Claude Code](https://code.claude.com/docs/en/setup), then claudectl:

```sh
brew install Sawmills/tap/claudectl
```

Or build from source with Rust:

```sh
cargo install --git https://github.com/Sawmills/claudectl
```

## Quick Start

Use the account server URL supplied by your company. Connect once per machine
with your company sign-in, then start Claude Code:

```sh
claudectl server connect https://accounts.example.com --name laptop
claudectl status
claudectl use
claude
```

`use` selects the account for new plain `claude` launches. It installs or updates
the launcher and prints one PATH line if this shell needs it. Run that line once;
claudectl leaves shell startup files unchanged. Running sessions keep their account.

## Choose an Account and Resume

```sh
claudectl use work
claudectl run work
claudectl run work --failover
claudectl run -- --resume SESSION_ID
```

Automatic `use` and `run` choose an eligible account with the earliest weekly reset.
They exclude accounts with 5% or less weekly headroom and accounts that may bill
extra usage. An automatic run resumes the conversation on
another account at a usage limit. A named run stays on that account unless you
add `--failover`; `--no-failover` disables recovery.

## Manage Accounts and Machines

```sh
claudectl add work
claudectl renew work
claudectl rm work
claudectl server devices
claudectl server revoke MACHINE_ID
```

Use `add` for a new account or `renew` when a login needs attention. Complete the
Claude sign-in and paste the returned code when prompted. `rm` asks for
confirmation. `revoke` stops the listed machine from getting more access tokens;
tokens already issued expire on their own.

The server's browser dashboard also manages accounts and machines. See the
[account server guide](docs/account-server.md) for commands and migration.

## Check Usage and Apply a Reset

```sh
claudectl status --cached
claudectl status --details
claudectl status --json
claudectl resets
claudectl reset work
```

`--cached` reads saved usage without network requests. A reset requires a fresh
exhausted window and a usable offer, then asks for confirmation. See the
[usage reference](docs/cli-reference.md#check-usage-and-capacity) for JSON fields,
cache rules, reset selection, and diagnostics.

## Use Plain `claude` with a Server Account

```sh
claudectl use work
```

The shim routes plain `claude` launches through the selected account on the account
server. `claudectl status` marks that account when PATH reaches the launcher.
Local profiles still use the local login swap. See the
[shim reference](docs/account-server.md#plain-claude-through-the-server-shim).

## Reference

- [Local profiles, Keychain behavior, pinned commands, and lanes](docs/cli-reference.md)
- [Shell completions](docs/cli-reference.md#shell-completions)
- [Session settings and diagnostics](docs/session-settings.md)
- [Server operations runbook](docs/account-server-runbook.md)
- [codexctl](https://github.com/Sawmills/codexctl), the companion for Codex accounts
