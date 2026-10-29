# claudectl

Run Claude Code with accounts held by a company account server. claudectl checks
usage and selects an eligible account. The server holds refresh credentials;
connected machines receive access tokens only.

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
claudectl run
```

## Choose an Account and Resume

```sh
claudectl run work
claudectl run work --failover
claudectl run -- --resume SESSION_ID
```

An automatic run chooses an eligible account with the earliest weekly reset and
excludes accounts that may bill extra usage. Current hook-only sessions do not
automatically restart at idle or move accounts at a usage limit, including with
`--failover`. Missing input-admission proof defers renewal and failover as
`evidence_unknown`; the held token may expire while the child stays alive. After
work and cleanup finish, end the session explicitly and resume it in a new run.

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
claudectl shim install --account work
export PATH="$HOME/.local/claudectl/bin:$PATH"
```

The shim routes plain `claude` launches through the account server. Installation
prints the PATH instruction and leaves shell startup files unchanged. See the
[shim reference](docs/account-server.md#plain-claude-through-the-server-shim).

## Reference

- [Local profiles, Keychain behavior, pinned commands, and lanes](docs/cli-reference.md)
- [Shell completions](docs/cli-reference.md#shell-completions)
- [Session settings and diagnostics](docs/session-settings.md)
- [Server operations runbook](docs/account-server-runbook.md)
- [codexctl](https://github.com/Sawmills/codexctl), the companion for Codex accounts
