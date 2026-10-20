# claudectl

Run Claude Code on shared company accounts or local profiles. claudectl shows
account usage and selects the account whose week resets first. At a usage limit,
it can resume the conversation on another account. The account server
runs in production and keeps refresh credentials on the server; connected machines
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
with your company sign-in. To add an account, complete the Claude sign-in and paste the
returned code when prompted.

```sh
claudectl server connect https://accounts.example.com --name laptop
claudectl add work
claudectl status
claudectl run
claudectl run work
claudectl renew work
```

Use `renew` when the account's login needs attention. You can also add, renew, or
remove accounts and revoke machines in the server's browser dashboard after
signing in with Google.

## Choose an Account and Resume a Conversation

```sh
claudectl run work --failover
claudectl run -- --resume SESSION_ID
```

An automatic run chooses an eligible account with the earliest weekly reset. It
resumes the same conversation on another account at a usage limit and never
selects an account that may bill extra usage. A named run stays on that account
unless you add `--failover`; `--no-failover` disables recovery.

See [session settings and diagnostics](docs/session-settings.md) for per-session
Claude settings, tool PATH behavior, and the cron recovery log.

## Check Usage and Apply a Reset

```sh
claudectl status --details
claudectl status --json
claudectl resets
claudectl reset work
```

`status --cached` reads saved usage without network requests. `status --refresh`
requests fresh data but still obeys cooldowns. A reset requires a fresh exhausted
window and a usable offer; it asks for confirmation and uses the offer closest to
expiry. It is separate from billing and session recovery.

See the [usage and JSON reference](docs/cli-reference.md#check-usage-and-capacity)
for fields, cache rules, limits, and troubleshooting messages.

## Use Plain `claude` with a Server Account

```sh
claudectl shim install --account work
export PATH="$HOME/.local/claudectl/bin:$PATH"
```

The shim sends plain `claude` launches through the account server. Installation
prints the PATH instruction and leaves shell startup files unchanged. See the
[shim reference](docs/account-server.md#plain-claude-through-the-server-shim).

## Manage Accounts and Machines

```sh
claudectl rm work
claudectl server devices
claudectl server revoke MACHINE_ID
```

`rm` asks for confirmation before removing an account. `revoke` stops a machine
from getting more access tokens; tokens already issued expire on their own. Use
the ID printed by `server devices`.

## Use Local Profiles Without a Server

```sh
claudectl save work
claudectl login personal
claudectl use work
```

`save` records the current live login; `login` signs in to another account and saves
it as a profile. `use` switches the live login locally. Claude Code owns refresh
for the active profile. See [local profiles and CLI reference](docs/cli-reference.md)
for Keychain preflight, pinned commands, lanes, rate reports, and the status line.

## Shell Completions

```sh
source <(claudectl completions zsh)
```

Other supported shells: `bash`, `elvish`, `fish`, and `powershell`.

## Reference

- [Account server commands, sessions, and migration](docs/account-server.md)
- [Server operations runbook](docs/account-server-runbook.md)
- [Session settings and diagnostics](docs/session-settings.md)
- [Local profiles, usage JSON, lanes, and credential behavior](docs/cli-reference.md)
- [codexctl](https://github.com/Sawmills/codexctl), the companion for Codex accounts
