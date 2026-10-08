# SAW-12610: `server run` survives server token expiry

## Problem

Since claudectl#40, `server run` passes the server access token in `CLAUDE_CODE_OAUTH_TOKEN`, fixed for the life of the Claude process. A server token lives about 8 h. On 2026-10-08, about 10 tabs on the Mac mini failed when their tokens expired.

## What Claude Code can reload (evidence already in this repo)

`docs/superpowers/specs/2026-10-03-claudectl-credential-reload-experiment.md` (Claude 2.1.280, synthetic API) and `experiments/settings-renewal/host-config.py` (#40):

| Token source | Reloaded in the same process | Usable for `server run` |
| --- | --- | --- |
| `CLAUDE_CODE_OAUTH_TOKEN` env, OAuth descriptor | no | current design |
| `--settings <file>` env | no (host-config.py, A/401/401) | no |
| Host-managed credentials file (OAuth) | no | no |
| `<config dir>/.credentials.json` | yes, on a 401 | no: it is the host login in `~/.claude` |
| `<config dir>/settings.json` env | yes | no: it is the host's user settings |
| Generic-bearer host file, `apiKeyHelper` | yes | no: requests lose the OAuth beta header; `apiKeyHelper` sends an API-key header (billing risk) |

The only reloadable sources live in the config dir, which #40 deliberately keeps as the host's own `~/.claude`. A private overlay config dir (symlinks to the host entries plus a private `settings.json` that carries the token) would reload in place. It is rejected: it brings back a per-session Keychain item name, a copied `settings.json` that misses later host edits, and the first-run and trust risks that #40 removed.

## Choice: restart an idle Claude with `--resume` on a fresh token

`server run` already supervises the child (process group, signals, terminal foreground). It adds a renewal loop:

1. **Session and idle state from Claude Code hooks.** `server run` passes its own `--settings <session dir>/hooks.json` (users still cannot pass `--settings`). It registers command hooks for `SessionStart`, `UserPromptSubmit`, `Stop` and `Notification`. Each runs `claudectl server hook <session dir>`, which appends the event name, `session_id` and time to `<session dir>/events` (0600) and prints nothing. It never reads or writes a token.
2. **When to restart.** All of these hold:
   - less than 45 min of token life remains (or the token has expired);
   - the last event is `Stop`, or `Notification` of type `idle_prompt`, with no `UserPromptSubmit` after it;
   - that idle state has lasted at least 60 s;
   - a `session_id` is known.

   A turn in progress is never interrupted. If Claude never goes idle before expiry, the next request gets one authentication error, and the restart happens at the next idle point.
3. **Restart.** First acquire a fresh token. If the server refuses or is down, keep the current process and retry every 5 min. Then send SIGTERM to the Claude process group, wait for exit (SIGKILL after 10 s), and start Claude again in the same cwd and terminal. It gets the user's arguments with `--resume/-r [X]`, `--continue/-c`, `--session-id` and `--fork-session` removed, plus `--resume <session_id>`. The build is the same qualified snapshot. stderr gets one line: `claudectl: server token renewed; resuming session <id>`.
4. **Not covered.**
   - `-p`/`--print` runs are one-shot and never restarted.
   - A draft typed but not sent is lost on restart. The idle wait (60 s after `Stop`, or the `idle_prompt` notification) makes this rare. This limit is documented.
   - A restart budget of 3 per hour stops loops: past it, claudectl logs and stops renewing.

## Phase 0 (before code, 30 min)

Run `host-config.py` on the current Claude build (2.1.294) for `flag_proactive`, `hostfile_*` and `env_only`. If any now reloads in the same process, report it to HQ before building the restart. On the Mac, the drill confirms that hooks from `--settings` run together with the host's own hooks, and that `Stop` and `idle_prompt` carry `session_id`.

## Tests (test-first)

- Event parsing and the idle decision: Stop, then UserPromptSubmit, is busy; Stop for 60 s is idle; `idle_prompt` is idle; no session id means no restart; an unknown event is ignored.
- Argument rewrite: each resume and continue form is stripped, `--resume <id>` is added once, other arguments keep their order, and `-p` disables renewal.
- Restart decision: margin, expired token, a failed acquire (no restart, retry), the restart budget.
- `server hook`: writes only the event, session id and time, never token-shaped data. 0600, and a symlink is refused.
- Integration (fake Claude script, fake server): the first child records its token and calls the hook binary for SessionStart and Stop. The renewal fires with a short test margin. A second child starts with the new token and `--resume <id>`, and no Keychain or `~/.claude` file changes.

## Drill (done line)

On the Mac mini, with a test-only override that shortens the margin (`CLAUDECTL_TEST_RENEW_MARGIN_S`, honored only by debug builds): start `server run` with a real tab, chat, go idle, and watch the restart line. The next prompt continues the same session on the new token, and the server audit shows a second `issue`.
