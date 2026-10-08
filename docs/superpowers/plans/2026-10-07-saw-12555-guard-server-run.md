# SAW-12555: capacity guard moves idle Claude tabs to server accounts

Scope: the claudectl side. The guard runner (w9W:pG) belongs to the guide; this plan fixes the interface it calls. The guard keeps its own idle check (never a working tab, never an open menu), its one-tab-at-a-time order, and its verification.

## Facts the design rests on

- `claudectl use` and the guard switch the host Keychain login, which goes through `ensure_local`; a migrated account is refused there by design, and that stays.
- `claudectl server run <alias> -- <claude args>` starts Claude with a private config dir whose `projects` links to `~/.claudectl/server/conversations/<account_id>`, bound to that account. A tab that started on the host login keeps its transcript in `~/.claude/projects/<cwd-slug>/<session>.jsonl`, so `--resume <session>` under `server run` does not find it today.
- `server run` refuses inherited credential or routing variables and the `--settings`, `--setting-sources` and `--bare` flags.

## Interface (all JSON, no token ever printed or written outside the server path)

1. `claudectl capacity --json`: one list of candidates.
   - Local profiles: alias, `kind: "local"`, active flag, 5 h and 7 d utilization and resets, `usable`, and the billing fields from `status --json` (SAW-12468).
   - Server accounts: alias, `kind: "server"`, account_id, `available`, 5 h and 7 d from the server usage route (server cache; `stale` when the server cannot answer), and `qualified: true|false` for the host's Claude build (K3).
   - `auto_select: false` for any account that would bill usage (same rule as `claudectl claude`: never auto-select usage-billed accounts), and for a server account when the build is not qualified or the account is not available.
2. `claudectl server handoff --json <alias> --session <id> --cwd <dir> -- <claude args>`: prepares one idle tab's move to a server account.
   - Checks: `<alias>` is a migrated server account on this machine; the session transcript exists under `~/.claude/projects/<slug>/`; the args contain none of the refused flags.
   - Copies the transcript (and its `<session>/` subagent folder, if present) into the account's conversation store under the server lock; idempotent for an identical copy; refuses when a different file with that session id already exists there.
   - Prints `{"argv": ["claudectl","server","run","<alias>","--", <args without --resume/--continue/-r/-c>, "--resume","<id>"], "cwd": "<dir>", "env_clear": ["<names server run refuses>"]}`. The guard runs exactly that argv in the tab's shell, in that cwd, without those variables.
3. `claudectl server handback --json <alias> --session <id> --cwd <dir> -- <claude args>`: the reverse for the drill and for moving back when local room returns: copies the (now longer) transcript back to `~/.claude/projects/<slug>/` (refuses if the local file changed since the handoff) and prints the local `claude --resume <id>` argv.

Never: write a server token into the Keychain or `~/.claude/.credentials.json`, refresh a server grant locally, or select an account the guard must not use. The server stays the only refresh owner.

## Tests (test-first, temporary homes, synthetic server)

- `capacity --json`: local + server rows; billed and unqualified rows have `auto_select: false`; server down = server rows `stale`, local rows still listed.
- `handoff`: transcript copied and argv exact (old `--resume` stripped, refused flags refused); idempotent rerun; a conflicting transcript refused; a non-server alias refused.
- `handback`: copies back, refuses a locally changed transcript.
- No Keychain or credentials file is touched (the Linux file store stays byte-identical).

## Drill (done line)

On the Mac, with the guide: pick one idle tab, `handoff` to `amir@`, relaunch, the conversation continues (`--resume`), then `handback` and relaunch on the local login. Evidence: pane output, server audit `issue` to `mac-mini`.

## Open points for the rule 57 challenge

1. Copy, not move, of the transcript (the original stays for a rollback). Recommendation: copy.
2. Three commands vs one `capacity --json` that also emits relaunch argv. Recommendation: three; `handoff` has a side effect (the copy) and should be explicit.
3. Server usage freshness: live call with the server's cache vs local cache only. Recommendation: live (the guard polls every 5 min; the server rate-limits provider calls).

## HQ rule 57 changes (17:4x PDT), binding for the build

- M1: find the transcript as `*/<id>.jsonl` under a `--projects-root` (host `~/.claude/projects`, lane `~/.claudectl/lanes/<lane>/config/projects`, or `CLAUDE_CONFIG_DIR`); exactly one match or refuse; reuse that slug directory name in `conversations/<account_id>/<slug>/<id>.jsonl` (never recompute it from `--cwd`); refuse a lane tab while its lane lock is held.
- M2: one stateless prefix rule in both directions: overwrite only when the destination is a byte prefix of the source, else refuse; temp file and rename under the server lock.
- M3: `env_clear` is a fixed list of known names (always `CLAUDE_CONFIG_DIR`, `ANTHROPIC_API_KEY` and the other names `server run` refuses), not computed from the guard's environment. Contract: any `server run` refusal means the guard relaunches the local `claude --resume <id>` (fail closed).
- M4: seed the onboarding and trust keys in server sessions (as `exec::seed_claude_json` does), or prove in the drill that no theme or trust prompt appears.
- M5: server rows take `billing_class` from `data.extra_usage` through the `status.rs` billing function; stale, errored or login-required rows have `auto_select: false`; a test proves a stale server row is never auto-selected.
- M6: document the order (idle, exit Claude, handoff, relaunch); check size and mtime before and after the copy; strip `--resume=X`, `-r [X]`, `--continue`, `--session-id`, `--fork-session` and refuse unknown forms; the drill proves the session id is unchanged after the server `--resume`; document that file history and todos do not move.
