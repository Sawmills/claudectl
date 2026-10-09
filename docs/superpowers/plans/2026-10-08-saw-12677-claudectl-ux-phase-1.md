# SAW-12677: claudectl UX phase 1

Source: `~/Code/.fleet/codexctl/claudectl-ux-review.md` (sections 1 to 4). One PR, from main 3e9fc71; rebased on #56 (shim) after it merges.

## Core: one shared model (new `src/accounts.rs`, lib)

- `resolve(input, names) -> Result<&str>`: exact (case-insensitive), then email local part (`amir2`), then unique prefix. No match or ambiguity: an error that lists the accounts, says `did you mean <x>?` when one is close, and ends with `Try: claudectl status`.
- `state(windows) -> State`: `Ready`, `Low { window }` (any window above 80%), `Limit { window, resets_at }` (any window at 100%). Windows: 5h, week, Fable (`fable_weekly()`), and Opus/Sonnet weekly when present.
- `best(rows) -> Option<&Row>`: excludes `Limit`, stale or unknown usage, and any usage-billed account; then the most room (lowest highest-window use); tie: the soonest week reset. The CLI status, `run` with no account, and the dashboard all call these two functions, so they cannot disagree.

## CLI

1. `claudectl` with no arguments runs the compact status (the subcommand becomes optional).
2. Compact status (default): one line per account, `Account | 5h | Week | Fable | Resets | State`, short names (local part when all accounts share a domain), `→` on `best`, `*` on the active local login. One `Next:` line. The disclaimer footer and the `Data` column move to `--details` (kept there, unchanged).
3. Top-level `run [account] [-- args]` = `server run` with `resolve` or `best` (no failover yet; Phase 2). `add <name>` = `server login`, `renew <account>` = `server renew`, `rm <account>` = `server remove` with a confirmation and `--yes`.
4. Hidden, still working: `qualify`, `refresh-access`, `complete-login`, `statusline`, `server statusline`, and `migrate --abort` (`#[command(hide = true)]`). Nothing is removed; a test runs each old command's `--help`.
5. `server status <account>`: human reset times (`in 11h 52m (Fri 08:10)`) and a Fable row; `resolve` for the name.
6. Errors: `Try: <command>` on the seven messages in review item 6; a test lists user-path `bail!`s that lack one.
7. Help: a one-line description for every argument; an example each for `run`, `add`, `status`.

## Dashboard

- Snapshot gains the Fable window; `render` uses `accounts::state` and `accounts::best`. "Nearly exhausted" and any 100% window no longer count as available.
- Hero: `Use amir3` with the rooms left and the next reset, and a copy button for `claudectl run amir3`. The count moves below it.
- The migration subtitle shows only for `pending` and `unrotated`. One "Updated N s ago"; no repeated refresh or "POSIX shell syntax." notes.

## Tests (devbox, rule 67)

- `accounts`: resolve (exact, local part, prefix, ambiguous, did-you-mean), state (Fable at 100% is a limit), best (excludes limit, stale, billed; tie rule).
- CLI snapshots: compact table, no-args, did-you-mean error, `server status` times, old commands still parse.
- Render: Fable limit is not available; hero names `best`; empty and all-limited states.

## Evidence for Amir in the PR

Before and after terminal output (`claudectl`, `status`, a bad name, `server status`), and dashboard screenshots (light, dark, 360 px), all with synthetic data.

## Open points for HQ

1. `rm` asks for confirmation and accepts `--yes`. Recommend yes.
2. `run` with no account never picks a usage-billed account, and refuses with the list when none has room. Recommend yes.
3. Hidden commands print no deprecation note in Phase 1 (Phase 2 adds one). Recommend yes.
