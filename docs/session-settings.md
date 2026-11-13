# Session Settings and Diagnostics

New server and pinned local sessions put `~/.local/lib/lane-bin` first on PATH
when that directory exists. Any later copy of that entry is removed; all other
entries keep their order. Without the directory, PATH stays unchanged. This lets
session tools use installed lane wrappers, including the GitHub App wrapper.
Existing sessions keep their original environment until restarted.

Pass per-session Claude settings after `--`:

```bash
claudectl run work -- --settings '{"crossSessionInbound":"accept","isolatePeerMachines":true}'
claudectl server run work -- --settings ./pilot-settings.json
```

Both run commands accept repeated `--settings <JSON-or-file>` or
`--settings=<JSON-or-file>`. They merge objects in argument order; later values win,
except hook arrays are appended to preserve claudectl's renewal hooks. Claude receives
one private settings file, kept across token renewal and rebuilt after account failover.
Unreadable files, invalid JSON, credential or routing overrides, malformed hook arrays,
and `disableAllHooks: true` stop the launch. Global `~/.claude` settings are not changed.

claudectl checks JSON syntax and account isolation, not Claude's full settings schema.
Use settings valid for your installed Claude version. A schema error such as `"model": 5`
can make Claude ignore the entire merged file, including claudectl's renewal and failover
hooks. Check Claude's startup settings warnings and correct invalid values.

After token renewal or account failover, Operator-card cron recovery writes its results to
`~/.claudectl/server/cron-recovery.jsonl` (mode `0600`). Each JSON line has the
time in milliseconds (`at`), the run directory name (`session`), and `message`.
Verified, missing, duplicate, skipped, and unverified results stay in this log
after the run exits. They never print over Claude's terminal or enter its input.
The log contains no tokens or saved prompt contents.

Authentication failure or expiry restarts the same conversation on the same account
immediately, once a replacement token is available. Turns, background tasks, typing,
production markers and unrelated hook errors do not defer that recovery. Other renewals
become eligible only within five minutes of the held token's expiry and retain workload
and quiet admission. A new revision alone starts neither a restart nor its deadline.
Explicit production holds block every restart until hold end, including auth recovery. Unknown SessionEnd
intent also prevents restart, with one failure record while that uncertainty persists. Account failover still
requires ten continuous minutes of observed quiet. A forced restart can discard a draft
or background task. Recovery omits the original
task and missed fires; saved-card cron recovery
still restores its job definitions. A failed authentication resume reports an error and
stops instead of opening a different conversation. These workload samples do not close all
input sources: a late or invisible prompt can still be cut off. Claudectl does not collect
or replay prompts.

Renewal and failover also write deferred restart decisions to
`~/.claudectl/server/restart-decisions.jsonl`. A running turn, live Claude task-output
child or explicit run hold prevents ordinary restart admission. `claudectl status`, `status --json` and
the session's status line show the reason. Five minutes before token expiry the wrapper
warns; expiry or authentication failure starts recovery, except when an explicit hold or unknown SessionEnd intent vetoes restart.
See [production holds and deferred restarts](account-server.md#production-holds-and-deferred-restarts).

Most failures name the next command on a last line that starts with `Try:`. Setup
failures, such as a `~/.claudectl` directory that cannot be created, print only the
error.
See the [account server commands and migration](account-server.md).
