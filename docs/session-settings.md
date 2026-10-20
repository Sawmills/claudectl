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

After token renewal, Operator-card cron recovery writes its results to
`~/.claudectl/server/cron-recovery.jsonl` (mode `0600`). Each JSON line has the
time in milliseconds (`at`), the run directory name (`session`), and `message`.
Verified, missing, duplicate, skipped, and unverified results stay in this log
after the run exits. They never print over Claude's terminal or enter its input.
The log contains no tokens or saved prompt contents.

Most failures name the next command on a last line that starts with `Try:`. Setup
failures, such as a `~/.claudectl` directory that cannot be created, print only the
error.
See the [account server commands and migration](account-server.md).
