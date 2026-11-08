# Offline cron and terminal respawn check

This fixture uses the real claudectl supervisor, child process groups, PTYs,
hooks and native `hc` OSC 7501 reader. Claude, the account server and CronList
results are synthetic. It makes no provider calls and runs no scheduled prompts.
It proves recovery wiring and terminal transport, not Claude compliance or actual
scheduled fires. Jobs without an Operator card remain unverified.

Use Linux, Python 3 and native `hc` (tested with 0.1.14). Build claudectl in the
task's admitted target directory. Each restart case waits the normal 600-second
quiet window. The renewal case keeps one existing job and restores one missing
job; the failover case restores both in the new run directory. Both compare the
two definitions and schedules, require verified CronList evidence, and check
native `idle` and `working` after resume. The control case runs without claudectl.

Create a private native core and save its identity. The fixture checks this
identity before creating its own labeled terminals. Do not point it at a live
fleet core or any existing session:

```sh
probe_root=$(mktemp -d /var/tmp/flt675-core-probe-XXXXXX)
python3 - "$probe_root" <<'PY'
import json, os, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
env = dict(os.environ, HC_SESSION="flt675-offline-probe")
for key, leaf in [("XDG_CONFIG_HOME", "config"), ("XDG_STATE_HOME", "state"),
                  ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data"),
                  ("XDG_RUNTIME_DIR", "runtime")]:
    env[key] = str(root / leaf)
env.pop("HC_TERMINAL_ID", None)
status = subprocess.run(["hc", "server", "status"], env=env, check=True,
                        capture_output=True, text=True)
(root / "core.json").write_text(json.dumps({"root": str(root), "stdout": status.stdout}))
PY

python3 experiments/respawn-crons/probe.py \
  --binary /absolute/path/to/claudectl \
  --core-receipt "$probe_root/core.json" --output "$probe_root/control" \
  --case control

python3 experiments/respawn-crons/probe.py \
  --binary /absolute/path/to/claudectl \
  --core-receipt "$probe_root/core.json" --output "$probe_root/respawns" \
  --case renewal --case failover
```

Run these checks through the host testslot when required. Output directories must
be new. Each case saves native status, child launch metadata, synthetic inventories
and its result. A failed case removes only its own labeled terminal.

After all cases exit and receipts are saved, stop only this private core. This
command verifies its identity again and refuses to stop it if any terminal remains:

```sh
PYTHONPATH=experiments/respawn-crons python3 - "$probe_root/core.json" <<'PY'
import sys
from pathlib import Path
from probe import Core
core = Core(Path(sys.argv[1]))
assert not core.call("ls", "--all")["terminals"]
core.call("server", "stop")
PY
```
