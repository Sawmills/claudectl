# SAW-12595: `server run` qualifies an unknown Claude build on first use

## Problem

Claude Code updates itself. On 2026-10-07 at about 22:5x PDT, the Mac mini moved to 2.1.294. `claudectl server run` refused the new build because it was not in `qualified-host-config-builds.json`. The guide's tab move fell back to the local login until HQ ran `claudectl server qualify` by hand.

## Choice: option 1 (qualify on first use, inside `server run`)

- Cost: one qualification takes 15 seconds on the Mac mini (measured 2026-10-08, Claude 2.1.294, throwaway HOME). Only the first launch after an update pays it.
- Option 2 (a launchd or brew hook after each update) is rejected. It needs per-host setup, and it races: a tab that starts before the hook finishes is still refused.
- Option 3 (pin Claude Code updates) is rejected. It stops security and model updates and needs a manual step for each release.

## Behavior

In `server run`, the qualification check of the resolved build (before the snapshot) changes from "refuse" to:

1. If the build is built in or qualified: continue (no change).
2. Otherwise, take `~/.claudectl/server/qualify.lock` (an exclusive file lock, separate from `state.lock`). Other tabs that start at the same time wait on it. After the lock is held, read the list again: another tab may have qualified the build already.
3. If a failure record for this digest is younger than 1 hour (`qualify-failures.json`: sha256, platform, check, failed_at), refuse at once and name `claudectl server qualify` (which always runs the check again). This stops every tab from rerunning a failing 15 s check.
4. Run the same harness as `server qualify` (`qualify_with`) on a private snapshot of the build. On a pass, record it (no change to the record format). On a fail or an error (no `python3`, no `unshare`, a harness crash), record the failure and refuse.
5. Print one stderr line before the check: `claudectl: qualifying Claude build <short digest> (first use, about 15 s)`.

The copy that was checked is the file that runs (M1): it is renamed into the session directory after the token is issued. Fail-closed is kept: a server token is fetched only after the build passes.

## Not changed

- `claudectl server qualify` (manual) stays and always reruns the check.
- The record file, the check name `supervised_host_config` and the harness script stay the same. The harness runner copies the build into its temp dir (the macOS harness sandbox reads builds only there; the seeded digest makes the launcher refuse a copy that differs).
- The guard always launches `server run`, which waits for or runs the check and refuses visibly. There is never a host-login or billing fallback for a refused build (HQ M3). Waiting launches print one stderr line, `waiting for qualification (pid N)`.

## HQ rule 57 changes (2026-10-08 01:4x PDT), binding

- M1: copy the binary once before `acquire`; that copy and its hash serve the failure lookup, the check, the record and the run. Test: binary swapped mid-check.
- M2: `qualify.lock` waits (limit 90 s); hard time limit on the harness run (75 s); manual `server qualify` takes the same lock; the failure record is read only under the lock.
- M3: see "Not changed" above.
- M4: failure record keyed like a pass (sha256, platform, check), private 0600, unknown fields denied; a damaged file refuses; a manual pass clears it.

## Tests (test-first, synthetic harness injected through `qualify_with`)

- An unknown build passes the injected harness: it is recorded, and the run continues.
- An unknown build fails: a failure record is written, the run is refused, and no token is acquired.
- A failure record younger than 1 hour: the harness is not run again; an older record runs it again.
- Two concurrent auto-qualifies of the same build run the harness once (the second one finds the record after the lock).
- `server qualify` ignores a failure record and clears it on a pass.

## Drill

On the Mac mini, with a copied build that is not qualified in a throwaway HOME: `server run` prints the qualifying line, passes in about 15 s, and runs `-p`. A second launch starts with no delay.
