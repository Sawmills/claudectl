//! SAW-12693: `claudectl run` resumes the Claude session on another server account when the
//! account reaches a usage limit. A turn that fails with `rate_limit` (the StopFailure hook)
//! starts it; a fresh usage read must show a full window; the next account has room, never
//! bills, and is not crowded (the guide's 50% cap).
use super::*;
use std::{collections::HashMap, ffi::OsString};

/// What a fresh usage read says about a `rate_limit` turn failure.
#[derive(Debug, PartialEq)]
pub(super) enum Confirm {
    /// A full window: the account is at a usage limit.
    Limit,
    /// No current answer yet (stale, failed, or observed before the failure): ask again.
    NotYet,
    /// Observed after the failure without a full window: a short throttle, never a switch.
    Throttle,
}

/// Whether `usage` confirms the limit a turn hit at `failed_at` (ms).
pub(super) fn confirm(usage: &Usage, failed_at: i64) -> Confirm {
    let parsed = usage
        .data
        .clone()
        .and_then(|d| serde_json::from_value::<crate::api::UsageResponse>(d).ok());
    let (Some(parsed), Some(observed_at)) = (parsed, usage.observed_at) else {
        return Confirm::NotYet;
    };
    if usage.stale || observed_at < failed_at {
        return Confirm::NotYet;
    }
    match crate::accounts::state(&crate::accounts::windows(&parsed)) {
        crate::accounts::State::Limit { .. } => Confirm::Limit,
        crate::accounts::State::Unknown => Confirm::NotYet,
        _ => Confirm::Throttle,
    }
}

/// One account switch, kept on disk: the stagger rule reads the recent ones of every run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct Record {
    pub at: i64,
    pub from: String,
    pub to: String,
    pub session_id: String,
}

/// No new failover onto an account that got one this recently (ms): tabs that hit a limit
/// together spread out instead of all landing on the same account.
pub(super) const STAGGER_MS: i64 = 60_000;

fn records_path(paths: &Paths) -> PathBuf {
    root(paths).join("failovers.jsonl")
}

/// Append one switch record.
pub(super) fn record(paths: &Paths, record: &Record) -> Result<()> {
    private_dir(&root(paths))?;
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(records_path(paths))?;
    writeln!(file, "{}", serde_json::to_string(record)?)?;
    Ok(())
}

/// The switch records of the last `within` ms. A missing or damaged file reads as none.
pub(super) fn recent(paths: &Paths, now: i64, within: i64) -> Vec<Record> {
    std::fs::read_to_string(records_path(paths))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Record>(line).ok())
        .filter(|r| now - r.at < within)
        .collect()
}

/// Live `server run` sessions on this machine per alias (a held `owner.lock`), without the
/// session in `own`.
pub(super) fn live_sessions(paths: &Paths, own: &Path) -> HashMap<String, usize> {
    let mut live = HashMap::new();
    let own = own.canonicalize().ok();
    let entries = std::fs::read_dir(root(paths).join("sessions"))
        .into_iter()
        .flatten()
        .flatten();
    for entry in entries {
        let dir = entry.path();
        let is_session = entry.file_name().to_string_lossy().starts_with("run-");
        if !is_session || dir.canonicalize().ok() == own {
            continue;
        }
        // A lease that can be taken has no live owner.
        let Ok(lock) = File::open(dir.join("owner.lock")) else {
            continue;
        };
        if lock.try_lock().is_ok() {
            continue;
        }
        let alias = std::fs::read(dir.join("session.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| v["alias"].as_str().map(str::to_owned));
        if let Some(alias) = alias {
            *live.entry(alias).or_default() += 1;
        }
    }
    live
}

/// The account to move to: a fresh, never-billed account in the Ready state (not Low, not
/// at a limit), not the current or an already tried one, not a recent failover target, and
/// not one that would then hold more than half of the live sessions.
pub(super) fn choose(
    rows: &[ServerRow],
    current: &str,
    tried: &[String],
    live: &HashMap<String, usize>,
    recent: &[Record],
) -> Option<String> {
    let same = |a: &str, b: &str| a.eq_ignore_ascii_case(b);
    // This session moves too: it counts on the target after the switch.
    let total = live.values().sum::<usize>() + 1;
    let crowded = |alias: &str| {
        let after = live
            .iter()
            .filter(|(a, _)| same(a, alias))
            .map(|(_, n)| n)
            .sum::<usize>()
            + 1;
        total >= 2 && after * 2 > total
    };
    let open: Vec<&ServerRow> = rows
        .iter()
        .filter(|r| {
            !same(&r.alias, current)
                && !tried.iter().any(|t| same(t, &r.alias))
                && !recent.iter().any(|f| same(&f.to, &r.alias))
                && !crowded(&r.alias)
        })
        .collect();
    let candidates: Vec<_> = open
        .iter()
        .map(|r| candidate(r))
        .map(|mut c| {
            // Ready only: a Low account would hit its own limit soon after the switch.
            if crate::accounts::state(&c.windows) != crate::accounts::State::Ready {
                c.fresh = false;
            }
            c
        })
        .collect();
    crate::accounts::best(&candidates).map(|i| open[i].alias.clone())
}

/// The prompt a moved session resumes with, so the failed turn continues.
pub(super) const RECOVERY_PROMPT: &str = "Continue the previous request.";

/// The arguments of a moved session: the user's arguments resumed on `session`
/// (`renew::relaunch_args`), with the recovery prompt in place of a prompt the user gave (the
/// resumed conversation already holds it, and Claude takes one prompt). An argument that does
/// not start with `-` is a prompt when it is first or follows another such argument; after a
/// flag it is that flag's value. None for a one-shot run.
pub(super) fn resume_args(args: &[OsString], session: &str) -> Option<Vec<OsString>> {
    let mut resumed = super::renew::relaunch_args(args, session)?;
    // `relaunch_args` ends with `--resume <session>`.
    let tail = resumed.split_off(resumed.len() - 2);
    let mut out = Vec::new();
    let mut after_flag = false;
    for arg in resumed {
        if arg.to_string_lossy().starts_with('-') {
            after_flag = true;
            out.push(arg);
        } else if after_flag {
            after_flag = false;
            out.push(arg);
        }
    }
    out.extend(tail);
    out.push(RECOVERY_PROMPT.into());
    Some(out)
}

/// The time limit for confirming one limit. It starts when Claude is first idle enough to
/// move (the idle gate), not at the failure: a user who typed after the error still gets
/// the full window once the terminal is quiet.
#[derive(Default)]
pub(super) struct Deadline {
    failure: Option<i64>,
    opened_at: i64,
}
impl Deadline {
    /// Called on each tick the idle gate passes; true once `CONFIRM_FOR_MS` passed since the
    /// first such tick for this failure.
    pub(super) fn expired(&mut self, failed_at: i64, now: i64) -> bool {
        if self.failure != Some(failed_at) {
            self.failure = Some(failed_at);
            self.opened_at = now;
        }
        now - self.opened_at > CONFIRM_FOR_MS
    }
}
/// How long a limit may wait for a usage read that confirms it (ms): the server reads the
/// provider at most every 5 minutes.
pub(super) const CONFIRM_FOR_MS: i64 = 6 * 60_000;

/// Choose the account to move to and record the switch, under a lock on this machine's
/// records: sessions that hit the limit together then see each other's choice (the stagger
/// and the 50% cap), instead of all choosing the same account.
/// What `reserve` found.
#[derive(Debug, PartialEq)]
pub(super) enum Reserved<T> {
    /// The account to move to, taken and recorded.
    Taken(String, T),
    /// No account has room.
    NoRoom,
    /// An account has room but could not be taken now (no token): try again.
    NotTaken,
}

/// `take` gets the chosen account ready (its token); only a taken account is recorded.
pub(super) fn reserve<T>(
    paths: &Paths,
    rows: &[ServerRow],
    current: &str,
    tried: &[String],
    own: &Path,
    session_id: &str,
    take: impl FnOnce(&str) -> Option<T>,
) -> Result<Reserved<T>> {
    private_dir(&root(paths))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(root(paths).join("failovers.lock"))?;
    lock.lock()?;
    let live = live_sessions(paths, own);
    let recent = recent(paths, now(), STAGGER_MS);
    let Some(to) = choose(rows, current, tried, &live, &recent) else {
        return Ok(Reserved::NoRoom);
    };
    let Some(taken) = take(&to) else {
        return Ok(Reserved::NotTaken);
    };
    record(
        paths,
        &Record {
            at: now(),
            from: current.to_string(),
            to: to.clone(),
            session_id: session_id.to_string(),
        },
    )?;
    Ok(Reserved::Taken(to, taken))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(data: Value, observed_at: i64, stale: bool) -> Usage {
        Usage {
            data: Some(data),
            observed_at: Some(observed_at),
            next_retry_at: 0,
            stale,
            error: None,
        }
    }
    fn full() -> Value {
        json!({"five_hour": {"utilization": 100.0}, "seven_day": {"utilization": 40.0},
            "extra_usage": {"is_enabled": false}})
    }
    fn room(five: f64, week: f64) -> Value {
        json!({"five_hour": {"utilization": five}, "seven_day": {"utilization": week},
            "extra_usage": {"is_enabled": false}})
    }
    fn row(alias: &str, data: Value) -> ServerRow {
        ServerRow {
            alias: alias.into(),
            available: true,
            usage: Ok(usage(data, now(), false)),
        }
    }

    #[test]
    fn only_a_fresh_full_window_confirms_a_limit() {
        assert_eq!(confirm(&usage(full(), 2_000, false), 1_000), Confirm::Limit);
        // A stale or older answer proves nothing yet.
        assert_eq!(confirm(&usage(full(), 2_000, true), 1_000), Confirm::NotYet);
        assert_eq!(
            confirm(&usage(room(10.0, 10.0), 500, false), 1_000),
            Confirm::NotYet
        );
        let failed = Usage {
            data: None,
            observed_at: None,
            next_retry_at: 0,
            stale: true,
            error: Some("usage_unavailable".into()),
        };
        assert_eq!(confirm(&failed, 1_000), Confirm::NotYet);
        // Observed after the failure with room left: a short throttle.
        assert_eq!(
            confirm(&usage(room(10.0, 10.0), 2_000, false), 1_000),
            Confirm::Throttle
        );
        // A full Fable window is a limit too.
        let fable = json!({"five_hour": {"utilization": 1.0}, "seven_day": {"utilization": 1.0},
            "limits": [{"kind": "weekly_scoped", "percent": 100,
                "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}]});
        assert_eq!(confirm(&usage(fable, 2_000, false), 1_000), Confirm::Limit);
    }

    #[test]
    fn the_next_account_is_ready_unbilled_untried_and_not_crowded() {
        let rows = vec![
            row("cur", full()),
            row("low", room(85.0, 10.0)),
            row("tried", room(1.0, 1.0)),
            row(
                "billed",
                json!({"five_hour": {"utilization": 1.0},
                "seven_day": {"utilization": 1.0}}),
            ),
            row("busy", room(40.0, 40.0)),
            row("free", room(20.0, 20.0)),
        ];
        let none = HashMap::new();
        let tried = vec!["tried".to_string()];
        assert_eq!(
            choose(&rows, "cur", &tried, &none, &[]).as_deref(),
            Some("free")
        );
        // A recent failover target is skipped (stagger), then the next best is used.
        let recent = [Record {
            at: now(),
            from: "x".into(),
            to: "free".into(),
            session_id: "s".into(),
        }];
        assert_eq!(
            choose(&rows, "cur", &tried, &none, &recent).as_deref(),
            Some("busy")
        );
        // The 50% cap: 4 live sessions, 2 already on `free`: a third would hold 3 of 4.
        let live = HashMap::from([("free".to_string(), 2), ("cur".to_string(), 2)]);
        assert_eq!(
            choose(&rows, "cur", &tried, &live, &[]).as_deref(),
            Some("busy")
        );
        // Nothing left: no switch.
        let only = vec![row("cur", full()), row("low", room(85.0, 1.0))];
        assert_eq!(choose(&only, "cur", &[], &none, &[]), None);
    }

    #[test]
    fn a_single_session_is_never_blocked_by_the_cap() {
        let rows = vec![row("cur", full()), row("free", room(1.0, 1.0))];
        let live = HashMap::from([("cur".to_string(), 1)]);
        assert_eq!(
            choose(&rows, "cur", &[], &live, &[]).as_deref(),
            Some("free")
        );
    }

    #[test]
    fn switch_records_round_trip_and_age_out() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().to_path_buf());
        assert!(recent(&paths, now(), STAGGER_MS).is_empty());
        let old = Record {
            at: now() - 2 * STAGGER_MS,
            from: "a".into(),
            to: "b".into(),
            session_id: "s-1".into(),
        };
        let new = Record {
            at: now(),
            to: "c".into(),
            ..old.clone()
        };
        record(&paths, &old).unwrap();
        record(&paths, &new).unwrap();
        assert_eq!(recent(&paths, now(), STAGGER_MS), vec![new]);
        assert_eq!(recent(&paths, now(), 3 * STAGGER_MS).len(), 2);
    }

    #[test]
    fn live_sessions_count_held_leases_only() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().to_path_buf());
        let sessions = root(&paths).join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let session = |name: &str, alias: &str, held: bool| {
            let dir = sessions.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(
                dir.join("session.json"),
                json!({"alias": alias}).to_string(),
            )
            .unwrap();
            let lock = File::create(dir.join("owner.lock")).unwrap();
            if held {
                lock.try_lock().unwrap();
            }
            (dir, lock)
        };
        let (own, _a) = session("run-own", "cur", true);
        let (_, _b) = session("run-b", "free", true);
        let (_, _c) = session("run-c", "free", true);
        let (_, _d) = session("run-d", "free", false);
        let (_, _e) = session("run-e", "cur", true);
        let live = live_sessions(&paths, &own);
        assert_eq!(live.get("free"), Some(&2));
        assert_eq!(live.get("cur"), Some(&1));
    }

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn a_moved_session_resumes_with_the_recovery_prompt_in_place_of_the_users() {
        let resumed = |args: &[&str]| resume_args(&os(args), "S").unwrap();
        assert_eq!(
            resumed(&["--model", "opus"]),
            os(&["--model", "opus", "--resume", "S", RECOVERY_PROMPT])
        );
        assert_eq!(
            resumed(&["fix the tests"]),
            os(&["--resume", "S", RECOVERY_PROMPT])
        );
        assert_eq!(
            resumed(&["--model", "opus", "fix the tests", "--resume", "old"]),
            os(&["--model", "opus", "--resume", "S", RECOVERY_PROMPT])
        );
        assert_eq!(resume_args(&os(&["-p", "hi"]), "S"), None);
    }

    #[test]
    fn the_confirm_window_starts_when_claude_is_first_idle_enough() {
        let mut deadline = Deadline::default();
        // The gate first opens 6.5 min after the failure (the user typed): not expired.
        assert!(!deadline.expired(0, 390_000));
        assert!(!deadline.expired(0, 390_000 + CONFIRM_FOR_MS - 1));
        assert!(deadline.expired(0, 390_000 + CONFIRM_FOR_MS + 1));
        // A new failure starts a new window.
        assert!(!deadline.expired(500_000, 800_000));
    }

    #[test]
    fn sessions_that_hit_the_limit_together_choose_different_accounts() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().to_path_buf());
        let rows = vec![
            row("cur", full()),
            row("a", room(10.0, 10.0)),
            row("b", room(20.0, 20.0)),
        ];
        let own = home.path().join("none");
        let take = |_: &str| Some(());
        let first = reserve(&paths, &rows, "cur", &[], &own, "s-1", take).unwrap();
        let second = reserve(&paths, &rows, "cur", &[], &own, "s-2", take).unwrap();
        assert_eq!(first, Reserved::Taken("a".into(), ()));
        assert_eq!(second, Reserved::Taken("b".into(), ()));
        let records = recent(&paths, now(), STAGGER_MS);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].session_id, "s-1");
        // Nothing left, or the account could not be taken: no record.
        assert_eq!(
            reserve(&paths, &rows, "cur", &[], &own, "s-3", take).unwrap(),
            Reserved::NoRoom
        );
        let rows = vec![row("cur", full()), row("c", room(1.0, 1.0))];
        let failed = reserve(&paths, &rows, "cur", &[], &own, "s-4", |_| None::<()>).unwrap();
        assert_eq!(failed, Reserved::NotTaken);
        assert_eq!(recent(&paths, now(), STAGGER_MS).len(), 2);
    }
}
