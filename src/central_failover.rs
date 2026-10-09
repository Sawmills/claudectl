//! SAW-12693: `claudectl run` resumes the Claude session on another server account when the
//! account reaches a usage limit. A turn that fails with `rate_limit` (the StopFailure hook)
//! starts it; a fresh usage read must show a full window; the next account has room, never
//! bills, and is not crowded (the guide's 50% cap).
use super::*;
use std::collections::HashMap;

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
}
