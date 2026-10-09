//! The account model shared by `claudectl status`, `claudectl run` and the dashboard
//! (SAW-12677): name resolution, per-account state, and the best-account pick.
use claudectl::accounts::{self, Candidate, State, Window};

fn w(name: &'static str, used: f64, resets_at: Option<i64>) -> Window {
    Window {
        name,
        used: Some(used),
        resets_at,
    }
}
fn ready(name: &str, five: f64, week: f64, week_reset: i64) -> Candidate {
    Candidate {
        name: name.into(),
        windows: vec![w("5h", five, Some(100)), w("week", week, Some(week_reset))],
        fresh: true,
        billed: false,
    }
}

#[test]
fn a_name_resolves_by_exact_then_local_part_then_unique_prefix() {
    let names = [
        "amir@sawmills.ai",
        "amir2@sawmills.ai",
        "amir3@sawmills.ai",
        "work",
    ];
    assert_eq!(
        accounts::resolve("AMIR2@sawmills.ai", &names).unwrap(),
        "amir2@sawmills.ai"
    );
    assert_eq!(
        accounts::resolve("amir3", &names).unwrap(),
        "amir3@sawmills.ai"
    );
    // `amir` is the exact local part of one account, not a prefix of three.
    assert_eq!(
        accounts::resolve("amir", &names).unwrap(),
        "amir@sawmills.ai"
    );
    assert_eq!(accounts::resolve("wo", &names).unwrap(), "work");
}

#[test]
fn an_unknown_or_ambiguous_name_lists_the_accounts_and_the_next_command() {
    let names = ["amir2@sawmills.ai", "amir3@sawmills.ai"];
    let error = accounts::resolve("amir4", &names).unwrap_err().to_string();
    assert!(
        error.contains("amir2@sawmills.ai") && error.contains("amir3@sawmills.ai"),
        "{error}"
    );
    assert!(error.contains("Try: claudectl status"), "{error}");
    // One edit away: a suggestion.
    let error = accounts::resolve("amr2", &names).unwrap_err().to_string();
    assert!(error.contains("did you mean amir2@sawmills.ai?"), "{error}");
    // A prefix of two accounts is ambiguous, never a guess.
    let error = accounts::resolve("amir", &names).unwrap_err().to_string();
    assert!(error.contains("matches more than one account"), "{error}");
}

#[test]
fn short_names_drop_a_shared_domain_only() {
    let same = ["amir@sawmills.ai", "amir2@sawmills.ai"];
    assert_eq!(accounts::short_names(&same), ["amir", "amir2"]);
    let mixed = ["amir@sawmills.ai", "me@example.com"];
    assert_eq!(accounts::short_names(&mixed), mixed);
}

#[test]
fn a_full_window_is_a_limit_and_fable_counts() {
    assert_eq!(
        accounts::state(&[w("5h", 10.0, None), w("week", 20.0, None)]),
        State::Ready
    );
    assert_eq!(
        accounts::state(&[w("5h", 10.0, None), w("week", 85.0, Some(9))]),
        State::Low { window: "week" }
    );
    assert_eq!(
        accounts::state(&[
            w("5h", 0.0, None),
            w("week", 98.0, Some(9)),
            w("Fable", 100.0, None)
        ]),
        State::Limit {
            window: "Fable",
            resets_at: None
        }
    );
    assert_eq!(accounts::state(&[]), State::Unknown);
}

#[test]
fn best_skips_limits_stale_and_billed_and_prefers_room_then_the_soonest_reset() {
    let mut fable_full = ready("amir4", 0.0, 10.0, 50);
    fable_full.windows.push(w("Fable", 100.0, None));
    let mut stale = ready("old", 0.0, 0.0, 10);
    stale.fresh = false;
    let mut billed = ready("billed", 0.0, 0.0, 10);
    billed.billed = true;
    let rows = vec![
        fable_full,
        stale,
        billed,
        ready("amir", 55.0, 76.0, 20),
        ready("amir2", 3.0, 1.0, 900),
        ready("amir3", 2.0, 1.0, 800),
    ];
    // amir2 and amir3 have the same room (highest window 3% vs 2%: amir3 wins on room).
    assert_eq!(
        accounts::best(&rows).map(|i| rows[i].name.as_str()),
        Some("amir3")
    );
    // Equal room: the soonest week reset wins.
    let tie = vec![ready("a", 1.0, 2.0, 900), ready("b", 1.0, 2.0, 800)];
    assert_eq!(
        accounts::best(&tie).map(|i| tie[i].name.as_str()),
        Some("b")
    );
    // Nothing usable: no pick.
    let none = vec![ready("full", 100.0, 1.0, 1)];
    assert_eq!(accounts::best(&none), None);
}

#[test]
fn windows_come_from_a_usage_response_including_fable() {
    let usage: claudectl::api::UsageResponse = serde_json::from_value(serde_json::json!({
        "five_hour": {"utilization": 2.0, "resets_at": "2099-01-01T00:00:00Z"},
        "seven_day": {"utilization": 98.0, "resets_at": "2099-01-02T00:00:00Z"},
        "limits": [{"kind": "weekly_scoped", "percent": 100.0,
            "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}]
    }))
    .unwrap();
    let windows = accounts::windows(&usage);
    let names: Vec<_> = windows.iter().map(|w| w.name).collect();
    assert_eq!(names, ["5h", "week", "Fable"]);
    assert_eq!(windows[2].used, Some(100.0));
}

#[test]
fn reset_times_read_as_time_from_now_and_a_local_clock_time() {
    let now = 1_000_000;
    assert_eq!(accounts::until(now + 7 * 3_600 + 52 * 60, now), "in 7h 52m");
    assert_eq!(
        accounts::until(now + 2 * 86_400 + 4 * 3_600, now),
        "in 2d 4h"
    );
    assert_eq!(accounts::until(now + 30, now), "in 1m");
    assert_eq!(accounts::until(now - 5, now), "now");
}

#[test]
fn detail_rows_show_every_window_with_a_human_reset() {
    let usage: claudectl::api::UsageResponse = serde_json::from_value(serde_json::json!({
        "five_hour": {"utilization": 3.0, "resets_at": "1970-01-12T15:46:40Z"},
        "seven_day": {"utilization": 1.0},
        "limits": [{"kind": "weekly_scoped", "percent": 16.0,
            "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}]
    }))
    .unwrap();
    let rows = accounts::detail_rows(&usage, 1_000_000);
    assert_eq!(rows[0][0], "5h");
    assert_eq!(rows[0][1], "3%");
    // No raw RFC 3339 timestamp: time from now, then the clock time.
    assert!(rows[0][2].starts_with("in "), "{rows:?}");
    assert!(
        !rows[0][2].contains("+00:00") && !rows[0][2].contains(":00Z"),
        "{rows:?}"
    );
    assert_eq!(rows[1][2], "-");
    assert_eq!(rows[2], ["Fable", "16%", "-"]);
}

#[test]
fn a_missing_5h_or_week_figure_makes_the_whole_account_unknown() {
    let none = |name| Window {
        name,
        used: None,
        resets_at: None,
    };
    // Only model windows (a partial response): never ready, never picked.
    let partial = vec![none("5h"), none("week"), w("Fable", 1.0, None)];
    assert_eq!(accounts::state(&partial), State::Unknown);
    let no_week = vec![w("5h", 1.0, Some(100)), none("week")];
    assert_eq!(accounts::state(&no_week), State::Unknown);
    // A full window still wins: a known limit is not unknown.
    let limited = vec![w("5h", 100.0, Some(100)), none("week")];
    assert!(matches!(accounts::state(&limited), State::Limit { .. }));
    let candidates = [Candidate {
        name: "partial".into(),
        windows: partial,
        fresh: true,
        billed: false,
    }];
    assert_eq!(accounts::best(&candidates), None);
}
