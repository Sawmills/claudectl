use anyhow::{Result, bail};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;

use crate::commands::status::{self, FetchedUsage};

pub fn run(alias: Option<&str>) -> Result<()> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());

    match alias {
        Some(a) => switch_explicit(&store, &paths, profile::validate_alias(a)?),
        None => {
            // Only the auto-select path needs this here: it fetches usage over
            // the network before it knows which profile to activate, and
            // `switch_to` already preflights on the explicit-alias path.
            store.ensure_keychain_ready()?;
            let fetched = status::fetch_all_usages()?;
            if fetched.is_empty() {
                bail!("no profiles saved. Use 'claudectl save' or 'claudectl login <alias>'.");
            }
            let candidates: Vec<Candidate> = fetched.iter().map(candidate_from).collect();
            let Some(best) = select_most_available(&candidates) else {
                bail!(
                    "no accounts with fresh usage below the general limits; run claudectl status"
                );
            };
            let best = best.to_string();
            let email = profile::switch_to(&store, &paths, &best)?;
            println!("auto-selected most available: {best} ({email})");
            println!();
            status::print_focused(&fetched, &best);
            Ok(())
        }
    }
}

fn switch_explicit(store: &AuthStore, paths: &config::Paths, alias: &str) -> Result<()> {
    let email = profile::switch_to(store, paths, alias)?;
    println!("switched to {alias} ({email})");
    println!();
    if let Err(error) = status::run_focused(store, paths, alias) {
        eprintln!("warning: profile switch completed; cached usage unavailable: {error}");
    }
    Ok(())
}

struct Candidate {
    alias: String,
    /// max(5h, 7d) utilization; f64::MAX when the account errored.
    score: f64,
    /// 7d reset unix ts; i64::MAX when unknown (never preferred on ties).
    d7_reset_ts: i64,
}

fn candidate_from(f: &FetchedUsage) -> Candidate {
    match &f.usage {
        Some(u) if f.snapshot.is_fresh_at(chrono::Utc::now().timestamp()) && f.error.is_none() => {
            let h5 = u
                .five_hour
                .as_ref()
                .and_then(|w| w.utilization)
                .unwrap_or(f64::MAX);
            let d7 = u
                .seven_day
                .as_ref()
                .and_then(|w| w.utilization)
                .unwrap_or(f64::MAX);
            Candidate {
                alias: f.alias.clone(),
                score: h5.max(d7),
                d7_reset_ts: u
                    .seven_day
                    .as_ref()
                    .and_then(|w| w.reset_timestamp())
                    .unwrap_or(i64::MAX),
            }
        }
        _ => Candidate {
            alias: f.alias.clone(),
            score: f64::MAX,
            d7_reset_ts: i64::MAX,
        },
    }
}

/// Lowest max-utilization wins; near-ties (within half a percent) break toward
/// the soonest 7d reset. Errored/expired candidates (score MAX) never win.
fn select_most_available(candidates: &[Candidate]) -> Option<&str> {
    candidates
        .iter()
        .filter(|c| c.score < 100.0)
        .min_by_key(|c| ((c.score * 2.0).round() as i64, c.d7_reset_ts))
        .map(|c| c.alias.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(alias: &str, score: f64, d7_reset_ts: i64) -> Candidate {
        Candidate {
            alias: alias.to_string(),
            score,
            d7_reset_ts,
        }
    }

    fn fetched(fresh: bool, usage: &str) -> FetchedUsage {
        FetchedUsage {
            alias: "candidate".into(),
            usage: Some(serde_json::from_str(usage).unwrap()),
            snapshot: claudectl::usage_cache::Snapshot {
                fresh,
                fetched_at: Some(0),
                valid_until: Some(i64::MAX),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn switch_fixture() -> (tempfile::TempDir, config::Paths, AuthStore) {
        let root = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(root.path().to_path_buf());
        let creds = serde_json::from_str(r#"{"claudeAiOauth":{"accessToken":"test-only-switch"}}"#)
            .unwrap();
        profile::save_profile_to(&paths, "chosen", &creds, None).unwrap();
        let store = AuthStore::file_only(paths.clone());
        (root, paths, store)
    }

    #[test]
    fn switch_succeeds_when_another_process_holds_usage_lock() {
        let (_root, paths, store) = switch_fixture();
        let _lock = claudectl::usage_cache::UsageCache::open(&paths.claudectl_dir()).unwrap();

        let result = switch_explicit(&store, &paths, "chosen");

        assert!(result.is_ok());
        assert_eq!(
            profile::get_active_from(&paths).unwrap().as_deref(),
            Some("chosen")
        );
    }

    #[test]
    fn stale_usage_never_becomes_a_candidate() {
        let status = fetched(
            false,
            r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2}}"#,
        );
        assert!(select_most_available(&[candidate_from(&status)]).is_none());
    }

    #[test]
    fn missing_usage_is_not_zero_usage() {
        let status = fetched(true, "{}");
        assert!(select_most_available(&[candidate_from(&status)]).is_none());
    }

    #[test]
    fn exhausted_general_limit_is_not_selected() {
        let status = fetched(
            true,
            r#"{"five_hour":{"utilization":0},"seven_day":{"utilization":100}}"#,
        );
        assert!(select_most_available(&[candidate_from(&status)]).is_none());
    }

    #[test]
    fn picks_lowest_max_utilization() {
        let c = vec![candidate("busy", 80.0, 100), candidate("fresh", 10.0, 9000)];
        assert_eq!(select_most_available(&c), Some("fresh"));
    }

    #[test]
    fn ties_break_by_soonest_7d_reset() {
        let c = vec![candidate("late", 20.0, 9000), candidate("soon", 20.0, 100)];
        assert_eq!(select_most_available(&c), Some("soon"));
    }

    #[test]
    fn skips_errored_candidates() {
        let c = vec![candidate("err", f64::MAX, 0), candidate("ok", 90.0, 100)];
        assert_eq!(select_most_available(&c), Some("ok"));
    }

    #[test]
    fn returns_none_when_all_errored() {
        let c = vec![candidate("a", f64::MAX, 0), candidate("b", f64::MAX, 0)];
        assert_eq!(select_most_available(&c), None);
    }
}

#[cfg(test)]
#[test]
fn snapshot_that_expires_during_batch_is_not_selected() {
    let status = FetchedUsage {
        usage: Some(
            serde_json::from_str(
                r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2}}"#,
            )
            .unwrap(),
        ),
        snapshot: claudectl::usage_cache::Snapshot {
            fresh: true,
            fetched_at: Some(1),
            valid_until: Some(2),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(select_most_available(&[candidate_from(&status)]).is_none());
}
