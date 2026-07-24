use anyhow::{Result, bail};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;

use crate::commands::status::{self, FetchedUsage};

pub fn run(alias: Option<&str>) -> Result<()> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    store.ensure_keychain_ready()?;

    match alias {
        Some(a) => {
            let a = profile::validate_alias(a)?;
            let email = profile::switch_to(&store, &paths, a)?;
            println!("switched to {a} ({email})");
            println!();
            status::run_focused(a)
        }
        None => {
            let fetched = status::fetch_all_usages()?;
            if fetched.is_empty() {
                bail!("no profiles saved. Use 'claudectl save' or 'claudectl login <alias>'.");
            }
            let candidates: Vec<Candidate> = fetched.iter().map(candidate_from).collect();
            let Some(best) = select_most_available(&candidates) else {
                bail!("no usable accounts found (all expired or errored)");
            };
            let best = best.to_string();
            let email = profile::switch_to(&store, &paths, &best)?;
            println!("auto-selected most available: {best} ({email})");
            println!();
            status::run_focused(&best)
        }
    }
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
        Some(u) => {
            let h5 = u
                .five_hour
                .as_ref()
                .and_then(|w| w.utilization)
                .unwrap_or(0.0);
            let d7 = u
                .seven_day
                .as_ref()
                .and_then(|w| w.utilization)
                .unwrap_or(0.0);
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
        None => Candidate {
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
        .filter(|c| c.score < f64::MAX)
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
