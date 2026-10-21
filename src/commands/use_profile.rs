use anyhow::{Context, Result, bail};
use claudectl::accounts;
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;

use crate::commands::status;
#[cfg(test)]
use crate::commands::status::FetchedUsage;

pub fn run(alias: Option<&str>) -> Result<()> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    let alias = alias.map(profile::validate_alias).transpose()?;
    let local = profile::list_profiles_from(&paths)?;
    if let Some(alias) = alias
        && local.iter().any(|p| p.meta.alias == alias)
        && !claudectl::central::is_migrated(&paths, alias)
    {
        return switch_explicit(&store, &paths, alias);
    }
    if paths
        .claudectl_dir()
        .join("server/connection.json")
        .try_exists()?
        || claudectl::central::service_account::configured()
    {
        let alias = match alias {
            Some(alias) => {
                claudectl::central::Client::load(&paths)?
                    .account(alias)?
                    .alias
            }
            None => claudectl::central::pick_account(&paths)?,
        };
        return point_server_account(&alias);
    }

    match alias {
        Some(alias) => {
            let names: Vec<_> = local.iter().map(|p| p.meta.alias.as_str()).collect();
            let alias = accounts::resolve(alias, &names)?;
            switch_explicit(&store, &paths, alias)
        }
        None => {
            // Only the auto-select path needs this here: it fetches usage over
            // the network before it knows which profile to activate, and
            // `switch_to` already preflights on the explicit-alias path.
            store.ensure_keychain_ready()?;
            let fetched = status::fetch_all_usages()?;
            if fetched.is_empty() {
                bail!("no profiles saved. Use 'claudectl save' or 'claudectl login <alias>'.");
            }
            let now = chrono::Utc::now().timestamp();
            let candidates: Vec<_> = fetched
                .iter()
                .map(|f| status::candidate_of(f, now))
                .collect();
            let Some(best) = accounts::best(&candidates) else {
                bail!(
                    "no local profile is eligible:\n{}\nTry: claudectl status --details",
                    accounts::selection_failures(&candidates)
                );
            };
            let best = fetched[best].alias.clone();
            let email = profile::switch_to(&store, &paths, &best)?;
            point_local_account(&paths, &best).context("local login switched, but plain claude still needs repair\nTry: claudectl shim status")?;
            status::record_statusline_for(&paths, &fetched, &best);
            println!("auto-selected by weekly reset: {best} ({email})");
            println!();
            status::print_focused(&fetched, &best);
            Ok(())
        }
    }
}

fn point_server_account(alias: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use claudectl::central::shim;
        shim::dispatch(shim::Command::Install {
            account: Some(alias.to_owned()),
            claude: None,
            dir: shim::active_dir(&std::env::var_os("PATH").unwrap_or_default()),
        })?;
        println!("plain claude account: {alias} (new launches only)");
        Ok(())
    }
    #[cfg(not(unix))]
    bail!(
        "server account switching requires the Claude PATH shim on Unix\nTry: claudectl run {alias}"
    );
}

fn switch_explicit(store: &AuthStore, paths: &config::Paths, alias: &str) -> Result<()> {
    let email = profile::switch_to(store, paths, alias)?;
    point_local_account(paths, alias).context(
        "local login switched, but plain claude still needs repair\nTry: claudectl shim status",
    )?;
    println!("switched to {alias} ({email})");
    println!();
    if let Err(error) = status::run_focused(store, paths, alias) {
        eprintln!("warning: profile switch completed; cached usage unavailable: {error}");
    }
    Ok(())
}

fn point_local_account(paths: &config::Paths, alias: &str) -> Result<()> {
    #[cfg(unix)]
    claudectl::central::shim::use_local(paths, alias)?;
    #[cfg(not(unix))]
    let _ = (paths, alias);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetched(fresh: bool, usage: &str) -> FetchedUsage {
        FetchedUsage {
            alias: "candidate".into(),
            plan: Some("max".into()),
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
    fn a_fresh_unbilled_profile_is_eligible() {
        let status = fetched(
            true,
            r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2},"extra_usage":{"is_enabled":false}}"#,
        );
        assert_eq!(accounts::best(&[status::candidate_of(&status, 1)]), Some(0));
    }

    #[test]
    fn a_billed_profile_is_never_selected_automatically() {
        let status = fetched(
            true,
            r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2},"extra_usage":{"is_enabled":true}}"#,
        );
        assert!(accounts::best(&[status::candidate_of(&status, 1)]).is_none());
    }

    #[test]
    fn stale_usage_never_becomes_a_candidate() {
        let status = fetched(
            false,
            r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2},"extra_usage":{"is_enabled":false}}"#,
        );
        assert!(accounts::best(&[status::candidate_of(&status, 1)]).is_none());
    }

    #[test]
    fn missing_usage_is_not_zero_usage() {
        let status = fetched(true, "{}");
        assert!(accounts::best(&[status::candidate_of(&status, 1)]).is_none());
    }

    #[test]
    fn exhausted_general_limit_is_not_selected() {
        let status = fetched(
            true,
            r#"{"five_hour":{"utilization":0},"seven_day":{"utilization":100},"extra_usage":{"is_enabled":false}}"#,
        );
        assert!(accounts::best(&[status::candidate_of(&status, 1)]).is_none());
    }
}

#[cfg(test)]
#[test]
fn snapshot_that_expires_during_batch_is_not_selected() {
    let status = FetchedUsage {
        plan: Some("max".into()),
        usage: Some(
            serde_json::from_str(
                r#"{"five_hour":{"utilization":1},"seven_day":{"utilization":2},"extra_usage":{"is_enabled":false}}"#,
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
    assert!(accounts::best(&[status::candidate_of(&status, 3)]).is_none());
}
