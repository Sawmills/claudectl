use std::time::Duration;

use anyhow::Result;
use claudectl::api::{self, UsageResponse, UsageWindow};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;
use claudectl::usage_cache::{FetchMode, Snapshot, UsageCache};
use comfy_table::{Cell, Color, Table, presets::UTF8_FULL_CONDENSED};

/// One profile's fetched usage, shared by `status` and `use` auto-select.
#[derive(Default)]
pub struct FetchedUsage {
    pub snapshot: Snapshot,
    pub alias: String,
    pub usage: Option<UsageResponse>,
    pub token_expiry_secs: Option<i64>,
    pub is_active: bool,
    pub error: Option<String>,
}

struct AccountStatus {
    snapshot: Snapshot,
    alias: String,
    h5_pct: Option<f64>,
    d7_pct: Option<f64>,
    h5_reset: String,
    d7_reset: String,
    opus_pct: Option<f64>,
    sonnet_pct: Option<f64>,
    fable_pct: Option<f64>,
    has_fable_limit: bool,
    token_expiry_secs: Option<i64>,
    is_active: bool,
    is_error: bool,
    error_msg: String,
}

impl AccountStatus {
    /// Lower is more available. Mirrors codexctl's ordering semantics.
    fn availability_score(&self) -> f64 {
        if self.is_error {
            return 1000.0;
        }
        let h5 = self.h5_pct.unwrap_or(0.0);
        let d7 = self.d7_pct.unwrap_or(0.0);
        if h5 >= 100.0 && d7 >= 100.0 {
            return 900.0;
        }
        if d7 >= 100.0 {
            return 700.0 + h5;
        }
        if h5 >= 100.0 {
            return 500.0 + d7;
        }
        h5 * 2.0 + d7
    }
}

pub fn run(alias: Option<&str>, mode: FetchMode) -> Result<()> {
    let fetched = fetch_usages(alias, mode)?;
    if fetched.is_empty() {
        println!("no profiles saved. Use 'claudectl save' or 'claudectl login <alias>'.");
        return Ok(());
    }

    let mut accounts: Vec<AccountStatus> = fetched.iter().map(to_account_status).collect();
    accounts.sort_by(|a, b| {
        a.availability_score()
            .partial_cmp(&b.availability_score())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    print_fetched_at();
    print_table(&accounts);
    Ok(())
}

/// Explicit switching stays local: show only this account's cached data.
pub fn run_focused(store: &AuthStore, paths: &config::Paths, alias: &str) -> Result<()> {
    let fetched = fetch_usages_from(store, paths, Some(alias), FetchMode::Cached)?;
    print_focused(&fetched, alias);
    Ok(())
}

/// Reuse the selection snapshot after switching; never issue a second batch.
pub fn print_focused(fetched: &[FetchedUsage], alias: &str) {
    let accounts: Vec<_> = fetched
        .iter()
        .filter(|f| f.alias == alias)
        .map(|f| {
            let mut account = to_account_status(f);
            account.is_active = true;
            account
        })
        .collect();
    print_table(&accounts);
}

pub fn fetch_all_usages() -> Result<Vec<FetchedUsage>> {
    fetch_usages(None, FetchMode::Normal)
}

fn fetch_usages(alias: Option<&str>, mode: FetchMode) -> Result<Vec<FetchedUsage>> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    fetch_usages_from(&store, &paths, alias, mode)
}

fn fetch_usages_from(
    store: &AuthStore,
    paths: &config::Paths,
    alias: Option<&str>,
    mode: FetchMode,
) -> Result<Vec<FetchedUsage>> {
    let profiles = match alias {
        Some(alias) => vec![profile::get_profile_from(
            paths,
            profile::validate_alias(alias)?,
        )?],
        None => profile::list_profiles_from(paths)?,
    };
    if profiles.is_empty() {
        return Ok(vec![]);
    }
    let mut cache = UsageCache::open(&paths.claudectl_dir())?;
    let active = profile::get_active_from(paths)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        let mut fetched = Vec::new();
        for profile in profiles {
            let is_active = active.as_deref() == Some(profile.meta.alias.as_str());
            let mut result = FetchedUsage {
                alias: profile.meta.alias.clone(),
                is_active,
                ..FetchedUsage::default()
            };
            let creds = if is_active {
                store.read_credentials()
            } else {
                profile.read_credentials()
            };
            let mut creds = match creds {
                Ok(creds) => creds,
                Err(_) => {
                    result.error = Some("credentials unavailable or invalid".into());
                    fetched.push(result);
                    continue;
                }
            };
            result.token_expiry_secs = creds.claude_ai_oauth.expiry_secs();
            if creds.claude_ai_oauth.access_token.trim().is_empty() {
                result.error = Some("missing access token; log in again".into());
                fetched.push(result);
                continue;
            }
            let now = chrono::Utc::now().timestamp();
            let mut profile_save_error = None;
            // Claude Code owns refresh for the active profile. Cached and cooldown
            // paths do not contact either the usage endpoint or the token endpoint.
            if !is_active
                && creds.claude_ai_oauth.is_expired()
                && creds.claude_ai_oauth.refresh_token.is_some()
                && cache.should_request(&creds.claude_ai_oauth.access_token, mode, now)
            {
                match api::refresh_credentials_async(&client, &creds.claude_ai_oauth).await {
                    Ok(rotated) => {
                        creds.claude_ai_oauth = rotated;
                        if let Err(error) = profile.write_credentials(&creds) {
                            profile_save_error = Some(format!(
                                "token refreshed but profile save failed; usage data is not persisted ({error})"
                            ));
                        }
                        result.token_expiry_secs = creds.claude_ai_oauth.expiry_secs();
                    }
                    Err(error) => {
                        result.snapshot = cache.refresh_failed(
                            &creds.claude_ai_oauth.access_token,
                            &error,
                            chrono::Utc::now().timestamp(),
                        )?;
                        result.usage = result.snapshot.usage.clone();
                        result.error = result.snapshot.error.clone();
                        fetched.push(result);
                        continue;
                    }
                }
            }
            result.snapshot = cache
                .get(
                    &client,
                    &creds.claude_ai_oauth.access_token,
                    mode,
                    chrono::Utc::now().timestamp(),
                )
                .await?;
            result.usage = result.snapshot.usage.clone();
            result.error = profile_save_error.or_else(|| result.snapshot.error.clone());
            if result.usage.is_none() && result.error.is_none() {
                result.error = Some("no cached data; run claudectl status".into());
            }
            fetched.push(result);
        }
        Ok(fetched)
    })
}

fn to_account_status(f: &FetchedUsage) -> AccountStatus {
    match (&f.usage, &f.error) {
        (Some(usage), _) => AccountStatus {
            alias: f.alias.clone(),
            snapshot: f.snapshot.clone(),
            h5_pct: usage.five_hour.as_ref().and_then(|w| w.utilization),
            d7_pct: usage.seven_day.as_ref().and_then(|w| w.utilization),
            h5_reset: format_window_reset(usage.five_hour.as_ref()),
            d7_reset: format_window_reset(usage.seven_day.as_ref()),
            opus_pct: usage.seven_day_opus.as_ref().and_then(|w| w.utilization),
            sonnet_pct: usage.seven_day_sonnet.as_ref().and_then(|w| w.utilization),
            fable_pct: usage.fable_weekly().and_then(|l| l.percent),
            has_fable_limit: usage.fable_weekly().is_some(),
            token_expiry_secs: f.token_expiry_secs,
            is_active: f.is_active,
            is_error: f.error.is_some() || !f.snapshot.fresh,
            error_msg: f.error.clone().unwrap_or_default(),
        },
        (None, err) => AccountStatus {
            alias: f.alias.clone(),
            snapshot: f.snapshot.clone(),
            h5_pct: None,
            d7_pct: None,
            h5_reset: "-".to_string(),
            d7_reset: "-".to_string(),
            opus_pct: None,
            sonnet_pct: None,
            fable_pct: None,
            has_fable_limit: false,
            token_expiry_secs: f.token_expiry_secs,
            is_active: f.is_active,
            is_error: true,
            error_msg: err.clone().unwrap_or_else(|| "error".to_string()),
        },
    }
}

fn print_fetched_at() {
    let local = chrono::Local::now();
    println!("Usage checked at {}", local.format("%a %b %d %H:%M:%S"));
    println!();
}

fn print_table(accounts: &[AccountStatus]) {
    let show_models = accounts
        .iter()
        .any(|a| a.opus_pct.is_some() || a.sonnet_pct.is_some());
    let show_fable = show_fable_column(accounts);

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    let mut header = vec!["Account", "5h", "5h Reset", "7d", "7d Reset"];
    if show_models {
        header.push("Opus 7d");
        header.push("Sonnet 7d");
    }
    if show_fable {
        header.push("Fable 7d");
    }
    header.push("Token expiry");
    header.extend(["Account capacity", "Data age", "Next fetch", "Usage fetch"]);
    table.set_header(header);

    for account in accounts {
        table.add_row(render_row(account, show_models, show_fable));
    }
    println!("{table}");
    println!("Percentages are used capacity. Fetch success does not prove model access.");
    println!(
        "Cached data can lag by 5m. HTTP 429 limits usage checks, not proof of exhausted capacity."
    );
}

fn show_fable_column(accounts: &[AccountStatus]) -> bool {
    accounts.iter().any(|a| a.has_fable_limit)
}

fn render_row(s: &AccountStatus, show_models: bool, show_fable: bool) -> Vec<Cell> {
    let alias = if s.is_active {
        format!("* {}", s.alias)
    } else {
        s.alias.clone()
    };

    let mut row = vec![
        Cell::new(alias),
        colorize_usage_pct(s.h5_pct),
        Cell::new(&s.h5_reset),
        colorize_usage_pct(s.d7_pct),
        Cell::new(&s.d7_reset),
    ];
    if show_models {
        row.push(colorize_usage_pct(s.opus_pct));
        row.push(colorize_usage_pct(s.sonnet_pct));
    }
    if show_fable {
        row.push(colorize_usage_pct(s.fable_pct));
    }
    row.push(token_cell(s.token_expiry_secs));
    row.push(Cell::new(capacity(s)));
    let now = chrono::Utc::now().timestamp();
    row.push(Cell::new(
        s.snapshot
            .fetched_at
            .map(|at| {
                let age = format!("{}s", now.saturating_sub(at).max(0));
                if s.snapshot.fresh && !s.is_error {
                    age
                } else {
                    format!("{age} (stale)")
                }
            })
            .unwrap_or_else(|| "unknown".into()),
    ));
    row.push(Cell::new(
        s.snapshot
            .next_fetch_at
            .map(|at| {
                if at > now {
                    format!("in {}s", at.saturating_sub(now))
                } else {
                    "on next check".into()
                }
            })
            .unwrap_or_else(|| "-".into()),
    ));
    let fetch = if s.error_msg.is_empty() {
        s.snapshot.source.to_string()
    } else if s.snapshot.source.is_empty() {
        s.error_msg.clone()
    } else {
        format!("{}: {}", s.snapshot.source, s.error_msg)
    };
    row.push(Cell::new(fetch));
    row
}

fn capacity(s: &AccountStatus) -> String {
    if s.is_error {
        return "unknown; see last data".into();
    }
    if s.d7_pct.is_some_and(|pct| pct >= 100.0) {
        return "weekly limit reached".into();
    }
    if s.h5_pct.is_some_and(|pct| pct >= 100.0) {
        return "5h limit reached".into();
    }
    let models: Vec<_> = [
        ("Fable", s.fable_pct),
        ("Opus", s.opus_pct),
        ("Sonnet", s.sonnet_pct),
    ]
    .into_iter()
    .filter_map(|(name, pct)| pct.filter(|p| *p >= 100.0).map(|_| name))
    .collect();
    if !models.is_empty() {
        return format!("{} limit reached", models.join("/"));
    }
    if s.h5_pct.is_none() || s.d7_pct.is_none() {
        return "unknown".into();
    }
    "below reported limits".into()
}

/// Stored expiry is independent of whether the usage API accepted the request.
fn token_cell(expiry_secs: Option<i64>) -> Cell {
    match expiry_secs {
        None => Cell::new("unknown"),
        Some(exp) => {
            let diff = exp - chrono::Utc::now().timestamp();
            if diff <= 0 {
                return Cell::new("expired").fg(Color::Red);
            }
            let color = if diff >= 86400 {
                Color::Green
            } else if diff >= 3600 {
                Color::Yellow
            } else {
                Color::Red
            };
            Cell::new(format_duration(diff)).fg(color)
        }
    }
}

fn colorize_usage_pct(pct: Option<f64>) -> Cell {
    let Some(pct) = pct else {
        return Cell::new("-");
    };
    let color = if pct >= 80.0 {
        Color::Red
    } else if pct >= 50.0 {
        Color::Yellow
    } else {
        Color::Green
    };
    Cell::new(format!("{pct:.0}%")).fg(color)
}

fn format_window_reset(window: Option<&UsageWindow>) -> String {
    let Some(reset_ts) = window.and_then(|w| w.reset_timestamp()) else {
        return "-".to_string();
    };
    let now = chrono::Utc::now().timestamp();
    let diff_secs = reset_ts - now;
    if diff_secs <= 0 {
        "now".to_string()
    } else if diff_secs >= 86400 {
        format!(
            "in {} ({})",
            format_duration(diff_secs),
            format_reset_timestamp(reset_ts)
        )
    } else {
        format!("in {}", format_duration(diff_secs))
    }
}

fn format_reset_timestamp(reset_ts: i64) -> String {
    chrono::DateTime::from_timestamp(reset_ts, 0)
        .map(|dt| {
            let local = dt.with_timezone(&chrono::Local);
            local.format("%a %b %d %H:%M").to_string()
        })
        .unwrap_or_else(|| "-".to_string())
}

fn format_duration(secs: i64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;

    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes:02}m")
    } else {
        format!("{minutes}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(h5: Option<f64>, d7: Option<f64>, is_error: bool) -> AccountStatus {
        AccountStatus {
            alias: "a@x".to_string(),
            snapshot: Snapshot {
                fresh: !is_error,
                source: "live",
                ..Snapshot::default()
            },
            h5_pct: h5,
            d7_pct: d7,
            h5_reset: "-".to_string(),
            d7_reset: "-".to_string(),
            opus_pct: None,
            sonnet_pct: None,
            fable_pct: None,
            has_fable_limit: false,
            token_expiry_secs: None,
            is_active: false,
            is_error,
            error_msg: String::new(),
        }
    }

    #[test]
    fn weekly_exhaustion_is_distinct_from_fetch_success() {
        let a = account(Some(0.0), Some(100.0), false);
        let cells: Vec<_> = render_row(&a, false, false)
            .into_iter()
            .map(|c| c.content())
            .collect();
        assert!(cells.iter().any(|c| c == "weekly limit reached"));
    }

    #[test]
    fn availability_score_orders_correctly() {
        let fresh = account(Some(5.0), Some(10.0), false).availability_score();
        let busy = account(Some(70.0), Some(60.0), false).availability_score();
        let h5_out = account(Some(100.0), Some(20.0), false).availability_score();
        let d7_out = account(Some(20.0), Some(100.0), false).availability_score();
        let both_out = account(Some(100.0), Some(100.0), false).availability_score();
        let error = account(None, None, true).availability_score();

        assert!(fresh < busy);
        assert!(busy < h5_out);
        assert!(h5_out < d7_out);
        assert!(d7_out < both_out);
        assert!(both_out < error);
    }

    #[test]
    fn render_row_column_count() {
        for a in [
            account(Some(10.0), Some(20.0), false),
            account(None, None, true),
        ] {
            assert_eq!(render_row(&a, false, false).len(), 10);
            assert_eq!(render_row(&a, true, false).len(), 12);
            assert_eq!(render_row(&a, false, true).len(), 11);
            assert_eq!(render_row(&a, true, true).len(), 13);
        }
    }

    #[test]
    fn fable_column_shows_weekly_usage() {
        let mut a = account(Some(10.0), Some(20.0), false);
        a.fable_pct = Some(100.0);
        assert_eq!(render_row(&a, false, true)[5].content(), "100%");
        assert_eq!(render_row(&a, true, true)[7].content(), "100%");

        a.fable_pct = None;
        assert_eq!(render_row(&a, false, true)[5].content(), "-");
    }

    #[test]
    fn fable_limit_without_percent_still_shows_column() {
        let usage: UsageResponse = serde_json::from_str(
            r#"{"limits":[{"kind":"weekly_scoped","percent":null,
                "scope":{"model":{"display_name":"Fable"}}}]}"#,
        )
        .unwrap();
        let status = to_account_status(&FetchedUsage {
            alias: "a@x".to_string(),
            usage: Some(usage),
            token_expiry_secs: None,
            is_active: false,
            error: None,
            ..FetchedUsage::default()
        });
        assert!(show_fable_column(&[status]));
        assert!(!show_fable_column(&[account(Some(1.0), Some(1.0), false)]));
    }

    #[test]
    fn rate_limit_does_not_replace_token_expiry() {
        let mut a = account(None, None, true);
        a.token_expiry_secs = Some(chrono::Utc::now().timestamp() + 7200);
        a.error_msg = "rate limited (HTTP 429); retry in 207s".into();
        for show_models in [false, true] {
            let row = render_row(&a, show_models, false);
            assert!(row[row.len() - 5].content().contains('h'));
            assert!(row[row.len() - 1].content().ends_with(&a.error_msg));
        }
        a.token_expiry_secs = Some(1);
        let row = render_row(&a, false, false);
        assert_eq!(row[5].content(), "expired");
        assert!(row[9].content().ends_with(&a.error_msg));
    }

    #[test]
    fn format_duration_cases() {
        assert_eq!(format_duration(3 * 86400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 05m");
        assert_eq!(format_duration(9 * 60), "9m");
    }
}
