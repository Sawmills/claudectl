use std::path::PathBuf;

use anyhow::Result;
use claudectl::api::{self, CredentialsFile, UsageResponse, UsageWindow};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;
use comfy_table::{Cell, Color, Table, presets::UTF8_FULL_CONDENSED};

/// One profile's fetched usage, shared by `status` and `use` auto-select.
pub struct FetchedUsage {
    pub alias: String,
    pub usage: Option<UsageResponse>,
    pub token_expiry_secs: Option<i64>,
    pub is_active: bool,
    pub error: Option<String>,
}

struct AccountStatus {
    alias: String,
    h5_pct: Option<f64>,
    d7_pct: Option<f64>,
    h5_reset: String,
    d7_reset: String,
    opus_pct: Option<f64>,
    sonnet_pct: Option<f64>,
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

pub fn run() -> Result<()> {
    let fetched = fetch_all_usages()?;
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

/// Print a single account's status (used after a switch).
pub fn run_focused(alias: &str) -> Result<()> {
    let fetched = fetch_all_usages()?;
    let accounts: Vec<AccountStatus> = fetched
        .iter()
        .filter(|f| f.alias == alias)
        .map(to_account_status)
        .collect();
    if accounts.is_empty() {
        println!("status unavailable for {alias}");
        return Ok(());
    }
    print_table(&accounts);
    Ok(())
}

/// Fetch usage for every profile in parallel. The active profile is read from
/// the live auth store (Claude Code keeps it fresh); non-active profiles with
/// an expired access token get a refresh first, persisted back to the profile.
/// The active profile is NEVER refreshed here — Claude Code owns its refresh
/// token, and rotating it would log the user out.
pub fn fetch_all_usages() -> Result<Vec<FetchedUsage>> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    let profiles = profile::list_profiles_from(&paths)?;
    if profiles.is_empty() {
        return Ok(vec![]);
    }
    let active = profile::get_active_from(&paths)?;

    // Pre-read credentials synchronously; only network work goes async.
    let inputs: Vec<(String, bool, anyhow::Result<CredentialsFile>, PathBuf)> = profiles
        .iter()
        .map(|p| {
            let is_active = active.as_deref() == Some(p.meta.alias.as_str());
            let creds = if is_active {
                store.read_credentials()
            } else {
                p.read_credentials()
            };
            (p.meta.alias.clone(), is_active, creds, p.credentials_path())
        })
        .collect();

    let rt = tokio::runtime::Runtime::new()?;
    Ok(rt.block_on(async {
        let client = reqwest::Client::new();
        let futures: Vec<_> = inputs
            .into_iter()
            .map(|(alias, is_active, creds, creds_path)| {
                let client = client.clone();
                async move {
                    let mut creds = match creds {
                        Ok(c) => c,
                        Err(_) => {
                            return FetchedUsage {
                                alias,
                                usage: None,
                                token_expiry_secs: None,
                                is_active,
                                error: Some("bad credentials".to_string()),
                            };
                        }
                    };

                    if !is_active
                        && creds.claude_ai_oauth.is_expired()
                        && creds.claude_ai_oauth.refresh_token.is_some()
                        && let Ok(rotated) =
                            api::refresh_credentials_async(&client, &creds.claude_ai_oauth).await
                    {
                        creds.claude_ai_oauth = rotated;
                        if let Ok(json) = serde_json::to_string(&creds) {
                            let _ = std::fs::write(&creds_path, json);
                        }
                    }

                    let token_expiry_secs = creds.claude_ai_oauth.expiry_secs();
                    match api::fetch_usage_async(&client, &creds.claude_ai_oauth.access_token).await
                    {
                        Ok(usage) => FetchedUsage {
                            alias,
                            usage: Some(usage),
                            token_expiry_secs,
                            is_active,
                            error: None,
                        },
                        Err(e) => {
                            let msg = if e.to_string() == "expired" {
                                "expired"
                            } else {
                                "error"
                            };
                            FetchedUsage {
                                alias,
                                usage: None,
                                token_expiry_secs,
                                is_active,
                                error: Some(msg.to_string()),
                            }
                        }
                    }
                }
            })
            .collect();
        futures::future::join_all(futures).await
    }))
}

fn to_account_status(f: &FetchedUsage) -> AccountStatus {
    match (&f.usage, &f.error) {
        (Some(usage), _) => AccountStatus {
            alias: f.alias.clone(),
            h5_pct: usage.five_hour.as_ref().and_then(|w| w.utilization),
            d7_pct: usage.seven_day.as_ref().and_then(|w| w.utilization),
            h5_reset: format_window_reset(usage.five_hour.as_ref()),
            d7_reset: format_window_reset(usage.seven_day.as_ref()),
            opus_pct: usage.seven_day_opus.as_ref().and_then(|w| w.utilization),
            sonnet_pct: usage.seven_day_sonnet.as_ref().and_then(|w| w.utilization),
            token_expiry_secs: f.token_expiry_secs,
            is_active: f.is_active,
            is_error: false,
            error_msg: String::new(),
        },
        (None, err) => AccountStatus {
            alias: f.alias.clone(),
            h5_pct: None,
            d7_pct: None,
            h5_reset: "-".to_string(),
            d7_reset: "-".to_string(),
            opus_pct: None,
            sonnet_pct: None,
            token_expiry_secs: f.token_expiry_secs,
            is_active: f.is_active,
            is_error: true,
            error_msg: err.clone().unwrap_or_else(|| "error".to_string()),
        },
    }
}

fn print_fetched_at() {
    let local = chrono::Local::now();
    println!(
        "Live status fetched at {}",
        local.format("%a %b %d %H:%M:%S")
    );
    println!();
}

fn print_table(accounts: &[AccountStatus]) {
    let show_models = accounts
        .iter()
        .any(|a| a.opus_pct.is_some() || a.sonnet_pct.is_some());

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED);
    let mut header = vec!["Account", "5h", "5h Reset", "7d", "7d Reset"];
    if show_models {
        header.push("Opus 7d");
        header.push("Sonnet 7d");
    }
    header.push("Token");
    table.set_header(header);

    for account in accounts {
        table.add_row(render_row(account, show_models));
    }
    println!("{table}");
}

fn render_row(s: &AccountStatus, show_models: bool) -> Vec<Cell> {
    let alias = if s.is_active {
        format!("* {}", s.alias)
    } else {
        s.alias.clone()
    };

    if s.is_error {
        let mut row = vec![Cell::new(alias)];
        let cols = if show_models { 6 } else { 4 };
        row.extend(std::iter::repeat_with(|| Cell::new("-")).take(cols));
        row.push(token_cell(s.token_expiry_secs, true, &s.error_msg));
        return row;
    }

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
    row.push(token_cell(s.token_expiry_secs, false, &s.error_msg));
    row
}

/// The "Token" column: how long the stored access token is good for without a
/// refresh, or — for an errored row — what went wrong.
fn token_cell(expiry_secs: Option<i64>, is_error: bool, error_msg: &str) -> Cell {
    if is_error {
        return Cell::new(error_msg).fg(Color::Red);
    }
    match expiry_secs {
        None => Cell::new("-"),
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
            h5_pct: h5,
            d7_pct: d7,
            h5_reset: "-".to_string(),
            d7_reset: "-".to_string(),
            opus_pct: None,
            sonnet_pct: None,
            token_expiry_secs: None,
            is_active: false,
            is_error,
            error_msg: String::new(),
        }
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
        let a = account(Some(10.0), Some(20.0), false);
        assert_eq!(render_row(&a, false).len(), 6);
        assert_eq!(render_row(&a, true).len(), 8);

        let e = account(None, None, true);
        assert_eq!(render_row(&e, false).len(), 6);
        assert_eq!(render_row(&e, true).len(), 8);
    }

    #[test]
    fn format_duration_cases() {
        assert_eq!(format_duration(3 * 86400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 05m");
        assert_eq!(format_duration(9 * 60), "9m");
    }
}
