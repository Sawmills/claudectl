use std::time::Duration;

use anyhow::Result;
use claudectl::api::{self, UsageResponse, UsageWindow};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::profile;
use claudectl::usage_cache::{FetchMode, Snapshot, UsageCache};
use comfy_table::{
    Attribute, Cell, Color, Table,
    modifiers::UTF8_ROUND_CORNERS,
    presets::{UTF8_FULL, UTF8_FULL_CONDENSED},
};

/// One profile's fetched usage, shared by `status` and `use` auto-select.
#[derive(Default)]
pub struct FetchedUsage {
    pub snapshot: Snapshot,
    pub alias: String,
    pub account_uuid: Option<String>,
    pub label: Option<String>,
    /// `subscriptionType` from the saved credentials, such as "max" or "team".
    pub plan: Option<String>,
    pub usage: Option<UsageResponse>,
    pub token_expiry_secs: Option<i64>,
    pub is_active: bool,
    pub error: Option<String>,
}

struct AccountStatus {
    snapshot: Snapshot,
    alias: String,
    label: Option<String>,
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

pub fn run(alias: Option<&str>, mode: FetchMode, details: bool, json: bool) -> Result<()> {
    let fetched = fetch_usages(alias, mode)?;
    if json {
        let report = status_json(&fetched, chrono::Utc::now().timestamp());
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
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
    if details {
        print_table(&accounts);
    } else {
        print_summary(&accounts);
    }
    Ok(())
}

/// Version of the `status --json` shape.
pub const STATUS_JSON_VERSION: u32 = 1;

/// How an account is paid for. Only `rate_limited` accounts are ever picked
/// automatically: `usage_based` has extra usage on, so running past a plan
/// window bills credits, and `unknown` cannot be proven safe. Missing or null
/// extra-usage data is not proof that extra usage is off.
pub fn billing_class(usage: Option<&UsageResponse>, plan: Option<&str>) -> &'static str {
    let Some(usage) = usage else {
        return "unknown";
    };
    match usage
        .extra_usage
        .as_ref()
        .and_then(|extra| extra.is_enabled)
    {
        Some(true) => "usage_based",
        Some(false)
            if plan.is_some_and(|plan| !plan.trim().is_empty())
                && (usage.five_hour.is_some() || usage.seven_day.is_some()) =>
        {
            "rate_limited"
        }
        _ => "unknown",
    }
}

/// Whether any window, including the model-scoped Opus, Sonnet and Fable
/// limits, is used up.
pub fn exhausted(usage: &UsageResponse) -> bool {
    let windows = [
        &usage.five_hour,
        &usage.seven_day,
        &usage.seven_day_opus,
        &usage.seven_day_sonnet,
    ];
    windows
        .into_iter()
        .flatten()
        .filter_map(|window| window.utilization)
        .chain(usage.fable_weekly().and_then(|limit| limit.percent))
        .any(|used| used >= 100.0)
}

fn window_json(window: Option<&api::UsageWindow>) -> serde_json::Value {
    match window {
        Some(window) => serde_json::json!({
            "used_percent": window.utilization,
            "resets_at": window.resets_at,
        }),
        None => serde_json::Value::Null,
    }
}

/// The `status --json` document: `{version, accounts: [...]}`, sorted by alias.
pub fn status_json(fetched: &[FetchedUsage], now: i64) -> serde_json::Value {
    let mut fetched: Vec<&FetchedUsage> = fetched.iter().collect();
    fetched.sort_by(|a, b| a.alias.cmp(&b.alias));
    let accounts: Vec<serde_json::Value> = fetched
        .into_iter()
        .map(|f| {
            let usage = f.usage.as_ref();
            serde_json::json!({
                "alias": f.alias,
                "label": f.label,
                "active": f.is_active,
                "plan": f.plan,
                "billing_class": billing_class(usage, f.plan.as_deref()),
                "exhausted": usage.map(exhausted),
                "windows": {
                    "five_hour": window_json(usage.and_then(|u| u.five_hour.as_ref())),
                    "seven_day": window_json(usage.and_then(|u| u.seven_day.as_ref())),
                    "seven_day_opus": window_json(usage.and_then(|u| u.seven_day_opus.as_ref())),
                    "seven_day_sonnet": window_json(usage.and_then(|u| u.seven_day_sonnet.as_ref())),
                    "fable_weekly": usage
                        .and_then(|u| u.fable_weekly())
                        .map(|limit| serde_json::json!({ "used_percent": limit.percent })),
                },
                "extra_usage": usage.and_then(|u| u.extra_usage.as_ref()).map(|extra| {
                    serde_json::json!({
                        "enabled": extra.is_enabled,
                        "used_credits": extra.used_credits,
                    })
                }),
                // `token_expiry_secs` is the absolute expiry (Unix seconds).
                "token_expires_in_seconds": f
                    .token_expiry_secs
                    .map(|expires_at| expires_at.saturating_sub(now).max(0)),
                "usage_age_seconds": f.snapshot.fetched_at.map(|at| now.saturating_sub(at).max(0)),
                "usage_stale": !f.snapshot.is_fresh_at(now),
                "error": f.error,
            })
        })
        .collect();
    serde_json::json!({ "version": STATUS_JSON_VERSION, "accounts": accounts })
}

/// Explicit switching stays local: show only this account's cached data.
pub fn run_focused(store: &AuthStore, paths: &config::Paths, alias: &str) -> Result<()> {
    let fetched = fetch_usages_from(store, paths, Some(alias), FetchMode::Cached)?;
    record_statusline_for(paths, &fetched, alias);
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
    print_summary(&accounts);
}

/// One saved profile's usage.
pub fn fetch_alias(alias: &str, mode: FetchMode) -> Result<Option<FetchedUsage>> {
    Ok(fetch_usages(Some(alias), mode)?.into_iter().next())
}

pub fn fetch_all_usages() -> Result<Vec<FetchedUsage>> {
    fetch_usages(None, FetchMode::Normal)
}

fn fetch_usages(alias: Option<&str>, mode: FetchMode) -> Result<Vec<FetchedUsage>> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    let fetched = fetch_usages_from(&store, &paths, alias, mode)?;
    record_statusline(&paths, &fetched, alias.is_none());
    Ok(fetched)
}

/// Keep the statusline sample in step with the active account's latest
/// usage. A failure only affects the statusline, so it is a warning.
fn record_statusline(paths: &config::Paths, fetched: &[FetchedUsage], all_profiles: bool) {
    let active = fetched.iter().find(|f| f.is_active);
    // A check of one other profile says nothing about the active one.
    if active.is_none() && !all_profiles {
        return;
    }
    record_statusline_entry(paths, active);
}

/// After a switch to `alias`, record its usage as the active account's.
pub fn record_statusline_for(paths: &config::Paths, fetched: &[FetchedUsage], alias: &str) {
    record_statusline_entry(paths, fetched.iter().find(|f| f.alias == alias));
}

fn record_statusline_entry(paths: &config::Paths, entry: Option<&FetchedUsage>) {
    let now = chrono::Utc::now().timestamp();
    let active = entry.map(|f| claudectl::statusline::Active {
        alias: &f.alias,
        account_uuid: f.account_uuid.as_deref(),
        usage: f
            .usage
            .as_ref()
            .filter(|_| f.error.is_none() && f.snapshot.is_fresh_at(now)),
    });
    if let Err(error) = claudectl::statusline::record(paths, active, now) {
        eprintln!("warning: statusline sample not updated: {error:#}");
    }
}

fn fetch_usages_from(
    store: &AuthStore,
    paths: &config::Paths,
    alias: Option<&str>,
    mode: FetchMode,
) -> Result<Vec<FetchedUsage>> {
    fetch_usages_with_refresh(store, paths, alias, mode, api::refresh_credentials_async)
}

fn fetch_usages_with_refresh(
    store: &AuthStore,
    paths: &config::Paths,
    alias: Option<&str>,
    mode: FetchMode,
    mut refresh: impl AsyncFnMut(&reqwest::Client, &api::OauthCreds) -> Result<api::OauthCreds>,
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
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        let mut fetched = Vec::new();
        let mut refreshes = std::collections::HashMap::<String, Result<api::OauthCreds>>::new();
        for profile in profiles {
            // Switching and saved-profile mutations use this same lock. Read
            // ownership and credentials only after acquiring it, and retain it
            // through refresh and persistence. Usage GETs do not hold it.
            let auth_lock = store.lock_auth_state()?;
            let active = profile::get_active_from(paths)?;
            let refresh_owner = store.read_refresh_owner();
            let refresh_owner_known = refresh_owner.is_ok();
            let live_creds = match refresh_owner {
                Ok(creds) => creds,
                // A fallback remains usable for display, never for refresh authority.
                Err(_) => store.read_credentials().ok(),
            };
            let live_grant_key = live_creds.as_ref().and_then(|creds| {
                creds.claude_ai_oauth.refresh_token.as_deref().map(UsageCache::key)
            });
            let is_active = active.as_deref() == Some(profile.meta.alias.as_str());
            let saved_uuid = profile.meta.account_uuid().map(str::to_string);
            // The active alias is checked with the live credentials. Name its
            // account only when the live login is still that account.
            let account_uuid = if is_active {
                let live_uuid = store.read_oauth_account().ok().flatten().and_then(|account| {
                    account.get("accountUuid")?.as_str().map(str::to_string)
                });
                saved_uuid.filter(|saved| live_uuid.as_deref() == Some(saved.as_str()))
            } else {
                saved_uuid
            };
            let mut result = FetchedUsage {
                alias: profile.meta.alias.clone(),
                label: profile.meta.label.clone(),
                account_uuid,
                is_active,
                ..FetchedUsage::default()
            };
            let creds = if is_active {
                live_creds
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("live credentials unavailable"))
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
            result.plan = creds
                .claude_ai_oauth
                .subscription_type
                .as_deref()
                .map(str::trim)
                .filter(|plan| !plan.is_empty())
                .map(str::to_string);
            if creds.claude_ai_oauth.access_token.trim().is_empty() {
                result.error = Some("missing access token; log in again".into());
                fetched.push(result);
                continue;
            }
            let now = chrono::Utc::now().timestamp();
            let mut profile_save_error = None;
            let grant_key = creds
                .claude_ai_oauth
                .refresh_token
                .as_deref()
                .map(UsageCache::key);
            // A saved alias can hold the same grant as the live login. Its name
            // does not transfer refresh ownership away from Claude Code.
            if creds.claude_ai_oauth.is_expired()
                && (!refresh_owner_known || is_active || (grant_key.is_some() && grant_key == live_grant_key))
            {
                result.snapshot = cache
                    .get(
                        &client,
                        &creds.claude_ai_oauth.access_token,
                        FetchMode::Cached,
                        now,
                    )
                    .await?;
                result.usage = result.snapshot.usage.clone();
                // No request was sent. Report the current refresh blocker before
                // any historical fetch error retained in the usage cache.
                result.error = if !result.snapshot.is_fresh_at(now) {
                    Some(if refresh_owner_known {
                        "expired token belongs to live login; let Claude Code refresh it".into()
                    } else {
                        "live refresh ownership unknown; check Claude Code login or Keychain access".into()
                    })
                } else {
                    result.snapshot.error.clone()
                };
                fetched.push(result);
                continue;
            }
            if creds.claude_ai_oauth.is_expired()
                && let Some(grant) = creds.claude_ai_oauth.refresh_token.as_deref()
                && let Some(snapshot) = cache.refresh_cooldown(&creds.claude_ai_oauth.access_token, grant, now)
            {
                result.usage = snapshot.usage.clone();
                result.error = snapshot.error.clone();
                result.snapshot = snapshot;
                fetched.push(result);
                continue;
            }
            // Claude Code owns refresh for the active profile. Cached and cooldown
            // paths do not contact either the usage endpoint or the token endpoint.
            if !is_active
                && creds.claude_ai_oauth.is_expired()
                && creds.claude_ai_oauth.refresh_token.is_some()
                && (grant_key
                    .as_ref()
                    .is_some_and(|key| refreshes.contains_key(key))
                    || cache.should_request(&creds.claude_ai_oauth.access_token, mode, now))
            {
                let key_for_grant = creds.claude_ai_oauth.refresh_token.clone().expect("refresh token checked above");
                let key = grant_key.expect("refresh token checked above");
                let refreshed = match refreshes.entry(key.clone()) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(refresh(&client, &creds.claude_ai_oauth).await)
                    }
                };
                match refreshed {
                    Ok(rotated) => {
                        creds.claude_ai_oauth = rotated.clone();
                        if let Err(error) = persist_rotated_grant(paths, active.as_deref(), &profile, &creds, &key) {
                            profile_save_error = Some(format!(
                                "token refreshed but saving profiles failed; affected aliases may need login ({error})"
                            ));
                        }
                        cache.refresh_succeeded(&key_for_grant)?;
                        result.token_expiry_secs = creds.claude_ai_oauth.expiry_secs();
                    }
                    Err(error) => {
                        result.snapshot = cache.refresh_failed_for_grant(
                            &creds.claude_ai_oauth.access_token,
                            creds.claude_ai_oauth.refresh_token.as_deref().expect("refresh token checked"),
                            error,
                            chrono::Utc::now().timestamp(),
                        )?;
                        result.usage = result.snapshot.usage.clone();
                        result.error = result.snapshot.error.clone();
                        fetched.push(result);
                        continue;
                    }
                }
            }
            drop(auth_lock);
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

fn persist_rotated_grant(
    paths: &config::Paths,
    active: Option<&str>,
    origin: &profile::Profile,
    rotated: &api::CredentialsFile,
    original_grant_key: &str,
) -> Result<()> {
    let mut failures = Vec::new();
    if origin.write_credentials(rotated).is_err() {
        failures.push(origin.meta.alias.clone());
    }
    // Rotation changes the grant for every saved copy, including unexpired
    // aliases and aliases excluded by a focused status request.
    for sibling in profile::list_profiles_from(paths)? {
        if sibling.meta.alias == origin.meta.alias || active == Some(sibling.meta.alias.as_str()) {
            continue;
        }
        let mut creds = match sibling.read_credentials() {
            Ok(creds) => creds,
            // An unreadable profile cannot be identified as a matching grant.
            // Its status row reports that error independently.
            Err(_) => continue,
        };
        if creds
            .claude_ai_oauth
            .refresh_token
            .as_deref()
            .map(UsageCache::key)
            .as_deref()
            != Some(original_grant_key)
        {
            continue;
        }
        creds.claude_ai_oauth.access_token = rotated.claude_ai_oauth.access_token.clone();
        creds.claude_ai_oauth.refresh_token = rotated.claude_ai_oauth.refresh_token.clone();
        creds.claude_ai_oauth.expires_at = rotated.claude_ai_oauth.expires_at;
        if sibling.write_credentials(&creds).is_err() {
            failures.push(sibling.meta.alias.clone());
        }
    }
    anyhow::ensure!(
        failures.is_empty(),
        "could not update saved aliases: {}",
        failures.join(", ")
    );
    Ok(())
}

fn to_account_status(f: &FetchedUsage) -> AccountStatus {
    match (&f.usage, &f.error) {
        (Some(usage), _) => AccountStatus {
            alias: f.alias.clone(),
            label: f.label.clone(),
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
            is_error: f.error.is_some() || !f.snapshot.is_fresh_at(chrono::Utc::now().timestamp()),
            error_msg: f.error.clone().unwrap_or_default(),
        },
        (None, err) => AccountStatus {
            alias: f.alias.clone(),
            label: f.label.clone(),
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
    if std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()) {
        table.force_no_tty();
    }
    let show_label = show_label_column(accounts);
    let mut header = vec!["Account", "5h", "5h Reset", "7d", "7d Reset"];
    if show_label {
        header.insert(1, "Label");
    }
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
        table.add_row(with_label(
            render_row(account, show_models, show_fable),
            account,
            show_label,
        ));
    }
    println!("{table}");
    println!("Percentages are used capacity. Fetch success does not prove model access.");
    println!(
        "Cached data can lag by 5m. HTTP 429 limits usage checks, not proof of exhausted capacity."
    );
}

/// Describe the next action without treating expired tokens or API throttling
/// as proof that an account needs login or has exhausted its allowance.
fn next_step(s: &AccountStatus) -> (String, String) {
    let error = s.error_msg.as_str();
    if error.contains("ownership unknown") {
        return (
            "Check live login".into(),
            "Check Keychain access and Claude Code login".into(),
        );
    }
    if error.contains("belongs to live login") {
        return (
            "Let Claude refresh".into(),
            "Open Claude Code; login only if refresh fails".into(),
        );
    }
    if error.contains("missing access token") || error.contains("authentication rejected") {
        let action = if s.is_active {
            "Open Claude Code and run /login".into()
        } else {
            format!("claudectl login {}", claudectl::shell::quote_arg(&s.alias))
        };
        return ("Login needed".into(), action);
    }
    if error.contains("saving profiles failed") {
        return (
            "Profile save failed".into(),
            "Check file permissions; log in again if needed".into(),
        );
    }
    if error.contains("HTTP 429") {
        let label = if error.contains("token refresh") {
            "Refresh throttled"
        } else {
            "Usage check throttled"
        };
        return (label.into(), retry_step(s));
    }
    if error.contains("HTTP 403") {
        return (
            "Access denied".into(),
            "Check account permissions in Claude Code".into(),
        );
    }
    if error.contains("credentials unavailable") {
        return if s.is_active {
            (
                "Cannot read login".into(),
                "Check Claude Code login and Keychain access".into(),
            )
        } else {
            (
                "Cannot read saved login".into(),
                "Check saved file permissions; re-save or log in".into(),
            )
        };
    }
    if !error.is_empty() && !error.contains("no cached data") {
        return (
            "Check failed".into(),
            format!("{}; see --details", retry_step(s)),
        );
    }
    if s.is_error || !s.snapshot.is_fresh_at(chrono::Utc::now().timestamp()) {
        return ("Usage unknown".into(), retry_step(s));
    }
    if s.d7_pct.is_some_and(|pct| pct >= 100.0) {
        return ("Weekly limit reached".into(), reset_step(&s.d7_reset));
    }
    if s.h5_pct.is_some_and(|pct| pct >= 100.0) {
        return ("5-hour limit reached".into(), reset_step(&s.h5_reset));
    }
    let limited = capacity(s);
    if limited.ends_with("limit reached") {
        return (limited, "Use another model or account".into());
    }
    if s.h5_pct.is_none() || s.d7_pct.is_none() {
        return (
            "Usage unknown".into(),
            "Check model access in Claude Code".into(),
        );
    }
    (
        "Within usage limits".into(),
        "No action needed for reported usage".into(),
    )
}

fn retry_step(s: &AccountStatus) -> String {
    let now = chrono::Utc::now().timestamp();
    match s.snapshot.next_fetch_at {
        Some(at) if at > now => format!("Run status in {}", short_duration(at - now)),
        _ => "Run claudectl status again".into(),
    }
}

fn short_duration(seconds: i64) -> String {
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format_duration(seconds)
    }
}

fn reset_step(reset: &str) -> String {
    match reset.split(" (").next().unwrap_or(reset) {
        "-" => "Wait for reset or use another account".into(),
        "now" => "Run status again to check reset".into(),
        relative => format!("Resets {relative}; or use another account"),
    }
}

fn summary_row(s: &AccountStatus) -> Vec<Cell> {
    let (status, action) = next_step(s);
    let alias = if s.is_active {
        format!("* {}", s.alias)
    } else {
        s.alias.clone()
    };
    let now = chrono::Utc::now().timestamp();
    let usage = if !s.is_error && s.snapshot.is_fresh_at(now) {
        [
            ("5h", s.h5_pct),
            ("week", s.d7_pct),
            ("Fable", s.fable_pct),
            ("Opus", s.opus_pct),
            ("Sonnet", s.sonnet_pct),
        ]
        .into_iter()
        .filter_map(|(name, pct)| pct.map(|p| format!("{name}: {}", usage_percent(p))))
        .collect::<Vec<_>>()
        .join("\n")
    } else {
        "Unknown".into()
    };
    let data = if s.snapshot.is_fresh_at(now) && !s.is_error {
        if s.snapshot.source == "live" {
            "Live".into()
        } else {
            "Recent cache".into()
        }
    } else if s.snapshot.is_fresh_at(now) {
        "Recent; check failed".into()
    } else if let Some(at) = s.snapshot.fetched_at {
        format!("Old: {} ago", short_duration(now.saturating_sub(at).max(0)))
    } else {
        "No data".into()
    };
    let status_color = if status == "Within usage limits" {
        Color::Green
    } else if status.ends_with("limit reached")
        || matches!(
            status.as_str(),
            "Login needed" | "Access denied" | "Profile save failed"
        )
    {
        Color::Red
    } else {
        Color::Yellow
    };
    // One color for the usage group: the most-used reported window wins.
    let usage_color = if s.is_error || !s.snapshot.is_fresh_at(now) {
        Color::Yellow
    } else {
        usage_color(
            [s.h5_pct, s.d7_pct, s.fable_pct, s.opus_pct, s.sonnet_pct]
                .into_iter()
                .flatten()
                .reduce(f64::max)
                .unwrap_or(0.0),
        )
    };
    let alias = if s.is_active {
        Cell::new(alias)
            .fg(Color::Cyan)
            .add_attribute(Attribute::Bold)
    } else {
        Cell::new(alias)
    };
    vec![
        alias,
        Cell::new(status)
            .fg(status_color)
            .add_attribute(Attribute::Bold),
        Cell::new(usage).fg(usage_color),
        Cell::new(data).add_attribute(Attribute::Dim),
        Cell::new(action),
    ]
}

fn summary_table(accounts: &[AccountStatus], no_color: bool) -> Table {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.style_text_only();
    table.apply_modifier(UTF8_ROUND_CORNERS);
    if no_color {
        table.force_no_tty();
    }
    let show_label = show_label_column(accounts);
    let mut header = vec!["Account", "Status", "Usage used", "Data", "Next step"];
    if show_label {
        header.insert(1, "Label");
    }
    table.set_header(header.into_iter().map(|label| {
        Cell::new(label)
            .fg(Color::Cyan)
            .add_attribute(Attribute::Bold)
    }));
    for account in accounts {
        table.add_row(with_label(summary_row(account), account, show_label));
    }
    table
}

/// The Label column appears only when some account has a label.
fn show_label_column(accounts: &[AccountStatus]) -> bool {
    accounts.iter().any(|a| a.label.is_some())
}

/// Insert the Label cell after the Account cell.
fn with_label(mut row: Vec<Cell>, account: &AccountStatus, show_label: bool) -> Vec<Cell> {
    if show_label {
        row.insert(1, Cell::new(account.label.as_deref().unwrap_or("")));
    }
    row
}

fn print_summary(accounts: &[AccountStatus]) {
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty());
    let table = summary_table(accounts, no_color);
    println!("{table}");
    println!();
    println!("* Active account. Old or failed-check usage is hidden. Cache can lag by 5 minutes.");
    println!(
        "Expired tokens alone do not mean login is needed. Usage checks do not test model access."
    );
    println!("Use claudectl status --details for token expiry, old usage, and fetch errors.");
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
                if s.snapshot.is_fresh_at(now) {
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
    Cell::new(usage_percent(pct)).fg(usage_color(pct))
}

fn usage_percent(pct: f64) -> String {
    // Do not round a window that still has capacity up to a full limit.
    if (99.5..100.0).contains(&pct) {
        "<100%".into()
    } else {
        format!("{pct:.0}%")
    }
}

fn usage_color(pct: f64) -> Color {
    if pct >= 80.0 {
        Color::Red
    } else if pct >= 50.0 {
        Color::Yellow
    } else {
        Color::Green
    }
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
            short_duration(diff_secs),
            format_reset_timestamp(reset_ts)
        )
    } else {
        format!("in {}", short_duration(diff_secs))
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

    fn fresh_account(h5: Option<f64>, d7: Option<f64>, is_error: bool) -> AccountStatus {
        let mut a = account(h5, d7, is_error);
        let now = chrono::Utc::now().timestamp();
        a.snapshot.fetched_at = Some(now);
        a.snapshot.valid_until = Some(now + 300);
        a
    }

    #[test]
    fn summary_styles_active_account_capacity_and_unknown_data() {
        let mut a = fresh_account(Some(20.0), Some(30.0), false);
        a.is_active = true;
        let row = summary_row(&a);
        assert_eq!(
            row[0],
            Cell::new("* a@x")
                .fg(Color::Cyan)
                .add_attribute(Attribute::Bold)
        );
        assert_eq!(
            row[1],
            Cell::new("Within usage limits")
                .fg(Color::Green)
                .add_attribute(Attribute::Bold)
        );
        assert_eq!(row[2], Cell::new("5h: 20%\nweek: 30%").fg(Color::Green));
        a.d7_pct = Some(100.0);
        assert_eq!(
            summary_row(&a)[1],
            Cell::new("Weekly limit reached")
                .fg(Color::Red)
                .add_attribute(Attribute::Bold)
        );
        assert_eq!(
            summary_row(&a)[2],
            Cell::new("5h: 20%\nweek: 100%").fg(Color::Red)
        );
        a.is_error = true;
        assert_eq!(summary_row(&a)[2], Cell::new("Unknown").fg(Color::Yellow));
    }

    #[test]
    fn summary_color_is_optional_and_plain_output_keeps_all_advice() {
        let a = fresh_account(Some(20.0), Some(30.0), false);
        let mut colored = summary_table(&[a], false);
        colored.enforce_styling();
        assert!(colored.to_string().contains("\x1b["));
        let plain =
            summary_table(&[fresh_account(Some(20.0), Some(30.0), false)], true).to_string();
        assert!(!plain.contains("\x1b["));
        assert!(plain.contains("Within usage limits"));
        assert!(plain.contains("No action needed for reported usage"));
        assert!(plain.starts_with('╭'));
    }

    #[test]
    fn nearly_full_usage_is_not_displayed_as_a_reached_limit() {
        assert_eq!(usage_percent(99.6), "<100%");
        assert_eq!(usage_percent(100.0), "100%");
        assert_eq!(usage_color(49.0), Color::Green);
        assert_eq!(usage_color(50.0), Color::Yellow);
        assert_eq!(usage_color(80.0), Color::Red);
        let a = fresh_account(Some(99.6), Some(20.0), false);
        assert_eq!(next_step(&a).0, "Within usage limits");
        assert!(summary_row(&a)[2].content().contains("5h: <100%"));
    }

    #[test]
    fn the_active_account_is_named_only_while_the_live_login_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken":"test-access", "refreshToken":"test-grant", "expiresAt":1}
        }))
        .unwrap();
        profile::save_profile_to(
            &paths,
            "work",
            &creds,
            Some(serde_json::json!({"accountUuid": "u1"})),
        )
        .unwrap();
        profile::set_active_from(&paths, "work").unwrap();
        store.write_credentials(&creds).unwrap();
        for (live, expected) in [("u2", None), ("u1", Some("u1"))] {
            std::fs::write(
                paths.claude_json(),
                serde_json::json!({"oauthAccount": {"accountUuid": live}}).to_string(),
            )
            .unwrap();
            let fetched =
                fetch_usages_with_refresh(&store, &paths, None, FetchMode::Cached, async |_, _| {
                    panic!("no refresh in this test")
                })
                .unwrap();
            assert_eq!(
                fetched[0].account_uuid.as_deref(),
                expected,
                "live login {live}"
            );
        }
    }

    #[test]
    fn expired_live_token_reports_current_blocker_before_cached_throttling() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken":"test-expired-access", "refreshToken":"test-live-grant", "expiresAt":1}
        })).unwrap();
        profile::save_profile_to(&paths, "live", &creds, None).unwrap();
        profile::set_active_from(&paths, "live").unwrap();
        store.write_credentials(&creds).unwrap();
        let now = chrono::Utc::now().timestamp();
        let key = UsageCache::key("test-expired-access");
        std::fs::create_dir_all(paths.claudectl_dir().join("usage")).unwrap();
        std::fs::write(
            paths.claudectl_dir().join("usage/cache-v1.json"),
            serde_json::to_vec(&serde_json::json!({
                "entries": {key: {"usage":null,"fetched_at":now-3600,"next_attempt":now-1,
                    "failures":1,"error":"usage fetch failed (HTTP 429)"}},
                "rate_until":0,"rate_failures":0,"next_request_ms":0
            }))
            .unwrap(),
        )
        .unwrap();
        for expected in ["Let Claude refresh", "Check live login"] {
            let fetched =
                fetch_usages_with_refresh(&store, &paths, None, FetchMode::Normal, async |_, _| {
                    panic!("live-owned token must not refresh")
                })
                .unwrap();
            assert_eq!(next_step(&to_account_status(&fetched[0])).0, expected);
            profile::set_active_from(&paths, "other").unwrap();
            std::fs::write(paths.claude_credentials_file(), "invalid test data").unwrap();
        }
    }

    #[test]
    fn summary_reset_advice_uses_seconds_below_one_minute() {
        let window = UsageWindow {
            utilization: Some(100.0),
            resets_at: Some((chrono::Utc::now() + chrono::Duration::seconds(30)).to_rfc3339()),
        };
        let reset = format_window_reset(Some(&window));
        let step = reset_step(&reset);
        assert!(step.contains("s; or use another account"), "{step}");
        assert!(!step.contains("0m"), "{step}");
    }

    #[test]
    fn summary_distinguishes_recent_failed_checks_and_short_retries() {
        let now = chrono::Utc::now().timestamp();
        let mut a = account(Some(100.0), Some(100.0), true);
        a.snapshot.fresh = true;
        a.snapshot.fetched_at = Some(now - 30);
        a.snapshot.valid_until = Some(now + 270);
        a.snapshot.next_fetch_at = Some(now + 30);
        a.error_msg = "usage fetch failed (HTTP 429)".into();
        let row = summary_row(&a);
        assert_eq!(row[3].content(), "Recent; check failed");
        assert!(row[4].content().ends_with('s'));
        a.error_msg = "token refresh fetch failed (HTTP 429)".into();
        assert_eq!(next_step(&a).0, "Refresh throttled");
        a.error_msg =
            "token refreshed but saving profiles failed; affected aliases may need login".into();
        assert_eq!(next_step(&a).0, "Profile save failed");
        assert!(next_step(&a).1.contains("permissions"));
    }

    #[test]
    fn summary_separates_login_refresh_and_usage_failures() {
        let mut a = account(Some(100.0), Some(100.0), true);
        for (error, label) in [
            (
                "live refresh ownership unknown; check Claude Code login or Keychain access",
                "Check live login",
            ),
            (
                "expired token belongs to live login; let Claude Code refresh it",
                "Let Claude refresh",
            ),
            ("missing access token; log in again", "Login needed"),
            (
                "token refresh: authentication rejected (HTTP 401)",
                "Login needed",
            ),
            (
                "shared HTTP 429 delay; no request sent",
                "Usage check throttled",
            ),
            ("usage: access denied (HTTP 403)", "Access denied"),
            (
                "token refresh failed (network or invalid response)",
                "Check failed",
            ),
            (
                "credentials unavailable or invalid",
                "Cannot read saved login",
            ),
            ("no cached data; run claudectl status", "Usage unknown"),
            (
                "token refreshed but saving profiles failed",
                "Profile save failed",
            ),
        ] {
            a.error_msg = error.into();
            assert_eq!(next_step(&a).0, label);
            assert_eq!(summary_row(&a)[2].content(), "Unknown");
        }
        a.is_active = true;
        a.error_msg = "missing access token; log in again".into();
        assert_eq!(next_step(&a).1, "Open Claude Code and run /login");
        a.error_msg = "credentials unavailable or invalid".into();
        assert_eq!(next_step(&a).0, "Cannot read login");
        assert!(next_step(&a).1.contains("Keychain"));
        a.is_active = false;
        assert_eq!(next_step(&a).0, "Cannot read saved login");
        assert!(next_step(&a).1.contains("saved file permissions"));
    }

    #[test]
    fn summary_hides_stale_limits_and_preserves_cooldown_action() {
        let mut a = account(Some(100.0), Some(100.0), false);
        let now = chrono::Utc::now().timestamp();
        a.snapshot.fetched_at = Some(now - 3600);
        a.snapshot.valid_until = Some(now - 1);
        a.snapshot.next_fetch_at = Some(now + 600);
        let row = summary_row(&a);
        assert_eq!(row[1].content(), "Usage unknown");
        assert_eq!(row[2].content(), "Unknown");
        assert!(row[3].content().starts_with("Old:"));
        assert!(row[4].content().starts_with("Run status in"));
    }

    #[test]
    fn summary_reports_fresh_limits_and_keeps_token_expiry_out_of_login_advice() {
        let mut a = account(Some(100.0), Some(67.0), false);
        let now = chrono::Utc::now().timestamp();
        a.snapshot.fetched_at = Some(now);
        a.snapshot.valid_until = Some(now + 300);
        a.token_expiry_secs = Some(1);
        a.h5_reset = "in 3h 20m (Wed Sep 30 18:00)".into();
        let row = summary_row(&a);
        assert_eq!(row[1].content(), "5-hour limit reached");
        assert!(row[2].content().contains("5h: 100%"));
        assert_eq!(row[4].content(), "Resets in 3h 20m; or use another account");
        a.h5_pct = Some(0.0);
        assert_eq!(next_step(&a).0, "Within usage limits");
        a.d7_pct = Some(100.0);
        assert_eq!(next_step(&a).0, "Weekly limit reached");
        a.d7_pct = Some(10.0);
        a.fable_pct = Some(100.0);
        assert_eq!(next_step(&a).0, "Fable limit reached");
        a.d7_pct = None;
        a.fable_pct = None;
        assert_eq!(next_step(&a).0, "Usage unknown");
    }

    #[test]
    fn unknown_live_owner_blocks_saved_token_refresh() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken": "test-saved-access", "refreshToken": "test-saved-grant", "expiresAt": 1}
        })).unwrap();
        profile::save_profile_to(&paths, "saved", &creds, None).unwrap();
        std::fs::create_dir_all(paths.claude_credentials_file().parent().unwrap()).unwrap();
        std::fs::write(paths.claude_credentials_file(), "invalid test data").unwrap();
        let fetched =
            fetch_usages_with_refresh(&store, &paths, None, FetchMode::Refresh, async |_, _| {
                panic!("unknown live ownership must prevent refresh")
            })
            .unwrap();
        assert_eq!(fetched.len(), 1);
        assert!(
            fetched[0]
                .error
                .as_deref()
                .unwrap()
                .contains("ownership unknown")
        );
        assert_eq!(
            profile::get_profile_from(&paths, "saved")
                .unwrap()
                .read_credentials()
                .unwrap()
                .claude_ai_oauth
                .refresh_token
                .as_deref(),
            Some("test-saved-grant")
        );
    }

    #[test]
    fn saved_alias_cannot_refresh_the_live_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken": "test-live-access", "refreshToken": "test-live-grant", "expiresAt": 1}
        })).unwrap();
        store.write_credentials(&creds).unwrap();
        for alias in ["active", "duplicate"] {
            profile::save_profile_to(&paths, alias, &creds, None).unwrap();
        }
        profile::set_active_from(&paths, "active").unwrap();
        for mode in [FetchMode::Normal, FetchMode::Refresh, FetchMode::Cached] {
            let fetched = fetch_usages_with_refresh(&store, &paths, None, mode, async |_, _| {
                panic!("Claude Code owns the live grant")
            })
            .unwrap();
            assert_eq!(fetched.len(), 2);
            assert!(
                fetched
                    .iter()
                    .all(|f| f.error.as_deref().unwrap().contains("live login"))
            );
        }
        let live = store.read_credentials().unwrap();
        assert_eq!(
            live.claude_ai_oauth.refresh_token.as_deref(),
            Some("test-live-grant")
        );
        let key = UsageCache::key("test-live-access");
        std::fs::write(
            paths.claudectl_dir().join("usage/cache-v1.json"),
            serde_json::to_vec(&serde_json::json!({
                "entries": {key: {"usage": {"five_hour": {"utilization": 10}},
                    "fetched_at": chrono::Utc::now().timestamp(), "next_attempt": 0,
                    "failures": 0, "error": null}},
                "rate_until": 0, "rate_failures": 0, "next_request_ms": 0
            }))
            .unwrap(),
        )
        .unwrap();
        let fresh =
            fetch_usages_with_refresh(&store, &paths, None, FetchMode::Refresh, async |_, _| {
                panic!("Claude Code owns the live grant")
            })
            .unwrap();
        assert_eq!(fresh.len(), 2);
        assert!(
            fresh
                .iter()
                .all(|f| f.snapshot.fresh && f.usage.is_some() && f.error.is_none())
        );
    }

    #[test]
    fn data_age_reports_freshness_separately_from_profile_errors() {
        let mut status = account(Some(10.0), Some(20.0), true);
        status.snapshot.fetched_at = Some(chrono::Utc::now().timestamp());
        status.snapshot.fresh = true;
        status.snapshot.valid_until = Some(i64::MAX);
        assert!(
            !render_row(&status, false, false)[7]
                .content()
                .contains("stale")
        );
        status.snapshot.valid_until = Some(chrono::Utc::now().timestamp() - 1);
        assert!(
            render_row(&status, false, false)[7]
                .content()
                .contains("stale")
        );
    }

    #[test]
    fn focused_status_obeys_saved_grant_cooldown_for_another_access_token() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        let store = AuthStore::file_only(paths.clone());
        let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken": "different-access", "refreshToken": "shared-test-grant", "expiresAt": 1}
        })).unwrap();
        profile::save_profile_to(&paths, "two", &creds, None).unwrap();
        drop(UsageCache::open(&paths.claudectl_dir()).unwrap());
        let key = format!("refresh:{}", UsageCache::key("shared-test-grant"));
        let now = chrono::Utc::now().timestamp();
        std::fs::write(paths.claudectl_dir().join("usage/cache-v1.json"), serde_json::to_vec(&serde_json::json!({
            "entries": {key: {"usage": null, "fetched_at": null, "next_attempt": now + 600, "failures": 1, "error": "token refresh fetch failed (HTTP 429)"}},
            "rate_until": 0, "rate_failures": 0, "next_request_ms": 0
        })).unwrap()).unwrap();
        let fetched = fetch_usages_with_refresh(
            &store,
            &paths,
            Some("two"),
            FetchMode::Refresh,
            async |_, _| panic!("saved shared-grant cooldown must prevent token refresh"),
        )
        .unwrap();
        assert_eq!(fetched[0].snapshot.source, "cooldown");
        assert_eq!(fetched[0].snapshot.next_fetch_at, Some(now + 600));
    }

    #[test]
    fn shared_refresh_failure_is_not_retried_for_another_alias() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        for alias in ["one", "two"] {
            let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
                "claudeAiOauth": {"accessToken": alias, "refreshToken": "shared-test-grant", "expiresAt": 1}
            })).unwrap();
            profile::save_profile_to(&paths, alias, &creds, None).unwrap();
        }
        let mut calls = 0;
        let fetched =
            fetch_usages_with_refresh(&store, &paths, None, FetchMode::Refresh, async |_, _| {
                calls += 1;
                anyhow::bail!("test refresh unavailable")
            })
            .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(fetched.len(), 2);
        assert!(
            fetched
                .iter()
                .all(|f| f.error.is_some() && f.usage.is_none())
        );
        let state: serde_json::Value = serde_json::from_slice(
            &std::fs::read(paths.claudectl_dir().join("usage/cache-v1.json")).unwrap(),
        )
        .unwrap();
        for alias in ["one", "two"] {
            assert_eq!(state["entries"][UsageCache::key(alias)]["failures"], 1);
        }
        let cached =
            fetch_usages_with_refresh(&store, &paths, None, FetchMode::Cached, async |_, _| {
                panic!("cached status must not refresh")
            })
            .unwrap();
        assert_eq!(cached.len(), 2);
    }

    #[test]
    fn shared_refresh_grant_is_rotated_once_and_saved_to_both_aliases() {
        check_shared_refresh(None, None);
    }

    #[test]
    fn rotation_updates_unexpired_siblings_in_either_order_and_focused_status() {
        check_shared_refresh(Some("one"), None);
        check_shared_refresh(Some("two"), None);
        check_shared_refresh(Some("one"), Some("one"));
    }

    fn check_shared_refresh(expired_alias: Option<&str>, focused: Option<&str>) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = config::Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        let live: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken": "different-live-access", "refreshToken": "different-live-grant", "expiresAt": 1}
        })).unwrap();
        store.write_credentials(&live).unwrap();
        let creds: api::CredentialsFile = serde_json::from_value(serde_json::json!({
            "claudeAiOauth": {"accessToken": "old-test-access", "refreshToken": "test-grant", "expiresAt": 1}
        })).unwrap();
        for alias in ["one", "two"] {
            let mut creds = creds.clone();
            creds
                .extra
                .insert("aliasMarker".into(), serde_json::json!(alias));
            if expired_alias.is_some_and(|expired| expired != alias) {
                creds.claude_ai_oauth.access_token = "valid-test-access".into();
                creds.claude_ai_oauth.expires_at =
                    Some(chrono::Utc::now().timestamp_millis() + 3600000);
            }
            profile::save_profile_to(&paths, alias, &creds, None).unwrap();
        }
        profile::save_profile_to(&paths, "broken", &live, None).unwrap();
        std::fs::write(
            paths.profiles_dir().join("broken/credentials.json"),
            "invalid test data",
        )
        .unwrap();
        // A cached result for the new token isolates the token endpoint boundary.
        std::fs::create_dir_all(paths.claudectl_dir().join("usage")).unwrap();
        let entries: serde_json::Map<String, serde_json::Value> =
            ["rotated-test-access", "valid-test-access"]
                .into_iter()
                .map(|token| {
                    (
                        UsageCache::key(token),
                        serde_json::json!({
                            "usage": {"five_hour": {"utilization": 10}},
                            "fetched_at": chrono::Utc::now().timestamp(), "next_attempt": 0,
                            "failures": 0, "error": null
                        }),
                    )
                })
                .collect();
        std::fs::write(
            paths.claudectl_dir().join("usage/cache-v1.json"),
            serde_json::to_vec(&serde_json::json!({
                "entries": entries,
                "rate_until": 0, "rate_failures": 0, "next_request_ms": 0
            }))
            .unwrap(),
        )
        .unwrap();
        let mut calls = 0;
        let fetched = fetch_usages_with_refresh(
            &store,
            &paths,
            focused,
            FetchMode::Normal,
            async |_, old| {
                calls += 1;
                let mut rotated = old.clone();
                let switched = profile::switch_to(&store, &paths, "one");
                assert!(switched.is_err(), "switch must not commit during refresh");
                rotated.access_token = "rotated-test-access".into();
                rotated.refresh_token = Some(format!("rotated-test-grant-{calls}"));
                rotated.expires_at = Some(chrono::Utc::now().timestamp_millis() + 3600000);
                Ok(rotated)
            },
        )
        .unwrap();
        assert_eq!(calls, 1, "aliases must share one refresh grant");
        assert_eq!(fetched.len(), if focused.is_some() { 1 } else { 3 });
        assert!(
            fetched
                .iter()
                .filter(|f| f.alias != "broken")
                .all(|f| f.snapshot.fresh && f.error.is_none())
        );
        for alias in ["one", "two"] {
            let saved = profile::get_profile_from(&paths, alias)
                .unwrap()
                .read_credentials()
                .unwrap();
            assert_eq!(saved.extra["aliasMarker"], alias);
            assert_eq!(
                saved.claude_ai_oauth.refresh_token.as_deref(),
                Some("rotated-test-grant-1")
            );
        }
    }

    fn account(h5: Option<f64>, d7: Option<f64>, is_error: bool) -> AccountStatus {
        AccountStatus {
            alias: "a@x".to_string(),
            label: None,
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

    fn fetched_json(alias: &str, usage: &str, plan: Option<&str>) -> FetchedUsage {
        FetchedUsage {
            alias: alias.into(),
            plan: plan.map(str::to_string),
            usage: Some(serde_json::from_str(usage).unwrap()),
            snapshot: Snapshot {
                fresh: true,
                fetched_at: Some(1_000),
                valid_until: Some(2_000),
                ..Snapshot::default()
            },
            ..FetchedUsage::default()
        }
    }

    #[test]
    fn billing_class_follows_extra_usage_and_plan() {
        let rate = fetched_json(
            "a",
            r#"{"five_hour":{"utilization":10},"extra_usage":{"is_enabled":false}}"#,
            Some("max"),
        );
        let no_extra = fetched_json("d", r#"{"five_hour":{"utilization":10}}"#, Some("max"));
        let null_extra = fetched_json(
            "e",
            r#"{"five_hour":{"utilization":10},"extra_usage":{"is_enabled":null}}"#,
            Some("max"),
        );
        let billed = fetched_json(
            "b",
            r#"{"five_hour":{"utilization":10},"extra_usage":{"is_enabled":true,"used_credits":3}}"#,
            Some("max"),
        );
        let no_plan = fetched_json("c", r#"{"five_hour":{"utilization":10}}"#, None);
        let class = |f: &FetchedUsage| billing_class(f.usage.as_ref(), f.plan.as_deref());
        assert_eq!(class(&rate), "rate_limited");
        assert_eq!(class(&billed), "usage_based");
        assert_eq!(class(&no_plan), "unknown");
        assert_eq!(
            class(&no_extra),
            "unknown",
            "missing extra_usage is not proof"
        );
        assert_eq!(
            class(&null_extra),
            "unknown",
            "null is_enabled is not proof"
        );
        assert_eq!(
            billing_class(rate.usage.as_ref(), Some("  ")),
            "unknown",
            "blank plan"
        );
        assert_eq!(billing_class(None, Some("max")), "unknown");
    }

    #[test]
    fn exhausted_counts_model_scoped_and_fable_limits() {
        let usage = |json: &str| serde_json::from_str::<UsageResponse>(json).unwrap();
        assert!(!exhausted(&usage(r#"{"five_hour":{"utilization":99.9}}"#)));
        assert!(exhausted(&usage(
            r#"{"seven_day_opus":{"utilization":100}}"#
        )));
        assert!(exhausted(&usage(
            r#"{"seven_day_sonnet":{"utilization":100}}"#
        )));
        assert!(exhausted(&usage(
            r#"{"limits":[{"kind":"weekly_scoped","percent":100,"scope":{"model":{"display_name":"Fable"}}}]}"#
        )));
    }

    #[test]
    fn status_json_has_a_stable_versioned_shape() {
        let mut a = fetched_json(
            "b-work",
            r#"{"five_hour":{"utilization":20,"resets_at":"2026-10-07T10:00:00Z"},
                "seven_day":{"utilization":100},
                "extra_usage":{"is_enabled":false,"used_credits":0}}"#,
            Some("team"),
        );
        a.label = Some("Team seat".into());
        a.is_active = true;
        a.token_expiry_secs = Some(1_500 + 600);
        let mut failed = FetchedUsage {
            alias: "a-broken".into(),
            error: Some("credentials unavailable or invalid".into()),
            ..FetchedUsage::default()
        };
        failed.snapshot.fresh = false;
        failed.token_expiry_secs = Some(1_000);
        let report = status_json(&[a, failed], 1_500);
        assert_eq!(report["version"], 1);
        let accounts = report["accounts"].as_array().unwrap();
        assert_eq!(accounts[0]["alias"], "a-broken", "sorted by alias");
        assert_eq!(accounts[0]["billing_class"], "unknown");
        assert_eq!(accounts[0]["exhausted"], serde_json::Value::Null);
        assert_eq!(accounts[0]["usage_stale"], true);
        assert_eq!(accounts[0]["error"], "credentials unavailable or invalid");
        assert_eq!(accounts[0]["token_expires_in_seconds"], 0, "expired");
        let b = &accounts[1];
        assert_eq!(b["label"], "Team seat");
        assert_eq!(b["active"], true);
        assert_eq!(b["plan"], "team");
        assert_eq!(b["billing_class"], "rate_limited");
        assert_eq!(b["exhausted"], true);
        assert_eq!(b["windows"]["five_hour"]["used_percent"], 20.0);
        assert_eq!(
            b["windows"]["five_hour"]["resets_at"],
            "2026-10-07T10:00:00Z"
        );
        assert_eq!(b["windows"]["seven_day_opus"], serde_json::Value::Null);
        assert_eq!(b["extra_usage"]["enabled"], false);
        assert_eq!(b["token_expires_in_seconds"], 600);
        assert_eq!(b["usage_age_seconds"], 500);
        assert_eq!(b["usage_stale"], false);
    }

    #[test]
    fn label_column_appears_only_when_an_account_has_a_label() {
        let plain = fresh_account(Some(20.0), Some(30.0), false);
        let table = summary_table(std::slice::from_ref(&plain), true).to_string();
        assert!(!table.contains("Label"), "{table}");
        let mut labelled = fresh_account(Some(20.0), Some(30.0), false);
        labelled.label = Some("Team seat".into());
        let table = summary_table(&[plain, labelled], true).to_string();
        assert!(
            table.contains("Label") && table.contains("Team seat"),
            "{table}"
        );
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
