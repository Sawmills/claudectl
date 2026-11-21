use std::io::IsTerminal;

use anyhow::{Context, Result, bail};
use claudectl::{api, central, config, limit_resets, profile};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize)]
struct ResetRow {
    alias: String,
    source: &'static str,
    exhausted: Vec<String>,
    offers: Vec<limit_resets::OfferSummary>,
}

fn row(
    alias: &str,
    source: &'static str,
    usage: Option<&api::UsageResponse>,
    stale: bool,
) -> ResetRow {
    let exhausted = usage_exhausted(usage);
    let offers = if stale {
        Vec::new()
    } else {
        usage
            .and_then(|usage| usage.cedar_ember.as_ref())
            .map(|offers| {
                let windows = exhausted.iter().map(String::as_str).collect::<Vec<_>>();
                let now = chrono::Utc::now().timestamp();
                if offers.closest_usable_grant_id(&windows, now).is_none() {
                    Vec::new()
                } else {
                    offers.usable_summaries(&windows, now)
                }
            })
            .unwrap_or_default()
    };
    ResetRow {
        alias: alias.into(),
        source,
        exhausted,
        offers,
    }
}

fn usage_exhausted(usage: Option<&api::UsageResponse>) -> Vec<String> {
    let mut exhausted = usage
        .map(limit_resets::exhausted_windows)
        .unwrap_or_default()
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some(offers) = usage.and_then(|usage| usage.cedar_ember.as_ref()) {
        for window in offers.provider_exhausted() {
            if !exhausted.iter().any(|current| current == window) {
                exhausted.push(window.to_owned());
            }
        }
    }
    exhausted
}

fn rows() -> Result<Vec<ResetRow>> {
    let paths = config::default_paths()?;
    let local = if central::service_account::configured() {
        Vec::new()
    } else {
        super::status::fetch_usages_for_resets()?
    };
    let mut rows = local
        .iter()
        .filter(|f| !f.on_server)
        .map(|f| {
            row(
                &f.alias,
                "local",
                f.usage.as_ref(),
                f.error.is_some() || !f.snapshot.is_fresh_at(chrono::Utc::now().timestamp()),
            )
        })
        .collect::<Vec<_>>();
    let server_aliases = central::server_aliases(&paths, false);
    match central::Client::load(&paths).and_then(|client| {
        let accounts = client.accounts()?;
        for account in &accounts {
            let _ = client.usage(&account.account_id, false);
        }
        client.resets()
    }) {
        Ok(accounts) => rows.extend(accounts.into_iter().map(|account| ResetRow {
            alias: account.alias,
            source: "server",
            exhausted: account.exhausted,
            offers: if account.stale {
                Vec::new()
            } else {
                account.offers
            },
        })),
        Err(error)
            if error
                .downcast_ref::<central::ServerError>()
                .is_some_and(|error| error.status == 404) => {}
        Err(_error) if server_aliases.is_empty() && !rows.is_empty() => {}
        Err(error) => bail!("the account server did not answer: {error:#}"),
    }
    rows.sort_by(|a, b| a.alias.cmp(&b.alias));
    Ok(rows)
}

fn resolve_alias(paths: &config::Paths, name: &str) -> Result<String> {
    let name = profile::validate_alias(name)?;
    let mut aliases = profile::list_profiles_from(paths)?
        .into_iter()
        .map(|profile| profile.meta.alias)
        .collect::<Vec<_>>();
    for alias in central::server_aliases(paths, false) {
        if !aliases
            .iter()
            .any(|current| current.eq_ignore_ascii_case(&alias))
        {
            aliases.push(alias);
        }
    }
    if aliases.is_empty() {
        return Ok(name.to_owned());
    }
    Ok(claudectl::accounts::resolve(name, &aliases)?.to_owned())
}

pub fn list(json_output: bool) -> Result<()> {
    let rows = rows()?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"version": 1, "accounts": rows}))?
        );
        return Ok(());
    }
    let mut table = comfy_table::Table::new();
    table.load_preset(comfy_table::presets::UTF8_FULL);
    table.set_header(["Account", "Source", "Exhausted", "Offers", "Limit / expiry"]);
    for row in rows {
        let exhausted = if row.exhausted.is_empty() {
            "-".into()
        } else {
            row.exhausted.join(", ")
        };
        let offers = row.offers.iter().fold(0_u64, |count, offer| {
            count.saturating_add(offer.resets_left)
        });
        let details = row
            .offers
            .iter()
            .map(|offer| {
                let extra = match (offer.gives_back_weekly, !offer.use_requires_limit) {
                    (true, true) => " (gives back weekly, anytime)",
                    (true, false) => " (gives back weekly)",
                    (false, true) => " (anytime)",
                    (false, false) => "",
                };
                format!(
                    "{}: {}{extra} / {}",
                    offer.resets_left,
                    offer.clears.join(" + "),
                    offer.ends_at.as_deref().unwrap_or("expiry unknown")
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        table.add_row([
            row.alias,
            row.source.into(),
            exhausted,
            offers.to_string(),
            details,
        ]);
    }
    println!("{table}");
    Ok(())
}

fn confirm(alias: &str, yes: bool) -> Result<()> {
    if yes {
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        bail!("{}", confirmation_message(alias));
    }
    if !dialoguer::Confirm::new()
        .with_prompt(format!("Apply one limit reset to {alias}?"))
        .default(false)
        .interact()?
    {
        bail!("reset not applied");
    }
    Ok(())
}

fn confirmation_message(alias: &str) -> String {
    format!(
        "resetting an account needs a confirmation\nTry: claudectl reset {} --yes",
        claudectl::shell::arg(alias)
    )
}

fn format_exhausted(exhausted: &[String]) -> String {
    if exhausted.is_empty() {
        "none (anytime offer)".into()
    } else {
        exhausted.join(", ")
    }
}

fn redacted_reset_url() -> Result<String> {
    let url =
        api::reset_rate_limits_url("ORG_PLACEHOLDER", "GRANT_PLACEHOLDER", "REQ_PLACEHOLDER")?;
    Ok(url.replace("ORG_PLACEHOLDER", "<organization>"))
}

fn local_organization(profile: &profile::Profile) -> Result<&str> {
    profile
        .meta
        .oauth_account
        .as_ref()
        .and_then(|account| account.get("organizationUuid"))
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("saved account identity has no organization")
}

#[derive(Deserialize, Serialize)]
struct PendingLocalReset {
    grant_id: String,
    request_id: String,
}

fn local_reset(alias: &str, fetched: &super::status::FetchedUsage) -> Result<String> {
    let paths = config::default_paths()?;
    let profile = profile::get_profile_from(&paths, alias)?;
    let usage = fetched
        .usage
        .as_ref()
        .context("reset requires fresh usage")?;
    if fetched.error.is_some() || !fetched.snapshot.is_fresh_at(chrono::Utc::now().timestamp()) {
        bail!("reset requires fresh usage");
    }
    let exhausted = usage_exhausted(Some(usage));
    let offers = usage.cedar_ember.as_ref();
    if fetched.is_active && fetched.account_uuid.is_none() {
        bail!("active Claude Code login does not match this account");
    }
    let lock_path = profile.dir.join("reset.lock");
    let lock = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock.try_lock()
        .context("another reset is already in progress")?;
    let organization = local_organization(&profile)?;
    let token = if fetched.is_active {
        claudectl::auth_store::AuthStore::real(paths.clone())
            .read_credentials()?
            .claude_ai_oauth
            .access_token
    } else {
        profile.read_credentials()?.claude_ai_oauth.access_token
    };
    let pending_path = profile.dir.join("reset-pending.json");
    let save_pending = |pending: &PendingLocalReset| -> Result<()> {
        let bytes = serde_json::to_vec(pending)?;
        let mut file = tempfile::NamedTempFile::new_in(&profile.dir)?;
        std::io::Write::write_all(&mut file, &bytes)?;
        file.as_file().sync_all()?;
        file.persist(&pending_path)
            .map_err(|_| anyhow::anyhow!("could not save pending local reset"))?;
        Ok(())
    };
    let pending = match std::fs::read(&pending_path) {
        Ok(bytes) => serde_json::from_slice::<PendingLocalReset>(&bytes)
            .context("invalid pending local reset; remove it only after checking provider state")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let offers = offers.context("no usable reset offer")?;
            let windows = exhausted.iter().map(String::as_str).collect::<Vec<_>>();
            let preferred_grant_id =
                match offers.closest_usable_grant_id(&windows, chrono::Utc::now().timestamp()) {
                    Some(id) => id,
                    None if exhausted.is_empty() || offers.at_limit() == Some(false) => {
                        bail!("reset requires an exhausted limit");
                    }
                    None => {
                        bail!("reset offer identifier unavailable; retry after a live usage fetch");
                    }
                };
            let pending = PendingLocalReset {
                grant_id: preferred_grant_id.to_owned(),
                request_id: format!(
                    "local-{}",
                    chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
                ),
            };
            save_pending(&pending)?;
            pending
        }
        Err(error) => return Err(error.into()),
    };
    // An existing pending request always wins, even when its grant no longer appears in
    // the current offer projection. The provider may have applied it before the reply was lost.
    let grant_id = pending.grant_id.as_str();
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(40))
        .build()?;
    let response = client
        .post(api::reset_rate_limits_url(
            organization,
            grant_id,
            &pending.request_id,
        )?)
        .bearer_auth(token)
        .header(api::OAUTH_BETA_HEADER.0, api::OAUTH_BETA_HEADER.1)
        .header(reqwest::header::USER_AGENT, api::CLAUDE_CLI_USER_AGENT)
        .json(
            &json!({"program":"cedar_ember", "grant_id":grant_id, "request_id":pending.request_id}),
        )
        .send()
        .map_err(|_| anyhow::anyhow!("limit reset provider request failed"))?;
    if !response.status().is_success() {
        if matches!(response.status().as_u16(), 400 | 401 | 403 | 404 | 422) {
            let _ = std::fs::remove_file(&pending_path);
        }
        bail!(
            "limit reset provider request rejected (HTTP {})",
            response.status()
        );
    }
    let result: serde_json::Value = response
        .json()
        .context("invalid limit reset provider response")?;
    match result["result"].as_str() {
        Some("reset") => {
            let _ = std::fs::remove_file(pending_path);
            Ok("reset".into())
        }
        Some("already_used") => {
            let _ = std::fs::remove_file(pending_path);
            Ok("already_used".into())
        }
        Some("not_limited") => {
            let _ = std::fs::remove_file(pending_path);
            Ok("not_limited".into())
        }
        _ => bail!("limit reset provider did not settle"),
    }
}

fn local_dry_run(
    paths: &config::Paths,
    alias: &str,
    local_profile: &profile::Profile,
) -> Result<()> {
    let active = profile::get_active_from(paths)?;
    let is_active = active.as_deref() == Some(local_profile.meta.alias.as_str());
    let creds = if is_active {
        let store = claudectl::auth_store::AuthStore::real(paths.clone());
        let live_uuid = store
            .read_oauth_account()
            .ok()
            .flatten()
            .and_then(|account| account.get("accountUuid")?.as_str().map(str::to_owned));
        if !local_profile
            .meta
            .account_uuid()
            .is_some_and(|saved| live_uuid.as_deref() == Some(saved))
        {
            bail!("active Claude Code login does not match this account");
        }
        store.read_credentials()?
    } else {
        local_profile.read_credentials()?
    };
    let _ = local_organization(local_profile)?;
    let pending_path = local_profile.dir.join("reset-pending.json");
    if pending_path.exists() {
        let bytes = std::fs::read(&pending_path)?;
        let _: PendingLocalReset = serde_json::from_slice(&bytes)
            .context("invalid pending local reset; remove it only after checking provider state")?;
        println!("Dry run: no request sent; no reset redeemed.");
        println!("Account: {alias} (local)");
        println!("Offer: pending local reset replay");
        println!("Request: POST {}", redacted_reset_url()?);
        println!(
            "Headers: {}: {}, user-agent: {}",
            api::OAUTH_BETA_HEADER.0,
            api::OAUTH_BETA_HEADER.1,
            api::CLAUDE_CLI_USER_AGENT
        );
        println!(
            "Body: {}",
            json!({"program": "cedar_ember", "grant_id": "<redacted>", "request_id": "<pending>"})
        );
        return Ok(());
    }
    if creds.claude_ai_oauth.access_token.trim().is_empty() {
        bail!("missing access token; log in again");
    }
    if creds.claude_ai_oauth.is_expired() {
        bail!("access token expired; refresh credentials before running reset --dry-run");
    }
    let usage = api::fetch_usage_blocking(&creds.claude_ai_oauth.access_token)?;
    let now = chrono::Utc::now().timestamp();
    let exhausted = usage_exhausted(Some(&usage));
    let offers = usage
        .cedar_ember
        .as_ref()
        .context("no usable reset offer")?;
    let windows = exhausted.iter().map(String::as_str).collect::<Vec<_>>();
    let selected = match offers.closest_usable_offer(&windows, now) {
        Some(offer) => offer,
        None if exhausted.is_empty() || offers.at_limit() == Some(false) => {
            bail!("reset requires an exhausted limit");
        }
        None => bail!("no usable reset offer for an exhausted limit"),
    };
    println!("Dry run: no request sent; no reset redeemed.");
    println!("Account: {alias} (local)");
    println!("Exhausted: {}", format_exhausted(&exhausted));
    println!("Offer: {}", selected.summary(now));
    println!("Request: POST {}", redacted_reset_url()?);
    println!(
        "Headers: {}: {}, user-agent: {}",
        api::OAUTH_BETA_HEADER.0,
        api::OAUTH_BETA_HEADER.1,
        api::CLAUDE_CLI_USER_AGENT
    );
    println!(
        "Body: {}",
        json!({"program": "cedar_ember", "grant_id": "<redacted>", "request_id": "<generated>"})
    );
    Ok(())
}

pub fn reset(alias: &str, yes: bool, dry_run: bool) -> Result<()> {
    let paths = config::default_paths()?;
    let alias = resolve_alias(&paths, alias)?;
    let local = profile::get_profile_from(&paths, &alias).ok();
    let migrated = local
        .as_ref()
        .is_some_and(|profile| central::is_migrated(&paths, &profile.meta.alias));
    if !central::service_account::configured()
        && let Some(local_profile) = local.as_ref()
        && !migrated
    {
        if dry_run {
            return local_dry_run(&paths, &alias, local_profile);
        }
        let fetched =
            super::status::fetch_alias(&alias, claudectl::usage_cache::FetchMode::Refresh)?
                .context("account usage unavailable")?;
        let pending_path = local_profile.dir.join("reset-pending.json");
        if pending_path.exists() {
            confirm(&alias, yes)?;
            println!("{}", local_reset(&alias, &fetched)?);
            return Ok(());
        }
        let now = chrono::Utc::now().timestamp();
        let usage = fetched
            .usage
            .as_ref()
            .context("reset requires fresh usage")?;
        if fetched.error.is_some() || !fetched.snapshot.is_fresh_at(now) {
            bail!("reset requires fresh usage");
        }
        if fetched.is_active && fetched.account_uuid.is_none() {
            bail!("active Claude Code login does not match this account");
        }
        let exhausted = usage_exhausted(Some(usage));
        let offers = usage
            .cedar_ember
            .as_ref()
            .context("no usable reset offer")?;
        let windows = exhausted.iter().map(String::as_str).collect::<Vec<_>>();
        match offers.closest_usable_offer(&windows, now) {
            Some(_) => {}
            None if exhausted.is_empty() || offers.at_limit() == Some(false) => {
                bail!("reset requires an exhausted limit");
            }
            None => bail!("no usable reset offer for an exhausted limit"),
        }
        confirm(&alias, yes)?;
        println!("{}", local_reset(&alias, &fetched)?);
        return Ok(());
    }
    let client = central::Client::load(&paths)?;
    let account = client.account(&alias)?;
    if !dry_run {
        client.usage(&account.account_id, false)?;
    }
    let reset = client
        .resets()?
        .into_iter()
        .find(|row| row.account_id == account.account_id)
        .context("account reset offer not found")?;
    if reset.stale {
        if dry_run {
            bail!("reset requires fresh usage\nTry: claudectl resets");
        }
        bail!("reset requires fresh usage");
    }
    let has_anytime = reset.offers.iter().any(|offer| !offer.use_requires_limit);
    if reset.exhausted.is_empty() && !has_anytime {
        bail!("reset requires an exhausted limit");
    }
    let selected = reset
        .offers
        .first()
        .context("no usable reset offer for an exhausted limit")?;
    if dry_run {
        let server = client.connection.server.trim_end_matches('/');
        println!("Dry run: no request sent; no reset redeemed.");
        println!("Account: {} (server)", account.alias);
        println!("Exhausted: {}", format_exhausted(&reset.exhausted));
        println!("Offer: {}", selected.summary());
        println!("Request: POST {server}/v2/anthropic/resets/redeem");
        println!("Body: {}", json!({"account_id": account.account_id}));
        return Ok(());
    }
    confirm(&account.alias, yes)?;
    let result = client.redeem_reset(&account.account_id)?;
    println!("{result}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_interactive_reset_requires_yes() {
        assert!(confirmation_message("work").contains("claudectl reset work --yes"));
    }

    #[test]
    fn provider_exhaustion_metadata_counts_as_an_exhausted_window() {
        let usage: api::UsageResponse = serde_json::from_value(json!({
            "cedar_ember": {"exhausted": ["five_hour"], "grants": []}
        }))
        .unwrap();
        assert_eq!(usage_exhausted(Some(&usage)), vec!["five_hour"]);
    }
}
