//! `claudectl claude`: run Claude Code in a lane on a saved account, and when
//! that account hits a usage limit, resume the same session on another
//! account with room.

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use claudectl::auth_store::AuthStore;
use claudectl::config;
use claudectl::exec::{self, ExecRequest, LiveIdentity, SelfIdentity};
use claudectl::lane::{self, Lane, RateLimitHit};
use claudectl::usage_cache::FetchMode;

use crate::commands::status::{self, FetchedUsage};

/// Recoveries allowed in one hour before the launcher stops.
const MAX_RECOVERIES_PER_HOUR: usize = 3;
/// How often the watcher reads the lane transcripts.
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

pub struct LaunchArgs {
    pub lane: String,
    pub account: Option<String>,
    pub allow_billing: bool,
    pub recovery_prompt: String,
    pub claude: OsString,
    pub args: Vec<OsString>,
}

/// Returns the process exit code: Claude's code, or 1 when the launcher fails.
pub fn run(args: LaunchArgs) -> i32 {
    match run_inner(args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("claudectl claude: {error:#}");
            1
        }
    }
}

fn run_inner(launch: LaunchArgs) -> Result<i32> {
    let paths = config::default_paths()?;
    let store = AuthStore::real(paths.clone());
    let lane = Lane::open(&paths, &launch.lane)?;
    let cwd = std::env::current_dir().context("cannot read the current directory")?;
    let mut tried: Vec<String> = Vec::new();
    let mut recoveries: Vec<Instant> = Vec::new();
    let mut alias = match &launch.account {
        Some(alias) => {
            confirm_explicit(alias, launch.allow_billing)?;
            alias.clone()
        }
        None => choose(&status::fetch_all_usages()?, &tried)
            .context("no rate-limited account with room; run claudectl status")?,
    };
    let mut args = launch.args.clone();
    loop {
        lane.clear_account_state()?;
        lane.assert_no_credentials()?;
        lane.log("start", &alias, None)?;
        let launched = chrono::Utc::now();
        let outcome = run_once(
            &paths,
            &store,
            &lane,
            &cwd,
            &alias,
            &launch.claude,
            &args,
            launched,
        );
        let hit = match outcome {
            Ok(Outcome::Exited(code)) => {
                lane.log("end", &alias, None)?;
                return Ok(code);
            }
            Ok(Outcome::Limited(hit)) => hit,
            Err(error) => {
                lane.log("end", &alias, None)?;
                return Err(error);
            }
        };
        lane.log("end", &alias, Some(&hit.session_id))?;
        recoveries.retain(|at| at.elapsed() < Duration::from_secs(3600));
        if recoveries.len() >= MAX_RECOVERIES_PER_HOUR {
            bail!(
                "{alias} reached its limit, and {MAX_RECOVERIES_PER_HOUR} recoveries ran in the last hour; \
                 stopped. Resume with: claudectl claude --lane {} -- --resume {}",
                launch.lane,
                hit.session_id
            );
        }
        recoveries.push(Instant::now());
        tried.push(alias.clone());
        let Some(next) = choose(&status::fetch_all_usages()?, &tried) else {
            bail!(
                "{alias} reached its limit and no other rate-limited account has room; \
                 session {} is kept in lane {}",
                hit.session_id,
                launch.lane
            );
        };
        eprintln!(
            "claudectl claude: {alias} reached its limit; resuming session {} on {next}",
            hit.session_id
        );
        args = relaunch_args(&launch.args, &hit.session_id, &launch.recovery_prompt);
        alias = next;
    }
}

enum Outcome {
    Exited(i32),
    Limited(RateLimitHit),
}

/// One Claude run in the lane, watched for a confirmed usage limit.
#[allow(clippy::too_many_arguments)]
fn run_once(
    paths: &config::Paths,
    store: &AuthStore,
    lane: &Lane,
    cwd: &Path,
    alias: &str,
    program: &OsString,
    args: &[OsString],
    launched: chrono::DateTime<chrono::Utc>,
) -> Result<Outcome> {
    let request = ExecRequest {
        alias: alias.to_string(),
        expect_account: None,
        expect_sha256: None,
        min_valid: Duration::from_secs(30 * 60),
        // Receipts go to the lane, not over the Claude screen.
        receipt: Some(lane.config_dir().with_file_name("receipts.jsonl")),
        program: program.clone(),
        args: args.to_vec(),
        state_dir: Some(lane.config_dir()),
    };
    let prepared = exec::prepare(
        paths,
        store,
        &request,
        &LiveIdentity,
        SelfIdentity::current()?,
    )?;

    let stop = Arc::new(AtomicBool::new(false));
    let limited: Arc<Mutex<Option<RateLimitHit>>> = Arc::new(Mutex::new(None));
    let watcher = {
        let (stop, limited) = (stop.clone(), limited.clone());
        let (config_dir, cwd, alias) = (lane.config_dir(), cwd.to_path_buf(), alias.to_string());
        std::thread::spawn(move || watch(&config_dir, &cwd, &alias, launched, &stop, &limited))
    };
    let result = exec::run(paths, store, prepared, &request);
    stop.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    let code = result?;
    let hit = limited.lock().unwrap_or_else(|e| e.into_inner()).take();
    Ok(match hit {
        Some(hit) => Outcome::Limited(hit),
        None => Outcome::Exited(code),
    })
}

/// Watch the lane transcripts for a rate-limit error from this run. Confirm
/// it with one usage read, then end the run through claudectl's own SIGTERM
/// forwarding, so Claude gets SIGTERM (and SIGCONT) and saves its session.
fn watch(
    config_dir: &Path,
    cwd: &Path,
    alias: &str,
    launched: chrono::DateTime<chrono::Utc>,
    stop: &AtomicBool,
    limited: &Mutex<Option<RateLimitHit>>,
) {
    let mut checked: Vec<String> = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        std::thread::sleep(WATCH_INTERVAL);
        let Some(hit) = lane::find_rate_limit_in(config_dir, cwd, launched) else {
            continue;
        };
        if checked.contains(&hit.uuid) {
            continue;
        }
        checked.push(hit.uuid.clone());
        if !limit_confirmed(alias) {
            continue;
        }
        *limited.lock().unwrap_or_else(|e| e.into_inner()) = Some(hit);
        // SAFETY: kill only sends a signal to this process.
        unsafe { libc::kill(libc::getpid(), libc::SIGTERM) };
        return;
    }
}

/// One usage read for the account: a transcript error alone can be a short
/// API throttle, not a used-up window.
fn limit_confirmed(alias: &str) -> bool {
    match status::fetch_alias(alias, FetchMode::Refresh) {
        Ok(Some(fetched)) => fetched.usage.as_ref().is_some_and(status::exhausted),
        _ => false,
    }
}

/// The next account: rate-limited (never billed), with fresh usage below
/// every limit, not the live login, and not tried in this launch. Most room
/// first: lowest weekly, then 5-hour use.
fn choose(fetched: &[FetchedUsage], tried: &[String]) -> Option<String> {
    let now = chrono::Utc::now().timestamp();
    fetched
        .iter()
        .filter(|f| !f.is_active && f.error.is_none() && !tried.contains(&f.alias))
        .filter(|f| f.snapshot.is_fresh_at(now))
        .filter_map(|f| {
            let usage = f.usage.as_ref()?;
            let rate_limited =
                status::billing_class(Some(usage), f.plan.as_deref()) == "rate_limited";
            (rate_limited && !status::exhausted(usage)).then_some((f, usage))
        })
        .min_by(|(_, a), (_, b)| {
            let used = |u: &claudectl::api::UsageResponse| {
                (
                    u.seven_day
                        .as_ref()
                        .and_then(|w| w.utilization)
                        .unwrap_or(0.0),
                    u.five_hour
                        .as_ref()
                        .and_then(|w| w.utilization)
                        .unwrap_or(0.0),
                )
            };
            used(a)
                .partial_cmp(&used(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(f, _)| f.alias.clone())
}

/// An explicitly chosen account that is not proven rate-limited may bill
/// credits: ask on a terminal, accept `--allow-billing`, otherwise refuse.
fn confirm_explicit(alias: &str, allow_billing: bool) -> Result<()> {
    let fetched = status::fetch_alias(alias, FetchMode::Cached)?
        .with_context(|| format!("profile '{alias}' not found"))?;
    let class = status::billing_class(fetched.usage.as_ref(), fetched.plan.as_deref());
    if class == "rate_limited" || allow_billing {
        return Ok(());
    }
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        bail!(
            "{alias} is {class}: it may bill credits; pass --allow-billing to use it without a terminal"
        );
    }
    let accepted = dialoguer::Confirm::new()
        .with_prompt(format!("{alias} is {class} and may bill credits. Use it?"))
        .default(false)
        .interact()?;
    if !accepted {
        bail!("not using {alias}");
    }
    Ok(())
}

/// The original Claude arguments without any resume or continue option,
/// then `--resume <session> <prompt>`.
fn relaunch_args(original: &[OsString], session_id: &str, prompt: &str) -> Vec<OsString> {
    let mut args = Vec::new();
    let mut iter = original.iter();
    while let Some(arg) = iter.next() {
        let text = arg.to_string_lossy();
        if text == "--resume" || text == "-r" {
            iter.next();
            continue;
        }
        if text.starts_with("--resume=") || text == "--continue" || text == "-c" {
            continue;
        }
        args.push(arg.clone());
    }
    args.extend([
        OsString::from("--resume"),
        OsString::from(session_id),
        OsString::from(prompt),
    ]);
    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use claudectl::usage_cache::Snapshot;

    fn fetched(alias: &str, usage: &str, plan: Option<&str>) -> FetchedUsage {
        let now = chrono::Utc::now().timestamp();
        FetchedUsage {
            alias: alias.into(),
            plan: plan.map(str::to_string),
            usage: Some(serde_json::from_str(usage).unwrap()),
            snapshot: Snapshot {
                fresh: true,
                fetched_at: Some(now),
                valid_until: Some(now + 300),
                ..Snapshot::default()
            },
            ..FetchedUsage::default()
        }
    }

    const OFF: &str = r#""extra_usage":{"is_enabled":false}"#;

    #[test]
    fn chooses_the_rate_limited_account_with_most_room() {
        let mut live = fetched(
            "live",
            &format!(r#"{{"seven_day":{{"utilization":1}},{OFF}}}"#),
            Some("max"),
        );
        live.is_active = true;
        let accounts = [
            live,
            fetched(
                "busy",
                &format!(r#"{{"seven_day":{{"utilization":70}},{OFF}}}"#),
                Some("max"),
            ),
            fetched(
                "roomy",
                &format!(r#"{{"seven_day":{{"utilization":20}},{OFF}}}"#),
                Some("max"),
            ),
            fetched(
                "billed",
                r#"{"seven_day":{"utilization":0},"extra_usage":{"is_enabled":true}}"#,
                Some("max"),
            ),
            fetched("unknown", r#"{"seven_day":{"utilization":0}}"#, Some("max")),
            fetched(
                "full",
                &format!(
                    r#"{{"seven_day":{{"utilization":30}},"seven_day_opus":{{"utilization":100}},{OFF}}}"#
                ),
                Some("max"),
            ),
        ];
        assert_eq!(choose(&accounts, &[]).as_deref(), Some("roomy"));
        assert_eq!(
            choose(&accounts, &["roomy".into()]).as_deref(),
            Some("busy")
        );
        assert_eq!(choose(&accounts, &["roomy".into(), "busy".into()]), None);
    }

    #[test]
    fn stale_or_failed_usage_is_never_chosen() {
        let mut stale = fetched(
            "stale",
            &format!(r#"{{"seven_day":{{"utilization":1}},{OFF}}}"#),
            Some("max"),
        );
        stale.snapshot.fresh = false;
        let mut failed = fetched(
            "failed",
            &format!(r#"{{"seven_day":{{"utilization":1}},{OFF}}}"#),
            Some("max"),
        );
        failed.error = Some("HTTP 500".into());
        assert_eq!(choose(&[stale, failed], &[]), None);
    }

    #[test]
    fn relaunch_drops_old_resume_options_and_resumes_the_session() {
        let original: Vec<OsString> = [
            "--dangerously-skip-permissions",
            "--resume",
            "old",
            "-c",
            "--model=opus",
            "--resume=x",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let args = relaunch_args(&original, "s2", "Continue.");
        assert_eq!(
            args,
            [
                "--dangerously-skip-permissions",
                "--model=opus",
                "--resume",
                "s2",
                "Continue."
            ]
            .map(OsString::from)
        );
    }
}
