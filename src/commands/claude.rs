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
use crate::commands::use_profile;

/// Token lifetime exec requires at launch.
const MIN_VALID: Duration = Duration::from_secs(30 * 60);
/// Recoveries allowed in one hour before the launcher stops.
const MAX_RECOVERIES_PER_HOUR: usize = 3;
/// How often the watcher reads the lane transcripts.
const WATCH_INTERVAL: Duration = Duration::from_secs(2);
/// Wait before another usage read when one failed or came back old.
const CONFIRM_RETRY: Duration = Duration::from_secs(30);
/// Time Claude gets to save its session after SIGTERM before SIGKILL.
const STOP_GRACE: Duration = Duration::from_secs(20);

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
    let mut alias = match &launch.account {
        Some(alias) => {
            confirm_explicit(alias, launch.allow_billing)?;
            alias.clone()
        }
        None => choose(
            &status::fetch_all_usages()?,
            &tried,
            live_uuid(&store).as_deref(),
        )
        .context("no rate-limited account with room; run claudectl status")?,
    };
    let mut args = launch.args.clone();
    loop {
        // Check first: cleanup would otherwise delete a credentials file.
        lane.assert_no_credentials()?;
        lane.clear_account_state()?;
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
        // Counted from the lane log, so a restarted launcher keeps the cap.
        if lane.recent_events("recovery", chrono::Duration::hours(1))? >= MAX_RECOVERIES_PER_HOUR {
            bail!(
                "{alias} reached its limit, and {MAX_RECOVERIES_PER_HOUR} recoveries ran in the last hour; \
                 stopped. Resume with: claudectl claude --lane {} -- --resume {}",
                launch.lane,
                hit.session_id
            );
        }
        tried.push(alias.clone());
        let Some(next) = choose(
            &status::fetch_all_usages()?,
            &tried,
            live_uuid(&store).as_deref(),
        ) else {
            bail!(
                "{alias} reached its limit and no other rate-limited account has room; \
                 session {} is kept in lane {}",
                hit.session_id,
                launch.lane
            );
        };
        // Counted only when a next run starts.
        lane.log("recovery", &alias, Some(&hit.session_id))?;
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
        min_valid: MIN_VALID,
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
/// it with one usage read, then end the run through exec's signal forwarder,
/// so Claude's group gets SIGTERM (and SIGCONT) and Claude saves its session.
fn watch(
    config_dir: &Path,
    cwd: &Path,
    alias: &str,
    launched: chrono::DateTime<chrono::Utc>,
    stop: &AtomicBool,
    limited: &Mutex<Option<RateLimitHit>>,
) {
    // Hits whose usage read showed room; a failed read is retried later.
    let mut handled: Vec<String> = Vec::new();
    let mut retry_at: Option<Instant> = None;
    let mut final_scan_done = false;
    loop {
        let exited = stop.load(Ordering::SeqCst);
        if exited {
            // After the run ends: one last scan for a record written at exit,
            // and keep a pending retry alive, so `claude -p` can recover too.
            let pending = retry_at.is_some_and(|at| Instant::now() < at + WATCH_INTERVAL);
            if final_scan_done && !pending {
                return;
            }
            final_scan_done = true;
        }
        std::thread::sleep(WATCH_INTERVAL);
        let Some(hit) = lane::find_rate_limit_in(config_dir, cwd, launched) else {
            continue;
        };
        if handled.contains(&hit.uuid) || retry_at.is_some_and(|at| Instant::now() < at) {
            continue;
        }
        match limit_check(alias) {
            Limit::Reached => {
                *limited.lock().unwrap_or_else(|e| e.into_inner()) = Some(hit);
                if !stop.load(Ordering::SeqCst) {
                    end_run(stop);
                }
                return;
            }
            Limit::Room => {
                handled.push(hit.uuid);
                retry_at = None;
            }
            Limit::Unknown => retry_at = Some(Instant::now() + CONFIRM_RETRY),
        }
    }
}

/// End the run through exec's child-group forwarder (a SIGTERM to this
/// process could be inherited as ignored). If Claude has not exited after
/// STOP_GRACE, for example because it inherited SIGTERM as ignored, kill its
/// group: transcripts are append-only, so the session still resumes.
fn end_run(stop: &AtomicBool) {
    exec::signals::forward(libc::SIGTERM);
    let started = Instant::now();
    while started.elapsed() < STOP_GRACE {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("claudectl claude: Claude did not stop on SIGTERM; killing it");
    exec::signals::forward(libc::SIGKILL);
}

enum Limit {
    /// Fresh usage shows a window at 100%.
    Reached,
    /// Fresh usage shows room: the error was a short API throttle.
    Room,
    /// The read failed or came back old; try again later.
    Unknown,
}

/// One usage read for the account: a transcript error alone can be a short
/// API throttle, not a used-up window.
fn limit_check(alias: &str) -> Limit {
    match status::fetch_alias(alias, FetchMode::Refresh) {
        Ok(Some(fetched))
            if fetched.error.is_none()
                && fetched.snapshot.is_fresh_at(chrono::Utc::now().timestamp()) =>
        {
            match fetched.usage.as_ref() {
                Some(usage) if status::exhausted(usage) => Limit::Reached,
                Some(_) => Limit::Room,
                None => Limit::Unknown,
            }
        }
        _ => Limit::Unknown,
    }
}

/// The next account: rate-limited (never billed), with fresh usage below
/// every limit, not the live login, and not tried in this launch, ranked as
/// `use` ranks: lowest max(5h, 7d), a missing window counting as unavailable.
fn choose(fetched: &[FetchedUsage], tried: &[String], live_uuid: Option<&str>) -> Option<String> {
    let usable_until = chrono::Utc::now().timestamp() + MIN_VALID.as_secs() as i64;
    let candidates: Vec<use_profile::Candidate> = fetched
        .iter()
        .filter(|f| !f.is_active && !tried.contains(&f.alias))
        // The live login's account, also when the active marker is stale:
        // exec refuses it.
        .filter(|f| live_uuid.is_none() || f.account_uuid.as_deref() != live_uuid)
        // exec refuses a profile without a known account or with a token that
        // expires within MIN_VALID; do not rank one.
        .filter(|f| f.account_uuid.is_some())
        .filter(|f| f.token_expiry_secs.is_some_and(|at| at >= usable_until))
        .filter(|f| {
            f.usage.as_ref().is_some_and(|usage| {
                status::billing_class(Some(usage), f.plan.as_deref()) == "rate_limited"
                    && !status::exhausted(usage)
            })
        })
        .map(use_profile::candidate_from)
        .collect();
    use_profile::select_most_available(&candidates).map(str::to_string)
}

/// The live login's account UUID from `~/.claude.json`.
fn live_uuid(store: &AuthStore) -> Option<String> {
    store
        .read_oauth_account()
        .ok()
        .flatten()?
        .get("accountUuid")?
        .as_str()
        .map(str::to_string)
}

/// An explicitly chosen account that is not proven rate-limited may bill
/// credits: ask on a terminal, accept `--allow-billing`, otherwise refuse.
fn confirm_explicit(alias: &str, allow_billing: bool) -> Result<()> {
    let fetched = status::fetch_alias(alias, FetchMode::Cached)?
        .with_context(|| format!("profile '{alias}' not found"))?;
    let fresh =
        fetched.error.is_none() && fetched.snapshot.is_fresh_at(chrono::Utc::now().timestamp());
    // Old or failed data cannot prove that extra usage is still off.
    let class = if fresh {
        status::billing_class(fetched.usage.as_ref(), fetched.plan.as_deref())
    } else {
        "unknown"
    };
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
            // `--resume` alone opens a picker; skip a value only when present.
            if iter
                .clone()
                .next()
                .is_some_and(|next| !next.to_string_lossy().starts_with('-'))
            {
                iter.next();
            }
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
            account_uuid: Some(format!("uuid-{alias}")),
            token_expiry_secs: Some(now + 3_600),
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
            &format!(
                r#"{{"five_hour":{{"utilization":1}},"seven_day":{{"utilization":1}},{OFF}}}"#
            ),
            Some("max"),
        );
        live.is_active = true;
        let accounts = [
            live,
            fetched(
                "busy",
                &format!(
                    r#"{{"five_hour":{{"utilization":5}},"seven_day":{{"utilization":70}},{OFF}}}"#
                ),
                Some("max"),
            ),
            fetched(
                "roomy",
                &format!(
                    r#"{{"five_hour":{{"utilization":5}},"seven_day":{{"utilization":20}},{OFF}}}"#
                ),
                Some("max"),
            ),
            fetched(
                "billed",
                r#"{"five_hour":{"utilization":0},"seven_day":{"utilization":0},"extra_usage":{"is_enabled":true}}"#,
                Some("max"),
            ),
            fetched(
                "unknown",
                r#"{"five_hour":{"utilization":0},"seven_day":{"utilization":0}}"#,
                Some("max"),
            ),
            fetched(
                "full",
                &format!(
                    r#"{{"five_hour":{{"utilization":0}},"seven_day":{{"utilization":30}},"seven_day_opus":{{"utilization":100}},{OFF}}}"#
                ),
                Some("max"),
            ),
        ];
        assert_eq!(choose(&accounts, &[], None).as_deref(), Some("roomy"));
        assert_eq!(
            choose(&accounts, &["roomy".into()], None).as_deref(),
            Some("busy")
        );
        assert_eq!(
            choose(&accounts, &["roomy".into(), "busy".into()], None),
            None
        );
    }

    #[test]
    fn a_nearly_full_five_hour_window_ranks_low_and_a_missing_one_is_unavailable() {
        let accounts = [
            fetched(
                "hot",
                &format!(
                    r#"{{"five_hour":{{"utilization":99}},"seven_day":{{"utilization":5}},{OFF}}}"#
                ),
                Some("max"),
            ),
            fetched(
                "calm",
                &format!(
                    r#"{{"five_hour":{{"utilization":20}},"seven_day":{{"utilization":20}},{OFF}}}"#
                ),
                Some("max"),
            ),
            fetched(
                "blind",
                &format!(r#"{{"seven_day":{{"utilization":1}},{OFF}}}"#),
                Some("max"),
            ),
        ];
        assert_eq!(choose(&accounts, &[], None).as_deref(), Some("calm"));
        assert_eq!(
            choose(&accounts, &["calm".into()], None).as_deref(),
            Some("hot")
        );
        assert_eq!(choose(&accounts[2..], &[], None), None, "missing 5h window");
    }

    #[test]
    fn profiles_exec_would_refuse_are_never_chosen() {
        let room =
            format!(r#"{{"five_hour":{{"utilization":1}},"seven_day":{{"utilization":1}},{OFF}}}"#);
        let mut no_uuid = fetched("no-uuid", &room, Some("max"));
        no_uuid.account_uuid = None;
        let mut expiring = fetched("expiring", &room, Some("max"));
        expiring.token_expiry_secs = Some(chrono::Utc::now().timestamp() + 60);
        let mut no_expiry = fetched("no-expiry", &room, Some("max"));
        no_expiry.token_expiry_secs = None;
        assert_eq!(choose(&[no_uuid, expiring, no_expiry], &[], None), None);
    }

    #[test]
    fn the_live_account_is_excluded_by_identity() {
        let room =
            format!(r#"{{"five_hour":{{"utilization":1}},"seven_day":{{"utilization":1}},{OFF}}}"#);
        let accounts = [
            fetched("a", &room, Some("max")),
            fetched("b", &room, Some("max")),
        ];
        assert_eq!(choose(&accounts, &[], Some("uuid-a")).as_deref(), Some("b"));
    }

    #[test]
    fn stale_or_failed_usage_is_never_chosen() {
        let mut stale = fetched(
            "stale",
            &format!(
                r#"{{"five_hour":{{"utilization":1}},"seven_day":{{"utilization":1}},{OFF}}}"#
            ),
            Some("max"),
        );
        stale.snapshot.fresh = false;
        let mut failed = fetched(
            "failed",
            &format!(
                r#"{{"five_hour":{{"utilization":1}},"seven_day":{{"utilization":1}},{OFF}}}"#
            ),
            Some("max"),
        );
        failed.error = Some("HTTP 500".into());
        assert_eq!(choose(&[stale, failed], &[], None), None);
    }

    #[test]
    fn a_bare_resume_keeps_the_next_option() {
        let original: Vec<OsString> = ["--resume", "--model", "opus"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert_eq!(
            relaunch_args(&original, "s2", "Go."),
            ["--model", "opus", "--resume", "s2", "Go."].map(OsString::from)
        );
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
