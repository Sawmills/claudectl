//! Admission for automatic renewal/failover. Workload evidence never authorizes a signal
//! on an I/O failure, and an expired token never overrides active work.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::os::unix::{
    ffi::OsStrExt,
    fs::{OpenOptionsExt, PermissionsExt},
};
use std::process::Command;

/// Serialize hold/hook publication with the final restart admission and signal.
pub(super) fn admission(directory: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("restart.lock"))?;
    file.lock()?;
    Ok(file)
}

/// Serialize recorded hook events with final restart admission, before `restart.lock`.
/// Pending intent is published before this lock so admission can see waiting hooks.
pub(super) fn hook_admission(directory: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("hook.lock"))?;
    #[cfg(test)]
    let _ = File::create(directory.join("hook.lock.opened"));
    file.lock()?;
    Ok(file)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Cause {
    Renewal,
    AuthRecovery,
    Failover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    RunningTurn,
    BackgroundTask,
    OpenProductionStep,
    QueuedHook,
    ExplicitHold,
    StaleHold,
    EvidenceUnknown,
    QuietWindow,
    TerminalInput,
    RestartPending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Stage {
    Deferred,
    Warn,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
struct Deferred {
    cause: Cause,
    reason: Reason,
    stage: Stage,
}

struct ObservedQuiet {
    idle: super::renew::Idle,
    input_at: Option<std::time::SystemTime>,
    since: Instant,
}

const QUIET_WINDOW: Duration = Duration::from_secs(600);

/// One gate per live Claude child. All automatic restart callers cross `check`.
pub(super) struct Gate {
    directory: PathBuf,
    home: PathBuf,
    pid: u32,
    alias: String,
    last: Option<Deferred>,
    total: u64,
    recorded_stage: Option<Stage>,
    last_session: Option<String>,
    recorded_session: Option<String>,
    log_error: bool,
    unknown_evidence: bool,
    quiet: Option<ObservedQuiet>,
    terminal: Option<PathBuf>,
    production: ProductionEvidence,
}

impl Gate {
    pub(super) fn new(home: &Path, directory: &Path, pid: u32, alias: &str) -> Self {
        Self {
            directory: directory.to_path_buf(),
            home: home.to_path_buf(),
            pid,
            alias: alias.to_owned(),
            last: None,
            total: private_read(&directory.join("restart-status.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .and_then(|v| v["restart_deferred_total"].as_u64())
                .unwrap_or(0),
            recorded_stage: None,
            last_session: None,
            recorded_session: None,
            log_error: false,
            unknown_evidence: false,
            quiet: None,
            terminal: None,
            production: ProductionEvidence::default(),
        }
    }

    pub(super) fn with_terminal(mut self, terminal: Option<PathBuf>) -> Self {
        self.terminal = terminal;
        self
    }

    /// Fresh workload evidence, with one diagnostic/counter per changed decision.
    /// Call once before provider reads and again under `admission` before SIGTERM.
    pub(super) fn check(
        &mut self,
        idle: &super::renew::Idle,
        cause: Cause,
        held_expires_at: i64,
    ) -> bool {
        self.check_at(idle, cause, held_expires_at, std::time::Instant::now())
    }

    pub(super) fn check_at(
        &mut self,
        idle: &super::renew::Idle,
        cause: Cause,
        held_expires_at: i64,
        observed_at: std::time::Instant,
    ) -> bool {
        if self.log_error {
            self.retry_error_status(idle, held_expires_at);
            return false;
        }
        let input_at = self
            .terminal
            .as_ref()
            .map(|path| std::fs::metadata(path).and_then(|metadata| metadata.accessed()))
            .transpose();
        let hook_failed = !matches!(
            std::fs::symlink_metadata(self.directory.join("hook-error")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        );
        let held = hold_reason(&self.home, &self.directory);
        let pending = hook_pending(&self.directory);
        let pending_reason = match pending {
            Ok(Some(_)) => Some(Reason::QueuedHook),
            Ok(None) => None,
            Err(_) => Some(Reason::EvidenceUnknown),
        };
        let reason = if self.unknown_evidence || input_at.is_err() || hook_failed {
            Some(Reason::EvidenceUnknown)
        } else if pending_reason.is_some() {
            pending_reason
        } else if let Ok(Some(reason)) = held {
            Some(reason)
        } else if held.is_err() || idle.session.is_none() || idle.ended.is_some() {
            Some(Reason::EvidenceUnknown)
        } else {
            match self.production.check(&self.home) {
                Ok(true) => Some(Reason::OpenProductionStep),
                Err(_) => Some(Reason::EvidenceUnknown),
                Ok(false) if idle.since.is_none() => Some(Reason::RunningTurn),
                Ok(false) => match live_task(self.pid) {
                    Ok(true) => Some(Reason::BackgroundTask),
                    Ok(false) => None,
                    Err(_) => Some(Reason::EvidenceUnknown),
                },
            }
        };
        let reason = if reason.is_some() {
            self.quiet = None;
            reason
        } else {
            let input_at = input_at.expect("terminal evidence was checked");
            let changed = self
                .quiet
                .as_ref()
                .is_none_or(|previous| previous.idle != *idle || previous.input_at != input_at);
            if changed {
                self.quiet = Some(ObservedQuiet {
                    idle: idle.clone(),
                    input_at,
                    since: observed_at,
                });
            }
            let quiet = self.quiet.as_ref().expect("quiet clock initialized");
            let terminal_quiet = input_at.is_none_or(|at| {
                std::time::SystemTime::now()
                    .duration_since(at)
                    .unwrap_or_default()
                    >= QUIET_WINDOW
            });
            if cause == Cause::AuthRecovery {
                // A dead token needs the next verified idle point, not ten minutes.
                // Terminal evidence must still survive a fresh sample without input.
                (input_at.is_some() && changed).then_some(Reason::TerminalInput)
            } else {
                (observed_at.saturating_duration_since(quiet.since) < QUIET_WINDOW
                    || !terminal_quiet)
                    .then_some(Reason::QuietWindow)
            }
        };
        // Workload observations do not close all inputs. A hook can still be
        // invisible or arrive between this sample and SIGTERM.
        let admitted = reason.is_none();
        // Quiet eligibility does not mean a token read, budget or account choice
        // will succeed. Keep expiry attention until this child actually exits.
        let diagnostic = reason.or_else(|| {
            (held_expires_at.saturating_sub(now()) <= 300_000 || idle.auth_failed.is_some())
                .then_some(Reason::RestartPending)
        });
        let recorded = self.record(diagnostic, idle, cause, held_expires_at);
        admitted && recorded
    }

    pub(super) fn unknown(&mut self, idle: &super::renew::Idle, cause: Cause, expires_at: i64) {
        self.unknown_evidence = true;
        self.record(Some(Reason::EvidenceUnknown), idle, cause, expires_at);
    }

    fn record(
        &mut self,
        reason: Option<Reason>,
        idle: &super::renew::Idle,
        cause: Cause,
        held_expires_at: i64,
    ) -> bool {
        if self.log_error {
            self.retry_error_status(idle, held_expires_at);
            return false;
        }
        let at = now();
        let decision = reason.map(|reason| Deferred {
            cause,
            reason,
            stage: if at >= held_expires_at
                || idle.auth_failed.is_some()
                || reason == Reason::StaleHold
            {
                Stage::Blocked
            } else if held_expires_at - at <= 300_000 {
                Stage::Warn
            } else {
                Stage::Deferred
            },
        });
        if self
            .publish(decision, idle.session.as_deref(), held_expires_at, at)
            .is_err()
        {
            self.log_error = true;
            // An uncertain journal write must not be retried and counted twice.
            self.retry_error_status(idle, held_expires_at);
            return false;
        }
        self.log_error = false;
        true
    }

    fn retry_error_status(&self, idle: &super::renew::Idle, expires_at: i64) {
        // The journal append and counter are intentionally never retried after
        // uncertain persistence. Status is independent and may recover later.
        let _ = atomic(
            &self.directory.join("restart-status.json"),
            &json!({
                "at":now(),"session_id":idle.session.as_deref(),"run":run_id(&self.directory).unwrap_or("unknown"),
                "alias":self.alias,"expires_at":expires_at,"deferred":true,
                "reason":"evidence_unknown","stage":"blocked","attention_required":true,
                "restart_deferred_total":self.total,
            }),
        );
    }

    fn publish(
        &mut self,
        decision: Option<Deferred>,
        session: Option<&str>,
        expires_at: i64,
        at: i64,
    ) -> Result<()> {
        if self.last == decision && self.last_session.as_deref() == session {
            return Ok(());
        }
        let run = run_id(&self.directory)?;
        let mut status = json!({"at":at,"session_id":session,"run":run,"alias":self.alias,
            "expires_at":expires_at,"deferred":decision.is_some(),
            "restart_deferred_total":self.total});
        if let Some(d) = decision {
            if self.recorded_stage != Some(d.stage) || self.recorded_session.as_deref() != session {
                let mut file = OpenOptions::new()
                    .read(true)
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(self.home.join(".claudectl/server/restart-decisions.jsonl"))?;
                file.lock()?;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
                let record = json!({"at":at,"event":"restart_deferred","session_id":session,
                "run":run,"cause":d.cause,"reason":d.reason,"stage":d.stage,
                "expires_at":expires_at,
                "metric":{"name":"claudectl_restart_deferred_total","value":1,
                    "labels":{"cause":d.cause,"reason":d.reason,"stage":d.stage}}});
                let mut line = serde_json::to_vec(&record)?;
                line.push(b'\n');
                file.write_all(&line)?;
                file.sync_data()?;
                self.total += 1;
                self.recorded_stage = Some(d.stage);
                self.recorded_session = session.map(str::to_owned);
            }
            status["cause"] = json!(d.cause);
            status["reason"] = json!(d.reason);
            status["stage"] = json!(d.stage);
            status["attention_required"] = json!(d.stage != Stage::Deferred);
            status["restart_deferred_total"] = json!(self.total);
        }
        atomic(&self.directory.join("restart-status.json"), &status)?;
        self.last = decision;
        self.last_session = session.map(str::to_owned);
        if decision.is_none() {
            self.recorded_stage = None;
            self.recorded_session = None;
        }
        Ok(())
    }
}

/// A production step explicitly prevents renewal/failover of its server run.
#[derive(clap::Subcommand)]
pub enum HoldCommand {
    /// Hold this run until `hold end`, even when the token expires
    Start {
        /// Ticket and production step; kept locally, never a metric label
        #[arg(long)]
        reason: String,
    },
    /// End this run's hold explicitly; stale holds are never cleared automatically
    End {
        /// Explicit run ID for a stale hold after its wrapper exited
        #[arg(long)]
        run: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct Hold {
    run: String,
    reason: String,
    owner_pid: u32,
    owner_started: String,
    at: i64,
    alias: String,
}

fn run_id(directory: &Path) -> Result<&str> {
    let name = directory
        .file_name()
        .and_then(|n| n.to_str())
        .context("missing server run identity")?;
    if !name.starts_with("run-")
        || name.len() <= 4
        || name.len() > 128
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("invalid server run identity");
    }
    Ok(name)
}

fn bound_directory(paths: &Paths) -> Result<PathBuf> {
    let marker = std::env::var_os(super::session::SERVER_RUN_ENV)
        .context("hold requires a server-run child (CLAUDECTL_SERVER_RUN is absent)")?;
    let directory = PathBuf::from(marker).canonicalize()?;
    let sessions = root(paths).join("sessions").canonicalize()?;
    if directory.parent() != Some(sessions.as_path()) {
        bail!("not this user's server run");
    }
    run_id(&directory)?;
    Ok(directory)
}

fn hold_path(home: &Path, directory: &Path) -> Result<PathBuf> {
    Ok(home
        .join(".claudectl/server/holds")
        .join(format!("{}.json", run_id(directory)?)))
}

fn process_start(pid: u32) -> Result<String> {
    let result = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "lstart="])
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()?;
    let value = std::str::from_utf8(&result.stdout)?.trim();
    if !result.status.success() || value.is_empty() {
        bail!("hold owner is no longer live");
    }
    Ok(value.to_owned())
}

fn read_hold(home: &Path, directory: &Path) -> Result<Option<Hold>> {
    let path = hold_path(home, directory)?;
    match private_read(&path) {
        Ok(bytes) => {
            let hold: Hold = serde_json::from_slice(&bytes)?;
            if hold.run != run_id(directory)? {
                bail!("hold run identity mismatch");
            }
            Ok(Some(hold))
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn hold_reason(home: &Path, directory: &Path) -> Result<Option<Reason>> {
    let Some(hold) = read_hold(home, directory)? else {
        return Ok(None);
    };
    Ok(Some(
        if process_start(hold.owner_pid).is_ok_and(|start| start == hold.owner_started) {
            Reason::ExplicitHold
        } else {
            Reason::StaleHold
        },
    ))
}

fn hook_pending(directory: &Path) -> Result<Option<u32>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(pid) = name
            .strip_prefix("hook-pending.")
            .and_then(|pid| pid.parse::<u32>().ok())
            .filter(|pid| *pid != 0)
        else {
            continue;
        };
        let bytes = match private_read(&path) {
            Ok(bytes) => bytes,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let saved = serde_json::from_slice::<Value>(&bytes)?["pid"]
            .as_u64()
            .context("hook pending PID unavailable")?;
        let saved = u32::try_from(saved).context("hook pending PID invalid")?;
        if saved != pid {
            bail!("hook pending PID does not match its owner file");
        }
        if process_live(pid)? {
            return Ok(Some(pid));
        }
        std::fs::remove_file(path)?;
    }
    Ok(None)
}

fn process_live(pid: u32) -> Result<bool> {
    match unsafe { libc::kill(pid as libc::pid_t, 0) } {
        0 => Ok(true),
        -1 => match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => bail!("could not inspect hook process"),
        },
        _ => bail!("could not inspect hook process"),
    }
}

/// Per-child source history. Keep only fingerprints and open state, never source text.
#[derive(Default)]
struct ProductionEvidence {
    sources: BTreeMap<PathBuf, Option<MarkerSnapshot>>,
}

struct MarkerSnapshot {
    length: usize,
    digest: [u8; 32],
    open: bool,
}

impl ProductionEvidence {
    fn check(&mut self, home: &Path) -> Result<bool> {
        let goal = std::env::var_os("LANE_GOAL_FILE")
            .or_else(|| std::env::var_os("SAW_GOAL_FILE"))
            .map(PathBuf::from);
        self.for_environment(
            home,
            goal,
            std::env::var_os("HERDR_TAB_ID"),
            std::env::var_os("HERDR_PANE_ID"),
        )
    }

    fn for_environment(
        &mut self,
        home: &Path,
        goal: Option<PathBuf>,
        tab: Option<std::ffi::OsString>,
        pane: Option<std::ffi::OsString>,
    ) -> Result<bool> {
        let supplied = tab.is_some() || pane.is_some();
        let lane = [tab, pane].into_iter().flatten().find_map(|value| {
            let value = value.into_string().ok()?;
            let lane = value.trim();
            let usable = lane.chars().any(|c| c.is_ascii_alphanumeric())
                && lane
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || ":_-./".contains(c))
                && lane_token(lane) == lane;
            usable.then(|| lane.to_owned())
        });
        if supplied && lane.is_none() {
            bail!("usable lane identity unavailable for production markers");
        }
        self.for_lane(home, goal, lane)
    }

    fn for_lane(
        &mut self,
        home: &Path,
        goal: Option<PathBuf>,
        lane: Option<String>,
    ) -> Result<bool> {
        // Standalone sessions do not consume machine-wide lane outboxes.
        if goal.is_none() && lane.is_none() {
            return Ok(false);
        }
        let lane = lane.context("lane identity unavailable for production markers")?;
        let mut sources = goal.into_iter().collect::<Vec<_>>();
        for path in &sources {
            self.sources.entry(path.clone()).or_default();
        }
        let root = home.join("Code/.fleet/voice-between");
        for name in ["agents-cases-outbox.md", "slack-outbox.md"] {
            let path = root.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(_) => {
                    self.sources.entry(path.clone()).or_default();
                    sources.push(path);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    self.sources.entry(path).or_default();
                    return Err(error.into());
                }
            }
        }
        // Once observed, a source cannot silently become optional again.
        sources.extend(self.sources.keys().cloned());
        sources.sort();
        sources.dedup();
        let mut open = false;
        for path in sources {
            let text = std::fs::read_to_string(&path)?;
            if let Some(Some(previous)) = self.sources.get(&path) {
                let same_prefix = text
                    .as_bytes()
                    .get(..previous.length)
                    .is_some_and(|prefix| {
                        let digest: [u8; 32] = Sha256::digest(prefix).into();
                        digest == previous.digest
                    });
                if previous.open && !same_prefix {
                    // Do not replace this checkpoint: another poll must not accept
                    // rewritten or truncated evidence as proof of completion.
                    bail!("open production marker history was replaced");
                }
            }
            let source_open = production_markers(&lane, std::slice::from_ref(&text));
            self.sources.insert(
                path,
                Some(MarkerSnapshot {
                    length: text.len(),
                    digest: Sha256::digest(text.as_bytes()).into(),
                    open: source_open,
                }),
            );
            open |= source_open;
        }
        Ok(open)
    }
}

#[cfg(test)]
fn production_step_with_lane(
    home: &Path,
    goal: Option<PathBuf>,
    lane: Option<String>,
) -> Result<bool> {
    ProductionEvidence::default().for_lane(home, goal, lane)
}

#[cfg(test)]
fn production_markers_from_paths(lane: &str, sources: &[PathBuf]) -> Result<bool> {
    let mut texts = Vec::new();
    for path in sources {
        texts.push(std::fs::read_to_string(path)?);
    }
    Ok(production_markers(lane, &texts))
}

fn production_markers(lane: &str, texts: &[String]) -> bool {
    // File order is not event order. A DONE in another source cannot prove
    // that this source's current production step completed.
    texts.iter().any(|text| {
        let mut open = HashSet::new();
        for line in text.lines() {
            if !line_has_lane(line, lane) {
                continue;
            }
            let Some(key) = marker_key(line) else {
                continue;
            };
            if line.contains("[starting]") || line.contains("STARTING NOW") {
                open.insert(key);
            } else if line.contains("[done]") || line.contains("DONE") {
                open.remove(&key);
            }
        }
        !open.is_empty()
    })
}

fn lane_token(word: &str) -> &str {
    word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != ':' && c != '_' && c != '-')
}

fn line_has_lane(line: &str, lane: &str) -> bool {
    line.split_whitespace().any(|word| lane_token(word) == lane)
}

fn marker_key(line: &str) -> Option<String> {
    let words: Vec<_> = line.split_whitespace().collect();
    let ticket = words.iter().position(|word| {
        let word = word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
        let Some((prefix, suffix)) = word.split_once('-') else {
            return false;
        };
        !prefix.is_empty()
            && prefix.chars().any(|c| c.is_ascii_alphabetic())
            && !suffix.is_empty()
            && suffix.chars().all(|c| c.is_ascii_digit())
    })?;
    Some(
        words[ticket..]
            .iter()
            .map(|word| word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-'))
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
    )
}

/// Local only. A hold is keyed by the inherited run identity, never by goal/outbox prose.
pub fn hold(paths: &Paths, command: HoldCommand) -> Result<()> {
    match command {
        HoldCommand::Start { reason } => {
            if reason.trim().is_empty()
                || reason.len() > 256
                || reason.chars().any(char::is_control)
            {
                bail!("hold reason must be 1..256 bytes without control characters");
            }
            let directory = bound_directory(paths)?;
            let _admission = admission(&directory)?;
            let owner = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(directory.join("owner.lock"))?;
            if !matches!(owner.try_lock(), Err(std::fs::TryLockError::WouldBlock)) {
                bail!("server run is no longer owned");
            }
            let status: Value =
                serde_json::from_slice(&private_read(&directory.join("session.json"))?)?;
            if status["restart_gate_version"] != 1 {
                bail!(
                    "this server wrapper does not support holds; do not start the production step"
                );
            }
            if status["renewal"] == "renewing" {
                bail!("server run is already restarting; hold was not started");
            }
            if let Some(existing) = read_hold(&paths.home, &directory)? {
                if existing.reason != reason {
                    bail!("this run already holds another step; end it explicitly first");
                }
                println!("hold already active for {}", existing.run);
                return Ok(());
            }
            // Bash tool shells are short-lived. The wrapper owns the run and its hold.
            let pid = status["pid"]
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .context("run owner unavailable")?;
            let hold = Hold {
                run: run_id(&directory)?.into(),
                reason,
                owner_pid: pid,
                owner_started: process_start(pid)?,
                at: now(),
                alias: status["alias"]
                    .as_str()
                    .context("run alias unavailable")?
                    .into(),
            };
            atomic(&hold_path(&paths.home, &directory)?, &hold)?;
            println!("hold started for {}", hold.run);
        }
        HoldCommand::End { run } => {
            let explicit_run = run.is_some();
            let directory = match run {
                Some(run) => {
                    let leaf = Path::new(&run);
                    if leaf.components().count() != 1 {
                        bail!("expected one server run ID");
                    }
                    run_id(leaf)?;
                    root(paths).join("sessions").join(run)
                }
                None => bound_directory(paths)?,
            };
            if explicit_run && owner_live(&directory) {
                bail!("cannot end a live server-run hold by ID; end it from that run");
            }
            let _admission = if directory.exists() {
                Some(admission(&directory)?)
            } else {
                None
            };
            let path = hold_path(&paths.home, &directory)?;
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                    std::fs::remove_file(&path)?;
                    File::open(path.parent().context("hold directory unavailable")?)?.sync_all()?;
                }
                Ok(_) => bail!("hold is not a regular file; explicit repair required"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            println!("hold ended for {}", run_id(&directory)?);
        }
    }
    Ok(())
}

/// Current deferred sessions, including holds retained after wrapper/process exit.
pub fn deferred_sessions(paths: &Paths) -> Result<Vec<Value>> {
    let mut rows = BTreeMap::new();
    let sessions = root(paths).join("sessions");
    match std::fs::read_dir(&sessions) {
        Ok(entries) => {
            for entry in entries {
                let directory = entry?.path();
                if run_id(&directory).is_err() {
                    continue;
                }
                let file = directory.join("restart-status.json");
                match private_read(&file)
                    .and_then(|bytes| Ok(serde_json::from_slice::<Value>(&bytes)?))
                {
                    Ok(value) => {
                        if value["deferred"] == true {
                            let live = owner_live(&directory);
                            let value = if live {
                                value
                            } else {
                                let mut stale = value;
                                stale["reason"] = "stale_run".into();
                                stale["stage"] = "blocked".into();
                                stale["attention_required"] = true.into();
                                stale
                            };
                            rows.insert(run_id(&directory)?.to_owned(), value);
                        }
                    }
                    Err(error)
                        if error
                            .downcast_ref::<std::io::Error>()
                            .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
                    Err(_) => {
                        rows.insert(
                            run_id(&directory)?.to_owned(),
                            unknown_status(run_id(&directory)?),
                        );
                    }
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    match std::fs::read_dir(root(paths).join("holds")) {
        Ok(entries) => {
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_none_or(|e| e != "json") {
                    continue;
                }
                let Some(run) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let directory = sessions.join(run);
                if run_id(&directory).is_err() {
                    continue;
                }
                let hold = match read_hold(&paths.home, &directory) {
                    Ok(Some(hold)) => hold,
                    Ok(None) => continue,
                    Err(_) => {
                        rows.insert(run.into(), unknown_status(run));
                        continue;
                    }
                };
                let stale = !directory.exists()
                    || !process_start(hold.owner_pid)
                        .is_ok_and(|start| start == hold.owner_started);
                let row = rows.entry(run.into()).or_insert_with(|| {
                    json!({"run":run,"alias":hold.alias,
                "deferred":true,"reason":if stale {"stale_hold"} else {"explicit_hold"},
                "stage":if stale {"blocked"} else {"deferred"}})
                });
                if stale {
                    row["reason"] = "stale_hold".into();
                    row["stage"] = "blocked".into();
                    row["attention_required"] = true.into();
                }
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(rows.into_values().collect())
}

fn unknown_status(run: &str) -> Value {
    json!({"run":run,"deferred":true,"reason":"evidence_unknown","stage":"blocked",
        "attention_required":true})
}

fn owner_live(directory: &Path) -> bool {
    let Ok(file) = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(directory.join("owner.lock"))
    else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

/// The inherited server run's status, without a network read.
pub fn current_line(paths: &Paths) -> Option<String> {
    std::env::var_os(super::session::SERVER_RUN_ENV)?;
    let directory = match bound_directory(paths) {
        Ok(directory) => directory,
        Err(_) => return Some("restart deferred: evidence_unknown (attention required)".into()),
    };
    match hold_reason(&paths.home, &directory) {
        Ok(Some(Reason::StaleHold)) => {
            return Some("restart deferred: stale_hold (blocked)".into());
        }
        Ok(None | Some(Reason::ExplicitHold)) => {}
        Ok(Some(_)) => {}
        Err(_) => return Some("restart deferred: evidence_unknown (attention required)".into()),
    }
    let path = directory.join("restart-status.json");
    match private_read(&path) {
        Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value["deferred"] == true => Some(format!(
                "restart deferred: {} ({})",
                value["reason"].as_str().unwrap_or("evidence_unknown"),
                value["stage"].as_str().unwrap_or("blocked")
            )),
            Ok(_) => None,
            Err(_) => Some("restart deferred: evidence_unknown (attention required)".into()),
        },
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            None
        }
        Err(_) => Some("restart deferred: evidence_unknown (attention required)".into()),
    }
}

#[derive(Clone, Copy)]
struct Process {
    parent: u32,
    group: u32,
    zombie: bool,
}

/// No argv/environment is requested from the process table.
fn processes() -> Result<BTreeMap<u32, Process>> {
    let result = Command::new("/bin/ps")
        .args(["-axo", "pid=,ppid=,pgid=,stat="])
        .output()?;
    if !result.status.success() {
        bail!("process inventory unavailable");
    }
    let mut found = BTreeMap::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 4 {
            bail!("incomplete process inventory");
        }
        found.insert(
            fields[0].parse()?,
            Process {
                parent: fields[1].parse()?,
                group: fields[2].parse()?,
                zombie: fields[3].starts_with('Z'),
            },
        );
    }
    Ok(found)
}

fn live_task(leader: u32) -> Result<bool> {
    let all = processes()?;
    if !all.contains_key(&leader) {
        bail!("Claude missing from process inventory");
    }
    let mut owned = HashSet::from([leader]);
    loop {
        let before = owned.len();
        for (&pid, process) in &all {
            if process.group == leader || owned.contains(&process.parent) {
                owned.insert(pid);
            }
        }
        if owned.len() == before {
            break;
        }
    }
    let pids: Vec<_> = owned
        .into_iter()
        .filter(|pid| *pid != leader && all.get(pid).is_some_and(|p| !p.zombie))
        .collect();
    task_descriptors(&pids)
}

fn is_task_output(path: &Path) -> bool {
    // Unlinking a still-open task log does not end its process.
    let bytes = path.as_os_str().as_bytes();
    let path = Path::new(std::ffi::OsStr::from_bytes(
        bytes.strip_suffix(b" (deleted)").unwrap_or(bytes),
    ));
    let uid = unsafe { libc::geteuid() };
    let name = format!("claude-{uid}");
    let roots = [
        std::env::temp_dir(),
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
    ];
    roots.iter().any(|root| {
        let root = root.canonicalize().unwrap_or_else(|_| root.clone());
        path.starts_with(root.join(&name))
            && path.extension().is_some_and(|ext| ext == "output")
            && path
                .parent()
                .and_then(Path::file_name)
                .is_some_and(|dir| dir == "tasks")
    })
}

#[cfg(not(target_os = "macos"))]
fn task_descriptors(pids: &[u32]) -> Result<bool> {
    for pid in pids {
        for fd in [1, 2] {
            match std::fs::read_link(format!("/proc/{pid}/fd/{fd}")) {
                Ok(path) if is_task_output(&path) => return Ok(true),
                Ok(_) => {}
                // A descriptor may be closed, or its process may have exited.
                Err(error) if crate::exec::process_gone(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
fn task_descriptors(pids: &[u32]) -> Result<bool> {
    // Darwin <sys/proc_info.h>: libc supplies vnode_info_path but not these wrappers.
    // https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
    #[repr(C)]
    struct FileInfo {
        flags: u32,
        status: u32,
        offset: libc::off_t,
        kind: i32,
        guards: u32,
    }
    #[repr(C)]
    struct VnodeFdInfo {
        file: FileInfo,
        path: libc::vnode_info_path,
    }
    const VNODE_PATH: i32 = 2;
    const VNODE: u32 = 1;
    for &pid in pids {
        let mut capacity = 64;
        let descriptors = loop {
            if capacity > 65_536 {
                bail!("descriptor inventory too large");
            }
            // SAFETY: proc_fdinfo contains only integer fields; the buffer is sized below.
            let mut fds: Vec<libc::proc_fdinfo> = (0..capacity)
                .map(|_| unsafe { std::mem::zeroed() })
                .collect();
            let size = std::mem::size_of_val(fds.as_slice());
            // SAFETY: errno is thread-local; proc_pidinfo writes at most `size` bytes.
            let bytes = unsafe {
                *libc::__error() = 0;
                libc::proc_pidinfo(
                    pid as i32,
                    libc::PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr().cast(),
                    size as i32,
                )
            };
            if bytes <= 0 {
                let error = std::io::Error::last_os_error();
                if bytes == 0 && error.raw_os_error() == Some(0) {
                    break Vec::new();
                }
                if crate::exec::process_gone(&error) {
                    break Vec::new();
                }
                return Err(error.into());
            }
            let bytes = bytes as usize;
            if bytes >= size {
                capacity *= 2;
                continue;
            }
            if bytes % std::mem::size_of::<libc::proc_fdinfo>() != 0 {
                bail!("partial descriptor inventory");
            }
            fds.truncate(bytes / std::mem::size_of::<libc::proc_fdinfo>());
            break fds;
        };
        for fd in descriptors
            .iter()
            .filter(|fd| matches!(fd.proc_fd, 1 | 2) && fd.proc_fdtype == VNODE)
        {
            // SAFETY: this C-layout buffer uses libc's exact vnode_info_path layout.
            let mut info: VnodeFdInfo = unsafe { std::mem::zeroed() };
            let size = std::mem::size_of::<VnodeFdInfo>();
            // SAFETY: the kernel is given the buffer's actual byte length.
            let bytes = unsafe {
                libc::proc_pidfdinfo(
                    pid as i32,
                    fd.proc_fd,
                    VNODE_PATH,
                    (&mut info as *mut VnodeFdInfo).cast(),
                    size as i32,
                )
            };
            if bytes != size as i32 {
                let error = std::io::Error::last_os_error();
                if crate::exec::process_gone(&error) || error.raw_os_error() == Some(libc::EBADF) {
                    continue;
                }
                bail!("task descriptor path unavailable");
            }
            let bytes: Vec<u8> = info
                .path
                .vip_path
                .iter()
                .flatten()
                .map(|&b| b as u8)
                .collect();
            let end = bytes
                .iter()
                .position(|&b| b == 0)
                .context("truncated descriptor path")?;
            if is_task_output(Path::new(std::ffi::OsStr::from_bytes(&bytes[..end]))) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _home: tempfile::TempDir,
        child: std::process::Child,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn setup() -> (Fixture, Gate, super::super::renew::Idle) {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".claudectl/server/sessions/run-gate");
        private_dir(&dir).unwrap();
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let gate = Gate::new(home.path(), &dir, child.id(), "work");
        let idle = super::super::renew::Idle {
            session: Some("same-session".into()),
            since: Some(0),
            ..Default::default()
        };
        (Fixture { _home: home, child }, gate, idle)
    }

    #[test]
    fn option_b_requires_ten_continuous_minutes_of_observed_quiet() {
        for cause in [Cause::Renewal, Cause::Failover] {
            let (_home, mut gate, idle) = setup();
            let start = std::time::Instant::now();
            assert!(!gate.check_at(&idle, cause, i64::MAX, start));
            assert!(!gate.check_at(&idle, cause, i64::MAX, start + Duration::from_secs(599)));
            assert!(
                gate.check_at(&idle, cause, i64::MAX, start + Duration::from_secs(600)),
                "B may admit only after a full ten-minute observation window"
            );
        }
    }

    #[test]
    fn option_b_observed_activity_restarts_the_entire_window() {
        let (_home, mut gate, mut idle) = setup();
        let start = Instant::now();
        assert!(!gate.check_at(&idle, Cause::Renewal, i64::MAX, start));
        idle.since = Some(1);
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(599)
        ));
        assert!(
            !gate.check_at(
                &idle,
                Cause::Renewal,
                i64::MAX,
                start + Duration::from_secs(600)
            ),
            "a new completed turn must not inherit old quiet time"
        );
        assert!(gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(1199)
        ));
    }

    #[test]
    fn option_b_blockers_restart_quiet_and_expiry_never_shortens_it() {
        for cause in [Cause::Renewal, Cause::Failover] {
            for blocker in ["turn", "hold", "pending", "damaged"] {
                let (_home, mut gate, mut idle) = setup();
                let start = Instant::now();
                assert!(!gate.check_at(&idle, cause, now() - 1, start));
                let path = if blocker == "pending" {
                    gate.directory
                        .join(format!("hook-pending.{}", std::process::id()))
                } else {
                    hold_path(&gate.home, &gate.directory).unwrap()
                };
                match blocker {
                    "turn" => idle.since = None,
                    "hold" => atomic(
                        &path,
                        &Hold {
                            run: "run-gate".into(),
                            reason: "production".into(),
                            owner_pid: std::process::id(),
                            owner_started: process_start(std::process::id()).unwrap(),
                            at: now(),
                            alias: "work".into(),
                        },
                    )
                    .unwrap(),
                    "pending" => atomic(&path, &json!({"pid": std::process::id()})).unwrap(),
                    _ => {
                        private_dir(path.parent().unwrap()).unwrap();
                        std::fs::write(&path, "broken").unwrap();
                    }
                }
                assert!(!gate.check_at(&idle, cause, now() - 1, start + Duration::from_secs(599)));
                if blocker == "turn" {
                    idle.since = Some(0);
                } else {
                    std::fs::remove_file(&path).unwrap();
                }
                assert!(!gate.check_at(&idle, cause, now() - 1, start + Duration::from_secs(600)));
                assert!(!gate.check_at(&idle, cause, now() - 1, start + Duration::from_secs(1199)));
                assert!(
                    gate.check_at(&idle, cause, now() - 1, start + Duration::from_secs(1200)),
                    "{blocker}"
                );
            }
        }
    }

    #[test]
    fn option_b_each_hook_record_resets_quiet_even_with_the_same_idle_timestamp() {
        let (_home, mut gate, mut idle) = setup();
        let start = Instant::now();
        assert!(!gate.check_at(&idle, Cause::Renewal, i64::MAX, start));
        super::super::renew::fold(&mut idle, &[(0, super::super::renew::Event::IdlePrompt)]);
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(599)
        ));
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(600)
        ));
        assert!(gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(1199)
        ));
        idle.session = Some("next-session".into());
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(1200)
        ));
    }

    #[test]
    fn option_b_terminal_activity_resets_quiet_and_unreadable_terminal_blocks() {
        let (_home, mut gate, idle) = setup();
        let terminal = gate.directory.join("synthetic-terminal");
        let file = File::create(&terminal).unwrap();
        file.set_times(
            std::fs::FileTimes::new().set_accessed(std::time::UNIX_EPOCH + Duration::from_secs(1)),
        )
        .unwrap();
        gate = gate.with_terminal(Some(terminal.clone()));
        let start = Instant::now();
        assert!(!gate.check_at(&idle, Cause::Renewal, i64::MAX, start));
        assert!(gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(600)
        ));
        file.set_times(std::fs::FileTimes::new().set_accessed(std::time::SystemTime::now()))
            .unwrap();
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(601)
        ));
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(1201)
        ));
        std::fs::remove_file(terminal).unwrap();
        assert!(!gate.check_at(
            &idle,
            Cause::Renewal,
            i64::MAX,
            start + Duration::from_secs(1801)
        ));
        let status: Value = serde_json::from_slice(
            &private_read(&gate.directory.join("restart-status.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(status["reason"], "evidence_unknown");
    }

    #[test]
    fn option_b_a_failed_hook_blocks_even_after_the_quiet_window() {
        let (_home, mut gate, idle) = setup();
        let start = Instant::now();
        assert!(!gate.check_at(&idle, Cause::Renewal, i64::MAX, start));
        File::create(gate.directory.join("hook-error")).unwrap();
        assert!(
            !gate.check_at(
                &idle,
                Cause::Renewal,
                i64::MAX,
                start + Duration::from_secs(600)
            ),
            "failed hook evidence must not become eligible after ten minutes"
        );
    }

    #[test]
    fn option_b_completed_quiet_retains_expiry_alert_until_the_child_restarts() {
        for cause in [Cause::Renewal, Cause::Failover] {
            let (_home, mut gate, idle) = setup();
            let start = Instant::now();
            assert!(!gate.check_at(&idle, cause, i64::MAX, start));
            assert!(gate.check_at(&idle, cause, i64::MAX, start + Duration::from_secs(600)));
            // A later token read, restart budget or candidate selection may still defer.
            for (remaining, stage) in [(300_000, "warn"), (-1, "blocked")] {
                for _ in 0..2 {
                    assert!(gate.check_at(
                        &idle,
                        cause,
                        now() + remaining,
                        start + Duration::from_secs(601)
                    ));
                }
                let status: Value = serde_json::from_slice(
                    &private_read(&gate.directory.join("restart-status.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(
                    status["stage"], stage,
                    "quiet eligibility must not clear expiry attention"
                );
                assert_eq!(status["attention_required"], true);
            }
            let rows: Vec<Value> = std::fs::read_to_string(
                gate.home.join(".claudectl/server/restart-decisions.jsonl"),
            )
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
            assert_eq!(rows.iter().filter(|row| row["stage"] == "warn").count(), 1);
            assert_eq!(
                rows.iter().filter(|row| row["stage"] == "blocked").count(),
                1
            );
        }
    }

    #[test]
    fn an_idle_hook_only_session_starts_a_new_quiet_window() {
        let (_home, mut gate, idle) = setup();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        let status: Value = serde_json::from_slice(
            &private_read(&gate.directory.join("restart-status.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(status["reason"], "quiet_window");
    }

    #[test]
    fn every_deferred_session_warns_before_expiry_and_stays_blocked_after_it() {
        for cause in [Cause::Renewal, Cause::Failover] {
            let (_home, mut gate, mut idle) = setup();
            for session in ["first", "second"] {
                idle.session = Some(session.into());
                for (remaining, stage) in
                    [(600_000, "deferred"), (300_000, "warn"), (-1, "blocked")]
                {
                    for _ in 0..2 {
                        assert!(!gate.check(&idle, cause, now() + remaining));
                    }
                    let status: Value = serde_json::from_slice(
                        &private_read(&gate.directory.join("restart-status.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(status["session_id"], session);
                    assert_eq!(status["reason"], "quiet_window");
                    assert_eq!(status["stage"], stage);
                    assert_eq!(status["attention_required"], stage != "deferred");
                }
            }
            let rows: Vec<Value> = std::fs::read_to_string(
                gate.home.join(".claudectl/server/restart-decisions.jsonl"),
            )
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
            assert_eq!(rows.len(), 6, "unchanged polls must not count twice");
            for session in ["first", "second"] {
                let alerts: Vec<_> = rows
                    .iter()
                    .filter(|row| row["session_id"] == session && row["stage"] == "warn")
                    .collect();
                assert_eq!(
                    alerts.len(),
                    1,
                    "every deferred session needs its expiry warning"
                );
                assert_eq!(alerts[0]["metric"]["labels"]["stage"], "warn");
                assert_eq!(alerts[0]["metric"]["value"], 1);
            }
        }
    }

    #[test]
    fn workload_changes_update_status_without_recounting_the_same_deferral_stage() {
        let (_home, mut gate, mut idle) = setup();
        for cause in [Cause::Renewal, Cause::Failover] {
            for since in [Some(1), None, Some(2)] {
                idle.since = since;
                assert!(!gate.check(&idle, cause, now() + 600_000));
                let status: Value = serde_json::from_slice(
                    &private_read(&gate.directory.join("restart-status.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(status["restart_deferred_total"], 1);
                assert_eq!(
                    status["reason"],
                    if since.is_some() {
                        "quiet_window"
                    } else {
                        "running_turn"
                    }
                );
            }
        }
        let rows =
            std::fs::read_to_string(gate.home.join(".claudectl/server/restart-decisions.jsonl"))
                .unwrap();
        assert_eq!(rows.lines().count(), 1);
        assert!(!gate.check(&idle, Cause::Failover, now() + 300_000));
        let rows =
            std::fs::read_to_string(gate.home.join(".claudectl/server/restart-decisions.jsonl"))
                .unwrap();
        assert_eq!(
            rows.lines().count(),
            2,
            "warning still creates its own alert"
        );
    }

    #[test]
    fn busy_valid_warn_and_expired_decisions_preserve_work_and_count_once() {
        let (_home, mut gate, mut idle) = setup();
        idle.since = None;
        for expiry in [now() + 600_000, now() + 200_000, now() - 1] {
            assert!(!gate.check(&idle, Cause::Renewal, expiry));
            assert!(!gate.check(&idle, Cause::Renewal, expiry));
        }
        let text =
            std::fs::read_to_string(gate.home.join(".claudectl/server/restart-decisions.jsonl"))
                .unwrap();
        let rows: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["stage"], "deferred");
        assert_eq!(rows[1]["stage"], "warn");
        assert_eq!(rows[2]["stage"], "blocked");
        let status: Value = serde_json::from_slice(
            &private_read(&gate.directory.join("restart-status.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(status["restart_deferred_total"], 3);
    }

    #[test]
    fn a_revoked_token_cannot_override_a_running_turn() {
        let (_home, mut gate, mut idle) = setup();
        idle.since = None;
        idle.auth_failed = Some(now());
        assert!(!gate.check(&idle, Cause::Failover, now() + 600_000));
        let status: Value = serde_json::from_slice(
            &private_read(&gate.directory.join("restart-status.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(status["stage"], "blocked");
        assert_eq!(status["cause"], "failover");
    }

    #[test]
    fn a_stale_hold_survives_and_does_not_hold_another_run() {
        let (_home, mut gate, idle) = setup();
        let path = hold_path(&gate.home, &gate.directory).unwrap();
        atomic(
            &path,
            &Hold {
                run: "run-gate".into(),
                reason: "FLT-553 prod".into(),
                owner_pid: 2_000_000_000,
                owner_started: "gone".into(),
                at: 0,
                alias: "work".into(),
            },
        )
        .unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        assert!(path.exists());
        let other = gate.directory.with_file_name("run-other");
        private_dir(&other).unwrap();
        let mut other_gate = Gate::new(&gate.home, &other, gate.pid, "work");
        assert_eq!(hold_reason(&gate.home, &other).unwrap(), None);
        assert!(!other_gate.check(&idle, Cause::Renewal, now() + 600_000));
    }

    #[test]
    fn unreadable_hold_evidence_defers_instead_of_authorizing_a_restart() {
        let (_home, mut gate, idle) = setup();
        let path = hold_path(&gate.home, &gate.directory).unwrap();
        private_dir(path.parent().unwrap()).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
    }

    #[test]
    fn a_marker_only_production_step_defers_until_matching_done() {
        let texts = [
            "- w28:t1 [starting] FLT-553 migration\n".to_string(),
            "- w28:t1 [done] FLT-553 migration\n".to_string(),
        ];
        assert!(production_markers("w28:t1", &texts[..1]));
        assert!(!production_markers("w28:t1", &[texts.concat()]));

        let repeated = vec![
            "- w28:t1 [done] FLT-553 migration\n".to_string(),
            "- w28:t1 [starting] FLT-553 migration\n".to_string(),
        ];
        assert!(production_markers("w28:t1", &repeated));

        let other_lane = vec!["- w28:t10 [starting] FLT-553 migration\n".to_string()];
        assert!(!production_markers("w28:t1", &other_lane));
    }

    #[test]
    fn a_queued_hook_defers_restart_admission() {
        let (_home, mut gate, idle) = setup();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        let pending = gate
            .directory
            .join(format!("hook-pending.{}", std::process::id()));
        atomic(&pending, &json!({"pid": std::process::id()})).unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        let status: Value = serde_json::from_slice(
            &private_read(&gate.directory.join("restart-status.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(status["reason"], "queued_hook");
    }

    #[test]
    fn a_stale_hook_marker_is_removed_but_quiet_starts_fresh() {
        let (_home, mut gate, idle) = setup();
        let mut stale = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let pid = stale.id();
        stale.kill().unwrap();
        stale.wait().unwrap();
        let pending = gate.directory.join(format!("hook-pending.{pid}"));
        atomic(&pending, &json!({"pid": pid})).unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        assert!(!pending.exists());
    }

    #[test]
    fn unreadable_marker_sources_fail_closed() {
        let missing = PathBuf::from("/definitely/missing/FLT-553-goal.md");
        assert!(production_markers_from_paths("w28:t1", &[missing]).is_err());
    }

    #[test]
    fn configured_unusable_lane_ids_leave_production_evidence_unknown() {
        use std::os::unix::ffi::OsStringExt;
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::fs::write(
            folder.join("agents-cases-outbox.md"),
            "w28:p1 [starting] FLT-553 migration\n",
        )
        .unwrap();
        let mut cases: Vec<(Option<std::ffi::OsString>, Option<std::ffi::OsString>)> = vec![
            (Some("".into()), None),
            (Some(" ".into()), Some("\t".into())),
            (Some("invalid lane".into()), Some("invalid pane".into())),
            (Some("?".into()), None),
            (Some("w28:p1,".into()), None),
        ];
        cases.push((Some(std::ffi::OsString::from_vec(vec![0xff])), None));
        for (tab, pane) in cases {
            assert!(
                ProductionEvidence::default()
                    .for_environment(home.path(), None, tab, pane)
                    .is_err(),
                "supplied unusable IDs must not be mistaken for a standalone session"
            );
        }
    }

    #[test]
    fn usable_tab_precedence_pane_fallback_and_standalone_behavior_are_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::fs::write(
            folder.join("agents-cases-outbox.md"),
            "w28:p1 [starting] FLT-553 migration\n",
        )
        .unwrap();
        for (tab, pane, open) in [
            (Some("w28:p1"), Some("w28:p2"), true),
            (Some("w28:p2"), Some("w28:p1"), false),
            (Some(" w28:p1 "), Some("w28:p2"), true),
            (None, Some("w28:p1"), true),
            (None, None, false),
        ] {
            assert_eq!(
                ProductionEvidence::default()
                    .for_environment(home.path(), None, tab.map(Into::into), pane.map(Into::into))
                    .unwrap(),
                open
            );
        }
        assert!(
            ProductionEvidence::default()
                .for_environment(
                    home.path(),
                    None,
                    Some(std::ffi::OsString::from_vec(vec![0xff])),
                    Some("w28:p1".into())
                )
                .unwrap()
        );
        let goal = home.path().join("goal.md");
        std::fs::write(&goal, "w28:p1 [starting] FLT-553 migration\n").unwrap();
        assert!(
            ProductionEvidence::default()
                .for_environment(home.path(), Some(goal), None, None)
                .is_err()
        );
    }

    #[test]
    fn blank_tab_uses_the_pane_identity_to_keep_production_steps_open() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::fs::write(
            folder.join("agents-cases-outbox.md"),
            "w28:p1 [starting] FLT-553 migration\n",
        )
        .unwrap();
        for tab in ["", " ", "\t", "invalid lane"] {
            let mut evidence = ProductionEvidence::default();
            assert!(
                evidence
                    .for_environment(home.path(), None, Some(tab.into()), Some("w28:p1".into()))
                    .unwrap(),
                "unusable tab {tab:?} must not hide the pane's open production step"
            );
        }
    }

    #[test]
    fn malformed_lane_alphabet_cannot_hide_a_valid_panes_production_step() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::fs::write(
            folder.join("agents-cases-outbox.md"),
            "w28:p1 [starting] FLT-553 migration\n",
        )
        .unwrap();
        // Include every ASCII byte, plus non-ASCII letters, punctuation and format characters.
        for c in (0..=127)
            .map(char::from)
            .chain(['é', '中', '，', '\u{200b}', '\u{a0}'])
        {
            if "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:_-./".contains(c) {
                continue;
            }
            let malformed = format!("w28:p1{c}junk");
            assert!(
                ProductionEvidence::default()
                    .for_environment(
                        home.path(),
                        None,
                        Some(malformed.clone().into()),
                        Some("w28:p1".into())
                    )
                    .unwrap(),
                "malformed TAB {malformed:?} must fall back to the protected PANE"
            );
        }
    }

    #[test]
    fn malformed_lane_alphabet_without_usable_fallback_remains_unknown() {
        let home = tempfile::tempdir().unwrap();
        for c in (0..=127)
            .map(char::from)
            .chain(['é', '中', '，', '\u{200b}', '\u{a0}'])
        {
            if "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:_-./".contains(c) {
                continue;
            }
            let malformed = format!("w28:p1{c}junk");
            for (tab, pane) in [
                (Some(malformed.clone().into()), None),
                (None, Some(malformed.clone().into())),
                (
                    Some(malformed.clone().into()),
                    Some(malformed.clone().into()),
                ),
            ] {
                assert!(
                    ProductionEvidence::default()
                        .for_environment(home.path(), None, tab, pane)
                        .is_err(),
                    "malformed identity {malformed:?} without fallback must remain unknown"
                );
            }
        }
    }

    #[test]
    fn supported_lane_alphabet_and_legacy_and_current_forms_keep_marker_protection() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        for lane in [
            "w28:t1",
            "w28:p1",
            "t1v",
            "amir-dev/t1v",
            "host.example/t1v",
            "wABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:tab_ID-2/child.3",
        ] {
            std::fs::write(
                folder.join("agents-cases-outbox.md"),
                format!("{lane} [starting] FLT-553 migration\n"),
            )
            .unwrap();
            for (tab, pane, open) in [
                (Some(lane.to_owned()), Some("other".to_owned()), true),
                (Some(format!(" {lane} ")), None, true),
                (None, Some(lane.to_owned()), true),
                (Some("other".to_owned()), Some(lane.to_owned()), false),
                (None, None, false),
            ] {
                assert_eq!(
                    ProductionEvidence::default()
                        .for_environment(
                            home.path(),
                            None,
                            tab.map(Into::into),
                            pane.map(Into::into)
                        )
                        .unwrap(),
                    open,
                    "lane {lane:?}"
                );
            }
        }
    }

    #[test]
    fn completing_one_step_cannot_clear_another_step_with_the_same_first_word() {
        let home = tempfile::tempdir().unwrap();
        let goal = home.path().join("goal.md");
        let starting = concat!(
            "w28:t1 [starting] FLT-553 migration account-a\n",
            "w28:t1 [starting] FLT-553 migration account-b\n"
        );
        std::fs::write(&goal, starting).unwrap();
        let mut evidence = ProductionEvidence::default();
        assert!(
            evidence
                .for_lane(home.path(), Some(goal.clone()), Some("w28:t1".into()))
                .unwrap()
        );
        let one_done = format!("{starting}w28:t1 [done] FLT-553 migration account-a\n");
        std::fs::write(&goal, &one_done).unwrap();
        assert!(
            evidence
                .for_lane(home.path(), Some(goal.clone()), Some("w28:t1".into()))
                .unwrap(),
            "account-b must remain open after completing account-a"
        );
        std::fs::write(
            &goal,
            format!("{one_done}w28:t1 [done] FLT-553 migration account-b\n"),
        )
        .unwrap();
        assert!(
            !evidence
                .for_lane(home.path(), Some(goal), Some("w28:t1".into()))
                .unwrap()
        );
    }

    #[test]
    fn rewritten_open_marker_history_stays_unknown_across_repeated_samples() {
        for replacement in ["", "w28:t1 [done] FLT-553 migration\n"] {
            let home = tempfile::tempdir().unwrap();
            let folder = home.path().join("Code/.fleet/voice-between");
            private_dir(&folder).unwrap();
            let outbox = folder.join("agents-cases-outbox.md");
            let starting = "w28:t1 [starting] FLT-553 migration\n";
            std::fs::write(&outbox, starting).unwrap();
            let mut evidence = ProductionEvidence::default();
            assert!(
                evidence
                    .for_lane(home.path(), None, Some("w28:t1".into()))
                    .unwrap()
            );
            std::fs::write(&outbox, replacement).unwrap();
            for _ in 0..2 {
                assert!(
                    evidence
                        .for_lane(home.path(), None, Some("w28:t1".into()))
                        .is_err(),
                    "rewrites must not replace the trusted open checkpoint"
                );
            }
            std::fs::write(
                &outbox,
                format!("{starting}w28:t1 [done] FLT-553 migration\n"),
            )
            .unwrap();
            assert!(
                !evidence
                    .for_lane(home.path(), None, Some("w28:t1".into()))
                    .unwrap()
            );
        }
    }

    #[test]
    fn an_observed_unreadable_outbox_cannot_become_optional_by_disappearing() {
        let home = tempfile::tempdir().unwrap();
        let outbox = home
            .path()
            .join("Code/.fleet/voice-between/agents-cases-outbox.md");
        private_dir(&outbox).unwrap(); // A directory cannot be read as marker text.
        let mut evidence = ProductionEvidence::default();
        assert!(
            evidence
                .for_lane(home.path(), None, Some("w28:t1".into()))
                .is_err()
        );
        std::fs::remove_dir(&outbox).unwrap();
        assert!(
            evidence
                .for_lane(home.path(), None, Some("w28:t1".into()))
                .is_err()
        );
        std::fs::write(&outbox, "").unwrap();
        assert!(
            !evidence
                .for_lane(home.path(), None, Some("w28:t1".into()))
                .unwrap()
        );
    }

    #[test]
    fn known_outbox_loss_keeps_production_evidence_unknown_until_history_is_restored() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        let outbox = folder.join("agents-cases-outbox.md");
        let starting = "w28:t1 [starting] FLT-553 migration\n";
        std::fs::write(&outbox, starting).unwrap();
        let mut evidence = ProductionEvidence::default();
        assert!(
            evidence
                .for_lane(home.path(), None, Some("w28:t1".into()))
                .unwrap()
        );
        std::fs::remove_file(&outbox).unwrap();
        for _ in 0..2 {
            assert!(
                evidence
                    .for_lane(home.path(), None, Some("w28:t1".into()))
                    .is_err(),
                "losing an observed source cannot close its production step"
            );
        }
        std::fs::write(
            &outbox,
            format!("{starting}w28:t1 [done] FLT-553 migration\n"),
        )
        .unwrap();
        assert!(
            !evidence
                .for_lane(home.path(), None, Some("w28:t1".into()))
                .unwrap(),
            "restoring history with an appended matching DONE permits recovery"
        );
    }

    #[test]
    fn historical_done_in_another_source_does_not_clear_a_current_step() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::fs::write(
            folder.join("slack-outbox.md"),
            "2026-11-06T23:00Z w28:t1 [done] FLT-553 migration\n",
        )
        .unwrap();
        let goal = home.path().join("goal.md");
        let starting = "2026-11-07T01:20Z w28:t1 [starting] FLT-553 migration\n";
        std::fs::write(&goal, starting).unwrap();
        assert!(
            production_step_with_lane(home.path(), Some(goal.clone()), Some("w28:t1".into()))
                .unwrap(),
            "an old DONE elsewhere cannot clear this source's newer START"
        );
        std::fs::write(
            &goal,
            format!("{starting}w28:t1 [done] FLT-553 migration\n"),
        )
        .unwrap();
        assert!(
            !production_step_with_lane(home.path(), Some(goal), Some("w28:t1".into())).unwrap(),
            "completion in the same source must retain idle recovery"
        );
    }

    #[test]
    fn unreadable_outbox_discovery_cannot_clear_production_evidence() {
        let home = tempfile::tempdir().unwrap();
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::fs::write(
            folder.join("agents-cases-outbox.md"),
            "w28:t1 [starting] FLT-553 migration\n",
        )
        .unwrap();
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o000)).unwrap();
        let lane = production_step_with_lane(home.path(), None, Some("w28:t1".into()));
        let standalone = production_step_with_lane(home.path(), None, None);
        std::fs::set_permissions(&folder, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            lane.is_err(),
            "an unreadable outbox must leave evidence unknown"
        );
        assert!(
            !standalone.unwrap(),
            "standalone sessions do not consume lane outboxes"
        );
    }

    #[test]
    fn an_absent_outbox_is_optional_but_a_broken_source_is_not_clear() {
        let home = tempfile::tempdir().unwrap();
        assert!(!production_step_with_lane(home.path(), None, Some("w28:t1".into())).unwrap());
        let folder = home.path().join("Code/.fleet/voice-between");
        private_dir(&folder).unwrap();
        std::os::unix::fs::symlink(
            folder.join("missing-target"),
            folder.join("agents-cases-outbox.md"),
        )
        .unwrap();
        assert!(
            production_step_with_lane(home.path(), None, Some("w28:t1".into())).is_err(),
            "an existing broken source must leave evidence unknown"
        );
    }

    #[test]
    fn outbox_markers_are_considered_without_a_goal_file() {
        let home = tempfile::tempdir().unwrap();
        let outbox = home
            .path()
            .join("Code/.fleet/voice-between/agents-cases-outbox.md");
        std::fs::create_dir_all(outbox.parent().unwrap()).unwrap();
        std::fs::write(&outbox, "- w28:t1 [starting] FLT-553 migration\n").unwrap();
        assert!(production_step_with_lane(home.path(), None, Some("w28:t1".into())).unwrap());
        assert!(production_markers_from_paths("w28:t1", &[outbox]).unwrap());
    }

    #[test]
    fn outboxes_without_a_lane_do_not_block_standalone_sessions() {
        let home = tempfile::tempdir().unwrap();
        let outbox = home
            .path()
            .join("Code/.fleet/voice-between/agents-cases-outbox.md");
        std::fs::create_dir_all(outbox.parent().unwrap()).unwrap();
        std::fs::write(&outbox, "- w28:t1 [starting] FLT-553 migration\n").unwrap();
        assert!(!production_step_with_lane(home.path(), None, None).unwrap());
        assert!(production_step_with_lane(home.path(), None, Some("w28:t1".into())).unwrap());
    }

    #[test]
    fn failed_logging_keeps_admission_closed_without_recounting() {
        let (_home, mut gate, mut idle) = setup();
        idle.since = None;
        std::fs::create_dir(gate.home.join(".claudectl/server/restart-decisions.jsonl")).unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        idle.since = Some(0);
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        assert_eq!(gate.total, 0);
    }

    #[test]
    fn failed_logging_retries_only_status_after_storage_recovers() {
        let (_home, mut gate, mut idle) = setup();
        idle.since = None;
        std::fs::create_dir(gate.home.join(".claudectl/server/restart-decisions.jsonl")).unwrap();
        let status = gate.directory.join("restart-status.json");
        std::fs::create_dir(&status).unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        std::fs::remove_dir(&status).unwrap();
        assert!(!gate.check(&idle, Cause::Renewal, now() + 600_000));
        let value: Value = serde_json::from_slice(&private_read(&status).unwrap()).unwrap();
        assert_eq!(value["reason"], "evidence_unknown");
        assert_eq!(value["stage"], "blocked");
        assert_eq!(gate.total, 0);
    }

    #[test]
    fn task_file_descriptor_names_exclude_helpers_and_include_unlinked_logs() {
        let uid = unsafe { libc::geteuid() };
        let root = std::env::temp_dir().canonicalize().unwrap();
        let path = root.join(format!("claude-{uid}/project/tasks/monitor.output"));
        assert!(is_task_output(&path));
        assert!(is_task_output(Path::new(&format!(
            "{} (deleted)",
            path.display()
        ))));
        assert!(!is_task_output(Path::new("pipe:[123]")));
        assert!(!is_task_output(Path::new("/dev/null")));
        assert!(!is_task_output(
            &root.join("unrelated/tasks/monitor.output")
        ));
        assert!(!is_task_output(
            &root.join(format!("claude-{uid}/project/tasks/monitor.txt"))
        ));
    }

    #[test]
    fn native_descriptor_reader_distinguishes_tasks_from_mcp_stdio() {
        let uid = unsafe { libc::geteuid() };
        let root = std::env::temp_dir().join(format!("claude-{uid}"));
        std::fs::create_dir_all(&root).unwrap();
        let scratch = tempfile::Builder::new()
            .prefix("flt553-")
            .tempdir_in(root)
            .unwrap();
        let tasks = scratch.path().join("tasks");
        std::fs::create_dir(&tasks).unwrap();
        let file = File::create(tasks.join("fixture.output")).unwrap();
        let mut child = Command::new("/bin/sleep")
            .arg("10")
            .stdout(file)
            .spawn()
            .unwrap();
        let task = task_descriptors(&[child.id()]);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(task.unwrap());
        let mut helper = Command::new("/bin/sleep")
            .arg("10")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let task = task_descriptors(&[helper.id()]);
        helper.kill().unwrap();
        helper.wait().unwrap();
        assert!(!task.unwrap());
    }
}
