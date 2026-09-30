//! Run one child process on one saved profile without touching the live login.
//!
//! The child receives the saved access token through an inherited pipe named by
//! `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`, and a fresh private
//! `CLAUDE_CONFIG_DIR`. The live Keychain entry, `~/.claude.json`,
//! `~/.claude/.credentials.json` and the active marker are never written.
//!
//! Refresh ownership: this module never refreshes a token. It refuses the
//! active profile and any saved grant that the live login shares, and it
//! refuses a token that expires before `min_valid` runs out.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::api;
use crate::auth_store::AuthStore;
use crate::config::Paths;
use crate::profile;

pub const TOKEN_FD_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR";
pub const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";

/// Credential sources the child must not inherit, so the saved profile is the
/// only login it can use.
const SCRUBBED_ENV: &[&str] = &[
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
    "CLAUDE_CODE_OAUTH_SCOPES",
    "CLAUDE_CODE_HOST_CREDS_FILE",
    "CCR_OAUTH_TOKEN_FILE",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
];

pub struct ExecRequest {
    pub alias: String,
    pub expect_account: Option<String>,
    pub expect_sha256: Option<String>,
    pub min_valid: Duration,
    pub receipt: Option<PathBuf>,
    pub program: OsString,
    pub args: Vec<OsString>,
}

/// Account lookup for the identity check. Production uses the OAuth profile
/// endpoint; tests supply a fake through the library API only.
pub trait IdentitySource {
    fn account_uuid(&self, access_token: &str) -> anyhow::Result<Option<String>>;
}

pub struct LiveIdentity;

impl IdentitySource for LiveIdentity {
    fn account_uuid(&self, access_token: &str) -> anyhow::Result<Option<String>> {
        Ok(api::fetch_oauth_account(access_token)?.and_then(|account| {
            account
                .get("accountUuid")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        }))
    }
}

#[derive(Debug)]
pub enum ExecError {
    /// Policy refusal: active alias, shared grant, short lifetime, bad profile.
    Refused(String),
    /// Identity missing or mismatched.
    Identity(String),
    /// Executable or claudectl pin failed.
    Pin(String),
    /// A receipt record could not be written.
    Receipt(String),
    /// The child could not be started.
    Spawn(String),
    /// The child ran, but its private config directory could not be removed.
    Cleanup(String),
}

impl ExecError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ExecError::Identity(_) => 3,
            ExecError::Pin(_) => 4,
            ExecError::Refused(_) => 5,
            ExecError::Receipt(_) => 6,
            ExecError::Spawn(_) => 7,
            ExecError::Cleanup(_) => 8,
        }
    }
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Refused(m) => write!(f, "refused: {m}"),
            ExecError::Identity(m) => write!(f, "identity check failed: {m}"),
            ExecError::Pin(m) => write!(f, "executable pin failed: {m}"),
            ExecError::Receipt(m) => write!(f, "receipt write failed: {m}"),
            ExecError::Spawn(m) => write!(f, "could not start child: {m}"),
            ExecError::Cleanup(m) => write!(f, "cleanup failed: {m}"),
        }
    }
}

/// A validated run. Holds the token only in memory; `Debug` is not derived so
/// the token cannot reach a log through formatting.
pub struct Prepared {
    alias: String,
    account_uuid: String,
    email: Option<String>,
    token: String,
    token_expires_at_ms: i64,
    program: PathBuf,
    program_sha256: String,
    claudectl: SelfIdentity,
}

#[derive(Clone)]
pub struct SelfIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

impl SelfIdentity {
    pub fn current() -> Result<Self, ExecError> {
        let path = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map_err(|e| ExecError::Pin(format!("cannot resolve claudectl path: {e}")))?;
        let sha256 = sha256_file(&path)?;
        Ok(Self {
            path,
            sha256,
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }
}

/// Validate everything before any child exists. `run` repeats the ownership
/// and lifetime checks under the auth lock right before the spawn.
pub fn prepare(
    paths: &Paths,
    store: &AuthStore,
    req: &ExecRequest,
    identity: &dyn IdentitySource,
    claudectl: SelfIdentity,
) -> Result<Prepared, ExecError> {
    let alias = profile::validate_alias(&req.alias)
        .map_err(|e| ExecError::Refused(format!("{e:#}")))?
        .to_string();
    let saved = profile::get_profile_from(paths, &alias)
        .map_err(|e| ExecError::Refused(format!("{e:#}")))?;

    let creds = {
        let _lock = lock_with_retry(store)?;
        check_ownership(paths, store, &alias, None, req.min_valid)?
    };
    let oauth = &creds.claude_ai_oauth;
    let expires_at_ms = oauth.expires_at.unwrap_or_default();

    let saved_uuid = saved
        .meta
        .account_uuid()
        .map(str::to_string)
        .ok_or_else(|| {
            ExecError::Identity(format!(
                "'{alias}' has no saved accountUuid; run `claudectl login {alias}` again"
            ))
        })?;
    if let Some(expected) = &req.expect_account
        && expected != &saved_uuid
    {
        return Err(ExecError::Identity(format!(
            "'{alias}' is account {saved_uuid}, expected {expected}"
        )));
    }
    let token_uuid = identity
        .account_uuid(&oauth.access_token)
        .map_err(|e| ExecError::Identity(format!("account lookup failed: {e:#}")))?
        .ok_or_else(|| ExecError::Identity("account lookup returned no account".into()))?;
    if token_uuid != saved_uuid {
        return Err(ExecError::Identity(format!(
            "'{alias}' token belongs to account {token_uuid}, profile says {saved_uuid}"
        )));
    }

    let program = resolve_program(&req.program)?;
    let program_sha256 = sha256_file(&program)?;
    if let Some(expected) = &req.expect_sha256
        && !expected.eq_ignore_ascii_case(&program_sha256)
    {
        return Err(ExecError::Pin(format!(
            "{} has sha256 {program_sha256}, expected {expected}",
            program.display()
        )));
    }

    Ok(Prepared {
        alias,
        account_uuid: saved_uuid,
        email: saved.meta.email().map(str::to_string),
        token: oauth.access_token.clone(),
        token_expires_at_ms: expires_at_ms,
        program,
        program_sha256,
        claudectl,
    })
}

/// Decide refresh ownership and lifetime. The caller holds the auth lock.
/// With `expected = (token, account_uuid)`, the saved token and the saved
/// account identity must still be the ones `prepare` verified.
fn check_ownership(
    paths: &Paths,
    store: &AuthStore,
    alias: &str,
    expected: Option<(&str, &str)>,
    min_valid: Duration,
) -> Result<crate::api::CredentialsFile, ExecError> {
    let active = profile::get_active_from(paths)
        .map_err(|e| ExecError::Refused(format!("cannot read active profile: {e:#}")))?;
    if active.as_deref() == Some(alias) {
        return Err(ExecError::Refused(format!(
            "'{alias}' is the active profile; Claude Code owns its login, run plain claude instead"
        )));
    }
    let saved = profile::get_profile_from(paths, alias)
        .map_err(|e| ExecError::Refused(format!("{e:#}")))?;
    let creds = saved
        .read_credentials()
        .map_err(|e| ExecError::Refused(format!("saved credentials unreadable: {e:#}")))?;
    let live = store
        .read_refresh_owner()
        .map_err(|e| ExecError::Refused(format!("live refresh ownership unknown: {e:#}")))?;
    let oauth = &creds.claude_ai_oauth;
    if oauth.access_token.trim().is_empty() {
        return Err(ExecError::Refused(format!(
            "'{alias}' has no access token; log in again"
        )));
    }
    if let Some((token, account)) = expected {
        if oauth.access_token != token {
            return Err(ExecError::Refused(format!(
                "'{alias}' credentials changed during preparation; run again"
            )));
        }
        if saved.meta.account_uuid() != Some(account) {
            return Err(ExecError::Identity(format!(
                "'{alias}' saved account identity changed during preparation; run again"
            )));
        }
    }
    if let Some(live) = live {
        let live = &live.claude_ai_oauth;
        let same_refresh =
            oauth.refresh_token.is_some() && oauth.refresh_token == live.refresh_token;
        let same_access = oauth.access_token == live.access_token;
        if same_refresh || same_access {
            return Err(ExecError::Refused(format!(
                "'{alias}' shares its grant with the live login; Claude Code owns that refresh"
            )));
        }
    }
    let expires_at_ms = oauth
        .expires_at
        .ok_or_else(|| ExecError::Refused(format!("'{alias}' has no token expiry")))?;
    let remaining_ms = expires_at_ms - chrono::Utc::now().timestamp_millis();
    let needed_ms = i64::try_from(min_valid.as_millis()).unwrap_or(i64::MAX);
    if remaining_ms <= 0 {
        return Err(ExecError::Refused(format!(
            "'{alias}' token has expired; run `claudectl status {alias}` to refresh it"
        )));
    }
    if remaining_ms < needed_ms {
        return Err(ExecError::Refused(format!(
            "'{alias}' token is valid for {} min, {} min required. claudectl refreshes a saved token only after it expires: retry after that and run `claudectl status {alias}`. `claudectl login {alias}` also gives a fresh token, but it makes '{alias}' the active profile, so switch back with `claudectl use <previous>` before running exec",
            remaining_ms / 60_000,
            needed_ms / 60_000
        )));
    }
    Ok(creds)
}

/// Start the child and wait for it. Returns the exit code to propagate.
/// A receipt failure before the spawn starts no child; after the spawn it
/// stops the child and fails.
pub fn run(
    paths: &Paths,
    store: &AuthStore,
    prepared: Prepared,
    req: &ExecRequest,
) -> Result<i32, ExecError> {
    let receipt = Receipt::open(req.receipt.as_deref())?;
    run_with_receipt(paths, store, prepared, req, receipt)
}

/// Like `run`, but writes receipt records to `sink`. For tests that need a
/// receipt sink which fails.
#[doc(hidden)]
pub fn run_with_writer(
    paths: &Paths,
    store: &AuthStore,
    prepared: Prepared,
    req: &ExecRequest,
    sink: Box<dyn Write>,
) -> Result<i32, ExecError> {
    run_with_receipt(paths, store, prepared, req, Receipt::from_writer(sink))
}

/// The descriptor number the child reads the token from.
pub const CHILD_TOKEN_FD: i32 = 3;

fn run_with_receipt(
    paths: &Paths,
    store: &AuthStore,
    prepared: Prepared,
    req: &ExecRequest,
    mut receipt: Receipt,
) -> Result<i32, ExecError> {
    let config_dir = fresh_config_dir(paths, &prepared.alias)?;
    let dir_path = config_dir.path().to_path_buf();
    let mut base = receipt_base(&prepared, &dir_path, req);
    let outcome = run_in_dir(
        paths,
        store,
        &prepared,
        req,
        &mut receipt,
        &dir_path,
        &mut base,
    );
    // Remove the private directory on every path, and never hide a removal
    // failure behind another error.
    match config_dir.close() {
        Ok(()) => outcome,
        Err(error) => {
            let earlier = match &outcome {
                Ok(code) => format!("child exited with {code}"),
                Err(e) => e.to_string(),
            };
            let message = format!("{earlier}; removing {} failed: {error}", dir_path.display());
            let _ = receipt.write(&with(
                &base,
                "cleanup_failed",
                serde_json::json!({ "error": error.to_string(), "earlier": earlier }),
            ));
            Err(ExecError::Cleanup(message))
        }
    }
}

fn run_in_dir(
    paths: &Paths,
    store: &AuthStore,
    prepared: &Prepared,
    req: &ExecRequest,
    receipt: &mut Receipt,
    config_dir: &Path,
    base: &mut serde_json::Value,
) -> Result<i32, ExecError> {
    // Execute a private copy, so the bytes that run are the bytes that were
    // hashed, even if the original path is replaced during the run.
    let snapshot = snapshot_executable(&prepared.program, config_dir)?;
    let snapshot_sha256 = sha256_file(&snapshot)?;
    if snapshot_sha256 != prepared.program_sha256 {
        return Err(ExecError::Pin(format!(
            "{} changed after it was verified",
            prepared.program.display()
        )));
    }
    // The parent keeps FD_CLOEXEC on the pipe, so no other child can inherit
    // it; only this child's pre-exec step maps it to CHILD_TOKEN_FD.
    let (reader, mut writer) =
        std::io::pipe().map_err(|e| ExecError::Spawn(format!("cannot create token pipe: {e}")))?;
    writer
        .write_all(prepared.token.as_bytes())
        .map_err(|e| ExecError::Spawn(format!("cannot write token pipe: {e}")))?;
    drop(writer);

    base["executed_snapshot"] = serde_json::json!(snapshot);
    receipt.write(&with(base, "prepared", serde_json::json!({})))?;

    let mut command = Command::new(&snapshot);
    command.args(&req.args);
    set_arg0(&mut command, &prepared.program);
    for name in SCRUBBED_ENV {
        command.env_remove(name);
    }
    command.env(CONFIG_DIR_ENV, config_dir);
    command.env(TOKEN_FD_ENV, CHILD_TOKEN_FD.to_string());
    map_token_fd(&mut command, &reader);

    // The child gets its own process group, so cancellation and teardown
    // reach its descendants and every signal reaches it exactly once, through
    // claudectl. `exec` is for non-interactive runs; a child in a background
    // group that reads the terminal is stopped by the terminal driver.
    set_process_group(&mut command);

    signals::install();
    let spawned = {
        // Hold the lock from the final ownership check through the spawn, so
        // no `use` can make this grant live in between.
        let lock = lock_with_retry(store);
        let checked = lock.and_then(|_lock| {
            check_ownership(
                paths,
                store,
                &prepared.alias,
                Some((&prepared.token, &prepared.account_uuid)),
                req.min_valid,
            )?;
            if signals::pending() {
                return Err(ExecError::Spawn(
                    "cancelled before the child started".into(),
                ));
            }
            Ok(command.spawn())
        });
        match checked {
            Ok(spawned) => spawned,
            Err(error) => {
                signals::reset();
                receipt.write(&with(
                    base,
                    "refused",
                    serde_json::json!({ "error": error.to_string() }),
                ))?;
                return Err(error);
            }
        }
    };
    drop(reader);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            signals::reset();
            receipt
                .write(&with(
                    base,
                    "spawn_failed",
                    serde_json::json!({ "error": error.to_string() }),
                ))
                .map_err(|receipt_error| {
                    ExecError::Receipt(format!("{receipt_error} (after spawn failure: {error})"))
                })?;
            return Err(ExecError::Spawn(error.to_string()));
        }
    };
    let pid = child.id();
    signals::watch(pid);
    // A signal that arrived between the final check and `watch` was not
    // forwarded; deliver it now. The child did start, so its PID and outcome
    // are still recorded below.
    let cancelled = signals::pending();
    if cancelled {
        terminate(pid, SIGTERM);
    }
    let started = receipt.write(&with(
        base,
        "started",
        serde_json::json!({ "pid": pid, "cancelled_at_start": cancelled }),
    ));
    if started.is_err() {
        terminate(pid, SIGKILL);
    }
    // Wait for the exit without reaping. While the child is an unreaped
    // zombie its PID stays reserved, so every signal to its process group,
    // through the final SIGKILL, can only reach this run's processes.
    let waited = wait_exit_no_reap(pid);
    let descendants = if waited.is_ok() {
        teardown_group(pid)
    } else {
        Descendants::Unknown
    };
    let status = child.wait();
    signals::reset();
    waited.map_err(|e| ExecError::Spawn(format!("cannot wait for child {pid}: {e}")))?;
    let status = status.map_err(|e| ExecError::Spawn(format!("cannot reap child {pid}: {e}")))?;
    let code = exit_code_of(&status);
    let exited = receipt.write(&with(
        base,
        "exited",
        serde_json::json!({
            "pid": pid,
            "exit_code": status.code(),
            "signal": signal_of(&status),
            "descendants": descendants.as_str(),
        }),
    ));
    started?;
    exited?;
    if matches!(descendants, Descendants::Survived | Descendants::Unknown) {
        return Err(ExecError::Cleanup(format!(
            "child {pid} exited with {code}, but its descendants survived SIGKILL"
        )));
    }
    Ok(code)
}

enum Descendants {
    None,
    Terminated,
    Killed,
    Survived,
    Unknown,
}

impl Descendants {
    fn as_str(&self) -> &'static str {
        match self {
            Descendants::None => "none",
            Descendants::Terminated => "terminated",
            Descendants::Killed => "killed",
            Descendants::Survived => "survived",
            Descendants::Unknown => "unknown",
        }
    }
}

/// Bounded TERM-to-KILL teardown of the child's process group. The caller
/// keeps the leader unreaped for the whole call.
fn teardown_group(leader: u32) -> Descendants {
    let Ok(members) = descendants_in_group(leader) else {
        return Descendants::Unknown;
    };
    if members.is_empty() {
        return Descendants::None;
    }
    terminate(leader, SIGTERM);
    if wait_descendants_gone(leader, Duration::from_secs(2)) {
        return Descendants::Terminated;
    }
    terminate(leader, SIGKILL);
    if wait_descendants_gone(leader, Duration::from_secs(2)) {
        Descendants::Killed
    } else {
        Descendants::Survived
    }
}

fn wait_descendants_gone(leader: u32, limit: Duration) -> bool {
    let started = std::time::Instant::now();
    loop {
        match descendants_in_group(leader) {
            Ok(members) if members.is_empty() => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        if started.elapsed() >= limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Live processes in the group led by `leader`, excluding the leader itself
/// (an unreaped zombie at this point).
#[cfg(target_os = "macos")]
fn descendants_in_group(leader: u32) -> std::io::Result<Vec<i32>> {
    // From <sys/proc_info.h>.
    const PROC_PGRP_ONLY: u32 = 2;
    let mut pids = vec![0i32; 4096];
    let size = i32::try_from(pids.len() * std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
    // SAFETY: the buffer is valid for `size` bytes.
    let bytes =
        unsafe { libc::proc_listpids(PROC_PGRP_ONLY, leader, pids.as_mut_ptr().cast(), size) };
    if bytes < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let count = usize::try_from(bytes).unwrap_or(0) / std::mem::size_of::<i32>();
    let leader = i32::try_from(leader).unwrap_or(0);
    Ok(pids[..count]
        .iter()
        .copied()
        .filter(|&pid| pid > 0 && pid != leader)
        .collect())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn descendants_in_group(leader: u32) -> std::io::Result<Vec<i32>> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if u32::try_from(pid).ok() == Some(leader) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // Fields after the ")" of the command name: state ppid pgrp ...
        let Some(rest) = stat.rsplit_once(')').map(|(_, rest)| rest) else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() > 2 && fields[0] != "Z" && fields[2].parse::<u32>().ok() == Some(leader) {
            members.push(pid);
        }
    }
    Ok(members)
}

#[cfg(not(unix))]
fn descendants_in_group(_leader: u32) -> std::io::Result<Vec<i32>> {
    Ok(Vec::new())
}

#[cfg(unix)]
fn wait_exit_no_reap(pid: u32) -> std::io::Result<()> {
    loop {
        // SAFETY: waitid writes only into `info`; WNOWAIT leaves the child
        // reapable by Child::wait.
        let result = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(not(unix))]
fn wait_exit_no_reap(_pid: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
const SIGTERM: i32 = libc::SIGTERM;
#[cfg(unix)]
const SIGKILL: i32 = libc::SIGKILL;
#[cfg(not(unix))]
const SIGTERM: i32 = 15;
#[cfg(not(unix))]
const SIGKILL: i32 = 9;

/// Signal the child's whole process group. Returns whether any process
/// received the signal.
#[cfg(unix)]
fn terminate(leader: u32, signal: i32) -> bool {
    let Ok(leader) = i32::try_from(leader) else {
        return false;
    };
    // SAFETY: kill only sends a signal.
    unsafe { libc::kill(-leader, signal) == 0 }
}

#[cfg(not(unix))]
fn terminate(_leader: u32, _signal: i32) -> bool {
    false
}

#[cfg(unix)]
fn set_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn set_process_group(_command: &mut Command) {}

fn snapshot_executable(program: &Path, config_dir: &Path) -> Result<PathBuf, ExecError> {
    let dir = config_dir.join("bin");
    std::fs::create_dir(&dir)
        .map_err(|e| ExecError::Pin(format!("cannot create snapshot dir: {e}")))?;
    let name = program
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("program"));
    let snapshot = dir.join(name);
    std::fs::copy(program, &snapshot)
        .map_err(|e| ExecError::Pin(format!("cannot snapshot {}: {e}", program.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o500))
            .map_err(|e| ExecError::Pin(format!("cannot restrict snapshot: {e}")))?;
    }
    Ok(snapshot)
}

#[cfg(unix)]
fn set_arg0(command: &mut Command, program: &Path) {
    use std::os::unix::process::CommandExt;
    command.arg0(program);
}

#[cfg(not(unix))]
fn set_arg0(_command: &mut Command, _program: &Path) {}

#[cfg(unix)]
fn map_token_fd(command: &mut Command, reader: &std::io::PipeReader) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let source = reader.as_raw_fd();
    // SAFETY: runs in the forked child before exec; dup2 and fcntl are
    // async-signal-safe and touch only this child's descriptor table.
    unsafe {
        command.pre_exec(move || {
            if source == CHILD_TOKEN_FD {
                if libc::fcntl(source, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(source, CHILD_TOKEN_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn map_token_fd(_command: &mut Command, _reader: &std::io::PipeReader) {}

/// Forward SIGTERM, SIGINT and SIGHUP to the child, so cancelling claudectl
/// cancels the run and cleanup still happens.
#[cfg(unix)]
mod signals {
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

    static CHILD: AtomicI32 = AtomicI32::new(0);
    static PENDING: AtomicBool = AtomicBool::new(false);
    const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];

    extern "C" fn forward(signal: libc::c_int) {
        // Record every signal, so a signal that races `watch` is not lost.
        PENDING.store(true, Ordering::SeqCst);
        let pid = CHILD.load(Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: kill is async-signal-safe. The child leads its own
            // process group, so this reaches its descendants too.
            unsafe { libc::kill(-pid, signal) };
        }
    }

    pub fn install() {
        CHILD.store(0, Ordering::SeqCst);
        PENDING.store(false, Ordering::SeqCst);
        for signal in SIGNALS {
            // SAFETY: installs a handler that only uses async-signal-safe
            // calls. SA_RESTART keeps interrupted system calls in other
            // threads from failing with EINTR.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = forward as *const () as libc::sighandler_t;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
        }
    }

    pub fn watch(pid: u32) {
        CHILD.store(i32::try_from(pid).unwrap_or(0), Ordering::SeqCst);
    }

    pub fn pending() -> bool {
        PENDING.load(Ordering::SeqCst)
    }

    pub fn reset() {
        CHILD.store(0, Ordering::SeqCst);
        for signal in SIGNALS {
            // SAFETY: restores the default disposition.
            unsafe { libc::signal(signal, libc::SIG_DFL) };
        }
    }
}

#[cfg(not(unix))]
mod signals {
    pub fn install() {}
    pub fn watch(_pid: u32) {}
    pub fn pending() -> bool {
        false
    }
    pub fn reset() {}
}

fn receipt_base(prepared: &Prepared, config_dir: &Path, req: &ExecRequest) -> serde_json::Value {
    serde_json::json!({
        "alias": prepared.alias,
        "account_uuid": prepared.account_uuid,
        "email": prepared.email,
        "executable": prepared.program,
        "executable_sha256": prepared.program_sha256,
        "claudectl": {
            "path": prepared.claudectl.path,
            "sha256": prepared.claudectl.sha256,
            "version": prepared.claudectl.version,
        },
        "token_expires_at": chrono::DateTime::from_timestamp_millis(prepared.token_expires_at_ms)
            .map(|t| t.to_rfc3339()),
        "min_valid_secs": req.min_valid.as_secs(),
        "config_dir": config_dir,
    })
}

fn with(base: &serde_json::Value, event: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut record = base.clone();
    let map = record.as_object_mut().expect("receipt base is an object");
    map.insert("event".into(), event.into());
    map.insert("at".into(), chrono::Utc::now().to_rfc3339().into());
    if let Some(extra) = extra.as_object() {
        for (key, value) in extra {
            map.insert(key.clone(), value.clone());
        }
    }
    record
}

struct Receipt {
    sink: Box<dyn Write>,
    sync: Option<std::fs::File>,
}

impl Receipt {
    fn open(path: Option<&Path>) -> Result<Self, ExecError> {
        let Some(path) = path else {
            return Ok(Self::from_writer(Box::new(std::io::stderr())));
        };
        let mut options = std::fs::File::options();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| ExecError::Receipt(format!("{}: {e}", path.display())))?;
        let sync = file
            .try_clone()
            .map_err(|e| ExecError::Receipt(format!("{}: {e}", path.display())))?;
        Ok(Self {
            sink: Box::new(file),
            sync: Some(sync),
        })
    }

    fn from_writer(sink: Box<dyn Write>) -> Self {
        Self { sink, sync: None }
    }

    fn write(&mut self, record: &serde_json::Value) -> Result<(), ExecError> {
        let line = format!("{record}\n");
        self.sink
            .write_all(line.as_bytes())
            .and_then(|()| self.sink.flush())
            .and_then(|()| self.sync.as_ref().map_or(Ok(()), |file| file.sync_data()))
            .map_err(|e| ExecError::Receipt(e.to_string()))
    }
}

/// A new private directory per run, removed when the run ends.
#[doc(hidden)]
pub fn fresh_config_dir(paths: &Paths, alias: &str) -> Result<tempfile::TempDir, ExecError> {
    let root = paths.claudectl_dir().join("run").join(alias);
    std::fs::create_dir_all(&root)
        .map_err(|e| ExecError::Spawn(format!("cannot create {}: {e}", root.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [paths.claudectl_dir().join("run"), root.clone()] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| ExecError::Spawn(format!("cannot restrict {}: {e}", dir.display())))?;
        }
    }
    let dir = tempfile::Builder::new()
        .prefix("config-")
        .tempdir_in(&root)
        .map_err(|e| ExecError::Spawn(format!("cannot create config dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| ExecError::Spawn(format!("cannot restrict config dir: {e}")))?;
    }
    Ok(dir)
}

fn resolve_program(program: &OsString) -> Result<PathBuf, ExecError> {
    let as_path = Path::new(program);
    let candidate = if as_path.components().count() > 1 {
        Some(as_path.to_path_buf())
    } else {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(as_path))
                .find(|p| is_executable(p))
        })
    };
    let candidate = candidate
        .ok_or_else(|| ExecError::Pin(format!("{} not found on PATH", as_path.display())))?;
    candidate
        .canonicalize()
        .map_err(|e| ExecError::Pin(format!("cannot resolve {}: {e}", candidate.display())))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

pub fn sha256_file(path: &Path) -> Result<String, ExecError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ExecError::Pin(format!("cannot read {}: {e}", path.display())))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + signal_of(status).unwrap_or(1))
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Retry briefly when another claudectl command holds the auth lock, so two
/// concurrent runs on different aliases do not fail each other.
fn lock_with_retry(store: &AuthStore) -> Result<std::fs::File, ExecError> {
    let mut last = None;
    for _ in 0..50 {
        match store.lock_auth_state() {
            Ok(lock) => return Ok(lock),
            Err(error) => last = Some(error),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(ExecError::Refused(format!(
        "auth state is busy: {:#}",
        last.expect("at least one attempt")
    )))
}

/// Parse `30m`, `900s`, `1h` or a bare number of seconds.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let input = input.trim();
    let (number, unit) = match input.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => input.split_at(i),
        None => (input, "s"),
    };
    let value: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration '{input}'"))?;
    let seconds = match unit {
        "s" => value,
        "m" => value
            .checked_mul(60)
            .ok_or_else(|| format!("duration '{input}' is too large"))?,
        "h" => value
            .checked_mul(3600)
            .ok_or_else(|| format!("duration '{input}' is too large"))?,
        _ => {
            return Err(format!(
                "invalid duration unit in '{input}' (use s, m or h)"
            ));
        }
    };
    Ok(Duration::from_secs(seconds))
}
