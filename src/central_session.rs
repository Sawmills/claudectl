//! One server account per Claude process. The process keeps the host Claude config (its
//! conversations, skills, hooks and trust) and receives only a server access token in
//! CLAUDE_CODE_OAUTH_TOKEN. The token cannot change inside a running Claude (see
//! experiments/settings-renewal/host-config.py). Authentication failure forces recovery;
//! unheld renewal waits at most ten minutes. Explicit holds and unknown SessionEnd intent
//! veto every automatic restart.
//! `session.json` records its expiry.
use super::*;
use crate::exec;
use std::{ffi::OsString, process::Command};

pub struct Session {
    home: PathBuf,
    directory: tempfile::TempDir,
    _lease: File,
    account: Account,
    current: Access,
    /// Token renewal state for supervisors (the capacity guard): on, off with a reason, or
    /// renewing. The guard leaves expiry to `server run` and skips a renewing session.
    renewal: String,
}
/// The Claude settings file for `dir`: every hook event the renewal monitor reads runs
/// `hook server hook <dir>`.
fn write_hook_settings(dir: &Path, hook: &Path) -> Result<PathBuf> {
    let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "'\\''"));
    let command = format!("{} server hook {}", quote(hook), quote(dir));
    let entry = json!([{"hooks": [{"type": "command", "command": command}]}]);
    let end =
        json!([{"hooks": [{"type": "command", "command": format!("{command} --session-end")}]}]);
    let settings = dir.join("hooks.json");
    atomic(
        &settings,
        &json!({"hooks": {"SessionStart": entry, "UserPromptSubmit": entry,
            "Stop": entry, "StopFailure": entry, "Notification": entry, "SessionEnd": end}}),
    )?;
    Ok(settings)
}
impl Session {
    pub fn new(paths: &Paths, account: &Account, access: Access) -> Result<Self> {
        validate(account, &access)?;
        if account.account_id.len() != 64
            || !account.account_id.bytes().all(|c| c.is_ascii_hexdigit())
        {
            bail!("invalid server account identifier");
        }
        let sessions = root(paths).join("sessions");
        private_dir(&sessions)?;
        retire_expired_sessions(&sessions)?;
        let directory = tempfile::Builder::new()
            .prefix("run-")
            .tempdir_in(&sessions)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lease = options.open(directory.path().join("owner.lock"))?;
        lease.try_lock()?;
        let session = Self {
            home: paths.home.clone(),
            directory,
            _lease: lease,
            account: account.clone(),
            current: access,
            renewal: "on".into(),
        };
        session.write()?;
        Ok(session)
    }
    pub fn directory(&self) -> &Path {
        self.directory.path()
    }
    fn write(&self) -> Result<()> {
        atomic(
            &self.directory.path().join("lease.json"),
            &json!({"expires_at":self.current.expires_at}),
        )?;
        // Only the token's digest: a nested run proves an inherited token is this
        // session's own (`own_session_token`) without the token on disk.
        atomic(
            &self.directory.path().join("token.sha256"),
            &sha256_hex(self.current.access_token.as_bytes()),
        )?;
        // No token here: the alias, account and expiry only.
        atomic(&self.directory.path().join("session.json"), &self.status())
    }
    fn status(&self) -> serde_json::Value {
        json!({"alias":self.account.alias,"account_id":self.account.account_id,
            "expires_at":self.current.expires_at,"pid":std::process::id(),
            "renewal":self.renewal,"restart_gate_version":if cfg!(unix) {1} else {0}})
    }
    /// Record the renewal state for supervisors.
    pub(super) fn set_renewal(&mut self, state: &str) -> Result<()> {
        self.renewal = state.into();
        self.write()
    }
    /// Adopt a newer token of the same account (after the server refreshed it).
    pub(super) fn renew(&mut self, access: Access) -> Result<()> {
        validate(&self.account, &access)?;
        if access.account_id != self.current.account_id
            || access.expires_at <= self.current.expires_at
        {
            bail!("the new token is not a newer token of this account");
        }
        self.current = access;
        self.write()
    }
    pub(super) fn revision(&self) -> &str {
        &self.current.revision
    }
    pub(super) fn account(&self) -> &Account {
        &self.account
    }
    /// Hook settings that use the hook copy of `previous` (moved here): a failover keeps the
    /// claudectl the session started with, even when the installed one changed since.
    #[cfg(unix)]
    pub(super) fn adopt_hook(&self, previous: &Session) -> Result<PathBuf> {
        let hook = self.directory().join("claudectl-hook");
        std::fs::rename(previous.directory().join("claudectl-hook"), &hook)?;
        write_hook_settings(self.directory(), &hook)
    }
    /// Claude settings that only register the renewal hooks. The hook runs a private copy of
    /// this claudectl, so an upgrade during the session cannot break it.
    #[cfg(unix)]
    pub(super) fn hook_settings(&self) -> Result<PathBuf> {
        let hook = self.directory().join("claudectl-hook");
        snapshot_binary(&std::env::current_exe()?, &hook)?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o500))?;
        }
        write_hook_settings(self.directory(), &hook)
    }
    pub fn expires_at(&self) -> i64 {
        self.current.expires_at
    }
    pub fn command(&self, program: &Path, args: &[OsString]) -> Result<Command> {
        let mut command = Command::new(program);
        exec::prefer_lane_bin(&mut command, &self.home).context("cannot build session PATH")?;
        command.args(args);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(exec::is_scrubbed_env) {
                command.env_remove(name);
            }
        }
        // The host config stays; the server token outranks the host login for this process
        // only, and Claude never stores or refreshes it.
        command.env_remove(exec::CONFIG_DIR_ENV);
        command.env("CLAUDE_CODE_OAUTH_TOKEN", &self.current.access_token);
        command.env("DISABLE_AUTOUPDATER", "1");
        // Names this session, so a nested `server run` can prove the token above is this
        // live session's own and not one a user set (`own_session_token`).
        command.env(SERVER_RUN_ENV, self.directory());
        Ok(command)
    }
}

fn retire_expired_sessions(sessions: &Path) -> Result<()> {
    for entry in std::fs::read_dir(sessions)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || !entry.file_name().to_string_lossy().starts_with("run-")
        {
            continue;
        }
        let path = entry.path();
        let lock_path = path.join("owner.lock");
        if !std::fs::symlink_metadata(&lock_path).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let owner = match OpenOptions::new().read(true).write(true).open(lock_path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        if owner.try_lock().is_err() {
            continue;
        }
        let lease = private_read(&path.join("lease.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        if lease
            .as_ref()
            .and_then(|v| v.get("expires_at"))
            .and_then(Value::as_i64)
            .is_some_and(|expiry| expiry <= now())
        {
            std::fs::remove_dir_all(path)?;
        }
    }
    Ok(())
}

fn validate(account: &Account, access: &Access) -> Result<()> {
    if account.provider != "anthropic"
        || access.provider != "anthropic"
        || access.account_id != account.account_id
        || access.identity != account.identity
        || access.user_id.is_empty()
        || access.access_token.is_empty()
        || access.expires_at <= now()
        || access.generation == 0
        || access.revision.is_empty()
        || !access.scopes.iter().any(|s| s == "user:inference")
    {
        bail!("access grant does not match the selected account or is expired");
    }
    Ok(())
}
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// True when `token` is the token a live `server run` session gave its Claude: `marker`
/// names a session directory under this user's private sessions root, that session still
/// holds its lease, and the token's digest matches the one it recorded. A marker alone
/// proves nothing: anyone can set an environment variable.
pub(super) fn own_session_token(
    paths: &Paths,
    marker: Option<&std::ffi::OsStr>,
    token: Option<&std::ffi::OsStr>,
) -> bool {
    let (Some(marker), Some(token)) = (marker, token) else {
        return false;
    };
    let Ok(sessions) = root(paths).join("sessions").canonicalize() else {
        return false;
    };
    let Ok(dir) = Path::new(marker).canonicalize() else {
        return false;
    };
    if dir.parent() != Some(sessions.as_path()) {
        return false;
    }
    // The owner holds this lock for the session's whole life: a free lock is no session.
    let live = std::fs::File::open(dir.join("owner.lock"))
        .is_ok_and(|lock| matches!(lock.try_lock(), Err(std::fs::TryLockError::WouldBlock)));
    let recorded = std::fs::read(dir.join("token.sha256"))
        .ok()
        .and_then(|b| serde_json::from_slice::<String>(&b).ok());
    live && token
        .to_str()
        .is_some_and(|t| recorded == Some(sha256_hex(t.as_bytes())))
}

fn preflight(paths: &Paths, cwd: &Path, args: &[OsString]) -> Result<()> {
    // A nested run inside a live session inherits that session's token; it may pass. Any
    // other inherited credential is refused.
    let own = own_session_token(
        paths,
        std::env::var_os(SERVER_RUN_ENV).as_deref(),
        std::env::var_os("CLAUDE_CODE_OAUTH_TOKEN").as_deref(),
    );
    for (name, _) in std::env::vars_os() {
        if own && name == "CLAUDE_CODE_OAUTH_TOKEN" {
            continue;
        }
        if name == exec::CONFIG_DIR_ENV || name.to_str().is_some_and(exec::is_scrubbed_env) {
            let name = name.to_string_lossy();
            bail!(
                "inherited credential or routing override: {name}\nTry: unset {name}; then run the command again"
            );
        }
    }
    for arg in args {
        if let Some(flag) = arg.to_str().and_then(|a| {
            ["--setting-sources", "--bare"]
                .into_iter()
                .find(|flag| a == *flag || a.starts_with(&format!("{flag}=")))
        }) {
            bail!(
                "launch argument overrides account isolation: {flag}\nTry: run again without {flag} (server run sets the Claude settings itself)"
            );
        }
    }
    exec::check_settings(cwd, &paths.home, &exec::managed_settings_dir())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // The child keeps the host config, so the host user settings load too: check them with
    // the same rules (no credential, endpoint or helper override of the server token).
    exec::check_user_settings(&paths.home).map_err(|e| anyhow::anyhow!("{e}"))
}
/// Set in a `server run` child to its session directory (see `own_session_token`).
pub const SERVER_RUN_ENV: &str = "CLAUDECTL_SERVER_RUN";

pub(super) fn program(path: &Path) -> Result<PathBuf> {
    if path.components().count() > 1 {
        return Ok(path.canonicalize()?);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(path))
        .find(|p| p.is_file())
        .context(
            "Claude executable not found on PATH\nTry: claudectl run --claude /path/to/claude",
        )?
        .canonicalize()
        .map_err(Into::into)
}
#[cfg(unix)]
/// A private copy of the Claude build, made once before any server call. Its hash is what is
/// checked, recorded and run, whatever happens to the source afterwards.
struct Build {
    _directory: tempfile::TempDir,
    file: PathBuf,
    digest: String,
}
#[cfg(unix)]
fn snapshot_build(paths: &Paths, binary: &Path) -> Result<Build> {
    let builds = root(paths).join("builds");
    private_dir(&builds)?;
    // A launch killed during its check (Ctrl-C, a closed tab) leaves its copy behind: remove
    // copies whose launch is gone, keep those of launches still waiting or checking.
    for entry in std::fs::read_dir(&builds)? {
        let path = entry?.path();
        let pid = path
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_prefix("build-"))
            .and_then(|rest| rest.split('-').next())
            .and_then(|pid| pid.parse::<i32>().ok());
        if let Some(pid) = pid
            && pid > 0
            && unsafe { libc::kill(pid, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
    let directory = tempfile::Builder::new()
        .prefix(&format!("build-{}-", std::process::id()))
        .tempdir_in(&builds)?;
    let file = directory.path().join("claude");
    snapshot_binary(binary, &file)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o500))?;
    }
    let digest = exec::sha256_file(&file).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(Build {
        _directory: directory,
        file,
        digest,
    })
}
#[cfg(unix)]
/// The build `server run` will execute, qualified on first use; nothing touches the server
/// before it passes.
fn qualified_build(
    paths: &Paths,
    binary: &Path,
    harness: impl FnOnce(&Path, &str) -> Result<bool>,
) -> Result<Build> {
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        bail!("server-account sessions support Linux and macOS");
    }
    let build = snapshot_build(paths, binary)?;
    super::qualify::ensure(paths, &build.file, &build.digest, harness)?;
    Ok(build)
}

#[cfg(unix)]
fn snapshot_binary(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let src = CString::new(source.as_os_str().as_bytes())?;
        let dst = CString::new(destination.as_os_str().as_bytes())?;
        // APFS clones preserve a private executable snapshot without duplicating all blocks.
        if unsafe { libc::clonefile(src.as_ptr(), dst.as_ptr(), 0) } == 0 {
            return Ok(());
        }
    }
    std::fs::copy(source, destination)?;
    Ok(())
}

/// The saved terminal modes of a session with a terminal, restored before a relaunch.
#[cfg(unix)]
struct Terminal {
    saved: libc::termios,
    /// The terminal device: its access time is the last input (as `w` reports idle time).
    path: Option<PathBuf>,
}
#[cfg(unix)]
impl Terminal {
    fn save() -> Option<Self> {
        // SAFETY: isatty, tcgetattr and ttyname only read terminal state into local memory.
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) != 1 {
                return None;
            }
            let mut saved: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) != 0 {
                return None;
            }
            let name = libc::ttyname(libc::STDIN_FILENO);
            let path = (!name.is_null()).then(|| {
                use std::os::unix::ffi::OsStrExt;
                PathBuf::from(std::ffi::OsStr::from_bytes(
                    std::ffi::CStr::from_ptr(name).to_bytes(),
                ))
            });
            Some(Self { saved, path })
        }
    }
    /// Put the terminal back as it was before Claude ran: line modes, then the screen modes a
    /// full-screen program may leave on (bracketed paste, focus and mouse reports, the
    /// alternate screen, a hidden cursor).
    fn restore(&self) {
        use std::io::Write;
        // SAFETY: tcsetattr reads the saved modes; claudectl owns the foreground again here.
        unsafe {
            libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
        }
        let mut out = std::io::stdout();
        let _ = out.write_all(
            b"\x1b[?2004l\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1049l\x1b[?25h\r\n",
        );
        let _ = out.flush();
    }
}

#[cfg(unix)]
enum RestartKind {
    /// A newer token of the same account (SAW-12610).
    Renew(Access),
    /// The account is at a usage limit: the session moves to `account` (SAW-12693).
    Failover { account: Account, access: Access },
}
#[cfg(unix)]
struct Restart {
    kind: RestartKind,
    session_id: String,
    cause: super::restart_gate::Cause,
}
#[cfg(unix)]
impl Restart {
    fn with_current_session(mut self, current: Option<&str>) -> Option<Self> {
        if matches!(&self.kind, RestartKind::Renew(_)) {
            self.session_id = current?.to_owned();
        }
        Some(self)
    }
}
/// Failover state that outlives one Claude process of the run.
#[cfg(unix)]
#[derive(Clone, Default)]
struct Failover {
    /// Accounts this run already left.
    tried: Vec<String>,
    /// Failovers in the last hour (its own budget, apart from renewals).
    last_hour: usize,
}
#[cfg(unix)]
#[derive(Default)]
struct Outcome {
    /// Set only after the monitor itself sent SIGTERM for a renewal.
    restart: Option<Restart>,
    /// A renewal state change to record (for example, hooks missing).
    note: Option<String>,
    /// A failover notice for stderr once Claude no longer owns the terminal.
    notice: Option<String>,
}
/// Watches one Claude process and publishes workload/expiry status. Authentication recovery
/// is immediate except for explicit holds/unknown exit intent; renewal has a deadline and failover retains observed quiet.
#[cfg(unix)]
struct Monitor {
    client: Client,
    paths: Paths,
    account_id: String,
    directory: PathBuf,
    held_revision: String,
    held_expires_at: i64,
    pid: u32,
    renewable: bool,
    recovery_resume: bool,
    restarts: usize,
    tty: Option<PathBuf>,
    /// The session.json content, to mark the session renewing before SIGTERM.
    status: serde_json::Value,
    /// The account's alias, and the failover state when this run may move accounts.
    alias: String,
    failover: Option<Failover>,
    crons: Option<super::crons::Recovery>,
}
/// Where the monitor is with the latest `rate_limit` turn failure.
#[cfg(unix)]
#[derive(Default)]
struct Pending {
    /// The failure (by its time) that is done: switched, a throttle, given up, or no room.
    handled: Option<i64>,
    last_read: i64,
    deadline: super::failover::Deadline,
    /// Shown when Claude exits: why the session did not move.
    notice: Option<String>,
}
/// Fold the events appended to `path` since the last read into the activity. A missing log
/// before the first event is no error. Salvage valid metadata after damaged records so
/// auth failure and session exit remain visible; corruption blocks ordinary admission.
#[cfg(unix)]
fn read_new_events(path: &Path, activity: &mut Activity) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !activity.seen_start => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let mut failure = None;
    if file.metadata()?.len() < activity.offset {
        activity.offset = 0;
        failure = Some(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "hook log truncated",
        ));
    }
    file.seek(SeekFrom::Start(activity.offset))?;
    let mut chunk = Vec::new();
    file.read_to_end(&mut chunk)?;
    let mut consumed = 0;
    let mut valid_records = String::new();
    for line in chunk.split_inclusive(|byte| *byte == b'\n') {
        if !line.ends_with(b"\n") {
            failure = Some(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "incomplete hook record",
            ));
            break;
        }
        consumed += line.len();
        let record = serde_json::from_slice::<Value>(line);
        let valid = record.as_ref().is_ok_and(|record| {
            record["at"].as_i64().is_some()
                && record["event"].as_str().is_some()
                && record["session_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty())
        });
        if !valid {
            failure = Some(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid hook record",
            ));
            continue;
        }
        valid_records.push_str(std::str::from_utf8(line).map_err(std::io::Error::other)?);
    }
    activity.offset += consumed as u64;
    if !valid_records.is_empty() {
        let events = super::renew::parse_events(&valid_records);
        activity.seen_start |= events
            .iter()
            .any(|(_, e)| matches!(e, super::renew::Event::SessionStart(_)));
        activity.successful_stops = activity.successful_stops.saturating_add(
            events
                .iter()
                .filter(|(_, e)| matches!(e, super::renew::Event::Stop))
                .count() as u64,
        );
        super::renew::fold(&mut activity.idle, &events);
    }
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(())
}

/// Whether the Claude that wrote `events` reported any session (its start or a turn).
#[cfg(unix)]
fn session_started(events: &Path) -> bool {
    std::fs::read_to_string(events).is_ok_and(|text| {
        super::renew::parse_events(&text).iter().any(|(_, e)| {
            matches!(
                e,
                super::renew::Event::SessionStart(_) | super::renew::Event::Session(_)
            )
        })
    })
}

/// What the monitor knows about Claude's activity, read incrementally.
#[cfg(unix)]
#[derive(Default)]
struct Activity {
    offset: u64,
    idle: super::renew::Idle,
    seen_start: bool,
    successful_stops: u64,
}
#[cfg(unix)]
impl Monitor {
    /// Fold the hook events appended since the last read into the activity.
    fn read_events(&self, activity: &mut Activity) -> std::io::Result<()> {
        // A healthy writer's in-progress append must not look like damaged evidence.
        let _admission = super::restart_gate::try_admission(&self.directory).map_err(|error| {
            error
                .downcast::<std::io::Error>()
                .unwrap_or_else(std::io::Error::other)
        })?;
        read_new_events(&self.directory.join("events"), activity)
    }
    /// The decision inputs from the current activity, terminal and process group. Without a
    /// server token, the server side equals the held one.
    fn inputs<'a>(
        &'a self,
        activity: &'a mut Activity,
        timing: &super::renew::Timing,
        server: Option<&'a Access>,
    ) -> super::renew::Inputs<'a> {
        let tty_idle_ms = self.tty.as_ref().map(|path| {
            std::fs::metadata(path)
                .and_then(|m| m.accessed())
                .ok()
                .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |at| now() - at.as_millis() as i64)
        });
        super::renew::Inputs {
            now: now(),
            held_revision: &self.held_revision,
            held_expires_at: self.held_expires_at,
            server_revision: server.map_or(&self.held_revision, |a| &a.revision),
            server_expires_at: server.map_or(self.held_expires_at, |a| a.expires_at),
            idle: &activity.idle,
            idle_after_ms: timing.idle_after_ms,
            tty_gate_ms: timing.tty_idle_ms,
            tty_idle_ms,
            restarts_last_hour: self.restarts,
        }
    }
}
#[cfg(unix)]
impl Monitor {
    fn check_crons(&mut self, finished: bool) -> Result<()> {
        let Some(recovery) = self.crons.take() else {
            return Ok(());
        };
        let report = match recovery.check(&self.directory, finished) {
            Ok(None) => {
                self.crons = Some(recovery);
                return Ok(());
            }
            Ok(Some(report)) => report,
            Err(_) => "cron recovery unverified: transcript evidence unavailable".into(),
        };
        super::crons::log_notice(&self.paths.home, &self.directory, &report)
    }
    fn watch(mut self, stopped: std::sync::mpsc::Receiver<()>) -> Outcome {
        use super::renew;
        struct StopChild(u32);
        impl Drop for StopChild {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(-(self.0 as i32), libc::SIGTERM);
                }
            }
        }
        let _stop_child = StopChild(self.pid);
        let timing = renew::timing();
        let started = now();
        let mut outcome = Outcome::default();
        let mut last_usage = 0;
        let mut usage_worker: Option<std::thread::JoinHandle<()>> = None;
        let mut last_check = 0;
        let mut activity = Activity::default();
        let mut was_recovering = false;
        let mut next_access: Option<Access> = None;
        let mut checked_auth = None;
        let mut checked_at = 0;
        let mut current_revision: Option<String> = None;
        let mut signalled_at: Option<Instant> = None;
        let mut no_session_reported = false;
        let mut replacement_backoff: Option<Instant> = None;
        let mut last_successful_stops = 0;
        let mut sent: Option<(i64, Restart)> = None;
        let mut pending = Pending::default();
        let mut cron_log_error = None;
        let mut gate = super::restart_gate::Gate::new(
            &self.paths.home,
            &self.directory,
            self.pid,
            &self.alias,
        )
        .with_terminal(self.tty.clone());
        while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            stopped.recv_timeout(Duration::from_millis(timing.tick_ms))
        {
            if let Err(error) = self.check_crons(false) {
                // Stderr is Claude's terminal until it exits. Defer only the log failure.
                cron_log_error = Some(format!("could not record cron recovery: {error:#}"));
            }
            if usage_worker
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
            {
                let _ = usage_worker.take().map(|worker| worker.join());
            }
            if usage_worker.is_none() && now() - last_usage >= 300_000 {
                let client = self.client.clone();
                let account_id = self.account_id.clone();
                let path = usage_path(&self.paths, &client.connection, &account_id);
                // Optional usage I/O must never hold recovery or child shutdown.
                usage_worker = std::thread::Builder::new()
                    .name("session-usage".into())
                    .spawn(move || {
                        if let Ok(usage) = client.usage(&account_id, false) {
                            let _ = atomic(&path, &usage);
                        }
                    })
                    .ok();
                last_usage = now();
            }
            if let Some((_, restart)) = &sent {
                // The owned leader gets the same save grace as other Claude launchers.
                // Never read hooks or wait for admission while this deadline runs.
                if signalled_at.is_some_and(|at| at.elapsed() >= exec::STOP_GRACE)
                    && !exec::has_exited(self.pid)
                {
                    if unsafe { libc::kill(self.pid as i32, libc::SIGKILL) } != 0 {
                        gate.failed(
                            &activity.idle,
                            restart.cause,
                            super::restart_gate::RecoveryFailure::Signal,
                        );
                    }
                    signalled_at = None;
                }
                continue;
            }
            if !self.renewable {
                continue;
            }
            let events_failed = self
                .read_events(&mut activity)
                .is_err_and(|error| error.kind() != std::io::ErrorKind::WouldBlock);
            gate.revisions(
                &self.held_revision,
                next_access.as_ref().map(|access| access.revision.as_str()),
                current_revision.as_deref(),
                self.held_expires_at,
                activity.idle.auth_failed,
            );
            if events_failed || self.directory.join("hook-error").exists() {
                outcome.note = Some("off: hook evidence unavailable".into());
                gate.unknown(
                    &activity.idle,
                    super::restart_gate::Cause::Renewal,
                    self.held_expires_at,
                );
            }
            let recovering = renew::held_token_dead(&self.inputs(&mut activity, &timing, None));
            if activity.idle.session.is_none() {
                if recovering && !no_session_reported {
                    gate.failed(
                        &activity.idle,
                        super::restart_gate::Cause::AuthRecovery,
                        super::restart_gate::RecoveryFailure::NoSession,
                    );
                    no_session_reported = true;
                }
                gate.check(
                    &activity.idle,
                    if recovering {
                        super::restart_gate::Cause::AuthRecovery
                    } else {
                        super::restart_gate::Cause::Renewal
                    },
                    self.held_expires_at,
                );
                if now() - started > timing.hooks_wait_ms {
                    outcome.note = Some("off: no hook events".into());
                }
                continue;
            }
            no_session_reported = false;
            if activity.idle.ended.is_some() || exec::signals::pending().is_some() {
                continue;
            }
            if activity.successful_stops != last_successful_stops {
                super::restart_gate::recovery_succeeded(
                    &self.directory,
                    activity.idle.session.as_deref(),
                );
                last_successful_stops = activity.successful_stops;
                self.recovery_resume = false;
            }
            if self.recovery_resume && activity.idle.auth_failed.is_some() {
                gate.failed(
                    &activity.idle,
                    super::restart_gate::Cause::AuthRecovery,
                    super::restart_gate::RecoveryFailure::ReplacementRejected,
                );
                replacement_backoff =
                    Some(Instant::now() + Duration::from_millis(timing.retry_ms as u64));
                self.recovery_resume = false;
            }
            if replacement_backoff.is_some_and(|until| Instant::now() < until) {
                continue;
            }
            if !recovering {
                gate.recovered();
            }
            let failover_pending = !recovering
                && self.failover.is_some()
                && activity.idle.limited.as_ref().is_some_and(|(session, at)| {
                    activity.idle.session.as_ref() == Some(session) && pending.handled != Some(*at)
                });
            let mut cause = if recovering {
                super::restart_gate::Cause::AuthRecovery
            } else if failover_pending {
                super::restart_gate::Cause::Failover
            } else {
                super::restart_gate::Cause::Renewal
            };
            let admitted = gate.check(&activity.idle, cause, self.held_expires_at);
            if failover_pending
                && admitted
                && let Some((session_id, failed_at)) = activity.idle.limited.clone()
                && let Some((account, access)) =
                    self.failover_target(&mut activity, &mut gate, &timing, &mut pending, failed_at)
            {
                match self.stop_for_restart(&mut activity, &mut gate, &timing, cause) {
                    Ok(Some(_)) => {
                        signalled_at = Some(Instant::now());
                        sent = Some((
                            now(),
                            Restart {
                                kind: RestartKind::Failover { account, access },
                                session_id,
                                cause,
                            },
                        ));
                        continue;
                    }
                    Ok(None) => break,
                    Err(()) => continue,
                }
            }
            // Waiting for an account switch cannot suspend same-account renewal.
            cause = if recovering {
                super::restart_gate::Cause::AuthRecovery
            } else {
                super::restart_gate::Cause::Renewal
            };
            // Observing an unexpired grant cannot rotate it. Read before workload
            // admission so a busy session can discover a pending renewal.
            let interval = if recovering {
                timing.retry_ms
            } else {
                timing.poll_near_ms.min(timing.poll_far_ms).min(30_000)
            };
            // A timestamp-valid candidate can have been revoked by another holder.
            // A new rejection needs an observation made after that rejection.
            let needs_token = next_access
                .as_ref()
                .is_none_or(|access| access.expires_at <= now());
            let unchecked_auth =
                activity.idle.auth_failed.is_some() && activity.idle.auth_failed != checked_auth;
            let entering_recovery = recovering && !was_recovering;
            let due = (needs_token || unchecked_auth || entering_recovery)
                && (entering_recovery || now() - last_check >= interval);
            was_recovering = recovering;
            if due {
                last_check = now();
                let request_auth = activity.idle.auth_failed;
                let cached_revision = next_access.as_ref().map(|access| access.revision.clone());
                gate.revisions(
                    &self.held_revision,
                    cached_revision.as_deref(),
                    current_revision.as_deref(),
                    self.held_expires_at,
                    request_auth,
                );
                let mut access = match self.client.observe(&self.account_id) {
                    Ok(access) => access,
                    Err(_) => {
                        if recovering || next_access.is_some() {
                            gate.failed(
                                &activity.idle,
                                cause,
                                super::restart_gate::RecoveryFailure::Observe,
                            );
                        }
                        last_check = now() - interval + timing.retry_ms;
                        continue;
                    }
                };
                if self
                    .read_events(&mut activity)
                    .is_err_and(|error| error.kind() != std::io::ErrorKind::WouldBlock)
                {
                    gate.unknown(&activity.idle, cause, self.held_expires_at);
                }
                if activity.idle.ended.is_some() || exec::signals::pending().is_some() {
                    continue;
                }
                if activity.idle.auth_failed.is_some() && activity.idle.auth_failed != request_auth
                {
                    next_access = None;
                    continue;
                }
                // A successful Stop during the request can clear a transient failure.
                let recovering = renew::held_token_dead(&self.inputs(&mut activity, &timing, None));
                cause = if recovering {
                    super::restart_gate::Cause::AuthRecovery
                } else {
                    super::restart_gate::Cause::Renewal
                };
                if !recovering {
                    gate.recovered();
                }
                if activity.idle.auth_failed.is_some() && access.revision == self.held_revision {
                    current_revision = Some(access.revision.clone());
                    gate.revisions(
                        &self.held_revision,
                        cached_revision.as_deref(),
                        current_revision.as_deref(),
                        self.held_expires_at,
                        activity.idle.auth_failed,
                    );
                    access = match self
                        .client
                        .acquire(&self.account_id, Some(&self.held_revision))
                    {
                        Ok(access) => access,
                        Err(_) => {
                            gate.failed(
                                &activity.idle,
                                cause,
                                super::restart_gate::RecoveryFailure::Acquire,
                            );
                            last_check = now() - interval + timing.retry_ms;
                            continue;
                        }
                    };
                    if self
                        .read_events(&mut activity)
                        .is_err_and(|error| error.kind() != std::io::ErrorKind::WouldBlock)
                    {
                        gate.unknown(&activity.idle, cause, self.held_expires_at);
                    }
                }
                current_revision = Some(access.revision.clone());
                gate.revisions(
                    &self.held_revision,
                    cached_revision.as_deref(),
                    current_revision.as_deref(),
                    self.held_expires_at,
                    activity.idle.auth_failed,
                );
                if access.revision != self.held_revision && access.expires_at > now() {
                    gate.request_at(cause, Instant::now());
                    next_access = Some(access);
                    checked_auth = request_auth;
                    checked_at = now();
                } else {
                    if recovering {
                        gate.failed(
                            &activity.idle,
                            cause,
                            super::restart_gate::RecoveryFailure::UnusableReplacement,
                        );
                    }
                    next_access = None;
                }
            }
            let Some(access) = next_access.as_ref() else {
                continue;
            };
            if activity.idle.auth_failed.is_some() && activity.idle.auth_failed != checked_auth {
                continue;
            }
            let admitted = gate.check(&activity.idle, cause, self.held_expires_at);
            let inputs = self.inputs(&mut activity, &timing, Some(access));
            let restart = renew::restart_needed(&inputs)
                && renew::replacement_ready(&inputs)
                && (gate.forced(cause).is_some()
                    || renew::decide(&inputs) == renew::Decision::Restart);
            if admitted && restart {
                // A hold or long workload wait must not relaunch a superseded snapshot.
                if now() - checked_at > interval.max(timing.tick_ms as i64) {
                    next_access = None;
                    last_check = now() - interval;
                    continue;
                }
                match self.stop_for_restart(&mut activity, &mut gate, &timing, cause) {
                    Ok(Some(session_id)) => {
                        signalled_at = Some(Instant::now());
                        sent = Some((
                            now(),
                            Restart {
                                kind: RestartKind::Renew(
                                    next_access.take().expect("replacement checked"),
                                ),
                                session_id,
                                cause,
                            },
                        ));
                    }
                    Ok(None) => break,
                    Err(()) => {}
                }
            }
        }
        // Claude may have ended its session just before our SIGTERM (a /exit while the
        // request ran): that exit is the user's, never a renewal (CX-0119).
        let drain_until = Instant::now() + Duration::from_secs(1);
        loop {
            let read = self.read_events(&mut activity);
            if read.is_ok() || activity.idle.ended.is_some() {
                break;
            }
            if Instant::now() >= drain_until {
                // The child has exited. A complete SessionEnd may already be visible
                // while a surviving hook still holds the admission lock.
                let _ = read_new_events(&self.directory.join("events"), &mut activity);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let exit_intent =
            super::renew::session_end_intent(&self.directory, activity.idle.session.as_deref());
        if exit_intent.is_err()
            && let Some((_, restart)) = &sent
        {
            gate.exit_intent_unknown(&activity.idle, restart.cause, self.held_expires_at);
        }
        let ended = activity
            .idle
            .ended
            .into_iter()
            .chain(exit_intent.as_ref().ok().copied().flatten())
            .min();
        let ended_first = matches!((&sent, ended), (Some((at, _)), Some(end)) if end <= *at);
        if let Err(error) = self.check_crons(true) {
            cron_log_error = Some(format!("could not record cron recovery: {error:#}"));
        }
        outcome.restart = sent
            .filter(|_| !ended_first && exit_intent.is_ok() && exec::signals::pending().is_none())
            .and_then(|(_, restart)| {
                // An in-flight /resume hook can finish while the child stops. The exit
                // intent above was checked for this final observed conversation.
                restart.with_current_session(activity.idle.session.as_deref())
            });
        outcome.notice = match (pending.notice.take(), cron_log_error) {
            (Some(notice), Some(error)) => Some(format!("{notice}\n{error}")),
            (notice, error) => notice.or(error),
        };
        outcome
    }
}

#[cfg(unix)]
impl Monitor {
    /// Mark renewing, then SIGTERM Claude, returning the final admitted conversation ID.
    /// None means Claude already exited; Err means admission or signalling failed.
    fn stop_for_restart(
        &self,
        activity: &mut Activity,
        gate: &mut super::restart_gate::Gate,
        timing: &super::renew::Timing,
        cause: super::restart_gate::Cause,
    ) -> std::result::Result<Option<String>, ()> {
        // Deferral must not publish renewing or signal before workload admission.
        // This guard and the locks do not close all input sources.
        let observed_auth = activity.idle.auth_failed;
        if cause != super::restart_gate::Cause::Failover
            && !super::renew::restart_needed(&self.inputs(activity, timing, None))
        {
            return Err(());
        }
        let _admission = gate.admit(&activity.idle, cause, self.held_expires_at)?;
        let forced = gate.forced(cause).is_some();
        if self.directory.join("hook-error").exists()
            || read_new_events(&self.directory.join("events"), activity).is_err()
        {
            gate.unknown(&activity.idle, cause, self.held_expires_at);
            if !forced {
                return Err(());
            }
        }
        let mut inputs = self.inputs(activity, timing, None);
        if cause == super::restart_gate::Cause::Failover {
            inputs.restarts_last_hour = self.failover.as_ref().map_or(0, |f| f.last_hour);
        }
        if cause != super::restart_gate::Cause::Failover
            && (!super::renew::restart_needed(&inputs)
                || inputs.idle.auth_failed != observed_auth
                || (cause == super::restart_gate::Cause::AuthRecovery
                    && !super::renew::held_token_dead(&inputs)))
        {
            return Err(());
        }
        if (!forced && super::renew::idle_gate(&inputs).is_err())
            || inputs.idle.session.is_none()
            || inputs.idle.ended.is_some()
            || !gate.check(&activity.idle, cause, self.held_expires_at)
        {
            return Err(());
        }
        let session_id = activity.idle.session.clone().ok_or(())?;
        let mut status = self.status.clone();
        status["renewal"] = "renewing".into();
        if atomic(&self.directory.join("session.json"), &status).is_err() {
            gate.failed(
                &activity.idle,
                cause,
                super::restart_gate::RecoveryFailure::StatusPublish,
            );
            if !forced {
                return Err(());
            }
        }
        // This last workload sample still leaves a sample-to-SIGTERM race.
        // Workload observations do not acknowledge prompt handover.
        if !gate.check(&activity.idle, cause, self.held_expires_at) {
            let mut status = self.status.clone();
            status["renewal"] = "on".into();
            let _ = atomic(&self.directory.join("session.json"), &status);
            return Err(());
        }
        // SIGTERM the leader; teardown of the rest of the group follows its exit. A leader
        // that already exited (not yet reaped, so kill would still succeed) left on its own.
        if exec::has_exited(self.pid) || exec::signals::pending().is_some() {
            let mut status = self.status.clone();
            status["renewal"] = "on".into();
            let _ = atomic(&self.directory.join("session.json"), &status);
            return Ok(None);
        }
        if unsafe { libc::kill(self.pid as i32, libc::SIGTERM) } != 0 {
            gate.failed(
                &activity.idle,
                cause,
                super::restart_gate::RecoveryFailure::Signal,
            );
            return Err(());
        }
        gate.signalled(cause, Some(&session_id));
        Ok(Some(session_id))
    }
    /// The account and token to move to for the limit a turn hit at `failed_at`, once a
    /// fresh usage read confirms it and Claude is idle. None: not yet, or `pending` records
    /// that this failure needs no switch (a throttle, no account with room, or no answer).
    fn failover_target(
        &self,
        activity: &mut Activity,
        gate: &mut super::restart_gate::Gate,
        timing: &super::renew::Timing,
        pending: &mut Pending,
        failed_at: i64,
    ) -> Option<(Account, Access)> {
        use super::failover::{self, Confirm};
        // No reservation, provider acquisition or budget/deadline accounting until
        // the quiet/workload gate permits it, including direct callers.
        if !gate.check(
            &activity.idle,
            super::restart_gate::Cause::Failover,
            self.held_expires_at,
        ) {
            return None;
        }
        let state = self.failover.as_ref()?;
        let mut inputs = self.inputs(activity, timing, None);
        inputs.restarts_last_hour = state.last_hour;
        super::renew::idle_gate(&inputs).ok()?;
        if pending.deadline.expired(failed_at, now()) {
            pending.handled = Some(failed_at);
            return None;
        }
        if now() - pending.last_read < timing.retry_ms {
            return None;
        }
        pending.last_read = now();
        // A fresh read, not this machine's copy: only a current full window is a limit.
        let usage = self.client.usage(&self.account_id, false).ok()?;
        match failover::confirm(&usage, failed_at) {
            Confirm::NotYet => return None,
            Confirm::Throttle => {
                pending.handled = Some(failed_at);
                return None;
            }
            Confirm::Limit => {}
        }
        let ServerView::Rows(rows) = server_view(&self.paths, false, &[], None) else {
            return None;
        };
        let session_id = activity.idle.session.clone()?;
        // The record is written before SIGTERM, so sessions that hit the limit together see
        // it. If Claude exits on its own meanwhile, the record stays without a switch (rare;
        // it only spreads the next failovers).
        let taken = failover::reserve(
            &self.paths,
            &rows,
            &self.alias,
            &state.tried,
            &self.directory,
            &session_id,
            |to| {
                let account = self.client.account(to).ok()?;
                // Automatic failover observes the target's current grant. The Engine owns
                // expiry, migration and explicit rotation.
                let access = self.client.observe(&account.account_id).ok()?;
                // All remote reads have completed. Do not reserve an account for work
                // that became busy during them; the signal still has its final admission.
                let _admission = gate
                    .admit(
                        &activity.idle,
                        super::restart_gate::Cause::Failover,
                        self.held_expires_at,
                    )
                    .ok()?;
                if self.directory.join("hook-error").exists()
                    || read_new_events(&self.directory.join("events"), activity).is_err()
                {
                    gate.unknown(
                        &activity.idle,
                        super::restart_gate::Cause::Failover,
                        self.held_expires_at,
                    );
                    return None;
                }
                let mut inputs = self.inputs(activity, timing, None);
                inputs.restarts_last_hour = state.last_hour;
                if super::renew::idle_gate(&inputs).is_err()
                    || !gate.check(
                        &activity.idle,
                        super::restart_gate::Cause::Failover,
                        self.held_expires_at,
                    )
                {
                    return None;
                }
                Some((account, access))
            },
        );
        match taken {
            Ok(failover::Reserved::Taken(_, target)) => Some(target),
            // The lock or the record failed, or the account had no token now: try again.
            Err(_) | Ok(failover::Reserved::NotTaken) => None,
            Ok(failover::Reserved::NoRoom) => {
                pending.handled = Some(failed_at);
                // Never printed over Claude's screen: session.json now, stderr at exit.
                let notice = format!(
                    "{} reached its usage limit and no other account has room now\nTry: claudectl status",
                    self.alias
                );
                let mut status = self.status.clone();
                status["failover"] = notice.clone().into();
                let _ = atomic(&self.directory.join("session.json"), &status);
                pending.notice = Some(notice);
                None
            }
        }
    }
}

#[cfg(unix)]
pub fn run(
    paths: &Paths,
    client: &Client,
    alias: &str,
    binary: &Path,
    args: &[OsString],
    failover: bool,
) -> Result<i32> {
    let _slot = exec::RunSlot::take().map_err(|error| anyhow::anyhow!("{error}"))?;
    let user_settings = super::settings::LaunchSettings::parse(args)?;
    let args = user_settings.args.as_slice();
    preflight(paths, &std::env::current_dir()?, args)?;
    let service_account = super::service_account::account(client, alias)?;
    let build = qualified_build(paths, &program(binary)?, super::qualify::harness)?;
    let account = match service_account {
        Some(account) => account,
        None => client.account(alias)?,
    };
    // Automatic launches observe the current grant; expiry and pending migration still
    // follow the Engine's rotation path.
    let access = client.observe(&account.account_id)?;
    let mut session = Session::new(paths, &account, access)?;
    // The checked copy itself runs (same filesystem, so the rename keeps the file).
    let mut snapshot = session.directory().join("claude");
    std::fs::rename(&build.file, &snapshot)?;
    // A one-shot `-p` run is never restarted; an interactive session follows the account's
    // token revision (SAW-12610).
    let renewable = super::renew::relaunch_args(args, "probe").is_some();
    let mut hooks = if renewable {
        Some(session.hook_settings()?)
    } else {
        session.set_renewal("off: one-shot run")?;
        None
    };
    let mut settings = user_settings.write(session.directory(), hooks.as_deref())?;
    let terminal = Terminal::save();
    struct Signals;
    impl Drop for Signals {
        fn drop(&mut self) {
            exec::signals::reset();
        }
    }
    exec::signals::install();
    let _signals = Signals;
    let mut launch_args = args.to_vec();
    let mut restarts: Vec<i64> = Vec::new();
    // Failovers have their own budget; they never use up renewals (and the reverse).
    let mut failovers: Vec<i64> = Vec::new();
    let mut tried: Vec<String> = Vec::new();
    // The session the running Claude was relaunched to resume, until its result is known.
    let mut resumed: Option<(String, super::restart_gate::Cause)> = None;
    let mut first = true;
    let mut cron_recovery = None;
    let mut relaunch: Option<super::restart_gate::RecoveryAttempt> = None;
    loop {
        if let Some(attempt) = relaunch.as_mut() {
            attempt.at(super::restart_gate::RecoveryFailure::Spawn);
        }
        let mut command = session.command(&snapshot, &[])?;
        if let Some(settings) = &settings {
            command.arg("--settings").arg(settings);
        }
        command.args(&launch_args);
        exec::set_process_group(&mut command);
        // Whether claudectl holds the terminal foreground now (the group to give it back to).
        // SAFETY: tcgetpgrp and getpgrp only read process state.
        let own_group = unsafe {
            let group = libc::getpgrp();
            (terminal.is_some() && libc::tcgetpgrp(libc::STDIN_FILENO) == group).then_some(group)
        };
        if !first {
            exec::take_foreground(&mut command);
        }
        let _ = std::fs::remove_file(session.directory().join("events"));
        super::renew::clear_session_end_intents(session.directory())?;
        if !first {
            // Before spawn: a failed write must not leave a Claude without its monitor.
            session.set_renewal("on")?;
        }
        let mut child = command.spawn().context("could not start Claude")?;
        if let Some(attempt) = relaunch.take() {
            attempt.started();
        }
        let pid = child.id();
        exec::signals::watch(pid);
        // A relaunch got the foreground before exec; give it back to claudectl's own group.
        let foreground = if first {
            Foreground::take(pid)
        } else {
            Foreground(own_group)
        };
        let (stop, stopped) = std::sync::mpsc::channel();
        let monitor = Monitor {
            client: client.clone(),
            paths: paths.clone(),
            account_id: session.account().account_id.clone(),
            directory: session.directory().to_path_buf(),
            held_revision: session.revision().to_string(),
            held_expires_at: session.expires_at(),
            pid,
            renewable: hooks.is_some(),
            recovery_resume: resumed
                .as_ref()
                .is_some_and(|(_, cause)| *cause == super::restart_gate::Cause::AuthRecovery),
            restarts: restarts
                .iter()
                .filter(|&&at| now() - at < 3_600_000)
                .count(),
            tty: terminal.as_ref().and_then(|t| t.path.clone()),
            status: session.status(),
            alias: session.account().alias.clone(),
            failover: (failover && hooks.is_some()).then(|| Failover {
                tried: tried.clone(),
                last_hour: failovers
                    .iter()
                    .filter(|&&at| now() - at < 3_600_000)
                    .count(),
            }),
            crons: cron_recovery.take(),
        };
        let watcher = std::thread::spawn(move || monitor.watch(stopped));
        let waited = exec::wait_exit_no_reap(pid, terminal.is_some());
        let _ = stop.send(());
        let outcome = watcher
            .join()
            .map_err(|_| anyhow::anyhow!("session monitor stopped unexpectedly"))?;
        if let Some(restart) = &outcome.restart {
            relaunch = Some(super::restart_gate::RecoveryAttempt::new(
                &paths.home,
                session.directory(),
                &restart.session_id,
                restart.cause,
            ));
        }
        let descendants = if waited.is_ok() {
            Some(exec::teardown_group(pid))
        } else {
            None
        };
        exec::signals::unwatch();
        drop(foreground);
        let status = child.wait()?;
        waited?;
        if !matches!(
            descendants,
            Some(
                exec::Descendants::None | exec::Descendants::Terminated | exec::Descendants::Killed
            )
        ) {
            bail!("Claude descendants could not be confirmed stopped");
        }
        if let Some(attempt) = relaunch.as_mut() {
            attempt.at(super::restart_gate::RecoveryFailure::Persist);
        }
        if let Some(note) = &outcome.note {
            session.set_renewal(note)?;
        }
        // Relaunch only after our own SIGTERM; any other exit ends `server run` with the
        // child's code.
        let Some(Restart {
            kind,
            session_id,
            cause,
        }) = outcome.restart
        else {
            if let Some(notice) = &outcome.notice {
                eprintln!("claudectl: {notice}");
            }
            // A relaunch whose resume failed (Claude exited with an error before any session
            // started, as with "No conversation found") must not leave the pane at a shell:
            // say so and start a new session on the same token, once (SAW-12882). A stop by
            // signal, or a code from 128 up (130 is Ctrl-C), is the user's stop: it ends the
            // run as before.
            if let Some((id, cause)) = resumed.take()
                && status.code().is_some_and(|code| (1..128).contains(&code))
                && !session_started(&session.directory().join("events"))
            {
                super::restart_gate::recovery_failed(
                    &paths.home,
                    session.directory(),
                    Some(&id),
                    cause,
                    super::restart_gate::RecoveryFailure::Resume,
                );
                if let Some(terminal) = &terminal {
                    terminal.restore();
                }
                if super::renew::failed_resume_stops(args, cause) {
                    let recovery = if cause == super::restart_gate::Cause::AuthRecovery {
                        "authentication recovery"
                    } else {
                        "token renewal"
                    };
                    eprintln!(
                        "claudectl: ERROR: Claude could not resume original session {id} (exit code {}). \
                         Automatic {recovery} stopped; use /resume {id} on the same account.",
                        exec::exit_code_of(&status)
                    );
                    return Ok(exec::exit_code_of(&status));
                }
                eprintln!(
                    "claudectl: ERROR: Claude could not resume session {id} (exit code {}). \
                     Starting a new session in this pane on the same token; open the old \
                     conversation with /resume {id}.",
                    exec::exit_code_of(&status)
                );
                launch_args =
                    super::renew::fresh_args(args).context("fresh start of a one-shot run")?;
                session.set_renewal("renewing")?;
                continue;
            }
            return Ok(exec::exit_code_of(&status));
        };
        resumed = Some((session_id.clone(), cause));
        if let Some(terminal) = &terminal {
            terminal.restore();
        }
        // A failover notice from this Claude, once the terminal is Claude's no longer.
        if let Some(notice) = &outcome.notice {
            eprintln!("claudectl: {notice}");
        }
        // Renewing until the next Claude runs.
        session.set_renewal("renewing")?;
        let continue_request = match kind {
            RestartKind::Renew(access) => {
                launch_args = if cause == super::restart_gate::Cause::AuthRecovery {
                    super::failover::unprompted_resume(args, &session_id)?
                } else {
                    super::failover::prompted_resume(args, &session_id, super::renew::CRON_NOTE)
                        .context("renewal of a one-shot run")?
                };
                session.renew(access)?;
                restarts.push(now());
                eprintln!("claudectl: server token renewed; resuming session {session_id}");
                false
            }
            RestartKind::Failover { account, access } => {
                // A new session for the new account: its session.json names the new alias
                // before Claude starts again. The checked binary moves with it.
                // The switch was recorded when the account was reserved (`failover::reserve`).
                launch_args = super::failover::resume_args(args, &session_id)
                    .context("failover of a one-shot run")?;
                let from = session.account().alias.clone();
                let next = Session::new(paths, &account, access)?;
                let moved = next.directory().join("claude");
                std::fs::rename(&snapshot, &moved)?;
                snapshot = moved;
                hooks = Some(next.adopt_hook(&session)?);
                settings = user_settings.write(next.directory(), hooks.as_deref())?;
                session = next;
                tried.push(from.clone());
                failovers.push(now());
                eprintln!(
                    "claudectl: {from} reached its usage limit; resuming session {session_id} on {}",
                    account.alias
                );
                true
            }
        };
        // Failover moves the hooks and settings into a new run directory. Arm cron
        // verification there, after either restart has selected its final session.
        cron_recovery =
            match super::crons::Recovery::prepare(&paths.home, session.directory(), &session_id) {
                Ok(recovery) => recovery,
                Err(error) => {
                    if let Err(error) = super::crons::log_notice(
                        &paths.home,
                        session.directory(),
                        &format!("cron recovery skipped: {error:#}"),
                    ) {
                        // The old child is stopped and the next has not spawned.
                        eprintln!("claudectl: could not record cron recovery: {error:#}");
                    }
                    None
                }
            };
        if let Some(mut recovery) = cron_recovery.take() {
            if continue_request {
                recovery.continue_request();
            }
            match recovery.resume_args(args, &session_id) {
                Ok(resumed_args) => {
                    launch_args = resumed_args;
                    cron_recovery = Some(recovery);
                }
                Err(error) => {
                    let message = match recovery.disarm(session.directory()) {
                        Ok(()) => format!("cron recovery skipped: {error:#}"),
                        Err(cleanup) => format!(
                            "cron recovery skipped: {error:#}; could not disarm: {cleanup:#}"
                        ),
                    };
                    if let Err(error) =
                        super::crons::log_notice(&paths.home, session.directory(), &message)
                    {
                        eprintln!("claudectl: could not record cron recovery: {error:#}");
                    }
                }
            }
        }
        first = false;
    }
}
#[cfg(not(unix))]
pub fn run(_: &Paths, _: &Client, _: &str, _: &Path, _: &[OsString], _: bool) -> Result<i32> {
    bail!("server sessions require Linux or macOS")
}

#[cfg(unix)]
struct Foreground(Option<libc::pid_t>);
#[cfg(unix)]
impl Foreground {
    fn set(group: libc::pid_t) -> bool {
        // Ignore terminal background-write suspension only while transferring foreground.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            let mut old: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTTOU);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old);
            let ok = libc::tcsetpgrp(libc::STDIN_FILENO, group) == 0;
            libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
            ok
        }
    }
    fn take(pid: u32) -> Self {
        let old = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
        if old > 0 && Self::set(pid as i32) {
            unsafe {
                libc::kill(-(pid as i32), libc::SIGCONT);
            };
            Self(Some(old))
        } else {
            Self(None)
        }
    }
}
#[cfg(unix)]
impl Drop for Foreground {
    fn drop(&mut self) {
        if let Some(group) = self.0 {
            Self::set(group);
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_hook_settings_record_failed_turns() {
        let home = tempfile::tempdir().unwrap();
        let paths = crate::config::Paths::from_home(home.path().into());
        let dir = paths.claudectl_dir().join("server/sessions/run-test");
        std::fs::create_dir_all(&dir).unwrap();
        let settings: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                super::write_hook_settings(&dir, std::path::Path::new("/bin/true")).unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "Stop",
            "StopFailure",
            "Notification",
            "SessionEnd",
        ] {
            assert!(settings["hooks"][event].is_array(), "{event}: {settings}");
        }
    }

    use super::*;

    #[cfg(unix)]
    #[test]
    fn a_shutdown_session_switch_retargets_only_same_account_recovery() {
        use super::super::restart_gate::Cause;
        let account = Account {
            provider: "anthropic".into(),
            account_id: "b".repeat(64),
            alias: "spare".into(),
            identity: Identity {
                account_uuid: "synthetic-account".into(),
                organization_uuid: "synthetic-org".into(),
            },
            available: true,
        };
        let access = Access {
            provider: account.provider.clone(),
            account_id: account.account_id.clone(),
            user_id: "synthetic-user".into(),
            identity: account.identity.clone(),
            access_token: "synthetic-token".into(),
            expires_at: i64::MAX,
            scopes: vec![],
            revision: "synthetic-revision".into(),
            generation: 1,
        };
        for (kind, cause, expected) in [
            (
                RestartKind::Renew(access.clone()),
                Cause::Renewal,
                "new-live",
            ),
            (
                RestartKind::Renew(access.clone()),
                Cause::AuthRecovery,
                "new-live",
            ),
            (
                RestartKind::Failover { account, access },
                Cause::Failover,
                "limited",
            ),
        ] {
            let restart = Restart {
                kind,
                session_id: "limited".into(),
                cause,
            }
            .with_current_session(Some("new-live"))
            .unwrap();
            assert_eq!(restart.session_id, expected, "{cause:?}");
        }
    }

    #[cfg(unix)]
    struct WaitingChild(std::process::Child);
    #[cfg(unix)]
    impl Drop for WaitingChild {
        fn drop(&mut self) {
            drop(self.0.stdin.take());
            let _ = self.0.wait();
        }
    }

    #[cfg(unix)]
    fn admission_fixture() -> (tempfile::TempDir, WaitingChild, Monitor, Activity) {
        use std::os::unix::process::CommandExt;
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let directory = root(&paths).join("sessions/run-admission");
        private_dir(&directory).unwrap();
        let child = WaitingChild(
            std::process::Command::new("/bin/sh")
                .args(["-c", "read -r _"])
                .stdin(std::process::Stdio::piped())
                .process_group(0)
                .spawn()
                .unwrap(),
        );
        let status = json!({"renewal":"on","alias":"work","pid":child.0.id()});
        atomic(&directory.join("session.json"), &status).unwrap();
        let at = now() - 600_000;
        std::fs::write(
            directory.join("events"),
            format!(
                "{}\n{}\n",
                json!({"at":at,"event":"SessionStart","session_id":"s"}),
                json!({"at":at,"event":"Stop","session_id":"s"}),
            ),
        )
        .unwrap();
        let mut activity = Activity::default();
        read_new_events(&directory.join("events"), &mut activity).unwrap();
        let monitor = Monitor {
            client: Client {
                connection: super::super::Connection {
                    server: "http://127.0.0.1:1".into(),
                    user_id: "offline".into(),
                    token_file: None,
                },
                token: "synthetic".into(),
                http: reqwest::blocking::Client::builder()
                    .no_proxy()
                    .build()
                    .unwrap(),
            },
            paths,
            directory,
            pid: child.0.id(),
            account_id: "a".repeat(64),
            held_revision: "old".into(),
            held_expires_at: now() + 240_000,
            renewable: true,
            recovery_resume: false,
            restarts: 1,
            tty: None,
            status,
            alias: "work".into(),
            failover: Some(Failover {
                tried: vec![],
                last_hour: 1,
            }),
            crons: None,
        };
        (home, child, monitor, activity)
    }

    #[cfg(unix)]
    #[test]
    fn completed_cron_recovery_logs_once_per_session() {
        const CHILD: &str = "CLAUDECTL_TEST_CRON_REPORT_ONCE";
        if std::env::var_os(CHILD).is_none() {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "central::session::tests::completed_cron_recovery_logs_once_per_session",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env("HERDR_TAB_ID", "w9C:tF")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let (_home, _child, mut monitor, _activity) = admission_fixture();
        let fleet = monitor.paths.home.join("Code/.fleet/example");
        private_dir(&fleet).unwrap();
        std::fs::write(fleet.join("check.txt"), "Check the owned lanes.\n").unwrap();
        std::fs::write(
            fleet.join("operator.md"),
            "operator_tab: w9C:tF\ncron_prompts: check.txt */5 * * * *\n",
        )
        .unwrap();
        let recovery =
            super::super::crons::Recovery::prepare(&monitor.paths.home, &monitor.directory, "s")
                .unwrap()
                .unwrap();
        let transcript = monitor.paths.home.join("recovery.jsonl");
        let rows = [
            json!({"type":"user","sessionId":"s","message":{"content":recovery.prompt()}}),
            json!({"type":"assistant","sessionId":"s","uuid":"a","message":{"content":[{"type":"tool_use","name":"CronList","id":"list","input":{}}]}}),
            json!({"type":"user","sessionId":"s","sourceToolAssistantUUID":"a","message":{"content":[{"type":"tool_result","tool_use_id":"list","content":"inventory"}]},"toolUseResult":{"jobs":[{"id":"kept","cron":"*/5 * * * *","prompt":"Check the owned lanes.\n","recurring":true,"durable":false}]}}),
        ];
        std::fs::write(
            &transcript,
            rows.iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
        monitor.crons = Some(recovery);
        let log = monitor
            .paths
            .home
            .join(".claudectl/server/cron-recovery.jsonl");
        monitor.check_crons(false).unwrap();
        assert!(!log.exists(), "no report before the recovery turn stops");
        super::super::crons::record_transcript(
            &monitor.directory,
            &json!({"hook_event_name":"Stop","session_id":"s","transcript_path":transcript}),
        )
        .unwrap();

        monitor.check_crons(false).unwrap();
        monitor.check_crons(true).unwrap();
        let text = std::fs::read_to_string(log).unwrap();
        let rows: Vec<Value> = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["session"], "run-admission");
        assert_eq!(rows[0]["message"], "crons intact: 1 jobs");
    }

    #[cfg(unix)]
    #[test]
    fn option_b_final_signal_requires_a_completed_quiet_window() {
        let (_home, mut child, monitor, mut activity) = admission_fixture();
        activity.idle.since = Some(now() - 600_001);
        let mut gate = super::super::restart_gate::Gate::new(
            &monitor.paths.home,
            &monitor.directory,
            monitor.pid,
            &monitor.alias,
        );
        let cause = super::super::restart_gate::Cause::Renewal;
        assert!(!gate.check_at(
            &activity.idle,
            cause,
            i64::MAX,
            Instant::now() - Duration::from_secs(600)
        ));
        assert_eq!(
            monitor.stop_for_restart(
                &mut activity,
                &mut gate,
                &super::super::renew::timing(),
                cause
            ),
            Ok(Some("s".into()))
        );
        let status: Value =
            serde_json::from_slice(&private_read(&monitor.directory.join("session.json")).unwrap())
                .unwrap();
        assert_eq!(status["renewal"], "renewing");
        assert!(!child.0.wait().unwrap().success());
    }

    #[cfg(unix)]
    #[test]
    fn captured_new_revision_does_not_restart_a_healthy_monitor() {
        let captured: Value =
            serde_json::from_str(include_str!("../tests/fixtures/restart-cadence.json")).unwrap();
        let held_for = captured["healthy_held"]["expires_at"].as_i64().unwrap()
            - captured["healthy_held"]["forced_at"].as_i64().unwrap();
        let waited = captured["healthy_held"]["forced_at"].as_i64().unwrap()
            - captured["healthy_held"]["observed_at"].as_i64().unwrap();
        for busy in [true, false] {
            let (_home, mut child, mut monitor, mut activity) = admission_fixture();
            monitor.held_expires_at = now() + held_for;
            activity.idle.since = (!busy).then(|| now() - 600_001);
            let mut gate = super::super::restart_gate::Gate::new(
                &monitor.paths.home,
                &monitor.directory,
                monitor.pid,
                &monitor.alias,
            );
            let cause = super::super::restart_gate::Cause::Renewal;
            gate.request_at(cause, Instant::now() - Duration::from_millis(waited as u64));
            assert_eq!(
                monitor.stop_for_restart(
                    &mut activity,
                    &mut gate,
                    &super::super::renew::timing(),
                    cause,
                ),
                Err(()),
                "a replacement revision must not restart a healthy child; busy={busy}",
            );
            assert!(child.0.try_wait().unwrap().is_none());
            let status: Value = serde_json::from_slice(
                &private_read(&monitor.directory.join("session.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(status["renewal"], "on");
        }
    }

    #[cfg(unix)]
    #[test]
    fn real_expiry_margin_and_fresh_rejection_still_restart_the_monitor() {
        use super::super::restart_gate::Cause;
        for (expires_in, rejected, cause) in [
            (-1, false, Cause::AuthRecovery),
            (240_000, false, Cause::Renewal),
            (28_000_000, true, Cause::AuthRecovery),
        ] {
            let (_home, mut child, mut monitor, mut activity) = admission_fixture();
            monitor.held_expires_at = now() + expires_in;
            activity.idle.since = None;
            if rejected {
                use std::io::Write;
                writeln!(std::fs::OpenOptions::new().append(true)
                    .open(monitor.directory.join("events")).unwrap(), "{}",
                    json!({"at":now(),"event":"StopFailure","session_id":"s","error":"authentication_failed"})).unwrap();
                monitor.read_events(&mut activity).unwrap();
            }
            let mut gate = super::super::restart_gate::Gate::new(
                &monitor.paths.home,
                &monitor.directory,
                monitor.pid,
                &monitor.alias,
            );
            gate.request_at(cause, Instant::now() - Duration::from_secs(600));
            assert_eq!(
                monitor.stop_for_restart(
                    &mut activity,
                    &mut gate,
                    &super::super::renew::timing(),
                    cause
                ),
                Ok(Some("s".into()))
            );
            assert!(!child.0.wait().unwrap().success());
        }
    }

    #[cfg(unix)]
    #[test]
    fn successful_stop_cancels_auth_recovery_before_the_final_signal() {
        use std::io::Write;
        let (_home, mut child, mut monitor, mut activity) = admission_fixture();
        monitor.held_expires_at = now() + 28_000_000;
        let events = monitor.directory.join("events");
        writeln!(std::fs::OpenOptions::new().append(true).open(&events).unwrap(), "{}",
            json!({"at":now(),"event":"StopFailure","session_id":"s","error":"authentication_failed"})).unwrap();
        monitor.read_events(&mut activity).unwrap();
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(&events)
                .unwrap(),
            "{}",
            json!({"at":now(),"event":"Stop","session_id":"s"})
        )
        .unwrap();
        let mut gate = super::super::restart_gate::Gate::new(
            &monitor.paths.home,
            &monitor.directory,
            monitor.pid,
            &monitor.alias,
        );
        assert_eq!(
            monitor.stop_for_restart(
                &mut activity,
                &mut gate,
                &super::super::renew::timing(),
                super::super::restart_gate::Cause::AuthRecovery
            ),
            Err(())
        );
        assert!(child.0.try_wait().unwrap().is_none());
        let status: Value =
            serde_json::from_slice(&private_read(&monitor.directory.join("session.json")).unwrap())
                .unwrap();
        assert_eq!(status["renewal"], "on");
    }

    #[cfg(unix)]
    #[test]
    fn captured_auth_failure_revalidates_cached_candidate_in_monitor() {
        const CHILD: &str = "CLAUDECTL_TEST_CADENCE_CANDIDATE";
        if std::env::var_os(CHILD).is_none() {
            for scenario in ["current", "observe-fails", "acquire-fails"] {
                let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "central::session::tests::captured_auth_failure_revalidates_cached_candidate_in_monitor",
                    "--nocapture",
                ])
                .env(CHILD, scenario)
                .env("CLAUDECTL_TEST_RENEW_FAST", "1")
                .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
                .output()
                .unwrap();
                assert!(
                    output.status.success(),
                    "{} {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr),
                );
            }
            return;
        }
        let scenario = std::env::var(CHILD).unwrap();
        let observation_failure = match scenario.as_str() {
            "observe-fails" => Some(("unavailable", "observe", "B")),
            "acquire-fails" => Some(("old", "acquire", "old")),
            _ => None,
        };

        use std::io::{BufRead, Read, Write};
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        };
        let (_home, mut child, mut monitor, _activity) = admission_fixture();
        let captured: Value =
            serde_json::from_str(include_str!("../tests/fixtures/restart-cadence.json")).unwrap();
        monitor.held_expires_at = now()
            + captured["fresh_auth"]["held_expires_at"].as_i64().unwrap()
            - captured["fresh_auth"]["at"].as_i64().unwrap();
        let events = monitor.directory.join("events");
        std::fs::write(
            &events,
            format!(
                "{}\n{}\n",
                json!({"at":now(),"event":"SessionStart","session_id":"s"}),
                json!({"at":now(),"event":"UserPromptSubmit","session_id":"s"}),
            ),
        )
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let current = Arc::new(Mutex::new("B"));
        let finished = Arc::new(AtomicBool::new(false));
        let server_current = current.clone();
        let server_finished = finished.clone();
        let server_events = events.clone();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut first = true;
            while !server_finished.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic server: {error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = std::io::BufReader::new(&mut stream);
                let mut request = String::new();
                reader.read_line(&mut request).unwrap();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                drop(reader);
                let (status, body) = if request.starts_with("POST /v2/anthropic/token ") {
                    let input: Value = serde_json::from_slice(&body).unwrap();
                    let current = *server_current.lock().unwrap();
                    let revision = if input["previous_revision"].is_string() {
                        if current == "old" {
                            "unavailable"
                        } else {
                            "unnecessary-forced-refresh"
                        }
                    } else {
                        current
                    };
                    if first {
                        first = false;
                        writeln!(
                            std::fs::OpenOptions::new()
                                .append(true)
                                .open(&server_events)
                                .unwrap(),
                            "{}",
                            json!({"at":now(),"event":"Stop","session_id":"s"})
                        )
                        .unwrap();
                    }
                    if revision == "unavailable" {
                        ("503 Unavailable", "{}".into())
                    } else {
                        ("200 OK", json!({"provider":"anthropic","account_id":"a".repeat(64),
                        "user_id":"offline","identity":{"account_uuid":"synthetic","organization_uuid":"synthetic"},
                        "access_token":"synthetic-only","expires_at":now()+28_800_000,
                        "scopes":[],"revision":revision,"generation":2}).to_string())
                    }
                } else {
                    ("503 Unavailable", "{}".into())
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        monitor.client.connection.server = origin;
        let directory = monitor.directory.clone();
        let (stop, stopped) = std::sync::mpsc::channel();
        let watcher = std::thread::spawn(move || monitor.watch(stopped));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = private_read(&directory.join("restart-status.json"))
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            if status.is_some_and(|status| status["reason"] == "quiet_window") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "Monitor never cached the first successor"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        *current.lock().unwrap() = observation_failure.map_or("C", |failure| failure.0);
        writeln!(std::fs::OpenOptions::new().append(true).open(&events).unwrap(),
            "{}", json!({"at":now(),"event":"StopFailure","session_id":"s","error":"authentication_failed"})).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        if let Some((_, failed_stage, expected_current)) = observation_failure {
            let journal = directory
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("restart-decisions.jsonl");
            loop {
                let observed = std::fs::read_to_string(&journal).unwrap_or_default();
                if observed.lines().any(|line| {
                    serde_json::from_str::<Value>(line).is_ok_and(|record| {
                        record["event"] == "recovery_failed" && record["reason"] == failed_stage
                    })
                }) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "failed observation was not reported"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "failed check used cached B"
            );
            let failure: Value = std::fs::read_to_string(&journal)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                .find(|record| {
                    record["event"] == "recovery_failed" && record["reason"] == failed_stage
                })
                .unwrap();
            assert_eq!(failure["held_revision"], "old");
            assert_eq!(failure["cached_revision"], "B");
            assert_eq!(failure["current_revision"], expected_current);
            let status: Value =
                serde_json::from_slice(&private_read(&directory.join("session.json")).unwrap())
                    .unwrap();
            assert_eq!(status["renewal"], "on");
            stop.send(()).unwrap();
            assert!(watcher.join().unwrap().restart.is_none());
            finished.store(true, Ordering::SeqCst);
            server.join().unwrap();
            return;
        }
        while child.0.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "Monitor did not recover a rejected token"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        stop.send(()).unwrap();
        let outcome = watcher.join().unwrap();
        finished.store(true, Ordering::SeqCst);
        server.join().unwrap();
        let RestartKind::Renew(access) = outcome.restart.unwrap().kind else {
            panic!("expected same-account recovery");
        };
        assert_eq!(
            access.revision, "C",
            "recovery reused the cached B revision"
        );
        let journal = std::fs::read_to_string(
            directory
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("restart-decisions.jsonl"),
        )
        .unwrap();
        let forced: Value = journal
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .find(|record| record["event"] == "restart_forced")
            .unwrap();
        assert_eq!(forced["held_revision"], "old");
        assert_eq!(forced["cached_revision"], "B");
        assert_eq!(forced["current_revision"], "C");
        assert!(
            !journal.contains("synthetic-only"),
            "token bytes leaked into diagnostics"
        );
    }

    #[cfg(unix)]
    #[test]
    fn renewal_deadline_uses_the_final_live_id_without_waiting_for_locks() {
        let (_home, mut child, monitor, mut activity) = admission_fixture();
        let lock = super::super::restart_gate::admission(&monitor.directory).unwrap();
        let hook_lock = super::super::restart_gate::hook_admission(&monitor.directory).unwrap();
        activity.idle.since = None;
        let mut gate = super::super::restart_gate::Gate::new(
            &monitor.paths.home,
            &monitor.directory,
            monitor.pid,
            &monitor.alias,
        );
        let cause = super::super::restart_gate::Cause::Renewal;
        gate.request_at(cause, Instant::now() - Duration::from_secs(600));
        use std::io::Write;
        let live = "31555be4-b5c0-4323-ab8b-5afe6b2ca78e";
        writeln!(
            std::fs::OpenOptions::new()
                .append(true)
                .open(monitor.directory.join("events"))
                .unwrap(),
            "{}",
            json!({"at":now(),"event":"UserPromptSubmit","session_id":live})
        )
        .unwrap();
        assert_eq!(
            monitor.stop_for_restart(
                &mut activity,
                &mut gate,
                &super::super::renew::timing(),
                cause,
            ),
            Ok(Some(live.into()))
        );
        drop(hook_lock);
        drop(lock);
        assert!(!child.0.wait().unwrap().success());
        let journal = std::fs::read_to_string(
            monitor
                .paths
                .home
                .join(".claudectl/server/restart-decisions.jsonl"),
        )
        .unwrap();
        let forced: Value = serde_json::from_str(journal.lines().last().unwrap()).unwrap();
        assert_eq!(forced["reason"], "renewal_deadline");
        assert_eq!(forced["session_id"], live);
        assert_eq!(forced["metric"]["value"], 1);
    }

    #[cfg(unix)]
    #[test]
    fn final_admission_defers_without_waiting_for_hook_or_restart_locks() {
        for hook_lock in [true, false] {
            for cause in [
                super::super::restart_gate::Cause::Renewal,
                super::super::restart_gate::Cause::Failover,
            ] {
                let (_home, mut child, monitor, mut activity) = admission_fixture();
                let directory = monitor.directory.clone();
                let lock = if hook_lock {
                    super::super::restart_gate::hook_admission(&directory).unwrap()
                } else {
                    super::super::restart_gate::admission(&directory).unwrap()
                };
                let (sent, received) = std::sync::mpsc::channel();
                let worker = std::thread::spawn(move || {
                    let mut gate = super::super::restart_gate::Gate::new(
                        &monitor.paths.home,
                        &monitor.directory,
                        monitor.pid,
                        &monitor.alias,
                    );
                    let deferred = monitor
                        .stop_for_restart(
                            &mut activity,
                            &mut gate,
                            &super::super::renew::timing(),
                            cause,
                        )
                        .is_err();
                    sent.send(deferred).unwrap();
                });
                let result = received.recv_timeout(Duration::from_secs(1));
                drop(lock);
                worker.join().unwrap();
                assert!(
                    matches!(result, Ok(true)),
                    "final admission waited or signaled without proof"
                );
                assert!(child.0.try_wait().unwrap().is_none());
                let status: Value =
                    serde_json::from_slice(&private_read(&directory.join("session.json")).unwrap())
                        .unwrap();
                assert_eq!(status["renewal"], "on");
                let deferred: Value = serde_json::from_slice(
                    &private_read(&directory.join("restart-status.json")).unwrap(),
                )
                .unwrap();
                assert_eq!(deferred["reason"], "quiet_window");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unknown_admission_does_not_consume_failover_deadline_or_accounting() {
        let (_home, mut child, monitor, mut activity) = admission_fixture();
        let mut gate = super::super::restart_gate::Gate::new(
            &monitor.paths.home,
            &monitor.directory,
            monitor.pid,
            &monitor.alias,
        );
        let mut pending = Pending::default();
        let target = monitor.failover_target(
            &mut activity,
            &mut gate,
            &super::super::renew::timing(),
            &mut pending,
            now(),
        );
        assert!(target.is_none());
        assert_eq!(pending.last_read, 0);
        assert!(pending.handled.is_none());
        assert_eq!(monitor.restarts, 1);
        assert_eq!(monitor.failover.as_ref().unwrap().last_hour, 1);
        assert!(!root(&monitor.paths).join("failovers.lock").exists());
        assert!(!root(&monitor.paths).join("failovers.jsonl").exists());
        assert!(child.0.try_wait().unwrap().is_none());
    }
    #[cfg(unix)]
    #[test]
    fn a_failover_session_keeps_the_hook_copy_it_started_with() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let identity = super::super::Identity {
            account_uuid: "a".into(),
            organization_uuid: "o".into(),
        };
        let account = |c: &str| Account {
            provider: "anthropic".into(),
            account_id: c.repeat(64),
            alias: c.into(),
            identity: identity.clone(),
            available: true,
        };
        let access = |a: &Account| Access {
            provider: "anthropic".into(),
            account_id: a.account_id.clone(),
            user_id: "u".into(),
            identity: identity.clone(),
            access_token: "synthetic".into(),
            expires_at: now() + 3_600_000,
            scopes: vec!["user:inference".into()],
            revision: "r".into(),
            generation: 1,
        };
        let (a, b) = (account("a"), account("b"));
        let first = Session::new(&paths, &a, access(&a)).unwrap();
        first.hook_settings().unwrap();
        let original = std::fs::read(first.directory().join("claudectl-hook")).unwrap();
        let next = Session::new(&paths, &b, access(&b)).unwrap();
        let settings = next.adopt_hook(&first).unwrap();
        let hook = next.directory().join("claudectl-hook");
        assert_eq!(std::fs::read(&hook).unwrap(), original);
        assert!(!first.directory().join("claudectl-hook").exists());
        let text = std::fs::read_to_string(settings).unwrap();
        assert!(text.contains(&hook.display().to_string()), "{text}");
        assert!(
            !text.contains(&first.directory().display().to_string()),
            "{text}"
        );
    }

    #[test]
    fn the_child_is_marked_as_a_server_run_session() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let identity = super::super::Identity {
            account_uuid: "a".into(),
            organization_uuid: "o".into(),
        };
        let account = Account {
            provider: "anthropic".into(),
            account_id: "a".repeat(64),
            alias: "work".into(),
            identity: identity.clone(),
            available: true,
        };
        let access = Access {
            provider: "anthropic".into(),
            account_id: account.account_id.clone(),
            user_id: "u".into(),
            identity,
            access_token: "synthetic".into(),
            expires_at: now() + 3_600_000,
            scopes: vec!["user:inference".into()],
            revision: "r".into(),
            generation: 1,
        };
        let session = Session::new(&paths, &account, access).unwrap();
        let command = session.command(Path::new("/bin/true"), &[]).unwrap();
        let env: std::collections::BTreeMap<_, _> = command.get_envs().collect();
        // The marker names this session's directory; a nested run checks it (preflight).
        assert_eq!(
            env.get(std::ffi::OsStr::new(SERVER_RUN_ENV))
                .copied()
                .flatten(),
            Some(session.directory().as_os_str())
        );
        let marker = session.directory().as_os_str();
        let token = std::ffi::OsStr::new("synthetic");
        // A live session's own token is accepted.
        assert!(own_session_token(&paths, Some(marker), Some(token)));
        // Another token, a missing marker, or a marker outside the sessions root is not.
        assert!(!own_session_token(
            &paths,
            Some(marker),
            Some("other".as_ref())
        ));
        assert!(!own_session_token(&paths, None, Some(token)));
        let forged = home.path().join("forged");
        std::fs::create_dir_all(&forged).unwrap();
        std::fs::write(
            forged.join("token.sha256"),
            serde_json::to_vec(&sha256_hex(b"synthetic")).unwrap(),
        )
        .unwrap();
        std::fs::write(forged.join("owner.lock"), "").unwrap();
        assert!(!own_session_token(
            &paths,
            Some(forged.as_os_str()),
            Some(token)
        ));
        // A session that ended (its lease released) no longer vouches for the token, even
        // when its files are still on disk.
        let kept = session.directory().with_extension("kept");
        std::fs::create_dir_all(&kept).unwrap();
        for file in ["token.sha256", "owner.lock"] {
            std::fs::copy(session.directory().join(file), kept.join(file)).unwrap();
        }
        assert!(!own_session_token(
            &paths,
            Some(kept.as_os_str()),
            Some(token)
        ));
        drop(command);
        let directory = session.directory().to_path_buf();
        drop(session);
        assert!(!own_session_token(
            &paths,
            Some(directory.as_os_str()),
            Some(token)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_event_log_is_an_error_and_keeps_no_new_idle_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("events");
        std::fs::write(
            &log,
            "{\"at\":1,\"event\":\"SessionStart\",\"session_id\":\"s\"}\n{\"at\":2,\"event\":\"Stop\",\"session_id\":\"s\"}\n",
        )
        .unwrap();
        let mut activity = Activity::default();
        read_new_events(&log, &mut activity).unwrap();
        assert_eq!(activity.idle.since, Some(2));
        // The log becomes unreadable (here: replaced by a directory) while a prompt runs.
        std::fs::remove_file(&log).unwrap();
        std::fs::create_dir(&log).unwrap();
        assert!(read_new_events(&log, &mut activity).is_err());
        // Missing after events were seen is an error too.
        std::fs::remove_dir(&log).unwrap();
        assert!(read_new_events(&log, &mut activity).is_err());
        // Missing before any event is no error.
        assert!(read_new_events(&log, &mut Activity::default()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn the_checked_copy_is_what_runs_when_the_source_is_swapped_mid_check() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let source = home.path().join("claude");
        std::fs::write(&source, b"checked build").unwrap();
        let original = exec::sha256_file(&source).unwrap();
        let build = qualified_build(&paths, &source, |snapshot, digest| {
            std::fs::write(&source, b"swapped build").unwrap();
            assert_eq!(exec::sha256_file(snapshot).unwrap(), digest);
            Ok(true)
        })
        .unwrap();
        assert_eq!(build.digest, original);
        assert_eq!(std::fs::read(&build.file).unwrap(), b"checked build");
        // The swapped source is not qualified by that check.
        let swapped = exec::sha256_file(&source).unwrap();
        assert!(!super::super::qualify::known(&paths, &swapped).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_launch_removes_build_copies_of_dead_launches_and_keeps_live_ones() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let builds = root(&paths).join("builds");
        let mut dead = std::process::Command::new("true").spawn().unwrap();
        let dead_pid = dead.id();
        dead.wait().unwrap();
        let stale = builds.join(format!("build-{dead_pid}-old"));
        let live = builds.join(format!("build-{}-busy", std::process::id()));
        for dir in [&stale, &live] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("claude"), b"copy").unwrap();
        }
        let source = home.path().join("claude");
        std::fs::write(&source, b"build").unwrap();
        let build = snapshot_build(&paths, &source).unwrap();
        assert!(!stale.exists(), "a dead launch's copy stays");
        assert!(live.exists(), "a live launch's copy was removed");
        assert!(build.file.exists());
    }

    #[cfg(unix)]
    #[test]
    fn a_build_that_fails_its_first_check_is_refused_before_any_server_call() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let source = home.path().join("claude");
        std::fs::write(&source, b"bad build").unwrap();
        assert!(qualified_build(&paths, &source, |_, _| Ok(false)).is_err());
    }

    #[test]
    fn host_user_settings_cannot_override_the_server_token_or_endpoint() {
        let home = tempfile::tempdir().unwrap();
        let cwd = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        std::fs::create_dir_all(home.path().join(".claude")).unwrap();
        assert!(preflight(&paths, cwd.path(), &[]).is_ok());
        for settings in [
            r#"{"env":{"ANTHROPIC_BASE_URL":"https://example.invalid"}}"#,
            r#"{"env":{"CLAUDE_CODE_OAUTH_TOKEN":"synthetic-other"}}"#,
            r#"{"apiKeyHelper":"/bin/echo synthetic"}"#,
        ] {
            std::fs::write(home.path().join(".claude/settings.json"), settings).unwrap();
            assert!(preflight(&paths, cwd.path(), &[]).is_err(), "{settings}");
        }
    }
}
