//! One server account per Claude process. The process keeps the host Claude config (its
//! conversations, skills, hooks and trust) and receives only a server access token in
//! CLAUDE_CODE_OAUTH_TOKEN. The token cannot change inside a running Claude (see
//! experiments/settings-renewal/host-config.py), so a session lasts until that token expires;
//! `session.json` records the expiry so a supervisor can relaunch with `--resume` first.
use super::*;
use crate::exec;
use std::{ffi::OsString, process::Command};

pub struct Session {
    directory: tempfile::TempDir,
    _lease: File,
    account: Account,
    current: Access,
    /// Token renewal state for supervisors (the capacity guard): on, off with a reason, or
    /// renewing. The guard leaves expiry to `server run` and skips a renewing session.
    renewal: String,
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
        // No token here: the alias, account and expiry only.
        atomic(&self.directory.path().join("session.json"), &self.status())
    }
    fn status(&self) -> serde_json::Value {
        json!({"alias":self.account.alias,"account_id":self.account.account_id,
            "expires_at":self.current.expires_at,"pid":std::process::id(),
            "renewal":self.renewal})
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
        let quote =
            |path: &Path| format!("'{}'", path.display().to_string().replace('\'', "'\\''"));
        let command = format!("{} server hook {}", quote(&hook), quote(self.directory()));
        let entry = json!([{"hooks": [{"type": "command", "command": command}]}]);
        let settings = self.directory().join("hooks.json");
        atomic(
            &settings,
            &json!({"hooks": {"SessionStart": entry, "UserPromptSubmit": entry,
                "Stop": entry, "Notification": entry}}),
        )?;
        Ok(settings)
    }
    pub fn expires_at(&self) -> i64 {
        self.current.expires_at
    }
    pub fn command(&self, program: &Path, args: &[OsString]) -> Result<Command> {
        let mut command = Command::new(program);
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
fn preflight(paths: &Paths, cwd: &Path, args: &[OsString]) -> Result<()> {
    for (name, _) in std::env::vars_os() {
        if name == exec::CONFIG_DIR_ENV || name.to_str().is_some_and(exec::is_scrubbed_env) {
            bail!(
                "inherited credential or routing override: {}",
                name.to_string_lossy()
            );
        }
    }
    for arg in args {
        if arg.to_str().is_some_and(|a| {
            ["--settings", "--setting-sources", "--bare"]
                .iter()
                .any(|flag| a == *flag || a.starts_with(&format!("{flag}=")))
        }) {
            bail!("launch argument overrides account isolation");
        }
    }
    exec::check_settings(cwd, &paths.home, &exec::managed_settings_dir())
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    // The child keeps the host config, so the host user settings load too: check them with
    // the same rules (no credential, endpoint or helper override of the server token).
    exec::check_user_settings(&paths.home).map_err(|e| anyhow::anyhow!("{e}"))
}
pub(super) fn program(path: &Path) -> Result<PathBuf> {
    if path.components().count() > 1 {
        return Ok(path.canonicalize()?);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|p| p.join(path))
        .find(|p| p.is_file())
        .context("Claude executable not found")?
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
struct Restart {
    access: Access,
    session_id: String,
}
#[cfg(unix)]
#[derive(Default)]
struct Outcome {
    /// Set only after the monitor itself sent SIGTERM for a renewal.
    restart: Option<Restart>,
    /// A renewal state change to record (for example, hooks missing).
    note: Option<String>,
}
/// Watches one Claude process: usage for the status line, and the account's token revision
/// for renewal (SAW-12610).
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
    restarts: usize,
    tty: Option<PathBuf>,
    /// The session.json content, to mark the session renewing before SIGTERM.
    status: serde_json::Value,
}
/// What the monitor knows about Claude's activity, read incrementally.
#[cfg(unix)]
#[derive(Default)]
struct Activity {
    offset: u64,
    idle: super::renew::Idle,
    seen_start: bool,
    baseline: Option<usize>,
}
#[cfg(unix)]
impl Monitor {
    /// Fold the hook events appended since the last read into the activity.
    fn read_events(&self, activity: &mut Activity) {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut file) = File::open(self.directory.join("events")) else {
            return;
        };
        let mut chunk = String::new();
        if file.seek(SeekFrom::Start(activity.offset)).is_ok()
            && file.read_to_string(&mut chunk).is_ok()
            && let Some(end) = chunk.rfind('\n')
        {
            activity.offset += end as u64 + 1;
            let events = super::renew::parse_events(&chunk[..end]);
            activity.seen_start |= events
                .iter()
                .any(|(_, e)| matches!(e, super::renew::Event::SessionStart(_)));
            super::renew::fold(&mut activity.idle, &events);
        }
    }
    /// The decision inputs from the current activity, terminal and process group. Without a
    /// server token, the server side equals the held one.
    fn inputs<'a>(
        &'a self,
        activity: &'a mut Activity,
        timing: &super::renew::Timing,
        started: i64,
        server: Option<&'a Access>,
    ) -> super::renew::Inputs<'a> {
        // Claude starts its MCP servers after SessionStart: take the baseline once it settled.
        if activity.idle.since.is_some()
            && activity.baseline.is_none()
            && now() - started >= timing.settle_ms
        {
            activity.baseline = exec::group_size(self.pid);
        }
        // Unknown membership counts as grown: never restart over unknown processes.
        let group_grew = match (activity.baseline, exec::group_size(self.pid)) {
            (Some(before), Some(current)) => current > before,
            _ => true,
        };
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
            group_grew,
            restarts_last_hour: self.restarts,
        }
    }
}
#[cfg(unix)]
impl Monitor {
    fn watch(self, stopped: std::sync::mpsc::Receiver<()>) -> Outcome {
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
        let mut last_check = 0;
        let mut renewing = self.renewable;
        let mut activity = Activity::default();
        let mut retry_now = false;
        let mut sent: Option<(i64, Restart)> = None;
        while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            stopped.recv_timeout(Duration::from_millis(timing.tick_ms))
        {
            if now() - last_usage >= 300_000 {
                if let Ok(usage) = self.client.usage(&self.account_id, false) {
                    let _ = atomic(
                        &usage_path(&self.paths, &self.client.connection, &self.account_id),
                        &usage,
                    );
                }
                last_usage = now();
            }
            if let Some((at, _)) = &sent {
                // Claude did not exit after SIGTERM: stop it.
                if now() - at > 10_000 {
                    unsafe {
                        libc::kill(self.pid as i32, libc::SIGKILL);
                    }
                }
                continue;
            }
            if !renewing {
                continue;
            }
            // A hook that could not record an event leaves this marker: the event log may
            // miss a prompt, so it can no longer prove Claude idle.
            if self.directory.join("hook-error").exists() {
                eprintln!(
                    "claudectl: a Claude hook event was not recorded; server token renewal is off for this session"
                );
                outcome.note = Some("off: hook write failed".into());
                renewing = false;
                continue;
            }
            self.read_events(&mut activity);
            if !activity.seen_start {
                if now() - started > timing.hooks_wait_ms {
                    eprintln!(
                        "claudectl: Claude sent no hook events; server token renewal is off for this session"
                    );
                    outcome.note = Some("off: no hook events".into());
                    renewing = false;
                }
                continue;
            }
            // Ask the server only while idle: near expiry the request refreshes the grant and
            // revokes the token a running turn would still use.
            if renew::idle_gate(&self.inputs(&mut activity, &timing, started, None)).is_err() {
                continue;
            }
            let interval = if self.held_expires_at - now() < 3_600_000 {
                timing.poll_near_ms
            } else {
                timing.poll_far_ms
            };
            if !retry_now && now() - last_check < interval {
                continue;
            }
            // Inside the server's refresh window our request would refresh the grant and
            // revoke the token a turn may still use: wait for expiry instead.
            if !renew::may_poll(now(), self.held_expires_at, timing.no_poll_ms) {
                continue;
            }
            last_check = now();
            retry_now = false;
            let access = match self.client.acquire(&self.account_id, None) {
                Ok(access) => access,
                Err(_) => {
                    // Retry soon: one failure near expiry must not use up the token's life.
                    // Nothing is printed: stderr is Claude's terminal.
                    last_check = now() - interval + timing.retry_ms;
                    continue;
                }
            };
            // Activity may have changed while the request ran (a prompt, typing): sample it
            // again and decide on the fresh state only.
            self.read_events(&mut activity);
            let inputs = self.inputs(&mut activity, &timing, started, Some(&access));
            if renew::idle_gate(&inputs).is_err() {
                // Claude became busy: restart at its next idle point, without the poll wait.
                retry_now = true;
            }
            let decision = renew::decide(&inputs);
            if decision == renew::Decision::Restart
                && let Some(session_id) = activity.idle.session.clone()
            {
                // Supervisors see the handoff before Claude stops.
                let mut status = self.status.clone();
                status["renewal"] = "renewing".into();
                if atomic(&self.directory.join("session.json"), &status).is_err() {
                    // Without the marker a supervisor could relaunch this session too.
                    continue;
                }
                // SIGTERM the leader; teardown of the rest of the group follows its exit.
                // Only a delivered signal makes the coming exit a renewal: if Claude already
                // exited, `server run` ends with its code.
                if unsafe { libc::kill(self.pid as i32, libc::SIGTERM) } != 0 {
                    let mut status = self.status.clone();
                    status["renewal"] = "on".into();
                    let _ = atomic(&self.directory.join("session.json"), &status);
                    break;
                }
                sent = Some((now(), Restart { access, session_id }));
            }
        }
        outcome.restart = sent.map(|(_, restart)| restart);
        outcome
    }
}

#[cfg(unix)]
pub fn run(
    paths: &Paths,
    client: &Client,
    alias: &str,
    binary: &Path,
    args: &[OsString],
) -> Result<i32> {
    let _slot = exec::RunSlot::take().map_err(|error| anyhow::anyhow!("{error}"))?;
    preflight(paths, &std::env::current_dir()?, args)?;
    let build = qualified_build(paths, &program(binary)?, super::qualify::harness)?;
    let account = client.account(alias)?;
    // Never force a refresh here: a provider refresh revokes the access token that every
    // other `server run` of this account is using (SAW-12610). The server refreshes on demand
    // near expiry.
    let access = client.acquire(&account.account_id, None)?;
    let mut session = Session::new(paths, &account, access)?;
    // The checked copy itself runs (same filesystem, so the rename keeps the file).
    let snapshot = session.directory().join("claude");
    std::fs::rename(&build.file, &snapshot)?;
    // A one-shot `-p` run is never restarted; an interactive session follows the account's
    // token revision (SAW-12610).
    let renewable = super::renew::relaunch_args(args, "probe").is_some();
    let hooks = if renewable {
        Some(session.hook_settings()?)
    } else {
        session.set_renewal("off: one-shot run")?;
        None
    };
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
    let mut first = true;
    loop {
        let mut command = session.command(&snapshot, &launch_args)?;
        if let Some(hooks) = &hooks {
            command.arg("--settings").arg(hooks);
        }
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
        if !first {
            // Before spawn: a failed write must not leave a Claude without its monitor.
            session.set_renewal("on")?;
        }
        let mut child = command.spawn().context("could not start Claude")?;
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
            account_id: account.account_id.clone(),
            directory: session.directory().to_path_buf(),
            held_revision: session.revision().to_string(),
            held_expires_at: session.expires_at(),
            pid,
            renewable: hooks.is_some(),
            restarts: restarts
                .iter()
                .filter(|&&at| now() - at < 3_600_000)
                .count(),
            tty: terminal.as_ref().and_then(|t| t.path.clone()),
            status: session.status(),
        };
        let watcher = std::thread::spawn(move || monitor.watch(stopped));
        let waited = exec::wait_exit_no_reap(pid, terminal.is_some());
        let _ = stop.send(());
        let outcome = watcher
            .join()
            .map_err(|_| anyhow::anyhow!("session monitor stopped unexpectedly"))?;
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
        if let Some(note) = &outcome.note {
            session.set_renewal(note)?;
        }
        // Relaunch only after our own SIGTERM; any other exit ends `server run` with the
        // child's code.
        let Some(Restart { access, session_id }) = outcome.restart else {
            return Ok(exec::exit_code_of(&status));
        };
        if let Some(terminal) = &terminal {
            terminal.restore();
        }
        // Renewing until the next Claude runs.
        session.set_renewal("renewing")?;
        session.renew(access)?;
        launch_args =
            super::renew::relaunch_args(args, &session_id).context("renewal of a one-shot run")?;
        restarts.push(now());
        first = false;
        eprintln!("claudectl: server token renewed; resuming session {session_id}");
    }
}
#[cfg(not(unix))]
pub fn run(_: &Paths, _: &Client, _: &str, _: &Path, _: &[OsString]) -> Result<i32> {
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
    use super::*;

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
