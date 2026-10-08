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
        atomic(
            &self.directory.path().join("session.json"),
            &json!({"alias":self.account.alias,"account_id":self.account.account_id,
                "expires_at":self.current.expires_at,"pid":std::process::id()}),
        )
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
    let session = Session::new(paths, &account, access)?;
    // The checked copy itself runs (same filesystem, so the rename keeps the file).
    let snapshot = session.directory().join("claude");
    std::fs::rename(&build.file, &snapshot)?;
    let mut command = session.command(&snapshot, args)?;
    exec::set_process_group(&mut command);
    struct Signals;
    impl Drop for Signals {
        fn drop(&mut self) {
            exec::signals::reset();
        }
    }
    exec::signals::install();
    let _signals = Signals;
    let mut child = command.spawn().context("could not start Claude")?;
    let pid = child.id();
    exec::signals::watch(pid);
    let foreground = Foreground::take(pid);
    let (stop, stopped) = std::sync::mpsc::channel();
    let writer_client = client.clone();
    let writer_paths = paths.clone();
    let writer = std::thread::spawn(move || {
        struct StopChild(u32);
        impl Drop for StopChild {
            fn drop(&mut self) {
                unsafe {
                    libc::kill(-(self.0 as i32), libc::SIGTERM);
                }
            }
        }
        let _stop_child = StopChild(pid);
        let mut last_usage = 0;
        while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            stopped.recv_timeout(Duration::from_secs(5))
        {
            if now() - last_usage >= 300_000 {
                if let Ok(usage) = writer_client.usage(&account.account_id, false) {
                    let _ = atomic(
                        &usage_path(
                            &writer_paths,
                            &writer_client.connection,
                            &account.account_id,
                        ),
                        &usage,
                    );
                }
                last_usage = now();
            }
        }
        session
    });
    let waited = exec::wait_exit_no_reap(pid, false);
    let _ = stop.send(());
    let session = writer
        .join()
        .map_err(|_| anyhow::anyhow!("credential writer stopped unexpectedly"));
    let descendants = if waited.is_ok() {
        Some(exec::teardown_group(pid))
    } else {
        None
    };
    exec::signals::unwatch();
    drop(foreground);
    let status = child.wait()?;
    waited?;
    let _session = session?;
    if !matches!(
        descendants,
        Some(exec::Descendants::None | exec::Descendants::Terminated | exec::Descendants::Killed)
    ) {
        bail!("Claude descendants could not be confirmed stopped");
    }
    Ok(exec::exit_code_of(&status))
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
