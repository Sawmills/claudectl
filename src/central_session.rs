//! One account per session; atomic settings publication outranks stored credentials.
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
        let conversations = root(paths).join("conversations").join(&account.account_id);
        private_dir(&conversations)?;
        let binding = conversations.join("account.json");
        let expected = json!({"provider":account.provider,"user_id":access.user_id,"identity":account.identity});
        if binding.try_exists()? {
            let stored: Value = serde_json::from_slice(&private_read(&binding)?)
                .context("invalid conversation account binding")?;
            if stored != expected {
                bail!("conversation storage belongs to another verified account");
            }
        } else {
            // Creating this binding is serialized with connection and migration changes.
            let _lock = lock(paths)?;
            if binding.try_exists()? {
                let stored: Value = serde_json::from_slice(&private_read(&binding)?)?;
                if stored != expected {
                    bail!("conversation storage belongs to another verified account");
                }
            } else {
                atomic(&binding, &expected)?;
            }
        }
        #[cfg(unix)]
        std::os::unix::fs::symlink(&conversations, directory.path().join("projects"))?;
        atomic(
            &directory.path().join(".claude.json"),
            &json!({"oauthAccount":{"accountUuid":account.identity.account_uuid,"organizationUuid":account.identity.organization_uuid}}),
        )?;
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
        atomic(
            &self.directory.path().join("settings.json"),
            &json!({"env":{"CLAUDE_CODE_OAUTH_TOKEN":self.current.access_token}}),
        )
    }
    pub fn publish(&mut self, access: Access) -> Result<()> {
        validate(&self.account, &access)?;
        if access.user_id != self.current.user_id || access.generation < self.current.generation {
            bail!("access grant changed company user or went backwards");
        }
        if access.generation == self.current.generation {
            if access.revision != self.current.revision
                || access.access_token != self.current.access_token
                || access.expires_at != self.current.expires_at
            {
                bail!("same revision contains different credentials");
            }
            return Ok(());
        }
        if access.revision == self.current.revision {
            bail!("new generation reused an old revision");
        }
        atomic(
            &self.directory.path().join("lease.json"),
            &json!({"expires_at":access.expires_at.max(self.current.expires_at)}),
        )?;
        atomic(
            &self.directory.path().join("settings.json"),
            &json!({"env":{"CLAUDE_CODE_OAUTH_TOKEN":access.access_token}}),
        )?;
        self.current = access;
        Ok(())
    }
    pub fn command(&self, program: &Path, args: &[OsString]) -> Result<Command> {
        let mut command = Command::new(program);
        command.args(args);
        for (name, _) in std::env::vars_os() {
            if name.to_str().is_some_and(exec::is_scrubbed_env) {
                command.env_remove(name);
            }
        }
        command.env(exec::CONFIG_DIR_ENV, self.directory.path());
        // If settings disappear, a fixed invalid fallback cannot select a local login.
        command.env(
            "CLAUDE_CODE_OAUTH_TOKEN",
            "claudectl-unavailable-access-token",
        );
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
fn preflight(paths: &Paths, args: &[OsString]) -> Result<()> {
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
    exec::check_settings(
        &std::env::current_dir()?,
        &paths.home,
        &exec::managed_settings_dir(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
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
/// Built-in hashes passed the synthetic checks in experiments/settings-renewal; other builds
/// need `claudectl server qualify` on this machine.
fn supported(paths: &Paths, path: &Path) -> Result<()> {
    let digest = exec::sha256_file(path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let allowed = if cfg!(target_os = "macos") {
        "bbe93063f7a0879a1021b2891e5c9354e5b3b98433e32efe6750f7710afed750"
    } else if cfg!(target_os = "linux") {
        "92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2"
    } else {
        bail!("server-account sessions support Linux and macOS");
    };
    if digest != allowed && !super::qualify::is_qualified(paths, &digest)? {
        bail!(
            "Claude build {digest} has not passed account-server compatibility checks; run `claudectl server qualify`"
        );
    }
    Ok(())
}

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
    preflight(paths, args)?;
    let binary = program(binary)?;
    supported(paths, &binary)?;
    let account = client.account(alias)?;
    let access = client.acquire(&account.account_id, None)?;
    let mut session = Session::new(paths, &account, access)?;
    // Snapshot before spawn, then verify the exact copy that will execute.
    let snapshot = session.directory().join("claude");
    snapshot_binary(&binary, &snapshot)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o500))?;
    }
    supported(paths, &snapshot)?;
    let mut launch_args = vec![OsString::from("--setting-sources"), OsString::from("user")];
    launch_args.extend_from_slice(args);
    let mut command = session.command(&snapshot, &launch_args)?;
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
        let mut outage = false;
        while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            stopped.recv_timeout(Duration::from_secs(5))
        {
            match writer_client.acquire(&account.account_id, None) {
                Ok(access) => {
                    if let Err(_error) = session.publish(access) {
                        eprintln!(
                            "Server grant or credential publication failed; stopping the pinned session."
                        );
                        // Leader remains unreaped until this thread joins, preventing PID reuse.
                        unsafe {
                            libc::kill(-(pid as i32), libc::SIGTERM);
                        }
                        break;
                    }
                    if outage {
                        eprintln!("Account server recovered; retry any failed prompt.");
                        outage = false;
                    }
                }
                Err(_) => {
                    if !outage {
                        eprintln!(
                            "Account server unavailable; keeping the current access token. Retry after recovery."
                        );
                        outage = true;
                    }
                }
            }
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
