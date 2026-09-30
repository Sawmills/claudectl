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
}

impl ExecError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ExecError::Identity(_) => 3,
            ExecError::Pin(_) => 4,
            ExecError::Refused(_) => 5,
            ExecError::Receipt(_) => 6,
            ExecError::Spawn(_) => 7,
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

/// Validate everything before any child exists. Takes the auth lock only for
/// the reads that decide refresh ownership.
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

    let (creds, live) = {
        let _lock = lock_with_retry(store)?;
        let active = profile::get_active_from(paths)
            .map_err(|e| ExecError::Refused(format!("cannot read active profile: {e:#}")))?;
        if active.as_deref() == Some(alias.as_str()) {
            return Err(ExecError::Refused(format!(
                "'{alias}' is the active profile; Claude Code owns its login, run plain claude instead"
            )));
        }
        let creds = saved
            .read_credentials()
            .map_err(|e| ExecError::Refused(format!("saved credentials unreadable: {e:#}")))?;
        let live = store
            .read_refresh_owner()
            .map_err(|e| ExecError::Refused(format!("live refresh ownership unknown: {e:#}")))?;
        (creds, live)
    };

    let oauth = &creds.claude_ai_oauth;
    if oauth.access_token.trim().is_empty() {
        return Err(ExecError::Refused(format!(
            "'{alias}' has no access token; log in again"
        )));
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
    let needed_ms = i64::try_from(req.min_valid.as_millis()).unwrap_or(i64::MAX);
    if remaining_ms < needed_ms {
        return Err(ExecError::Refused(format!(
            "'{alias}' token is valid for {} min, {} min required; run `claudectl status {alias}` to refresh it",
            (remaining_ms.max(0)) / 60_000,
            needed_ms / 60_000
        )));
    }

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

/// Start the child and wait for it. Returns the exit code to propagate.
/// A receipt failure before the spawn starts no child; after the spawn it
/// stops the child and fails.
pub fn run(paths: &Paths, prepared: Prepared, req: &ExecRequest) -> Result<i32, ExecError> {
    let config_dir = fresh_config_dir(paths, &prepared.alias)?;
    let (reader, mut writer) =
        std::io::pipe().map_err(|e| ExecError::Spawn(format!("cannot create token pipe: {e}")))?;
    writer
        .write_all(prepared.token.as_bytes())
        .map_err(|e| ExecError::Spawn(format!("cannot write token pipe: {e}")))?;
    drop(writer);
    let fd = inheritable_fd(&reader)?;

    let mut receipt = Receipt::open(req.receipt.as_deref())?;
    let base = receipt_base(&prepared, config_dir.path(), req);
    receipt.write(&with(&base, "prepared", serde_json::json!({})))?;

    let mut command = Command::new(&prepared.program);
    command.args(&req.args);
    for name in SCRUBBED_ENV {
        command.env_remove(name);
    }
    command.env(CONFIG_DIR_ENV, config_dir.path());
    command.env(TOKEN_FD_ENV, fd.to_string());
    let spawned = command.spawn();
    drop(reader);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            let _ = receipt.write(&with(
                &base,
                "spawn_failed",
                serde_json::json!({ "error": error.to_string() }),
            ));
            return Err(ExecError::Spawn(error.to_string()));
        }
    };
    if let Err(error) = receipt.write(&with(
        &base,
        "started",
        serde_json::json!({ "pid": child.id() }),
    )) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let status = child
        .wait()
        .map_err(|e| ExecError::Spawn(format!("cannot wait for child: {e}")))?;
    let code = exit_code_of(&status);
    receipt.write(&with(
        &base,
        "exited",
        serde_json::json!({ "pid": child.id(), "exit_code": status.code(), "signal": signal_of(&status) }),
    ))?;
    Ok(code)
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
    file: Option<std::fs::File>,
}

impl Receipt {
    fn open(path: Option<&Path>) -> Result<Self, ExecError> {
        let Some(path) = path else {
            return Ok(Self { file: None });
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
        Ok(Self { file: Some(file) })
    }

    fn write(&mut self, record: &serde_json::Value) -> Result<(), ExecError> {
        let line = format!("{record}\n");
        match &mut self.file {
            Some(file) => file
                .write_all(line.as_bytes())
                .and_then(|()| file.sync_data())
                .map_err(|e| ExecError::Receipt(e.to_string())),
            None => std::io::stderr()
                .write_all(line.as_bytes())
                .map_err(|e| ExecError::Receipt(e.to_string())),
        }
    }
}

/// A new private directory per run, removed when the run ends.
fn fresh_config_dir(paths: &Paths, alias: &str) -> Result<tempfile::TempDir, ExecError> {
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

#[cfg(unix)]
fn inheritable_fd(reader: &std::io::PipeReader) -> Result<i32, ExecError> {
    use std::os::fd::AsRawFd;
    let fd = reader.as_raw_fd();
    // SAFETY: fcntl on a descriptor this process owns; clears only FD_CLOEXEC.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    if result == -1 {
        return Err(ExecError::Spawn(format!(
            "cannot make token pipe inheritable: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(fd)
}

#[cfg(not(unix))]
fn inheritable_fd(_reader: &std::io::PipeReader) -> Result<i32, ExecError> {
    Err(ExecError::Spawn("claudectl exec supports Unix only".into()))
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
        "m" => value * 60,
        "h" => value * 3600,
        _ => {
            return Err(format!(
                "invalid duration unit in '{input}' (use s, m or h)"
            ));
        }
    };
    Ok(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests;
