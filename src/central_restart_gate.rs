//! Admission for automatic renewal/failover. Workload evidence never authorizes a signal
//! on an I/O failure, and an expired token never overrides active work.
use super::*;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Cause {
    Renewal,
    Failover,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Reason {
    RunningTurn,
    BackgroundTask,
    ExplicitHold,
    StaleHold,
    EvidenceUnknown,
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

/// One gate per live Claude child. All automatic restart callers cross `check`.
pub(super) struct Gate {
    directory: PathBuf,
    home: PathBuf,
    pid: u32,
    alias: String,
    last: Option<Deferred>,
    total: u64,
    recorded: Option<Deferred>,
    last_session: Option<String>,
    recorded_session: Option<String>,
    log_error: bool,
    unknown_evidence: bool,
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
            recorded: None,
            last_session: None,
            recorded_session: None,
            log_error: false,
            unknown_evidence: false,
        }
    }

    /// Fresh workload evidence, with one diagnostic/counter per changed decision.
    /// Call once before provider reads and again under `admission` before SIGTERM.
    pub(super) fn check(
        &mut self,
        idle: &super::renew::Idle,
        cause: Cause,
        held_expires_at: i64,
    ) -> bool {
        if self.log_error {
            self.retry_error_status(idle, held_expires_at);
            return false;
        }
        let held = hold_reason(&self.home, &self.directory);
        let reason = if self.unknown_evidence {
            Some(Reason::EvidenceUnknown)
        } else if let Ok(Some(reason)) = held {
            Some(reason)
        } else if held.is_err() || idle.session.is_none() || idle.ended.is_some() {
            Some(Reason::EvidenceUnknown)
        } else if idle.since.is_none() {
            Some(Reason::RunningTurn)
        } else {
            match live_task(self.pid) {
                Ok(true) => Some(Reason::BackgroundTask),
                Ok(false) => None,
                Err(_) => Some(Reason::EvidenceUnknown),
            }
        };
        self.record(reason, idle, cause, held_expires_at)
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
        decision.is_none()
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
            if self.recorded != Some(d) || self.recorded_session.as_deref() != session {
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
                self.recorded = Some(d);
                self.recorded_session = session.map(str::to_owned);
            }
            status["cause"] = json!(d.cause);
            status["reason"] = json!(d.reason);
            status["stage"] = json!(d.stage);
            status["restart_deferred_total"] = json!(self.total);
        }
        atomic(&self.directory.join("restart-status.json"), &status)?;
        self.last = decision;
        self.last_session = session.map(str::to_owned);
        if decision.is_none() {
            self.recorded = None;
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
    fn an_idle_session_is_admitted() {
        let (_home, mut gate, idle) = setup();
        assert!(gate.check(&idle, Cause::Renewal, now() + 600_000));
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
        assert!(other_gate.check(&idle, Cause::Renewal, now() + 600_000));
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
