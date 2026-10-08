//! Claude build qualification. `server run` accepts a build only when its hash is built in or
//! passed the launcher check on this machine; an unknown build is checked on first use. An
//! unknown or unreadable list refuses.
use super::*;
use crate::exec;
use std::time::{Duration, Instant};

/// How long a launch waits for another process's check of the same build.
const LOCK_WAIT: Duration = Duration::from_secs(90);
/// Hard limit on one harness run (about 15 s on the Mac mini for Claude 2.1.294).
const HARNESS_LIMIT: Duration = Duration::from_secs(75);
/// A failed build is not checked again on launch within this time; `server qualify` always is.
const FAILURE_HOLD_MINUTES: i64 = 60;

const HARNESS: [(&str, &str); 3] = [
    (
        "supervised.py",
        include_str!("../experiments/settings-renewal/supervised.py"),
    ),
    (
        "mac-settings-base.py",
        include_str!("../experiments/settings-renewal/mac-settings-base.py"),
    ),
    (
        "linux.py",
        include_str!("../experiments/settings-renewal/linux.py"),
    ),
];

/// The harness case a build must pass. A record from another case (an older launch model)
/// does not qualify the build for this one.
const CHECK: &str = "supervised_host_config";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Qualified {
    sha256: String,
    platform: String,
    qualified_at: String,
    #[serde(default)]
    check: String,
}

impl Qualified {
    fn covers(&self, digest: &str) -> bool {
        self.sha256 == digest && self.platform == std::env::consts::OS && self.check == CHECK
    }
}

/// A failed check, keyed like a pass.
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Failed {
    sha256: String,
    platform: String,
    check: String,
    failed_at: String,
}

impl Failed {
    fn covers(&self, digest: &str) -> bool {
        self.sha256 == digest && self.platform == std::env::consts::OS && self.check == CHECK
    }
}

fn failures_path(paths: &Paths) -> PathBuf {
    root(paths).join("qualify-failures.json")
}

/// A damaged failure list is an error, never "no failure".
fn load_failures(paths: &Paths) -> Result<Vec<Failed>> {
    let file = failures_path(paths);
    if !file.try_exists()? {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&private_read(&file)?).map_err(|_| {
        anyhow::anyhow!("Claude build qualification failure list is invalid; refusing")
    })
}

/// The Linux build that passed the host-config check on the devbox; no macOS build is built in.
fn builtin(digest: &str) -> bool {
    cfg!(target_os = "linux")
        && digest == "92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2"
}

/// Whether `server run` accepts this build without a check.
pub(super) fn known(paths: &Paths, digest: &str) -> Result<bool> {
    Ok(builtin(digest) || is_qualified(paths, digest)?)
}

/// Exclusive lock for one qualification at a time. Waits up to `wait`, naming the holder.
fn qualify_lock(paths: &Paths, wait: Duration) -> Result<File> {
    use std::io::{Read, Seek};
    let dir = root(paths);
    private_dir(&dir)?;
    let path = dir.join("qualify.lock");
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("qualification lock must not be a symlink");
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(&path)?;
    let start = Instant::now();
    let mut announced = false;
    loop {
        match file.try_lock() {
            Ok(()) => {
                file.set_len(0)?;
                file.rewind()?;
                write!(file, "{}", std::process::id())?;
                file.sync_all()?;
                return Ok(file);
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                let mut holder = String::new();
                file.rewind()?;
                let _ = file.read_to_string(&mut holder);
                let holder = holder.trim();
                if start.elapsed() >= wait {
                    bail!(
                        "Claude build qualification by pid {holder} did not finish within {} s; refusing",
                        wait.as_secs()
                    );
                }
                if !announced {
                    eprintln!("claudectl: waiting for qualification (pid {holder})");
                    announced = true;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(error.into()),
        }
    }
}

/// Run `harness` on `snapshot` and record the result. Call with the qualify lock held.
fn check(
    paths: &Paths,
    snapshot: &Path,
    digest: &str,
    harness: impl FnOnce(&Path, &str) -> Result<bool>,
) -> Result<()> {
    let result = harness(snapshot, digest);
    let _lock = lock(paths)?;
    let mut failures = load_failures(paths)?;
    failures.retain(|f| !f.covers(digest));
    match result {
        Ok(true) => {
            let mut builds = load(paths)?;
            if !builds.iter().any(|q| q.covers(digest)) {
                builds.push(Qualified {
                    sha256: digest.into(),
                    platform: std::env::consts::OS.into(),
                    qualified_at: chrono::Utc::now().to_rfc3339(),
                    check: CHECK.into(),
                });
                atomic(&path(paths), &builds)?;
            }
            atomic(&failures_path(paths), &failures)?;
            Ok(())
        }
        outcome => {
            // The latest result wins: a failed re-check withdraws an earlier pass.
            let builds = load(paths)?;
            if builds.iter().any(|q| q.covers(digest)) {
                let kept: Vec<Qualified> =
                    builds.into_iter().filter(|q| !q.covers(digest)).collect();
                atomic(&path(paths), &kept)?;
            }
            failures.push(Failed {
                sha256: digest.into(),
                platform: std::env::consts::OS.into(),
                check: CHECK.into(),
                failed_at: chrono::Utc::now().to_rfc3339(),
            });
            atomic(&failures_path(paths), &failures)?;
            let reason = match outcome {
                Err(error) => format!(": {error:#}"),
                _ => String::new(),
            };
            bail!("Claude build {digest} failed the launcher check{reason}; it is not qualified")
        }
    }
}

fn refuse_recent_failure(paths: &Paths, digest: &str) -> Result<()> {
    let hold = chrono::Duration::minutes(FAILURE_HOLD_MINUTES);
    if let Some(failed) = load_failures(paths)?.into_iter().find(|f| f.covers(digest))
        && chrono::DateTime::parse_from_rfc3339(&failed.failed_at)
            .is_ok_and(|at| chrono::Utc::now() - at.with_timezone(&chrono::Utc) < hold)
    {
        bail!(
            "Claude build {digest} failed the launcher check at {}; run `claudectl server qualify` to check it again",
            failed.failed_at
        );
    }
    Ok(())
}

/// `server run` on a build it does not know: check the exact snapshot it will run, once per
/// build across concurrent launches. A recent failure refuses without a new check.
pub(super) fn ensure(
    paths: &Paths,
    snapshot: &Path,
    digest: &str,
    harness: impl FnOnce(&Path, &str) -> Result<bool>,
) -> Result<()> {
    // A recent failure refuses even a built-in or earlier-qualified build.
    refuse_recent_failure(paths, digest)?;
    if known(paths, digest)? {
        return Ok(());
    }
    let _qualifying = qualify_lock(paths, LOCK_WAIT)?;
    refuse_recent_failure(paths, digest)?;
    if known(paths, digest)? {
        return Ok(());
    }
    eprintln!(
        "claudectl: qualifying Claude build {} (first use, about 15 s)",
        &digest[..12.min(digest.len())]
    );
    check(paths, snapshot, digest, harness)
}

/// Older clients keep `qualified-builds.json` and reject unknown fields, so these records live
/// in their own file; both client versions can run on one machine during an upgrade.
fn path(paths: &Paths) -> PathBuf {
    root(paths).join("qualified-host-config-builds.json")
}

fn load(paths: &Paths) -> Result<Vec<Qualified>> {
    let file = path(paths);
    if !file.try_exists()? {
        return Ok(Vec::new());
    }
    serde_json::from_slice(&private_read(&file)?)
        .map_err(|_| anyhow::anyhow!("qualified Claude build list is invalid; refusing"))
}

/// True when this machine qualified the build. A damaged list is an error, never a pass.
pub(super) fn is_qualified(paths: &Paths, digest: &str) -> Result<bool> {
    Ok(load(paths)?.iter().any(|q| q.covers(digest)))
}

/// Run `harness` on a private snapshot of `binary`; record the hash only when it returns true.
pub(super) fn qualify_with(
    paths: &Paths,
    binary: &Path,
    harness: impl FnOnce(&Path, &str) -> Result<bool>,
) -> Result<String> {
    // One copy: its hash is what is checked and recorded, whatever happens to `binary`.
    let directory = tempfile::tempdir()?;
    let snapshot = directory.path().join("claude");
    std::fs::copy(binary, &snapshot).context("could not copy the Claude build")?;
    let digest = exec::sha256_file(&snapshot).map_err(|e| anyhow::anyhow!("{e}"))?;
    let _qualifying = qualify_lock(paths, LOCK_WAIT)?;
    check(paths, &snapshot, &digest, harness)?;
    Ok(digest)
}

/// Run the synthetic launcher check: the real launcher and Claude build, a fake API and a host
/// login in the HOME; one tool call on the server token, then a `--resume` relaunch on a new
/// server token. The host token must never be sent and the host files must not change. The
/// harness blocks network access and the real credential store.
pub(super) fn harness(snapshot: &Path, digest: &str) -> Result<bool> {
    let directory = tempfile::tempdir()?;
    for (name, source) in HARNESS {
        std::fs::write(directory.path().join(name), source)?;
    }
    // The macOS harness sandbox reads builds only under the temp dir. The harness seeds this
    // digest as the only qualified build, so its launcher refuses a copy that differs.
    let copy = directory.path().join("claude");
    std::fs::copy(snapshot, &copy).context("could not copy the Claude build")?;
    let snapshot = copy.as_path();
    let launcher = std::env::current_exe()?;
    let script = directory.path().join("supervised.py");
    let mut command = if cfg!(target_os = "linux") {
        let mut command = std::process::Command::new("unshare");
        for kind in ["net", "mnt"] {
            let namespace = std::fs::read_link(format!("/proc/self/ns/{kind}"))?;
            command.env(
                format!("CLAUDECTL_PROBE_PARENT_{}", kind.to_uppercase()),
                namespace,
            );
        }
        command.args(["-Urnm", "python3", "-I"]).arg(&script);
        command
    } else if cfg!(target_os = "macos") {
        let mut command = std::process::Command::new("python3");
        command.arg("-I").arg(&script);
        command
    } else {
        bail!("Claude build qualification supports Linux and macOS");
    };
    command
        .env("CLAUDECTL_PROBE_BINARY", snapshot)
        .env("CLAUDECTL_PROBE_LAUNCHER", launcher)
        .env("CLAUDECTL_PROBE_QUALIFY_SHA256", digest)
        .current_dir(directory.path());
    let output = output_within(&mut command, HARNESS_LIMIT)?;
    let passed = output.status.success()
        && String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .is_ok_and(|v| v["case"] == CHECK && v["checks"] == "passed")
        });
    if !passed {
        print_tail(&output.stderr);
    }
    Ok(passed)
}

/// The last 20 lines of the harness's stderr, for the reason of a failed check.
fn print_tail(stderr: &[u8]) {
    let text = String::from_utf8_lossy(stderr);
    let lines: Vec<&str> = text.lines().collect();
    eprintln!("{}", lines[lines.len().saturating_sub(20)..].join("\n"));
}

/// Run `command` to completion within `limit`; past it, kill its process group and fail.
#[cfg(not(unix))]
fn output_within(
    _command: &mut std::process::Command,
    _limit: Duration,
) -> Result<std::process::Output> {
    bail!("Claude build qualification supports Linux and macOS")
}

/// Run `command` to completion within `limit`; past it, kill its process group and fail.
#[cfg(unix)]
fn output_within(
    command: &mut std::process::Command,
    limit: Duration,
) -> Result<std::process::Output> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .process_group(0);
    let mut child = command
        .spawn()
        .context("could not start the qualification harness (python3 required)")?;
    let mut stdout = child.stdout.take().context("no harness stdout")?;
    let mut stderr = child.stderr.take().context("no harness stderr")?;
    let out = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stdout.read_to_end(&mut buffer);
        buffer
    });
    let err = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        let _ = stderr.read_to_end(&mut buffer);
        buffer
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= limit {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            print_tail(&err.join().unwrap_or_default());
            bail!(
                "the qualification check did not finish within {} s",
                limit.as_secs_f32()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    Ok(std::process::Output {
        status,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

pub fn qualify(paths: &Paths, claude: &Path) -> Result<()> {
    let binary = session::program(claude)?;
    let digest = qualify_with(paths, &binary, harness)?;
    println!("Claude build {digest} passed the launcher check and is qualified.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Paths, PathBuf) {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let binary = home.path().join("claude-build");
        std::fs::write(&binary, b"synthetic claude build").unwrap();
        (home, paths, binary)
    }

    fn snapshot_of(paths: &Paths, binary: &Path) -> (tempfile::TempDir, PathBuf, String) {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("claude");
        std::fs::copy(binary, &file).unwrap();
        let digest = exec::sha256_file(&file).unwrap();
        private_dir(&root(paths)).unwrap();
        (dir, file, digest)
    }

    #[test]
    fn an_unknown_build_that_passes_on_first_use_is_recorded() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        ensure(&paths, &file, &digest, |snapshot, hash| {
            assert_eq!(snapshot, file.as_path());
            assert_eq!(hash, digest);
            Ok(true)
        })
        .unwrap();
        assert!(is_qualified(&paths, &digest).unwrap());
        // Known now: the check does not run again.
        ensure(&paths, &file, &digest, |_, _| panic!("checked twice")).unwrap();
    }

    #[test]
    fn a_failed_first_use_check_refuses_and_is_remembered_for_an_hour() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        assert!(ensure(&paths, &file, &digest, |_, _| Ok(false)).is_err());
        assert!(!is_qualified(&paths, &digest).unwrap());
        // A recent failure refuses without running the check again.
        let error = ensure(&paths, &file, &digest, |_, _| panic!("rerun")).unwrap_err();
        assert!(
            format!("{error:#}").contains("claudectl server qualify"),
            "{error:#}"
        );
        // An error from the harness counts as a failure too.
        let (_home2, paths2, binary2) = fixture();
        let (_dir2, file2, digest2) = snapshot_of(&paths2, &binary2);
        assert!(ensure(&paths2, &file2, &digest2, |_, _| bail!("no python3")).is_err());
        assert!(ensure(&paths2, &file2, &digest2, |_, _| panic!("rerun")).is_err());
    }

    #[test]
    fn a_failed_recheck_of_a_known_build_refuses_it() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        qualify_with(&paths, &binary, |_, _| Ok(true)).unwrap();
        assert!(qualify_with(&paths, &binary, |_, _| Ok(false)).is_err());
        assert!(
            !is_qualified(&paths, &digest).unwrap(),
            "the failed check kept the pass"
        );
        let error = ensure(&paths, &file, &digest, |_, _| panic!("rerun")).unwrap_err();
        assert!(
            format!("{error:#}").contains("claudectl server qualify"),
            "{error:#}"
        );
    }

    #[test]
    fn an_old_failure_runs_the_check_again() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        let old = vec![Failed {
            sha256: digest.clone(),
            platform: std::env::consts::OS.into(),
            check: CHECK.into(),
            failed_at: (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339(),
        }];
        atomic(&failures_path(&paths), &old).unwrap();
        ensure(&paths, &file, &digest, |_, _| Ok(true)).unwrap();
        assert!(is_qualified(&paths, &digest).unwrap());
        assert!(
            load_failures(&paths).unwrap().is_empty(),
            "a pass clears the failure"
        );
    }

    #[test]
    fn a_manual_qualify_ignores_a_recent_failure_and_clears_it() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        assert!(ensure(&paths, &file, &digest, |_, _| Ok(false)).is_err());
        assert_eq!(
            qualify_with(&paths, &binary, |_, _| Ok(true)).unwrap(),
            digest
        );
        assert!(load_failures(&paths).unwrap().is_empty());
        assert!(is_qualified(&paths, &digest).unwrap());
    }

    #[test]
    fn a_failure_for_another_platform_or_check_does_not_block() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        let now = chrono::Utc::now().to_rfc3339();
        let other = vec![
            Failed {
                sha256: digest.clone(),
                platform: "other-os".into(),
                check: CHECK.into(),
                failed_at: now.clone(),
            },
            Failed {
                sha256: digest.clone(),
                platform: std::env::consts::OS.into(),
                check: "old-check".into(),
                failed_at: now,
            },
        ];
        atomic(&failures_path(&paths), &other).unwrap();
        ensure(&paths, &file, &digest, |_, _| Ok(true)).unwrap();
    }

    #[test]
    fn a_damaged_failure_list_refuses() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        std::fs::write(failures_path(&paths), b"not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                failures_path(&paths),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        assert!(ensure(&paths, &file, &digest, |_, _| panic!("ran")).is_err());
        // Unknown fields are damage too.
        let extra = serde_json::json!([{"sha256": digest, "platform": std::env::consts::OS,
            "check": CHECK, "failed_at": "x", "note": 1}]);
        atomic(&failures_path(&paths), &extra).unwrap();
        assert!(load_failures(&paths).is_err());
    }

    #[test]
    fn concurrent_first_uses_run_the_check_once() {
        let (_home, paths, binary) = fixture();
        let (_dir, file, digest) = snapshot_of(&paths, &binary);
        let runs = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let threads: Vec<_> = (0..3)
            .map(|_| {
                let (paths, file, digest, runs) =
                    (paths.clone(), file.clone(), digest.clone(), runs.clone());
                std::thread::spawn(move || {
                    ensure(&paths, &file, &digest, |_, _| {
                        runs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(std::time::Duration::from_millis(300));
                        Ok(true)
                    })
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap().unwrap();
        }
        assert_eq!(runs.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn a_held_qualify_lock_is_waited_for_then_refused_at_the_limit() {
        let (_home, paths, _binary) = fixture();
        let _held = qualify_lock(&paths, std::time::Duration::from_secs(1)).unwrap();
        let start = std::time::Instant::now();
        let error = qualify_lock(&paths, std::time::Duration::from_millis(600)).unwrap_err();
        assert!(start.elapsed() >= std::time::Duration::from_millis(600));
        assert!(
            format!("{error:#}").contains(&std::process::id().to_string()),
            "{error:#}"
        );
    }

    #[test]
    fn the_manual_check_records_the_copy_it_checked_when_the_source_changes() {
        let (_home, paths, binary) = fixture();
        let original = exec::sha256_file(&binary).unwrap();
        let digest = qualify_with(&paths, &binary, |snapshot, hash| {
            std::fs::write(&binary, b"swapped mid-check").unwrap();
            assert_eq!(exec::sha256_file(snapshot).unwrap(), hash);
            Ok(true)
        })
        .unwrap();
        assert_eq!(digest, original);
        assert!(!is_qualified(&paths, &exec::sha256_file(&binary).unwrap()).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn a_harness_command_past_its_time_limit_is_killed() {
        let mut command = std::process::Command::new("sleep");
        command.arg("30");
        let start = std::time::Instant::now();
        let error = output_within(&mut command, std::time::Duration::from_millis(500)).unwrap_err();
        assert!(start.elapsed() < std::time::Duration::from_secs(10));
        assert!(format!("{error:#}").contains("did not finish"), "{error:#}");
        let mut quick = std::process::Command::new("sh");
        quick.args(["-c", "echo ok"]);
        let output = output_within(&mut quick, std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
    }

    #[test]
    fn a_build_that_fails_the_check_is_not_recorded() {
        let (_home, paths, binary) = fixture();
        assert!(qualify_with(&paths, &binary, |_, _| Ok(false)).is_err());
        assert!(qualify_with(&paths, &binary, |_, _| bail!("harness missing")).is_err());
        let digest = exec::sha256_file(&binary).unwrap();
        assert!(!is_qualified(&paths, &digest).unwrap());
    }

    #[test]
    fn a_build_that_passes_is_recorded_once_for_this_platform() {
        let (_home, paths, binary) = fixture();
        let digest = qualify_with(&paths, &binary, |snapshot, hash| {
            assert_ne!(snapshot, binary.as_path());
            assert_eq!(exec::sha256_file(snapshot).unwrap(), hash);
            Ok(true)
        })
        .unwrap();
        qualify_with(&paths, &binary, |_, _| Ok(true)).unwrap();
        assert!(is_qualified(&paths, &digest).unwrap());
        assert_eq!(load(&paths).unwrap().len(), 1);
        assert!(!is_qualified(&paths, &"0".repeat(64)).unwrap());
    }

    #[test]
    fn a_build_qualified_by_an_older_check_is_not_qualified() {
        let (_home, paths, _binary) = fixture();
        private_dir(&root(&paths)).unwrap();
        let digest = "1".repeat(64);
        let old = serde_json::json!([{
            "sha256": digest,
            "platform": std::env::consts::OS,
            "qualified_at": "2026-10-07T00:00:00Z",
        }]);
        atomic(&path(&paths), &old).unwrap();
        assert!(!is_qualified(&paths, &digest).unwrap());
    }

    #[test]
    fn qualifying_leaves_the_list_of_older_clients_unchanged() {
        // Older clients reject unknown fields, so they must never read a record with `check`.
        let (_home, paths, binary) = fixture();
        private_dir(&root(&paths)).unwrap();
        let legacy = root(&paths).join("qualified-builds.json");
        let old = serde_json::json!([{
            "sha256": "1".repeat(64),
            "platform": std::env::consts::OS,
            "qualified_at": "2026-10-07T00:00:00Z",
        }]);
        atomic(&legacy, &old).unwrap();
        let before = std::fs::read(&legacy).unwrap();
        let digest = qualify_with(&paths, &binary, |_, _| Ok(true)).unwrap();
        assert!(is_qualified(&paths, &digest).unwrap());
        assert_eq!(std::fs::read(&legacy).unwrap(), before);
    }

    #[test]
    fn the_harness_seeds_the_record_this_client_reads() {
        // The harness launches `server run` on the candidate build, so its throwaway HOME must
        // hold a record that `is_qualified` accepts, or every non-built-in build is refused.
        let (_home, paths, _binary) = fixture();
        let file = path(&paths);
        let name = file.file_name().unwrap().to_str().unwrap();
        let (_, source) = HARNESS[0];
        assert!(source.contains(&format!("client / '{name}'")), "{name}");
        assert!(source.contains(&format!("'check': '{CHECK}'")), "{CHECK}");
    }

    #[test]
    fn a_damaged_list_refuses_instead_of_passing() {
        let (_home, paths, _binary) = fixture();
        private_dir(&root(&paths)).unwrap();
        std::fs::write(path(&paths), b"not json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path(&paths), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(is_qualified(&paths, &"0".repeat(64)).is_err());
    }
}
