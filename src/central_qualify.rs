//! Claude build qualification. `server run` accepts a build only when its hash is built in or
//! passed the renewal handoff check on this machine. An unknown or unreadable list refuses.
use super::*;
use crate::exec;

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

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Qualified {
    sha256: String,
    platform: String,
    qualified_at: String,
}

fn path(paths: &Paths) -> PathBuf {
    root(paths).join("qualified-builds.json")
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
    let platform = std::env::consts::OS;
    Ok(load(paths)?
        .iter()
        .any(|q| q.sha256 == digest && q.platform == platform))
}

/// Run `harness` on a private snapshot of `binary`; record the hash only when it returns true.
pub(super) fn qualify_with(
    paths: &Paths,
    binary: &Path,
    harness: impl FnOnce(&Path, &str) -> Result<bool>,
) -> Result<String> {
    let directory = tempfile::tempdir()?;
    let snapshot = directory.path().join("claude");
    std::fs::copy(binary, &snapshot).context("could not copy the Claude build")?;
    let digest = exec::sha256_file(&snapshot).map_err(|e| anyhow::anyhow!("{e}"))?;
    if !harness(&snapshot, &digest)? {
        bail!("Claude build {digest} failed the renewal handoff check; it is not qualified");
    }
    let _lock = lock(paths)?;
    let mut builds = load(paths)?;
    if !builds
        .iter()
        .any(|q| q.sha256 == digest && q.platform == std::env::consts::OS)
    {
        builds.push(Qualified {
            sha256: digest.clone(),
            platform: std::env::consts::OS.into(),
            qualified_at: chrono::Utc::now().to_rfc3339(),
        });
        atomic(&path(paths), &builds)?;
    }
    Ok(digest)
}

/// Run the synthetic renewal handoff check: the real launcher and Claude build, a fake API, an
/// invalid process token, and one settings token change during a tool call. The harness blocks
/// network access and the real credential store.
fn harness(snapshot: &Path, digest: &str) -> Result<bool> {
    let directory = tempfile::tempdir()?;
    for (name, source) in HARNESS {
        std::fs::write(directory.path().join(name), source)?;
    }
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
    let output = command
        .env("CLAUDECTL_PROBE_BINARY", snapshot)
        .env("CLAUDECTL_PROBE_LAUNCHER", launcher)
        .env("CLAUDECTL_PROBE_QUALIFY_SHA256", digest)
        .current_dir(directory.path())
        .output()
        .context("could not start the qualification harness (python3 required)")?;
    let passed = output.status.success()
        && String::from_utf8_lossy(&output.stdout).lines().any(|line| {
            serde_json::from_str::<Value>(line)
                .is_ok_and(|v| v["case"] == "supervised_tool_renewal" && v["checks"] == "passed")
        });
    if !passed {
        eprintln!(
            "{}",
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .rev()
                .take(20)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
    Ok(passed)
}

pub fn qualify(paths: &Paths, claude: &Path) -> Result<()> {
    let binary = session::program(claude)?;
    let digest = qualify_with(paths, &binary, harness)?;
    println!("Claude build {digest} passed the renewal handoff check and is qualified.");
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
