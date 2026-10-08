#![cfg(unix)]
//! `claudectl shim`: a `claude` launcher first on PATH that runs Claude through
//! `claudectl server run` (SAW-12668). The generated script runs here against a fake
//! claudectl and a fake claude that print their argv, so no server and no real Claude.
use claudectl::central::shim::{self, Spec};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A fake program that prints its name and argv, one per line.
fn fake(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!("#!/bin/sh\necho {name}\nfor a in \"$@\"; do echo \"$a\"; done\n"),
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

struct Fixture {
    _root: tempfile::TempDir,
    dir: PathBuf,
    real: PathBuf,
    claudectl: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("real bin");
        std::fs::create_dir_all(&bin).unwrap();
        let real = fake(&bin, "claude");
        let claudectl = fake(&bin, "claudectl");
        Self {
            dir: root.path().join("shim"),
            _root: root,
            real,
            claudectl,
        }
    }
    fn spec(&self, alias: &str) -> Spec {
        Spec {
            alias: alias.into(),
            real: self.real.clone(),
            claudectl: self.claudectl.clone(),
        }
    }
    /// Run the installed shim: its stdout lines.
    fn run(&self, args: &[&str], env: &[(&str, &str)]) -> Vec<String> {
        // Linux: a parallel test may fork while a just-written script is still open for
        // writing in its child, so exec briefly fails with ETXTBSY. Retry only that.
        let output = (0..50)
            .find_map(|_| {
                match Command::new(self.dir.join("claude"))
                    .args(args)
                    .envs(env.iter().copied())
                    .output()
                {
                    Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                        std::thread::sleep(std::time::Duration::from_millis(20));
                        None
                    }
                    other => Some(other.unwrap()),
                }
            })
            .expect("the shim stayed busy");
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }
}

#[test]
fn the_shim_runs_claude_through_server_run_with_the_real_binary() {
    let f = Fixture::new();
    let installed = shim::install(&f.spec("amir3"), &f.dir).unwrap();
    assert_eq!(installed, f.dir.join("claude"));
    let mode = std::fs::metadata(&installed).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    assert!(shim::is_shim(&installed));
    let real = f.real.to_str().unwrap();
    assert_eq!(
        f.run(&["--resume", "abc", "two words"], &[]),
        [
            "claudectl",
            "server",
            "run",
            "amir3",
            "--claude",
            real,
            "--",
            "--resume",
            "abc",
            "two words"
        ]
    );
    // No arguments: an interactive session.
    assert_eq!(
        f.run(&[], &[]),
        [
            "claudectl",
            "server",
            "run",
            "amir3",
            "--claude",
            real,
            "--"
        ]
    );
}

#[test]
fn the_escape_hatch_and_token_free_commands_run_the_real_claude() {
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    assert_eq!(
        f.run(&["-p", "hi"], &[("CLAUDECTL_SHIM", "off")]),
        ["claude", "-p", "hi"]
    );
    for first in [
        "-v",
        "--version",
        "-h",
        "--help",
        "update",
        "doctor",
        "install",
    ] {
        assert_eq!(f.run(&[first], &[]), ["claude", first], "{first}");
    }
    // Only the first argument decides: a prompt that mentions --help still goes to the server.
    assert_eq!(f.run(&["-p", "--help"], &[])[0], "claudectl");
}

#[test]
fn quoting_survives_hostile_paths_and_aliases() {
    let f = Fixture::new();
    let root = f.dir.parent().unwrap().join("it's $(here)");
    std::fs::create_dir_all(&root).unwrap();
    let spec = Spec {
        alias: "a'b".into(),
        real: fake(&root, "claude"),
        claudectl: fake(&root, "claudectl"),
    };
    shim::install(&spec, &f.dir).unwrap();
    let out = f.run(&["x"], &[]);
    assert_eq!(out[..4], ["claudectl", "server", "run", "a'b"]);
    assert_eq!(out[5], spec.real.to_str().unwrap());
}

#[test]
fn install_refuses_recursion_and_foreign_files() {
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let shim_path = f.dir.join("claude");
    // The real Claude must not be the shim, or any shim.
    let mut spec = f.spec("amir3");
    spec.real = shim_path.clone();
    assert!(shim::install(&spec, &f.dir).is_err());
    let other = f.dir.parent().unwrap().join("other-shim");
    shim::install(&f.spec("amir3"), &other).unwrap();
    spec.real = other.join("claude");
    assert!(shim::install(&spec, &f.dir).is_err());
    // A symlink to the shim is the shim.
    let link = f.dir.parent().unwrap().join("link-to-shim");
    std::os::unix::fs::symlink(&shim_path, &link).unwrap();
    spec.real = link;
    assert!(shim::install(&spec, &f.dir).is_err());
    // A missing real binary is refused.
    spec.real = f.dir.parent().unwrap().join("missing");
    assert!(shim::install(&spec, &f.dir).is_err());
    // Re-install over our own shim works; a foreign file is never overwritten.
    shim::install(&f.spec("amir5"), &f.dir).unwrap();
    assert_eq!(f.run(&["x"], &[])[3], "amir5");
    let foreign = f.dir.parent().unwrap().join("foreign");
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(foreign.join("claude"), "#!/bin/sh\necho mine\n").unwrap();
    assert!(shim::install(&f.spec("amir3"), &foreign).is_err());
    assert_eq!(
        std::fs::read_to_string(foreign.join("claude")).unwrap(),
        "#!/bin/sh\necho mine\n"
    );
}

#[test]
fn the_real_claude_is_the_first_non_shim_claude_on_path() {
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let path =
        std::env::join_paths([f.dir.clone(), f.real.parent().unwrap().to_path_buf()]).unwrap();
    assert_eq!(shim::find_real(None, &path).unwrap(), f.real);
    let only_shim = std::env::join_paths([f.dir.clone()]).unwrap();
    assert!(shim::find_real(None, &only_shim).is_err());
    // An explicit path is kept as given, not canonicalized.
    assert_eq!(shim::find_real(Some(&f.real), &only_shim).unwrap(), f.real);
}

#[test]
fn uninstall_removes_only_a_shim_and_status_reads_path_order() {
    let f = Fixture::new();
    assert!(!shim::uninstall(&f.dir).unwrap());
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let real_dir = f.real.parent().unwrap().to_path_buf();
    let first = std::env::join_paths([f.dir.clone(), real_dir.clone()]).unwrap();
    let status = shim::status(&f.dir, &first).unwrap();
    assert_eq!(status.alias.as_deref(), Some("amir3"));
    assert_eq!(status.real.as_deref(), Some(f.real.as_path()));
    assert!(status.real_ok && status.first_on_path);
    let later = std::env::join_paths([real_dir, f.dir.clone()]).unwrap();
    assert!(!shim::status(&f.dir, &later).unwrap().first_on_path);
    std::fs::remove_file(&f.real).unwrap();
    assert!(!shim::status(&f.dir, &first).unwrap().real_ok);
    assert!(shim::uninstall(&f.dir).unwrap());
    assert!(!f.dir.join("claude").exists());
    std::fs::create_dir_all(&f.dir).unwrap();
    std::fs::write(f.dir.join("claude"), "#!/bin/sh\n").unwrap();
    assert!(shim::uninstall(&f.dir).is_err(), "a foreign file is kept");
    assert!(f.dir.join("claude").exists());
}

#[test]
fn server_run_refuses_the_shim_as_its_claude_before_any_server_call() {
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let home = f.dir.parent().unwrap().join("home");
    std::fs::create_dir_all(&home).unwrap();
    // No connection exists under this HOME: the refusal must come first.
    let output = Command::new(env!("CARGO_BIN_EXE_claudectl"))
        .args(["server", "run", "amir3", "--claude"])
        .arg(f.dir.join("claude"))
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("claudectl shim"), "{stderr}");
}

#[test]
fn an_absolute_path_call_bypasses_the_shim_and_its_directory_is_never_overwritten() {
    // OpenClaw runs the real binary by absolute path; the shim lives elsewhere.
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let direct = Command::new(&f.real).arg("-p").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&direct.stdout), "claude\n-p\n");
    // Installing into the real binary's own directory would replace it: refused, untouched.
    let before = std::fs::read(&f.real).unwrap();
    assert!(shim::install(&f.spec("amir3"), f.real.parent().unwrap()).is_err());
    assert_eq!(std::fs::read(&f.real).unwrap(), before);
    assert!(!shim::is_shim(&f.real));
}

#[test]
fn the_default_account_is_the_hook_for_a_later_picker() {
    assert_eq!(shim::default_account(), "amir@sawmills.ai");
}
