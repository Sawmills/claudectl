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

#[test]
fn install_never_writes_through_a_planted_symlink() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.dir).unwrap();
    let victim = f.dir.parent().unwrap().join("victim");
    std::fs::write(&victim, "keep me\n").unwrap();
    // The old fixed temporary name, pointed at a file outside the shim directory.
    std::os::unix::fs::symlink(&victim, f.dir.join(".claude.claudectl-shim.tmp")).unwrap();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me\n");
    assert!(shim::is_shim(&f.dir.join("claude")));
    // No temporary file is left behind.
    let left: Vec<_> = std::fs::read_dir(&f.dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".tmp") && n != ".claude.claudectl-shim.tmp")
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn a_non_executable_claude_is_never_the_real_claude() {
    let f = Fixture::new();
    let early = f.dir.parent().unwrap().join("early");
    std::fs::create_dir_all(&early).unwrap();
    std::fs::write(early.join("claude"), "not a program\n").unwrap();
    std::fs::set_permissions(early.join("claude"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let path =
        std::env::join_paths([early.clone(), f.real.parent().unwrap().to_path_buf()]).unwrap();
    // Discovery skips it; an explicit path or an install refuses it.
    assert_eq!(shim::find_real(None, &path).unwrap(), f.real);
    assert!(shim::find_real(Some(&early.join("claude")), &path).is_err());
    let mut spec = f.spec("amir3");
    spec.real = early.join("claude");
    assert!(shim::install(&spec, &f.dir).is_err());
    // Status reports a real Claude that lost its execute bit.
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    std::fs::set_permissions(&f.real, std::fs::Permissions::from_mode(0o644)).unwrap();
    let first = std::env::join_paths([f.dir.clone()]).unwrap();
    assert!(!shim::status(&f.dir, &first).unwrap().real_ok);
}

#[test]
fn server_qualify_refuses_the_shim_as_its_claude() {
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let home = f.dir.parent().unwrap().join("home-q");
    std::fs::create_dir_all(&home).unwrap();
    // The default `claude` resolves through PATH, where the shim comes first.
    let path =
        std::env::join_paths([f.dir.clone(), f.real.parent().unwrap().to_path_buf()]).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_claudectl"))
        .args(["server", "qualify"])
        .env("HOME", &home)
        .env("PATH", path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("claudectl shim"), "{stderr}");
}

#[test]
fn status_is_broken_when_the_recorded_claudectl_is_gone() {
    let f = Fixture::new();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let first = std::env::join_paths([f.dir.clone()]).unwrap();
    assert!(shim::status(&f.dir, &first).unwrap().claudectl_ok);
    std::fs::remove_file(&f.claudectl).unwrap();
    assert!(!shim::status(&f.dir, &first).unwrap().claudectl_ok);
}

#[test]
fn the_printed_path_line_is_shell_safe() {
    assert_eq!(
        shim::path_line(Path::new("/home/a/.local/claudectl/bin")),
        r#"export PATH="/home/a/.local/claudectl/bin:$PATH""#
    );
    let hostile = shim::path_line(Path::new("/tmp/$(touch x) \"q\" it's"));
    assert_eq!(
        hostile,
        r#"export PATH='/tmp/$(touch x) "q" it'\''s':"$PATH""#
    );
    // The shell reads it back as the literal directory.
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!("{hostile}; printf %s \"${{PATH%%:*}}\""))
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "/tmp/$(touch x) \"q\" it's"
    );
}

#[test]
fn the_shim_passes_the_environment_through_unchanged() {
    // `server run` decides whether an inherited token is its own session's (preflight);
    // the shim never strips one, so a forged marker cannot launder a hand-set token.
    let f = Fixture::new();
    std::fs::write(
        &f.claudectl,
        "#!/bin/sh\necho \"token=${CLAUDE_CODE_OAUTH_TOKEN-unset} marker=${CLAUDECTL_SERVER_RUN-unset}\"\n",
    )
    .unwrap();
    shim::install(&f.spec("amir3"), &f.dir).unwrap();
    let env = [
        ("CLAUDE_CODE_OAUTH_TOKEN", "mine"),
        ("CLAUDECTL_SERVER_RUN", "/forged"),
    ];
    assert_eq!(f.run(&["-p", "x"], &env), ["token=mine marker=/forged"]);
}

#[test]
fn an_alias_that_looks_like_an_option_is_refused() {
    let f = Fixture::new();
    for alias in ["-work", "--", "--claude"] {
        assert!(shim::install(&f.spec(alias), &f.dir).is_err(), "{alias}");
    }
    assert!(!f.dir.join("claude").exists());
}

#[test]
fn relative_paths_become_absolute_without_resolving_symlinks() {
    let f = Fixture::new();
    let bin = f.real.parent().unwrap();
    // A relative PATH entry, read against a base directory.
    let found = shim::find_real_from(
        None,
        std::ffi::OsStr::new("real bin"),
        bin.parent().unwrap(),
    )
    .unwrap();
    assert_eq!(found, f.real);
    assert!(found.is_absolute());
    // A symlinked real Claude stays the link, not its target.
    let link = bin.parent().unwrap().join("claude-link");
    std::os::unix::fs::symlink(&f.real, &link).unwrap();
    assert_eq!(
        shim::find_real(Some(&link), std::ffi::OsStr::new("")).unwrap(),
        link
    );
    // A relative --dir is absolute in the PATH line and on disk.
    assert_eq!(
        shim::absolute(Path::new("shim"), Path::new("/home/a")),
        Path::new("/home/a/shim")
    );
    assert_eq!(
        shim::absolute(Path::new("/x/shim"), Path::new("/home/a")),
        Path::new("/x/shim")
    );
}

#[test]
fn a_directory_with_a_colon_is_refused() {
    // PATH splits on ':', so the printed line could never name this directory.
    let f = Fixture::new();
    let dir = f.dir.parent().unwrap().join("shim:.:bin");
    assert!(shim::install(&f.spec("amir3"), &dir).is_err());
    assert!(!dir.join("claude").exists());
}

#[test]
fn the_recorded_claudectl_is_absolute_from_a_relative_path_entry() {
    let f = Fixture::new();
    let bin = f.claudectl.parent().unwrap();
    let base = bin.parent().unwrap();
    let found = shim::claudectl_path_from(std::ffi::OsStr::new("real bin"), base, &f.claudectl);
    assert_eq!(found, f.claudectl);
    assert!(found.is_absolute());
}

#[test]
fn execute_permission_is_checked_for_this_user_not_any_class() {
    let f = Fixture::new();
    // Executable for group and others, not for the owner (this user).
    std::fs::set_permissions(&f.real, std::fs::Permissions::from_mode(0o611)).unwrap();
    let mut spec = f.spec("amir3");
    spec.real = f.real.clone();
    assert!(shim::install(&spec, &f.dir).is_err());
    assert!(shim::find_real(Some(&f.real), std::ffi::OsStr::new("")).is_err());
}
