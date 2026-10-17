#![cfg(any(target_os = "linux", target_os = "macos"))]
//! Settings observed by the actual child launched through both public run commands.
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn private_write(path: &Path, value: &Value) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, value.to_string()).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Env {
    home: tempfile::TempDir,
    claude: std::path::PathBuf,
    log: std::path::PathBuf,
    shutdown: Arc<AtomicBool>,
    server: Option<std::thread::JoinHandle<()>>,
}

impl Env {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        // Use the same small HTTP fixture pattern as central_cli_test so these client
        // tests also run in the default-feature Darwin CI job, without server dependencies.
        let shutdown = Arc::new(AtomicBool::new(false));
        let stopped = shutdown.clone();
        let server_thread = std::thread::spawn(move || {
            while !stopped.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                        continue;
                    }
                    Err(error) => panic!("fake account server: {error}"),
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut input = std::io::BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                input.read_line(&mut first).unwrap();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    input.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = value.trim().parse().unwrap();
                    }
                }
                input.read_exact(&mut vec![0; length]).unwrap();
                let (status, body) = if first.starts_with("GET /v2/anthropic/accounts ") {
                    (
                        "200 OK",
                        json!([{"provider":"anthropic", "account_id":ACCOUNT,
                        "alias":"work", "identity":{"account_uuid":"test", "organization_uuid":"test"},
                        "available":true}]),
                    )
                } else if first.starts_with("POST /v2/anthropic/token ") {
                    (
                        "200 OK",
                        json!({"provider":"anthropic", "account_id":ACCOUNT, "user_id":"person",
                        "identity":{"account_uuid":"test", "organization_uuid":"test"},
                        "access_token":"synthetic", "expires_at":chrono::Utc::now().timestamp_millis()+3_600_000,
                        "scopes":["user:inference","user:profile"], "revision":"one", "generation":1}),
                    )
                } else {
                    ("404 Not Found", json!({}))
                };
                let body = body.to_string();
                write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        let server = home.path().join(".claudectl/server");
        private_write(
            &server.join("connection.json"),
            &json!({"server":origin,
            "user_id":"person", "token_file":server.join("machine.json")}),
        );
        private_write(&server.join("machine.json"), &json!("synthetic-machine"));
        let claude = home.path().join("claude");
        std::fs::write(
            &claude,
            r#"#!/usr/bin/env python3
import json, os, stat, sys
args = sys.argv[1:]
settings = [args[i+1] for i, arg in enumerate(args) if arg == "--settings"]
with open(os.environ["FAKE_LOG"], "w") as log:
    json.dump({"args": args, "files": settings,
               "settings": [json.load(open(path)) for path in settings],
               "modes": [stat.S_IMODE(os.stat(path).st_mode) for path in settings]}, log)
sys.exit(7)
"#,
        )
        .unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        let digest = claudectl::exec::sha256_file(&claude).unwrap();
        private_write(
            &server.join("qualified-host-config-builds.json"),
            &json!([{"sha256":digest,"platform":std::env::consts::OS,"qualified_at":"test","check":"supervised_host_config"}]),
        );
        let log = home.path().join("child.json");
        Self {
            home,
            claude,
            log,
            shutdown,
            server: Some(server_thread),
        }
    }

    fn run(&self, server: bool, args: &[&str]) -> std::process::Output {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
        cmd.env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/bin:/bin")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .env("FAKE_LOG", &self.log)
            .current_dir(self.home.path());
        if server {
            cmd.arg("server");
        }
        cmd.args(["run", "work", "--claude"])
            .arg(&self.claude)
            .arg("--")
            .args(args);
        assert_cmd::Command::from_std(cmd)
            .timeout(std::time::Duration::from_secs(15))
            .output()
            .unwrap()
    }

    fn observed(&self) -> Value {
        serde_json::from_slice(&std::fs::read(&self.log).unwrap()).unwrap()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(server) = self.server.take() {
            server.join().unwrap();
        }
    }
}

#[test]
fn a2a_settings_and_supervision_hooks_reach_both_run_commands() {
    for server in [false, true] {
        let env = Env::new();
        let output = env.run(
            server,
            &[
                "--settings",
                r#"{"crossSessionInbound":"accept","isolatePeerMachines":true}"#,
            ],
        );
        assert_eq!(
            output.status.code(),
            Some(7),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let observed = env.observed();
        assert_eq!(observed["files"].as_array().unwrap().len(), 1);
        assert_eq!(observed["settings"][0]["crossSessionInbound"], "accept");
        assert_eq!(observed["settings"][0]["isolatePeerMachines"], true);
        for event in [
            "SessionStart",
            "UserPromptSubmit",
            "Stop",
            "StopFailure",
            "Notification",
            "SessionEnd",
        ] {
            assert!(
                observed["settings"][0]["hooks"][event][0]["hooks"][0]["command"]
                    .as_str()
                    .unwrap()
                    .contains(" server hook ")
            );
        }
        assert_eq!(observed["modes"], json!([384]));
        assert!(!env.home.path().join(".claude/settings.json").exists());
    }
}

#[test]
fn user_settings_cannot_replace_or_disable_supervision_hooks() {
    for settings in [
        r#"{"hooks":null}"#,
        r#"{"hooks":{"Stop":{}}}"#,
        r#"{"disableAllHooks":true}"#,
    ] {
        let env = Env::new();
        let output = env.run(true, &["--settings", settings]);
        assert!(
            !output.status.success() && output.status.code() != Some(7),
            "invalid settings launched Claude: {settings}"
        );
        assert!(!env.log.exists());
    }
}

#[test]
fn even_empty_explicit_settings_are_a_single_private_file_for_one_shot_runs() {
    let env = Env::new();
    let output = env.run(false, &["-p", "hello", "--settings={}"]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observed = env.observed();
    assert_eq!(observed["files"].as_array().unwrap().len(), 1);
    assert_eq!(observed["settings"], json!([{}]));
    assert_eq!(observed["modes"], json!([384]));
}

#[test]
fn repeated_json_and_file_settings_merge_in_order_and_append_user_hooks() {
    let env = Env::new();
    let first = env.home.path().join("first settings.json");
    let first_value = json!({"model":"first", "env":{"KEEP":"yes", "CHOICE":"first"},
        "permissions":{"allow":["Read"],"deny":["Write"]},
        "hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo first"}]}]}});
    private_write(&first, &first_value);
    let last = env.home.path().join("last.json");
    private_write(&last, &json!({"model":"last"}));
    let last_arg = format!("--settings={}", last.display());
    let output = env.run(false, &["--model", "opus", "--settings", first.to_str().unwrap(),
        "--settings", r#"{"env":{"CHOICE":"second"},"permissions":{"allow":["Edit"]},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo second"}]}]}}"#,
        &last_arg]);
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let observed = env.observed();
    assert_eq!(observed["files"].as_array().unwrap().len(), 1);
    let settings = &observed["settings"][0];
    assert_eq!(settings["model"], "last");
    assert_eq!(settings["env"], json!({"KEEP":"yes","CHOICE":"second"}));
    assert_eq!(
        settings["permissions"],
        json!({"allow":["Edit"],"deny":["Write"]})
    );
    let stop = settings["hooks"]["Stop"].as_array().unwrap();
    assert_eq!(stop.len(), 3);
    assert!(
        stop[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains(" server hook ")
    );
    assert_eq!(stop[1]["hooks"][0]["command"], "echo first");
    assert_eq!(stop[2]["hooks"][0]["command"], "echo second");
    assert_eq!(
        observed["args"]
            .as_array()
            .unwrap()
            .iter()
            .skip(2)
            .collect::<Vec<_>>(),
        vec!["--model", "opus"]
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(first).unwrap()).unwrap(),
        first_value
    );
}

#[test]
fn bad_settings_fail_before_child_launch_without_echoing_values() {
    for args in [
        vec!["--settings"],
        vec!["--settings="],
        vec!["--settings", "missing.json"],
        vec!["--settings", r#"{"secret":"DO_NOT_ECHO",}"#],
        vec!["--settings", r#"["DO_NOT_ECHO"]"#],
        vec!["--settings", r#""DO_NOT_ECHO""#],
        vec!["--settings", r#"{"apiKeyHelper":"DO_NOT_ECHO"}"#],
        vec![
            "--settings",
            r#"{"env":{"ANTHROPIC_BASE_URL":"DO_NOT_ECHO"}}"#,
        ],
        vec![
            "--settings",
            r#"{"env":{"CLAUDE_CONFIG_DIR":"DO_NOT_ECHO"}}"#,
        ],
        vec!["--bare"],
        vec!["--setting-sources", "user"],
    ] {
        let env = Env::new();
        let output = env.run(true, &args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(!env.log.exists());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("DO_NOT_ECHO"));
    }
    let env = Env::new();
    let file = env.home.path().join("not-object.json");
    private_write(&file, &json!([]));
    let output = env.run(true, &["--settings", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(!env.log.exists());
}

#[test]
fn explicit_settings_refusal_explains_how_to_fix_the_supplied_value() {
    let env = Env::new();
    let output = env.run(false, &["--settings", r#"{"apiKeyHelper":"synthetic"}"#]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("remove credential and routing overrides from --settings"),
        "{stderr}"
    );
    assert!(!stderr.contains("run from another directory"), "{stderr}");
}
