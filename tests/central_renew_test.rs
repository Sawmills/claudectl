#![cfg(all(feature = "server", target_os = "linux"))]
//! SAW-12610: `claudectl server run` against a scripted account server and a fake Claude.
//! Linux only, debug build (the monitor's fast test clock). Synthetic tokens only.
use assert_cmd::Command;
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

const ACCOUNT: &str = "abababababababababababababababababababababababababababababababab";

#[derive(Default)]
struct Fake {
    /// The `previous_revision` of every token request, in order.
    requests: Vec<Value>,
    /// The token generation the server holds now.
    generation: u64,
    /// The server refreshes on the next token request (what a server-side refresh does).
    refresh_next: bool,
    /// After that, it refreshes again on this many further requests (a second refresh,
    /// for example `server refresh-access` on another machine).
    extra_refreshes: u32,
}
type Shared = Arc<Mutex<Fake>>;

fn identity() -> Value {
    json!({"account_uuid": "claude-account", "organization_uuid": "claude-org"})
}

async fn accounts() -> Json<Value> {
    Json(
        json!([{"provider": "anthropic", "account_id": ACCOUNT, "alias": "work",
        "identity": identity(), "available": true}]),
    )
}

async fn usage() -> Json<Value> {
    Json(
        json!({"data": null, "observed_at": null, "next_retry_at": 0, "stale": true, "error": null}),
    )
}

async fn token(State(fake): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let mut fake = fake.lock().unwrap();
    fake.requests.push(body["previous_revision"].clone());
    if fake.refresh_next {
        fake.refresh_next = false;
        fake.generation += 1;
    } else if fake.generation > 1 && fake.extra_refreshes > 0 {
        fake.extra_refreshes -= 1;
        fake.generation += 1;
    }
    let generation = fake.generation;
    let now = chrono::Utc::now().timestamp_millis();
    Json(json!({
        "provider": "anthropic", "account_id": ACCOUNT, "user_id": "person",
        "identity": identity(),
        "access_token": format!("token-{generation}"),
        // Each newer generation lives longer, as a refresh gives a fresh 8 h token.
        "expires_at": now + 1_800_000 * generation as i64,
        "scopes": ["user:inference", "user:profile"],
        "revision": format!("revision-{generation}"),
        "generation": generation,
    }))
}

fn private_write(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A fake Claude: one process (no children), logs its token and arguments, reports a
/// session and a finished turn through the renewal hook, then waits for SIGTERM. With the
/// renewed token it exits 7 at once.
const FAKE_CLAUDE: &str = r#"#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
args = sys.argv[1:]
token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
tty = os.isatty(0)
foreground = tty and os.tcgetpgrp(0) == os.getpgrp()
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"token": token, "args": args, "tty": tty, "foreground": foreground}) + "\n")
if token != "token-1":
    sys.exit(7)
settings = args[args.index("--settings") + 1]
command = json.load(open(settings))["hooks"]["Stop"][0]["hooks"][0]["command"]
for event in ({"hook_event_name": "SessionStart", "session_id": "sess-1"},
              {"hook_event_name": "Stop", "session_id": "sess-1"}):
    subprocess.run(["/bin/sh", "-c", command], input=json.dumps(event).encode(), check=True)
def term(*_):
    status = json.load(open(os.path.join(os.path.dirname(settings), "session.json")))
    with open(os.environ["FAKE_LOG"] + ".term", "w") as out:
        out.write(status.get("renewal", ""))
    sys.exit(143)
signal.signal(signal.SIGTERM, term)
with open(os.environ["FAKE_LOG"] + ".ready", "w") as ready:
    ready.write("idle")
# A watchdog: a build that never restarts fails the test instead of hanging it.
deadline = time.time() + 20
while time.time() < deadline:
    time.sleep(0.05)
sys.exit(99)
"#;

struct Env {
    home: tempfile::TempDir,
    fake: Shared,
    claude: std::path::PathBuf,
    log: std::path::PathBuf,
}

impl Env {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let fake: Shared = Arc::new(Mutex::new(Fake {
            generation: 1,
            ..Default::default()
        }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/v2/anthropic/accounts", get(accounts))
            .route("/v2/anthropic/usage", get(usage))
            .route("/v2/anthropic/token", post(token))
            .with_state(fake.clone());
        std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    axum::serve(listener, app).await.unwrap();
                });
        });
        let server = home.path().join(".claudectl/server");
        private_write(
            &server.join("connection.json"),
            &json!({"server": origin, "user_id": "person", "token_file": server.join("machine.json")})
                .to_string(),
        );
        private_write(
            &server.join("machine.json"),
            &json!("synthetic-machine").to_string(),
        );
        let claude = home.path().join("claude");
        std::fs::write(&claude, FAKE_CLAUDE).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let digest = claudectl::exec::sha256_file(&claude).unwrap();
        private_write(
            &server.join("qualified-host-config-builds.json"),
            &json!([{"sha256": digest, "platform": "linux", "qualified_at": "test",
                "check": "supervised_host_config"}])
            .to_string(),
        );
        let log = home.path().join("claude.log");
        Self {
            home,
            fake,
            claude,
            log,
        }
    }
    /// The server refreshes once the first Claude is idle (another client, or the margin).
    fn refresh_when_idle(&self) -> std::thread::JoinHandle<()> {
        let fake = self.fake.clone();
        let ready = self.log.with_extension("log.ready");
        std::thread::spawn(move || {
            for _ in 0..400 {
                if ready.exists() {
                    fake.lock().unwrap().refresh_next = true;
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        })
    }
    fn env(&self, command: &mut std::process::Command) {
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TERM", "xterm")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .env("CLAUDECTL_TEST_RENEW_FAST", "1")
            .env("FAKE_LOG", &self.log);
    }
    fn runs(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn assert_followed(&self, runs: &[Value], token: &str) {
        assert_eq!(runs.len(), 2, "{runs:?}");
        assert_eq!(runs[0]["token"], "token-1");
        assert_eq!(runs[1]["token"], token);
        // The supervisor-visible marker was set before Claude got SIGTERM.
        let term = std::fs::read_to_string(self.log.with_extension("log.term")).unwrap();
        assert_eq!(term, "renewing");
        let args: Vec<String> = serde_json::from_value(runs[1]["args"].clone()).unwrap();
        let settings = args.iter().position(|a| a == "--settings").unwrap();
        let mut user: Vec<&str> = args.iter().map(String::as_str).collect();
        user.drain(settings..settings + 2);
        assert_eq!(user, ["--model", "opus", "--resume", "sess-1"]);
        // No request ever forced a refresh (SAW-12610 root cause).
        let requests = self.fake.lock().unwrap().requests.clone();
        assert!(requests.iter().all(Value::is_null), "{requests:?}");
    }
}

#[test]
fn a_revoked_token_restarts_an_idle_claude_with_resume_on_the_new_token() {
    let env = Env::new();
    let refresher = env.refresh_when_idle();
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
    env.env(&mut command);
    command
        .args(["server", "run", "work", "--claude"])
        .arg(&env.claude)
        .args(["--", "--model", "opus", "--resume", "old"]);
    let output = Command::from_std(command)
        .timeout(std::time::Duration::from_secs(60))
        .output()
        .unwrap();
    refresher.join().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The second Claude's own exit code ends `server run`.
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert!(
        stderr.contains("server token renewed; resuming session sess-1"),
        "{stderr}"
    );
    env.assert_followed(&env.runs(), "token-2");
}

/// Under a terminal, the relaunched Claude gets the terminal and its foreground again.
#[test]
fn a_relaunch_under_a_terminal_owns_the_foreground() {
    if !Path::new("/usr/bin/script").exists() {
        eprintln!("skipped: util-linux script(1) is not installed");
        return;
    }
    let env = Env::new();
    let refresher = env.refresh_when_idle();
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let inner = format!(
        "{} server run work --claude {} -- --model opus --resume old; echo exit=$?; python3 -c 'import os; print(\"shell-foreground\", os.tcgetpgrp(0) == os.getpgrp())'",
        quote(
            &assert_cmd::cargo::cargo_bin("claudectl")
                .display()
                .to_string()
        ),
        quote(&env.claude.display().to_string()),
    );
    let mut command = std::process::Command::new("/usr/bin/script");
    env.env(&mut command);
    command.args(["-qec", &inner, "/dev/null"]);
    let output = Command::from_std(command)
        .timeout(std::time::Duration::from_secs(60))
        .output()
        .unwrap();
    refresher.join().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("exit=7"), "{text}");
    // After the relaunched Claude exits, the terminal goes back to the shell.
    assert!(text.contains("shell-foreground True"), "{text}");
    let runs = env.runs();
    env.assert_followed(&runs, "token-2");
    for run in &runs {
        assert_eq!(run["tty"], true, "{run}");
        assert_eq!(run["foreground"], true, "{run}");
    }
}

/// A second refresh after the successor was fetched: the relaunch uses the newest token,
/// never a revoked one.
#[test]
fn a_restart_uses_the_newest_token_when_the_server_refreshed_again() {
    let env = Env::new();
    env.fake.lock().unwrap().extra_refreshes = 1;
    let refresher = env.refresh_when_idle();
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
    env.env(&mut command);
    command
        .args(["server", "run", "work", "--claude"])
        .arg(&env.claude)
        .args(["--", "--model", "opus", "--resume", "old"]);
    let output = Command::from_std(command)
        .timeout(std::time::Duration::from_secs(60))
        .output()
        .unwrap();
    refresher.join().unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    env.assert_followed(&env.runs(), "token-3");
}
