#![cfg(all(feature = "server", target_os = "linux"))]
//! SAW-12693: `claudectl run` moves the Claude session to another server account when a turn
//! fails at a usage limit. A scripted account server and a fake Claude; synthetic tokens.
//! Linux only, debug build (the monitor's fast test clock).
use assert_cmd::Command;
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

const WORK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SPARE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Default)]
struct Fake {
    /// `work` is full once its token was issued (it starts with the most room).
    work_used: bool,
    /// `spare` is full too: no account to move to.
    spare_full: bool,
    /// `work` keeps room: the failed turn was a short throttle.
    throttle: bool,
    /// An observing token read of `work` returns a newer token (a renewal follows).
    renew_work: bool,
    /// Every usage read: (account id, cached).
    usage_reads: Vec<(String, String)>,
}
type Shared = Arc<Mutex<Fake>>;

fn identity(org: &str) -> Value {
    json!({"account_uuid": format!("claude-{org}"), "organization_uuid": org})
}

async fn accounts() -> Json<Value> {
    Json(json!([
        {"provider": "anthropic", "account_id": WORK, "alias": "work",
            "identity": identity("org-work"), "available": true},
        {"provider": "anthropic", "account_id": SPARE, "alias": "spare",
            "identity": identity("org-spare"), "available": true},
    ]))
}

async fn usage(
    State(shared): State<Shared>,
    Query(q): Query<HashMap<String, String>>,
) -> Json<Value> {
    let mut fake = shared.lock().unwrap();
    let id = q.get("account_id").cloned().unwrap_or_default();
    fake.usage_reads
        .push((id.clone(), q.get("cached").cloned().unwrap_or_default()));
    let five = match id.as_str() {
        WORK if fake.work_used && !fake.throttle => 100.0,
        WORK => 10.0,
        _ if fake.spare_full => 100.0,
        _ => 20.0,
    };
    // `work` has the most room at the start, so `run` picks it.
    let week = if id == WORK { 5.0 } else { 30.0 };
    Json(json!({
        "data": {"five_hour": {"utilization": five}, "seven_day": {"utilization": week},
            "extra_usage": {"is_enabled": false}},
        "observed_at": chrono::Utc::now().timestamp_millis(),
        "next_retry_at": 0, "stale": false, "error": null,
    }))
}

async fn token(State(shared): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let id = body["account_id"].as_str().unwrap_or_default().to_string();
    let renewed = id == WORK && body["observe"] == true && shared.lock().unwrap().renew_work;
    let (name, org) = if id == WORK {
        shared.lock().unwrap().work_used = true;
        ("work", "org-work")
    } else {
        ("spare", "org-spare")
    };
    let (token, revision, hours) = if renewed {
        (format!("token-{name}-2"), format!("revision-{name}-2"), 9)
    } else {
        (format!("token-{name}"), format!("revision-{name}"), 8)
    };
    Json(json!({
        "provider": "anthropic", "account_id": id, "user_id": "person",
        "identity": identity(org),
        "access_token": token,
        "expires_at": chrono::Utc::now().timestamp_millis() + hours * 3_600_000,
        "scopes": ["user:inference", "user:profile"],
        "revision": revision,
        "generation": 1,
    }))
}

fn private_write(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A fake Claude: logs its token and arguments. On `work` it reports a session, a prompt and
/// a turn that failed with `rate_limit`, then waits for SIGTERM. On any other token it exits 7.
const FAKE_CLAUDE: &str = r#"#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
args = sys.argv[1:]
token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"token": token, "args": args}) + "\n")
if token != "token-work":
    sys.exit(7)
settings = args[args.index("--settings") + 1]
command = json.load(open(settings))["hooks"]["StopFailure"][0]["hooks"][0]["command"]
for event in ({"hook_event_name": "SessionStart", "session_id": "sess-1"},
              {"hook_event_name": "UserPromptSubmit", "session_id": "sess-1"},
              {"hook_event_name": "StopFailure", "session_id": "sess-1", "error": "rate_limit",
               "error_details": "usage limit", "last_assistant_message": "secret"}):
    subprocess.run(["/bin/sh", "-c", command], input=json.dumps(event).encode(), check=True)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
deadline = time.time() + float(os.environ.get("FAKE_WATCHDOG_S", "20"))
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
        let fake = Shared::default();
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
    fn run(&self, args: &[&str], watchdog_s: &str) -> std::process::Output {
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
        command
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TERM", "xterm")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .env("CLAUDECTL_TEST_RENEW_FAST", "1")
            .env("FAKE_LOG", &self.log)
            .env("FAKE_WATCHDOG_S", watchdog_s)
            .args(args)
            .arg("--claude")
            .arg(&self.claude)
            .args(["--", "--model", "opus"]);
        Command::from_std(command)
            .timeout(std::time::Duration::from_secs(60))
            .output()
            .unwrap()
    }
    fn runs(&self) -> Vec<Value> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
    fn records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.home.path().join(".claudectl/server/failovers.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

#[test]
fn a_usage_limit_moves_the_session_to_the_account_with_room() {
    let env = Env::new();
    let output = env.run(&["run"], "20");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The second Claude's own exit code ends the run.
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    let runs = env.runs();
    assert_eq!(runs.len(), 2, "{runs:?}");
    assert_eq!(runs[0]["token"], "token-work");
    assert_eq!(runs[1]["token"], "token-spare");
    let args: Vec<String> = serde_json::from_value(runs[1]["args"].clone()).unwrap();
    let settings = args.iter().position(|a| a == "--settings").unwrap();
    let mut user: Vec<&str> = args.iter().map(String::as_str).collect();
    user.drain(settings..settings + 2);
    assert_eq!(
        user,
        [
            "--model",
            "opus",
            "--resume",
            "sess-1",
            "Continue the previous request."
        ]
    );
    assert!(
        stderr.contains("work reached its usage limit; resuming session sess-1 on spare"),
        "{stderr}"
    );
    // The limit was confirmed by a fresh (not cached) read of `work`.
    let reads = env.fake.lock().unwrap().usage_reads.clone();
    assert!(
        reads
            .iter()
            .any(|(id, cached)| id == WORK && cached == "false"),
        "{reads:?}"
    );
    let records = env.records();
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["from"], "work");
    assert_eq!(records[0]["to"], "spare");
    assert_eq!(records[0]["session_id"], "sess-1");
    // The hook kept the error type only.
    let sessions = env.home.path().join(".claudectl/server/sessions");
    for entry in std::fs::read_dir(sessions).unwrap().flatten() {
        let events = std::fs::read_to_string(entry.path().join("events")).unwrap_or_default();
        assert!(!events.contains("secret"), "{events}");
    }
}

#[test]
fn a_named_account_keeps_its_session_unless_failover_is_asked_for() {
    let env = Env::new();
    let output = env.run(&["run", "work"], "3");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(99), "{stderr}");
    assert_eq!(env.runs().len(), 1);
    assert!(env.records().is_empty());

    let env = Env::new();
    let output = env.run(&["run", "work", "--failover"], "20");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert_eq!(env.runs()[1]["token"], "token-spare");
}

#[test]
fn without_an_account_with_room_the_session_stays_and_says_so() {
    let env = Env::new();
    env.fake.lock().unwrap().spare_full = true;
    let output = env.run(&["run", "work", "--failover"], "4");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(99), "{stderr}");
    assert_eq!(env.runs().len(), 1);
    assert!(
        stderr.contains("work reached its usage limit and no other account has room now"),
        "{stderr}"
    );
    assert!(stderr.contains("Try: claudectl status"), "{stderr}");
    assert!(env.records().is_empty());
}

#[test]
fn a_throttle_without_a_full_window_never_moves_the_session() {
    let env = Env::new();
    env.fake.lock().unwrap().throttle = true;
    let output = env.run(&["run", "work", "--failover"], "4");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(99), "{stderr}");
    assert_eq!(env.runs().len(), 1);
    assert!(env.records().is_empty());
    assert!(!stderr.contains("usage limit"), "{stderr}");
}

/// The no-room notice waits for the terminal: when a renewal restarts Claude afterwards, it
/// is printed after the terminal was restored, before the next Claude starts.
#[test]
fn a_no_room_notice_before_a_renewal_is_printed_between_the_two_claudes() {
    let env = Env::new();
    {
        let mut fake = env.fake.lock().unwrap();
        fake.spare_full = true;
        fake.renew_work = true;
    }
    let output = env.run(&["run", "work", "--failover"], "20");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The renewed Claude (token-work-2) exits 7 at once.
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    let runs = env.runs();
    assert_eq!(runs.len(), 2, "{runs:?}");
    assert_eq!(runs[1]["token"], "token-work-2");
    let notice = stderr
        .find("no other account has room now")
        .unwrap_or_else(|| panic!("{stderr}"));
    let renewed = stderr
        .find("server token renewed")
        .unwrap_or_else(|| panic!("{stderr}"));
    assert!(notice < renewed, "{stderr}");
}
