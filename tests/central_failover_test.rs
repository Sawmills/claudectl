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
    token_requests: Vec<String>,
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
    shared.lock().unwrap().token_requests.push(id.clone());
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
/// a turn that failed with `rate_limit`, then waits for SIGTERM. On any other token it reports
/// its session start and exits 7.
const FAKE_CLAUDE: &str = r#"#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
args = sys.argv[1:]
token = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", "")
settings = args[args.index("--settings") + 1]
config = json.load(open(settings))
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps({"token": token, "args": args, "settings": config, "run": os.environ.get("CLAUDECTL_SERVER_RUN")}) + "\n")
command = config["hooks"]["StopFailure"][0]["hooks"][0]["command"]
if token != "token-work":
    # A resumed Claude reports its session start, then this fake exits 7.
    resumed = args[args.index("--resume") + 1] if "--resume" in args else "sess-new"
    subprocess.run(["/bin/sh", "-c", command], check=True, input=json.dumps(
        {"hook_event_name": "SessionStart", "session_id": resumed}).encode())
    sys.exit(7)
if os.environ.get("FAKE_TASK_CHILD"):
    task_dir = os.path.join(os.environ["TMPDIR"], "claude-" + str(os.getuid()), "project", "tasks")
    os.makedirs(task_dir, exist_ok=True)
    with open(os.path.join(task_dir, "monitor.output"), "w") as output:
        subprocess.Popen([sys.executable, "-c", '''
import os, time
deadline = time.monotonic() + 15
while not os.path.exists(os.environ["FAKE_LOG"] + ".release") and time.monotonic() < deadline:
    time.sleep(0.02)
if os.path.exists(os.environ["FAKE_LOG"] + ".release"):
    open(os.environ["FAKE_LOG"] + ".task-done", "w").close()
'''], stdout=output, stderr=output)
for event in ({"hook_event_name": "SessionStart", "session_id": "sess-1"},
              {"hook_event_name": "UserPromptSubmit", "session_id": "sess-1"},
              {"hook_event_name": "StopFailure", "session_id": "sess-1", "error": "rate_limit",
               "error_details": "usage limit", "last_assistant_message": "secret"}):
    subprocess.run(["/bin/sh", "-c", command], input=json.dumps(event).encode(), check=True)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
deadline = time.time() + float(os.environ.get("FAKE_WATCHDOG_S", "20"))
while time.time() < deadline:
    time.sleep(0.05)
# Preserve only the native status metadata before the wrapper cleans its run directory.
with open(os.environ["FAKE_LOG"] + ".deferred", "w") as out:
    json.dump(json.load(open(os.path.join(os.environ["CLAUDECTL_SERVER_RUN"], "restart-status.json"))), out)
sys.exit(99)
"#;

struct Env {
    home: tempfile::TempDir,
    fake: Shared,
    claude: std::path::PathBuf,
    log: std::path::PathBuf,
}

#[test]
fn a_usage_limit_does_not_move_an_account_while_a_task_is_live() {
    let env = Env::new();
    let temporary = env.home.path().join("tmp");
    std::fs::create_dir(&temporary).unwrap();
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
    command
        .env_clear()
        .env("HOME", env.home.path())
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .env("CLAUDECTL_TEST_RENEW_FAST", "1")
        .env("FAKE_LOG", &env.log)
        .env("TMPDIR", temporary)
        .env("FAKE_TASK_CHILD", "1")
        .env("FAKE_WATCHDOG_S", "3")
        .args(["run", "work", "--failover", "--claude"])
        .arg(&env.claude)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut deferred = false;
    while std::time::Instant::now() < deadline {
        // The journal keeps the first cause for a stage. Sample the live current status.
        deferred = env
            .runs()
            .first()
            .and_then(|run| run["run"].as_str())
            .and_then(|run| std::fs::read(Path::new(run).join("restart-status.json")).ok())
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .is_some_and(|status| {
                status["reason"] == "background_task" && status["cause"] == "failover"
            });
        if deferred || child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let records_while_live = env.records();
    std::fs::write(env.log.with_extension("log.release"), "").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        deferred,
        "failover killed the task: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        records_while_live.is_empty(),
        "account move was recorded while busy"
    );
    assert!(env.log.with_extension("log.task-done").exists());
    assert_eq!(output.status.code(), Some(99));
    assert!(env.records().is_empty());
    assert_eq!(env.runs().len(), 1);
    assert_eq!(env.fake.lock().unwrap().token_requests, [WORK]);
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
        self.run_with(args, watchdog_s, &[])
    }
    fn run_with(&self, args: &[&str], watchdog_s: &str, settings: &[&str]) -> std::process::Output {
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
            .args(["--", "--model", "opus"])
            .args(settings);
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

fn assert_deferred(env: &Env, output: &std::process::Output, cause: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(99), "{stderr}");
    let runs = env.runs();
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0]["token"], "token-work");
    assert!(env.records().is_empty());
    assert_eq!(env.fake.lock().unwrap().token_requests, [WORK]);
    assert!(!stderr.contains("resuming session"));
    let rows: Vec<Value> = std::fs::read_to_string(
        env.home
            .path()
            .join(".claudectl/server/restart-decisions.jsonl"),
    )
    .unwrap()
    .lines()
    .map(|line| serde_json::from_str(line).unwrap())
    .collect();
    assert!(!rows.is_empty());
    let status: Value =
        serde_json::from_slice(&std::fs::read(env.log.with_extension("log.deferred")).unwrap())
            .unwrap();
    // Stage-deduplicated journal rows retain the first cause; current status tracks the latest.
    assert_eq!(status["reason"], "evidence_unknown");
    assert_eq!(status["cause"], cause);
}

#[test]
fn a_usage_limit_defers_without_reserving_an_available_account() {
    let env = Env::new();
    let output = env.run_with(&["run"], "3", &["--settings", r#"{"crossSessionInbound":"accept","isolatePeerMachines":true,"hooks":{"StopFailure":[{"hooks":[{"type":"command","command":"echo user-hook"}]}]}}"#]);
    assert_deferred(&env, &output, "failover");
    let runs = env.runs();
    let run = &runs[0];
    assert_eq!(run["settings"]["crossSessionInbound"], "accept");
    assert_eq!(run["settings"]["isolatePeerMachines"], true);
    let hooks = run["settings"]["hooks"]["StopFailure"].as_array().unwrap();
    assert_eq!(hooks.len(), 2);
    assert_eq!(hooks[1]["hooks"][0]["command"], "echo user-hook");
    assert_eq!(
        run["args"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|arg| *arg == "--settings")
            .count(),
        1
    );
    assert!(
        !env.home
            .path()
            .join(".claudectl/server/failovers.lock")
            .exists()
    );
}

#[test]
fn neither_named_nor_automatic_account_selection_bypasses_input_admission() {
    for (args, cause) in [
        (&["run", "work"][..], "renewal"),
        (&["run", "work", "--failover"][..], "failover"),
    ] {
        let env = Env::new();
        let output = env.run(args, "3");
        assert_deferred(&env, &output, cause);
    }
}

#[test]
fn a_full_pool_does_not_turn_unknown_admission_into_a_claimed_failover() {
    let env = Env::new();
    env.fake.lock().unwrap().spare_full = true;
    let output = env.run(&["run", "work", "--failover"], "3");
    assert_deferred(&env, &output, "failover");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("no other account has room"));
}

#[test]
fn a_throttle_cannot_bypass_unknown_input_admission() {
    let env = Env::new();
    env.fake.lock().unwrap().throttle = true;
    let output = env.run(&["run", "work", "--failover"], "3");
    assert_deferred(&env, &output, "failover");
}

#[test]
fn a_new_revision_does_not_bypass_unknown_failover_admission() {
    let env = Env::new();
    {
        let mut fake = env.fake.lock().unwrap();
        fake.spare_full = true;
        fake.renew_work = true;
    }
    let output = env.run(&["run", "work", "--failover"], "3");
    assert_deferred(&env, &output, "failover");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("server token renewed"));
}
