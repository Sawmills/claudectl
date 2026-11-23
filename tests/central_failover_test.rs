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
const THIRD: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Default)]
struct Fake {
    /// `work` is full once its token was issued (it starts with the most room).
    work_used: bool,
    /// `spare` is full too: no account to move to.
    spare_full: bool,
    /// `work` keeps room: the failed turn was a short throttle.
    throttle: bool,
    weekly_limit: bool,
    /// An observing read after the first grant returns a newer token (a renewal follows).
    renew_work: bool,
    observed_renewal: bool,
    /// Every usage read: (account id, cached).
    usage_reads: Vec<(String, String)>,
    token_requests: Vec<String>,
    token_request_bodies: Vec<Value>,
    start_accounts: Option<Value>,
    start_usage: HashMap<String, Value>,
    post_start_usage: Option<Value>,
    target_barrier: Option<(std::path::PathBuf, std::path::PathBuf)>,
}
type Shared = Arc<Mutex<Fake>>;

fn identity(org: &str) -> Value {
    json!({"account_uuid": format!("claude-{org}"), "organization_uuid": org})
}

async fn accounts(State(shared): State<Shared>) -> Json<Value> {
    if let Some(accounts) = &shared.lock().unwrap().start_accounts {
        return Json(accounts.clone());
    }
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
    if id == WORK
        && fake.work_used
        && let Some(usage) = &fake.post_start_usage
    {
        return Json(usage.clone());
    }
    if let Some(data) = fake.start_usage.get(&id) {
        return Json(json!({
            "data": data,
            "observed_at": chrono::Utc::now().timestamp_millis(),
            "next_retry_at": 0, "stale": false, "error": null,
        }));
    }
    let five = match id.as_str() {
        WORK if fake.work_used && fake.weekly_limit => 0.0,
        WORK if fake.work_used && !fake.throttle && !fake.weekly_limit => 100.0,
        WORK => 10.0,
        _ if fake.spare_full => 100.0,
        _ => 20.0,
    };
    // `work` has the most room at the start, so `run` picks it.
    let week = if id == WORK && fake.work_used && fake.weekly_limit {
        100.0
    } else if id == WORK {
        5.0
    } else {
        30.0
    };
    Json(json!({
        "data": {"five_hour": {"utilization": five}, "seven_day": {"utilization": week},
            "extra_usage": {"is_enabled": false}},
        "observed_at": chrono::Utc::now().timestamp_millis(),
        "next_retry_at": chrono::Utc::now().timestamp_millis() + 300_000,
        "stale": false, "error": null,
    }))
}

async fn token(State(shared): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let id = body["account_id"].as_str().unwrap_or_default().to_string();
    {
        let mut fake = shared.lock().unwrap();
        fake.token_requests.push(id.clone());
        fake.token_request_bodies.push(body.clone());
    }
    let barrier = if id == SPARE {
        shared.lock().unwrap().target_barrier.clone()
    } else {
        None
    };
    if let Some((request, ready)) = barrier {
        std::fs::write(request, "").unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() && std::time::Instant::now() < until {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            ready.exists(),
            "fake child did not publish the late workload"
        );
    }
    let renewed = {
        let mut fake = shared.lock().unwrap();
        let renewed = id == WORK && body["observe"] == true && fake.work_used && fake.renew_work;
        fake.observed_renewal |= renewed;
        renewed
    };
    let (name, org) = if id == WORK {
        shared.lock().unwrap().work_used = true;
        ("work", "org-work")
    } else if id == SPARE {
        ("spare", "org-spare")
    } else {
        ("third", "org-third")
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
if os.environ.get("FAKE_START_ONLY"): sys.exit(7)
command = config["hooks"]["StopFailure"][0]["hooks"][0]["command"]
if token != "token-work":
    if os.environ.get("FAKE_FAIL_RESUME") and "--resume" in args: sys.exit(7)
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
    if os.environ.get("FAKE_DELAY_LIMIT") and event["hook_event_name"] == "StopFailure":
        subprocess.run(["/bin/sh", "-c", command], input=json.dumps(
            {"hook_event_name": "Stop", "session_id": "sess-1"}).encode(), check=True)
        until = time.monotonic() + 2
        while time.monotonic() < until:
            try:
                previous = json.load(open(os.path.join(os.environ["CLAUDECTL_SERVER_RUN"], "restart-status.json")))
                if previous.get("session_id") == "sess-1" and previous.get("cause") == "renewal" and previous.get("reason") == "quiet_window":
                    break
            except FileNotFoundError:
                pass
            time.sleep(.01)
        else:
            raise AssertionError("initial renewal quiet deferral was never observed")
    transcript = os.path.join(os.environ["HOME"], "live-model.jsonl")
    if os.path.exists(transcript): event["transcript_path"] = transcript
    subprocess.run(["/bin/sh", "-c", command], input=json.dumps(event).encode(), check=True)
signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
deadline = time.time() + float(os.environ.get("FAKE_WATCHDOG_S", "20"))
limit_turns = 1
next_limit = time.monotonic() + .25
blocked = False
while time.time() < deadline:
    if not blocked and os.path.exists(os.environ["FAKE_LOG"] + ".block"):
        mode = os.environ["FAKE_LATE_BLOCKER"]
        if mode == "foreground":
            subprocess.run(["/bin/sh", "-c", command], input=json.dumps(
                {"hook_event_name": "UserPromptSubmit", "session_id": "sess-1"}).encode(), check=True)
        elif mode == "background":
            task_dir = os.path.join(os.environ["TMPDIR"], "claude-" + str(os.getuid()), "project", "tasks")
            os.makedirs(task_dir, exist_ok=True)
            with open(os.path.join(task_dir, "late.output"), "w") as out:
                subprocess.Popen(["sleep", "15"], stdout=out, stderr=out)
        elif mode == "production":
            with open(os.environ["LANE_GOAL_FILE"], "a") as out:
                out.write("flt900:lane [starting] FLT-900 synthetic production step\n")
        elif mode == "hold":
            subprocess.run([os.environ["FAKE_WRAPPER_BIN"], "hold", "start", "--reason",
                            "FLT-900 synthetic production step"], check=True)
        elif mode == "evidence_expiry":
            time.sleep(2.2)
        else:
            raise AssertionError("unknown late blocker: " + mode)
        blocked = True
        open(os.environ["FAKE_LOG"] + ".blocked", "w").close()
    if os.environ.get("FAKE_LIMIT_CRONS") and time.monotonic() >= next_limit:
        for event in ({"hook_event_name": "UserPromptSubmit", "session_id": "sess-1"},
                      {"hook_event_name": "StopFailure", "session_id": "sess-1", "error": "rate_limit",
                       "error_details": "You've hit your weekly limit · resets 9pm"}):
            subprocess.run(["/bin/sh", "-c", command], input=json.dumps(event).encode(), check=True)
        limit_turns += 1
        next_limit = time.monotonic() + .25
        with open(os.environ["FAKE_LOG"] + ".limit-turns", "w") as out:
            out.write(str(limit_turns))
    time.sleep(0.05)
# Seek a spurious renewal decision during mixed-operation tests instead of relying
# on the phase of the final sample relative to the monitor's tick.
status_path=os.path.join(os.environ["CLAUDECTL_SERVER_RUN"], "restart-status.json")
status=json.load(open(status_path))
sample_until=time.monotonic()+(.5 if os.environ.get("FAKE_SAMPLE_RENEWAL") else 0)
while time.monotonic()<sample_until and status.get('cause')!='renewal':
    time.sleep(.001)
    status=json.load(open(status_path))
# Preserve only native status metadata before the wrapper cleans its run directory.
with open(os.environ["FAKE_LOG"] + ".deferred", "w") as out:
    json.dump(status, out)
sys.exit(99)
"#;

struct Env {
    home: tempfile::TempDir,
    fake: Shared,
    claude: std::path::PathBuf,
    log: std::path::PathBuf,
    sample_renewal: bool,
    fail_resume: bool,
    start_only: bool,
    limit_crons: bool,
    late_blocker: Option<&'static str>,
    delay_limit: bool,
}

#[test]
fn a_new_start_skips_amir_at_95_percent_when_cool_accounts_are_eligible() {
    let env = Env::new_start([95.0, 0.0, 0.0]);

    let output = env.run(&["run"], "3");
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        env.fake
            .lock()
            .unwrap()
            .token_requests
            .first()
            .map(String::as_str),
        Some(SPARE),
        "a new start must choose cool amir5 over hot amir's earlier weekly reset"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    for decision in [
        "start candidate amir: 5h=95%, week=1%; skipped: 5h at or above 80%",
        "start candidate amir5: 5h=0%, week=13%; eligible: weekly reset priority",
        "start candidate amir4: 5h=0%, week=21%; eligible: weekly reset priority",
        "starting Claude on amir5 (5h below 80%; weekly reset priority)",
    ] {
        assert!(
            stderr.contains(decision),
            "missing start decision {decision}: {stderr}"
        );
    }
}

#[test]
fn a_new_start_excludes_80_percent_and_keeps_weekly_order_below_it() {
    let env = Env::new_start([80.0, 79.9, 0.0]);
    // amir4 has more five-hour and weekly room; amir5 still resets first.
    env.fake.lock().unwrap().start_usage.get_mut(THIRD).unwrap()["seven_day"]["utilization"] =
        json!(1.0);
    let output = env.run(&["run"], "3");
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        env.fake
            .lock()
            .unwrap()
            .token_requests
            .first()
            .map(String::as_str),
        Some(SPARE)
    );
}

#[test]
fn a_new_start_preserves_the_weekly_fallback_when_all_eligible_accounts_are_hot() {
    let env = Env::new_start([95.0, 80.0, 99.0]);
    let output = env.run(&["run"], "3");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(7), "{stderr}");
    assert_eq!(
        env.fake
            .lock()
            .unwrap()
            .token_requests
            .first()
            .map(String::as_str),
        Some(WORK)
    );
    assert!(
        stderr.contains(
            "starting Claude on amir (no eligible account below 80%; existing weekly order)"
        ),
        "{stderr}"
    );
}

#[test]
fn an_ineligible_cool_account_does_not_remove_the_hot_fallback() {
    for blocked in ["unavailable", "billed", "weekly_headroom"] {
        let env = Env::new_start([95.0, 0.0, 0.0]);
        let mut fake = env.fake.lock().unwrap();
        for id in [SPARE, THIRD] {
            match blocked {
                "unavailable" => {
                    let accounts = fake
                        .start_accounts
                        .as_mut()
                        .unwrap()
                        .as_array_mut()
                        .unwrap();
                    accounts.iter_mut().find(|a| a["account_id"] == id).unwrap()["available"] =
                        json!(false);
                }
                "billed" => {
                    fake.start_usage.get_mut(id).unwrap()["extra_usage"]["is_enabled"] = json!(true)
                }
                "weekly_headroom" => {
                    fake.start_usage.get_mut(id).unwrap()["seven_day"]["utilization"] = json!(95.0)
                }
                _ => unreachable!(),
            }
        }
        drop(fake);
        let output = env.run(&["run"], "3");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(7), "{blocked}: {stderr}");
        assert_eq!(
            env.fake
                .lock()
                .unwrap()
                .token_requests
                .first()
                .map(String::as_str),
            Some(WORK),
            "{blocked}"
        );
        assert!(
            stderr.contains("start candidate amir5: 5h=0%, week="),
            "{blocked}: {stderr}"
        );
        assert!(stderr.contains("; ineligible:"), "{blocked}: {stderr}");
    }
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
    assert_observation_only(&env.fake.lock().unwrap());
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
            sample_renewal: false,
            fail_resume: false,
            start_only: false,
            limit_crons: false,
            late_blocker: None,
            delay_limit: false,
        }
    }
    fn new_start(five_hour: [f64; 3]) -> Self {
        let mut env = Env::new();
        env.start_only = true;
        let now = chrono::Utc::now();
        let mut fake = env.fake.lock().unwrap();
        fake.start_accounts = Some(json!([
            {"provider": "anthropic", "account_id": WORK, "alias": "amir",
                "identity": identity("org-work"), "available": true},
            {"provider": "anthropic", "account_id": SPARE, "alias": "amir5",
                "identity": identity("org-spare"), "available": true},
            {"provider": "anthropic", "account_id": THIRD, "alias": "amir4",
                "identity": identity("org-third"), "available": true},
        ]));
        // Week13/21 are from the report. Reset times and amir's week use are
        // synthetic: the old weekly order must prefer amir.
        for (id, five, week, reset_hours) in [
            (WORK, five_hour[0], 1.0, 1),
            (SPARE, five_hour[1], 13.0, 72),
            (THIRD, five_hour[2], 21.0, 120),
        ] {
            fake.start_usage.insert(
                id.into(),
                json!({
                    "five_hour": {"utilization": five},
                    "seven_day": {"utilization": week,
                        "resets_at": (now + chrono::Duration::hours(reset_hours)).to_rfc3339()},
                    "extra_usage": {"is_enabled": false},
                }),
            );
        }
        drop(fake);
        env
    }
    fn run(&self, args: &[&str], watchdog_s: &str) -> std::process::Output {
        self.run_with(args, watchdog_s, &[])
    }
    fn run_with(&self, args: &[&str], watchdog_s: &str, settings: &[&str]) -> std::process::Output {
        std::fs::create_dir_all(self.home.path().join("tmp")).unwrap();
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
            .env("TMPDIR", self.home.path().join("tmp"))
            .env(
                "FAKE_WRAPPER_BIN",
                assert_cmd::cargo::cargo_bin("claudectl"),
            )
            .args(args)
            .arg("--claude")
            .arg(&self.claude)
            .args(["--", "--model", "opus"])
            .args(settings);
        if self.sample_renewal {
            command.env("FAKE_SAMPLE_RENEWAL", "1");
        }
        if self.fail_resume {
            command.env("FAKE_FAIL_RESUME", "1");
        }
        if self.start_only {
            command.env("FAKE_START_ONLY", "1");
        }
        if self.limit_crons {
            command.env("FAKE_LIMIT_CRONS", "1");
        }
        if self.delay_limit {
            command.env("FAKE_DELAY_LIMIT", "1");
        }
        if let Some(blocker) = self.late_blocker {
            command.env("FAKE_LATE_BLOCKER", blocker);
            if blocker == "production" {
                let goal = self.home.path().join("goal.md");
                private_write(&goal, "");
                command
                    .env("LANE_GOAL_FILE", goal)
                    .env("HERDR_TAB_ID", "flt900:lane");
            }
        }
        Command::from_std(command)
            .timeout(std::time::Duration::from_secs(
                60.max(watchdog_s.parse::<u64>().unwrap() + 30),
            ))
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

fn assert_observation_only(fake: &Fake) {
    assert!(!fake.token_requests.is_empty());
    assert!(fake.token_requests.iter().all(|account| account == WORK));
    assert!(
        fake.token_request_bodies.iter().all(|request| {
            request["observe"] == true && request["previous_revision"].is_null()
        }),
        "deferral permits safe observation, never forced refresh or another account"
    );
}

fn assert_deferred(env: &Env, output: &std::process::Output, cause: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(99), "{stderr}");
    let runs = env.runs();
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert_eq!(runs[0]["token"], "token-work");
    assert!(env.records().is_empty());
    assert_observation_only(&env.fake.lock().unwrap());
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
    assert_eq!(status["reason"], "quiet_window");
    assert_eq!(status["cause"], cause);
}

#[test]
#[ignore = "exercises the real ten-minute account-failover quiet window"]
fn a_failover_keeps_the_live_model_from_the_outgoing_run() {
    let env = Env::new();
    private_write(
        &env.home.path().join("live-model.jsonl"),
        &json!({"type":"assistant","sessionId":"sess-1","message":{"model":"claude-fable-5-1"}})
            .to_string(),
    );
    let output = env.run(&["server", "run", "work", "--failover"], "660");
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runs = env.runs();
    assert_eq!(runs.len(), 2);
    assert_ne!(runs[0]["run"], runs[1]["run"]);
    let args = runs[1]["args"].as_array().unwrap();
    let model = args.iter().position(|arg| arg == "--model").unwrap();
    assert_eq!(args[model + 1], "claude-fable-5-1");
    let resume = args.iter().position(|arg| arg == "--resume").unwrap();
    assert_eq!(args[resume + 1], "sess-1");
}

#[test]
#[ignore = "exercises the real ten-minute account-failover quiet window"]
fn a_failed_failover_resume_keeps_the_live_model_when_starting_fresh() {
    let mut env = Env::new();
    env.fail_resume = true;
    private_write(
        &env.home.path().join("live-model.jsonl"),
        &json!({"type":"assistant","sessionId":"sess-1","message":{"model":"claude-fable-5-1"}})
            .to_string(),
    );
    let output = env.run(&["server", "run", "work", "--failover"], "660");
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let runs = env.runs();
    assert_eq!(
        runs.len(),
        3,
        "failed failover resume must start fresh once"
    );
    let args = runs[2]["args"].as_array().unwrap();
    assert!(!args.iter().any(|arg| arg == "--resume"));
    let model = args.iter().position(|arg| arg == "--model").unwrap();
    assert_eq!(args[model + 1], "claude-fable-5-1");
}

#[test]
fn weekly_limited_idle_cron_turns_failover_within_two_minutes() {
    let mut env = Env::new();
    env.fake.lock().unwrap().weekly_limit = true;
    env.limit_crons = true;

    let started = std::time::Instant::now();
    let output = env.run(&["run", "work", "--failover"], "3");
    let status = std::fs::read_to_string(env.log.with_extension("log.deferred"));
    let turns = std::fs::read_to_string(env.log.with_extension("log.limit-turns"));
    assert_eq!(
        output.status.code(),
        Some(7),
        "weekly-limited idle run did not move within the admission budget: {}\nstatus={status:?}\nlimit turns={turns:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(120));
    let runs = env.runs();
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[1]["token"], "token-spare");
    let args = runs[1]["args"].as_array().unwrap();
    let resume = args.iter().position(|arg| arg == "--resume").unwrap();
    assert_eq!(args[resume + 1], "sess-1");
}

fn current_weekly_limit_cache() -> Value {
    let observed = chrono::Utc::now();
    json!({
        "data": {
            "five_hour": {"utilization": 0.0},
            "seven_day": {"utilization": 100.0,
                "resets_at": (observed + chrono::Duration::hours(1)).to_rfc3339()},
            "extra_usage": {"is_enabled": false}
        },
        "observed_at": observed.timestamp_millis() - 1_000,
        "next_retry_at": observed.timestamp_millis() + 299_000,
        "stale": false, "error": null
    })
}

#[test]
fn a_current_weekly_limit_cache_does_not_wait_for_the_next_provider_poll() {
    let mut env = Env::new();
    env.limit_crons = true;
    env.fake.lock().unwrap().post_start_usage = Some(current_weekly_limit_cache());
    let started = std::time::Instant::now();
    let output = env.run(&["run", "work", "--failover"], "3");
    assert_eq!(
        output.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(started.elapsed() < std::time::Duration::from_secs(120));
    assert_eq!(env.runs().len(), 2);
    assert_eq!(env.runs()[1]["token"], "token-spare");
}

#[test]
fn weekly_limit_evidence_must_survive_target_reads() {
    for expiry in ["cache", "reset"] {
        let mut env = Env::new();
        let mut usage = current_weekly_limit_cache();
        if expiry == "cache" {
            usage["next_retry_at"] = (chrono::Utc::now().timestamp_millis() + 1_500).into();
        } else {
            usage["data"]["seven_day"]["resets_at"] = (chrono::Utc::now()
                + chrono::Duration::seconds(2))
            .to_rfc3339()
            .into();
        }
        env.late_blocker = Some("evidence_expiry");
        {
            let mut fake = env.fake.lock().unwrap();
            fake.post_start_usage = Some(usage);
            fake.target_barrier = Some((
                env.log.with_extension("log.block"),
                env.log.with_extension("log.blocked"),
            ));
        }
        let output = env.run(&["run", "work", "--failover"], "5");
        assert_eq!(
            output.status.code(),
            Some(99),
            "{expiry}: expired account proof moved the session"
        );
        assert!(env.log.with_extension("log.blocked").exists());
        assert_eq!(env.runs().len(), 1);
        assert!(
            env.records().is_empty(),
            "{expiry}: account was reserved on expired proof"
        );
    }
}

#[test]
fn deferred_limit_turns_leave_timestamps_after_run_cleanup() {
    let mut env = Env::new();
    env.limit_crons = true;
    env.delay_limit = true;
    env.fake.lock().unwrap().post_start_usage = Some(json!({
        "data": {"five_hour": {"utilization": 0.0}, "seven_day": {"utilization": 100.0}},
        "observed_at": chrono::Utc::now().timestamp_millis(),
        "next_retry_at": 0, "stale": true, "error": null
    }));
    let output = env.run(&["run", "work", "--failover"], "3");
    assert_eq!(output.status.code(), Some(99));
    let rows: Vec<Value> = std::fs::read_to_string(
        env.home
            .path()
            .join(".claudectl/server/restart-decisions.jsonl"),
    )
    .unwrap()
    .lines()
    .map(|line| serde_json::from_str(line).unwrap())
    .collect();
    assert!(
        rows.iter()
            .any(|row| row["cause"] == "renewal" && row["session_id"] == "sess-1")
    );
    let deferred: Vec<_> = rows
        .iter()
        .filter(|row| row["cause"] == "failover" && row["reason"] == "quiet_window")
        .collect();
    assert!(
        !deferred.is_empty(),
        "failover deferrals disappeared behind the earlier renewal: {rows:?}"
    );
    let failures: std::collections::BTreeSet<_> = deferred
        .iter()
        .map(|row| {
            row["activity"]["limit_failed_at"]
                .as_i64()
                .expect("durable failure timestamp")
        })
        .collect();
    assert!(
        failures.len() > 1,
        "later limit-only turns need their own durable timing evidence"
    );
    for row in deferred {
        assert_eq!(
            row["activity"]["idle_since"],
            row["activity"]["limit_failed_at"]
        );
        assert!(row["activity"]["quiet_since"].as_i64().is_some());
        assert!(
            row["at"].as_i64().unwrap() >= row["activity"]["limit_failed_at"].as_i64().unwrap()
        );
    }
    let runs = env.runs();
    assert!(!Path::new(runs[0]["run"].as_str().unwrap()).exists());
}

#[test]
fn weekly_limit_confirmation_keeps_late_workload_vetoes() {
    for (blocker, reason, cause) in [
        ("foreground", "running_turn", "renewal"),
        ("background", "background_task", "failover"),
        ("production", "open_production_step", "failover"),
        ("hold", "explicit_hold", "failover"),
    ] {
        let mut env = Env::new();
        env.late_blocker = Some(blocker);
        {
            let mut fake = env.fake.lock().unwrap();
            fake.weekly_limit = true;
            fake.target_barrier = Some((
                env.log.with_extension("log.block"),
                env.log.with_extension("log.blocked"),
            ));
        }
        let output = env.run(&["run", "work", "--failover"], "3");
        assert_eq!(
            output.status.code(),
            Some(99),
            "{blocker}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            env.log.with_extension("log.blocked").exists(),
            "{blocker}: account was never confirmed"
        );
        assert_eq!(env.runs().len(), 1, "{blocker}");
        assert!(
            env.records().is_empty(),
            "{blocker}: account was reserved while busy"
        );
        let status: Value =
            serde_json::from_slice(&std::fs::read(env.log.with_extension("log.deferred")).unwrap())
                .unwrap();
        assert_eq!(status["reason"], reason, "{blocker}: {status}");
        assert_eq!(status["cause"], cause, "{blocker}");
    }
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
    let mut env = Env::new();
    env.sample_renewal = true;
    {
        let mut fake = env.fake.lock().unwrap();
        fake.spare_full = true;
        fake.renew_work = true;
    }
    let output = env.run(&["run", "work", "--failover"], "3");
    assert!(env.fake.lock().unwrap().observed_renewal);
    assert_deferred(&env, &output, "failover");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("server token renewed"));
}

#[test]
fn a_pending_failover_still_observes_renewal_replacements() {
    let mut env = Env::new();
    env.sample_renewal = true;
    let shared = env.fake.clone();
    let log = env.log.clone();
    let observer = std::thread::spawn(move || {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < end {
            let pending = std::fs::read_to_string(&log)
                .ok()
                .and_then(|text| {
                    text.lines()
                        .next()
                        .and_then(|line| serde_json::from_str::<Value>(line).ok())
                })
                .and_then(|run| run["run"].as_str().map(std::path::PathBuf::from))
                .and_then(|run| std::fs::read(run.join("restart-status.json")).ok())
                .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                .is_some_and(|status| status["cause"] == "failover");
            if pending {
                shared.lock().unwrap().renew_work = true;
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("fixture did not observe a pending failover");
    });
    let output = env.run(&["run", "work", "--failover"], "3");
    observer.join().unwrap();
    let observed = env.fake.lock().unwrap().observed_renewal;
    assert!(
        observed,
        "a waiting failover must not suppress safe observation of a replacement"
    );
    assert_deferred(&env, &output, "failover");
}
