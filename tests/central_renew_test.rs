#![cfg(all(feature = "server", target_os = "linux"))]
//! Public CLI coverage of valid-token quiet admission and next-idle authentication recovery.
//! Broker/provider endpoints are synthetic; the automatic signal guard always stays active.
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const ACCOUNT: &str = "abababababababababababababababababababababababababababababababab";
#[derive(Default)]
struct Fake {
    requests: Vec<Value>,
    life_ms: i64,
    generation: u64,
    expires_at: i64,
    provider_requests: Vec<Value>,
    current_revoked: bool,
    pause_observe: bool,
    observe_pending: bool,
}
type Shared = Arc<Mutex<Fake>>;
fn identity() -> Value {
    json!({"account_uuid":"claude-account","organization_uuid":"claude-org"})
}
async fn accounts() -> Json<Value> {
    Json(
        json!([{"provider":"anthropic","account_id":ACCOUNT,"alias":"work","identity":identity(),"available":true}]),
    )
}
async fn usage() -> Json<Value> {
    Json(json!({"data":null,"observed_at":null,"next_retry_at":0,"stale":true,"error":null}))
}
async fn token(State(shared): State<Shared>, Json(body): Json<Value>) -> Json<Value> {
    let response = {
        let mut fake = shared.lock().unwrap();
        fake.requests.push(body);
        if fake.pause_observe && fake.requests.len() > 1 {
            fake.observe_pending = true;
        }
        let now = chrono::Utc::now().timestamp_millis();
        let revision = format!("revision-{}", fake.generation);
        let forced =
            fake.requests.last().unwrap()["previous_revision"].as_str() == Some(revision.as_str());
        if forced || fake.expires_at == 0 || fake.expires_at <= now {
            if fake.expires_at != 0 {
                fake.generation += 1;
            }
            fake.expires_at = now + fake.life_ms;
            fake.current_revoked = false;
        }
        json!({"provider":"anthropic","account_id":ACCOUNT,"user_id":"person","identity":identity(),
            "access_token":format!("token-{}",fake.generation),"expires_at":fake.expires_at,
            "scopes":["user:inference","user:profile"],"revision":format!("revision-{}",fake.generation),"generation":fake.generation})
    };
    loop {
        let paused = {
            let fake = shared.lock().unwrap();
            fake.observe_pending && fake.pause_observe
        };
        if !paused {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Json(response)
}
async fn provider(State(shared): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let mut fake = shared.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let current = format!("Bearer token-{}", fake.generation);
    let revoked = fake.current_revoked
        || headers.get("authorization").and_then(|h| h.to_str().ok()) != Some(current.as_str());
    let status = if revoked || now >= fake.expires_at {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::OK
    };
    let expires_at = fake.expires_at;
    fake.provider_requests.push(json!({
        "at":now,"status":status.as_u16(),"revoked":revoked,"expires_at":expires_at
    }));
    (status, Json(json!({"account_id":ACCOUNT})))
}
fn private_write(path: &Path, value: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
const FAKE_CLAUDE: &str = r#"#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path
home=Path(os.environ['HOME'])
log=home/'claude.log'
first_launch=not log.exists()
mode=os.environ['FAKE_MODE']
args=sys.argv[1:]
settings=json.load(open(args[args.index('--settings')+1]))
run=Path(os.environ['CLAUDECTL_SERVER_RUN'])
with log.open('a') as out:
    out.write(json.dumps({'token':os.environ['CLAUDE_CODE_OAUTH_TOKEN'],'args':args,'settings':settings,'run':str(run),'session':json.load(open(run/'session.json')),'pid':os.getpid(),'tty':os.isatty(0),'foreground':not os.isatty(0) or os.tcgetpgrp(0)==os.getpgrp()})+'\n')
if mode=='auth_resume_fails' and not first_launch: sys.exit(7)
def term(*_):
    (home/'terminated').touch()
    sys.exit(143)
signal.signal(signal.SIGTERM,term)
command=settings['hooks']['Stop'][0]['hooks'][0]['command']
def hook(event, **details):
    subprocess.run(['/bin/sh','-c',command],input=json.dumps({'hook_event_name':event,'session_id':'s',**details}).encode(),check=True)
if mode != 'no_hooks':
    hook('SessionStart'); hook('UserPromptSubmit')
    if mode != 'busy' or not first_launch: hook('Stop')
task=None
if mode=='task' and first_launch:
    folder=Path(os.environ['TMPDIR'])/('claude-'+str(os.getuid()))/'project/tasks'
    folder.mkdir(parents=True)
    with (folder/'task.output').open('w') as out:
        task=subprocess.Popen([sys.executable,'-c',"import os,time; from pathlib import Path; h=Path(os.environ['HOME']); end=time.monotonic()+15\nwhile not (h/'release').exists() and not (h/'task-release').exists() and time.monotonic()<end:\n (h/'task-progress').write_text(str(time.monotonic())); time.sleep(.02)\n(h/'task-done').touch()"],stdout=out,stderr=out)
if mode=='hold':
    subprocess.run([os.environ['FAKE_WRAPPER_BIN'],'hold','start','--reason','FLT-553 synthetic step'],check=True)
if mode=='hook_error': (run/'hook-error').touch()
if mode=='damaged':
    with (run/'events').open('a') as out: out.write('broken record\n')
if mode=='extra': task=subprocess.Popen(['sleep','15'])
(home/'ready').touch()
deadline=time.monotonic()+15
prompted=False
probed=False
became_idle=False
while not (home/'release').exists() and time.monotonic()<deadline:
    if mode in ('auth_recovery','auth_prompt','auth_resume_fails','task','busy') and (home/'provider-probe').exists() and not probed:
        request=urllib.request.Request(os.environ['FAKE_PROVIDER_URL'],headers={'Authorization':'Bearer '+os.environ['CLAUDE_CODE_OAUTH_TOKEN']})
        try:
            with urllib.request.urlopen(request,timeout=2) as response: status=response.status
        except urllib.error.HTTPError as error: status=error.code
        if mode!='busy' or not first_launch:
            hook('StopFailure',error='authentication_failed') if status==401 else hook('Stop')
        probed=True
    if (home/'become-idle').exists() and not became_idle:
        hook('Stop'); became_idle=True
    if mode=='busy' and first_launch and not became_idle:
        (home/'busy-progress').write_text(str(time.monotonic()))
    if (home/'submit').exists() and not prompted:
        hook('UserPromptSubmit'); prompted=True
    if (home/'turn-done').exists() and prompted:
        hook('Stop'); prompted=False; (home/'submit').unlink(missing_ok=True)
    time.sleep(.02)
if task is not None:
    if mode=='extra': task.terminate()
    task.wait(timeout=3)
if mode not in ['no_hooks','hook_error','damaged']: hook('SessionEnd')
sys.exit(23)
"#;

struct Fixture {
    home: tempfile::TempDir,
    state: Shared,
    mode: String,
    child: Option<Child>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<std::thread::JoinHandle<()>>,
}
impl Fixture {
    fn start(mode: &str, life_ms: i64, tty: bool) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let home = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(Fake {
            life_ms,
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
            .route("/synthetic/provider", get(provider))
            .with_state(state.clone());
        let (shutdown, done) = tokio::sync::oneshot::channel();
        let server = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app)
                        .with_graceful_shutdown(async {
                            let _ = done.await;
                        })
                        .await
                        .unwrap();
                })
        });
        let root = home.path().join(".claudectl/server");
        private_write(
            &root.join("connection.json"),
            &json!({"server":origin,"user_id":"person","token_file":root.join("machine.json")})
                .to_string(),
        );
        private_write(&root.join("machine.json"), "\"synthetic-machine\"");
        let claude = home.path().join("claude");
        std::fs::write(&claude, FAKE_CLAUDE).unwrap();
        std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_write(&root.join("qualified-host-config-builds.json"), &json!([{"sha256":claudectl::exec::sha256_file(&claude).unwrap(),"platform":"linux","qualified_at":"test","check":"supervised_host_config"}]).to_string());
        std::fs::create_dir(home.path().join("tmp")).unwrap();
        let binary = assert_cmd::cargo::cargo_bin("claudectl");
        let settings = r#"{"crossSessionInbound":"accept","isolatePeerMachines":true}"#;
        let mut command = if tty {
            let quote = |s: &Path| format!("'{}'", s.display().to_string().replace('\'', "'\\''"));
            let mut c = Command::new("/usr/bin/script");
            c.args([
                "-qec",
                &format!(
                    "{} server run work --claude {} -- --model opus --settings '{}'",
                    quote(&binary),
                    quote(&claude),
                    settings
                ),
                "/dev/null",
            ]);
            c
        } else {
            let mut c = Command::new(&binary);
            c.args(["server", "run", "work", "--claude"])
                .arg(&claude)
                .args([
                    "--",
                    "--model",
                    "opus",
                    "--resume",
                    "old",
                    "--settings",
                    settings,
                ]);
            c
        };
        if mode == "auth_prompt" {
            command.args(["--", "synthetic original task that must not be replayed"]);
        }
        command
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TERM", "xterm")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .env("CLAUDECTL_TEST_RENEW_FAST", "1")
            .env("TMPDIR", home.path().join("tmp"))
            .env("FAKE_MODE", mode)
            .env("FAKE_PROVIDER_URL", format!("{origin}/synthetic/provider"))
            .env("FAKE_WRAPPER_BIN", binary)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child = command.spawn().unwrap();
        Self {
            home,
            state,
            mode: mode.into(),
            child: Some(child),
            shutdown: Some(shutdown),
            server: Some(server),
        }
    }
    fn run(&self) -> Value {
        serde_json::from_str(
            std::fs::read_to_string(self.home.path().join("claude.log"))
                .unwrap()
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap()
    }
    fn runs(&self) -> Vec<Value> {
        std::fs::read_to_string(self.home.path().join("claude.log"))
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn revoke(&self) {
        let mut fake = self.state.lock().unwrap();
        fake.generation += 1;
        fake.expires_at = chrono::Utc::now().timestamp_millis() + fake.life_ms;
    }
    fn wait_recovered(&self) -> Vec<Value> {
        let end = Instant::now() + Duration::from_secs(4);
        while Instant::now() < end {
            let runs = self.runs();
            if runs.len() >= 2 {
                return runs;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the child did not automatically resume at the next verified idle point");
    }
    fn finish_recovered(&mut self) {
        std::fs::write(self.home.path().join("release"), "").unwrap();
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(23));
        let runs = self.runs();
        assert_eq!(
            runs.len(),
            2,
            "the old failure observation must not restart twice"
        );
        assert_ne!(runs[0]["pid"], runs[1]["pid"]);
        assert_eq!(runs[1]["token"], "token-2");
        assert_eq!(runs[1]["run"], runs[0]["run"]);
        assert_eq!(runs[1]["session"]["account_id"], ACCOUNT);
        let args = runs[1]["args"].as_array().unwrap();
        let resume = args.iter().position(|arg| arg == "--resume").unwrap();
        assert_eq!(args[resume + 1], "s");
        assert!(
            self.state
                .lock()
                .unwrap()
                .requests
                .iter()
                .all(|r| r["account_id"] == ACCOUNT)
        );
    }
    fn directory(&self) -> PathBuf {
        PathBuf::from(self.run()["run"].as_str().unwrap())
    }
    fn wait(&mut self, reason: &str, stage: &str) -> Value {
        let end = Instant::now() + Duration::from_secs(7);
        while Instant::now() < end {
            if self.home.path().join("ready").exists() {
                let file = self.directory().join("restart-status.json");
                if let Ok(bytes) = std::fs::read(file)
                    && let Ok(status) = serde_json::from_slice::<Value>(&bytes)
                    && status["reason"] == reason
                    && status["stage"] == stage
                    && (matches!(self.mode.as_str(), "no_hooks" | "hook_error" | "damaged")
                        || status["session_id"] == "s")
                {
                    return status;
                }
            }
            if self.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("no {reason}/{stage} status; child exited or admission stalled");
    }
    fn journal(&self) -> Vec<Value> {
        std::fs::read_to_string(
            self.home
                .path()
                .join(".claudectl/server/restart-decisions.jsonl"),
        )
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
    }
    fn finish(&mut self) -> Output {
        std::fs::write(self.home.path().join("release"), "").unwrap();
        let output = self.child.take().unwrap().wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(23),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!self.home.path().join("terminated").exists());
        assert_eq!(
            std::fs::read_to_string(self.home.path().join("claude.log"))
                .unwrap()
                .lines()
                .count(),
            1
        );
        assert_eq!(self.run()["token"], "token-1");
        assert_eq!(
            self.state.lock().unwrap().requests.len(),
            1,
            "only the initial token grant is allowed"
        );
        assert!(
            !self
                .home
                .path()
                .join(".claudectl/server/failovers.jsonl")
                .exists()
        );
        assert!(!String::from_utf8_lossy(&output.stderr).contains("resuming session"));
        output
    }
}

#[test]
fn a_revoked_idle_child_automatically_resumes_the_same_session_and_account() {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    let first = f.run();
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline && f.runs().len() < 2 {
        std::thread::sleep(Duration::from_millis(20));
    }
    let requests = f.state.lock().unwrap().provider_requests.clone();
    assert!(
        requests
            .iter()
            .any(|r| r["status"] == 401 && r["revoked"] == true),
        "the synthetic provider must reject the held grant before testing recovery"
    );
    assert!(requests[0]["at"].as_i64().unwrap() < first["session"]["expires_at"].as_i64().unwrap());
    let runs = f.runs();
    assert_eq!(
        runs.len(),
        2,
        "an idle child with a provider-rejected grant must restart before ten minutes of quiet"
    );
    assert_ne!(runs[1]["pid"], first["pid"]);
    assert_eq!(runs[1]["token"], "token-2");
    assert_eq!(runs[1]["run"], first["run"]);
    assert_eq!(runs[1]["session"]["account_id"], ACCOUNT);
    let args = runs[1]["args"].as_array().unwrap();
    let resume = args.iter().position(|a| a == "--resume").unwrap();
    assert_eq!(args[resume + 1], "s");
    std::fs::write(f.home.path().join("release"), "").unwrap();
    let output = f.child.take().unwrap().wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23));
}

#[test]
fn a_revoked_busy_child_alerts_and_resumes_only_after_its_task_finishes() {
    let mut f = Fixture::start("task", 600_000, false);
    f.wait("background_task", "deferred");
    let first = f.run();
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let blocked = f.wait("background_task", "blocked");
    assert_eq!(blocked["attention_required"], true);
    assert_eq!(f.runs(), vec![first]);
    assert!(!f.home.path().join("terminated").exists());
    let progress = std::fs::read(f.home.path().join("task-progress")).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    assert_ne!(
        std::fs::read(f.home.path().join("task-progress")).unwrap(),
        progress
    );
    let count = f
        .journal()
        .iter()
        .filter(|row| row["stage"] == "blocked")
        .count();
    assert_eq!(
        count, 1,
        "one actionable blocked alert for this observation"
    );
    std::fs::write(f.home.path().join("task-release"), "").unwrap();
    f.wait_recovered();
    assert!(f.home.path().join("task-done").exists());
    std::thread::sleep(Duration::from_millis(450));
    f.finish_recovered();
}

#[test]
fn an_auth_recovery_preserves_terminal_foreground_for_the_same_session() {
    let mut f = Fixture::start("auth_recovery", 600_000, true);
    f.wait("quiet_window", "deferred");
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let runs = f.wait_recovered();
    assert!(
        runs.iter()
            .all(|run| run["tty"] == true && run["foreground"] == true)
    );
    f.finish_recovered();
}

#[test]
fn a_naturally_expired_busy_child_alerts_then_resumes_once_after_its_turn() {
    let mut f = Fixture::start("busy", 2_500, false);
    f.wait("running_turn", "warn");
    let blocked = f.wait("running_turn", "blocked");
    assert_eq!(blocked["attention_required"], true);
    assert_eq!(f.runs().len(), 1);
    assert!(!f.home.path().join("terminated").exists());
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    while f.state.lock().unwrap().provider_requests.is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    let requests = f.state.lock().unwrap().provider_requests.clone();
    assert_eq!(requests[0]["status"], 401);
    assert_eq!(requests[0]["revoked"], false);
    assert!(requests[0]["at"].as_i64().unwrap() >= requests[0]["expires_at"].as_i64().unwrap());
    let progress = std::fs::read(f.home.path().join("busy-progress")).unwrap();
    std::thread::sleep(Duration::from_millis(150));
    assert_ne!(
        std::fs::read(f.home.path().join("busy-progress")).unwrap(),
        progress
    );
    f.state.lock().unwrap().life_ms = 600_000;
    std::fs::write(f.home.path().join("become-idle"), "").unwrap();
    f.wait_recovered();
    std::thread::sleep(Duration::from_millis(450));
    f.finish_recovered();
}

#[test]
fn an_auth_resume_replays_neither_the_original_task_nor_missed_jobs() {
    for mode in ["auth_recovery", "auth_prompt"] {
        let mut f = Fixture::start(mode, 600_000, false);
        f.wait("quiet_window", "deferred");
        f.revoke();
        std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
        let runs = f.wait_recovered();
        let args = runs[1]["args"].as_array().unwrap();
        assert!(
            !args.iter().any(|arg| arg
                .as_str()
                .is_some_and(|text| text.contains("Run CronList")
                    || text.contains("synthetic original task"))),
            "auth recovery must not inject a catch-up task or replay the original prompt"
        );
        f.finish_recovered();
    }
}

#[test]
fn a_failed_auth_resume_does_not_start_a_different_conversation() {
    let mut f = Fixture::start("auth_resume_fails", 600_000, false);
    f.wait("quiet_window", "deferred");
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(4);
    while f.child.as_mut().unwrap().try_wait().unwrap().is_none() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(f.child.as_mut().unwrap().try_wait().unwrap().is_some());
    let output = f.child.take().unwrap().wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(
        f.runs().len(),
        2,
        "auth recovery must stop when the original conversation cannot resume, not start a fresh one"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("authentication recovery stopped"));
}

#[test]
fn a_rejected_current_grant_is_replaced_once_at_idle_on_the_same_account() {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    f.state.lock().unwrap().current_revoked = true;
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    while f.state.lock().unwrap().provider_requests.is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.state.lock().unwrap().provider_requests[0]["status"], 401);
    f.wait_recovered();
    std::thread::sleep(Duration::from_millis(450));
    let requests = f.state.lock().unwrap().requests.clone();
    assert_eq!(
        requests
            .iter()
            .filter(|r| r["previous_revision"] == "revision-1")
            .count(),
        1,
        "refresh only the exact rejected revision, once, after idle admission"
    );
    f.finish_recovered();
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.state.lock().unwrap().pause_observe = false;
        if let Some(child) = self.child.take() {
            let _ = std::fs::write(self.home.path().join("release"), "");
            let _ = child.wait_with_output();
        }
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.join();
        }
    }
}

struct HookInput(Option<Child>);
impl HookInput {
    fn reading(f: &Fixture) -> Self {
        use std::io::Write;
        let mut child = Command::new(assert_cmd::cargo::cargo_bin("claudectl"))
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", f.home.path())
            .args(["server", "hook"])
            .arg(f.directory())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"{\"hook_event_name\":\"UserPromptSubmit\",")
            .unwrap();
        let hook = Self(Some(child));
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            let pid = hook.0.as_ref().unwrap().id();
            if std::fs::read_to_string(format!("/proc/{pid}/wchan"))
                .is_ok_and(|state| state.contains("pipe_read"))
            {
                return hook;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("fixture setup UNKNOWN: public hook did not reach its blocked input read");
    }
    fn submit(mut self) {
        use std::io::Write;
        let mut child = self.0.take().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"\"session_id\":\"s\"}\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
impl Drop for HookInput {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            drop(child.stdin.take());
            let _ = child.wait_with_output();
        }
    }
}

#[test]
fn a_prompt_hook_reading_input_blocks_the_auth_recovery_signal() {
    hook_input_blocks_recovery(false);
}

#[test]
fn a_prompt_hook_blocks_refreshing_the_rejected_current_grant_until_idle() {
    hook_input_blocks_recovery(true);
}

fn hook_input_blocks_recovery(reject_current: bool) {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    if reject_current {
        f.state.lock().unwrap().current_revoked = true;
    } else {
        f.revoke();
    }
    f.state.lock().unwrap().pause_observe = true;
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    while !f.state.lock().unwrap().observe_pending && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        f.state.lock().unwrap().observe_pending,
        "fixture setup UNKNOWN: no pending token read"
    );
    let hook = HookInput::reading(&f);
    f.state.lock().unwrap().pause_observe = false;
    let end = Instant::now() + Duration::from_secs(4);
    let mut queued = false;
    while Instant::now() < end && f.runs().len() == 1 {
        if let Ok(bytes) = std::fs::read(f.directory().join("restart-status.json"))
            && let Ok(status) = serde_json::from_slice::<Value>(&bytes)
            && status["reason"] == "queued_hook"
            && status["stage"] == "blocked"
        {
            queued = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        queued,
        "a prompt hook already reading input must block auth-recovery SIGTERM"
    );
    assert!(!f.home.path().join("terminated").exists());
    hook.submit();
    f.wait("running_turn", "blocked");
    assert_eq!(f.runs().len(), 1);
    assert!(
        f.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|r| r["previous_revision"].is_null())
    );
    std::fs::write(f.home.path().join("become-idle"), "").unwrap();
    f.wait_recovered();
    f.finish_recovered();
}

#[test]
fn quiet_window_preserves_child_token_settings_and_accounting() {
    let mut f = Fixture::start("idle", 600_000, false);
    let status = f.wait("quiet_window", "deferred");
    let recorded = status["restart_deferred_total"].clone();
    let journal_len = f.journal().len();
    f.state.lock().unwrap().generation = 2; // Another client changes the available revision.
    std::thread::sleep(Duration::from_millis(350));
    assert!(f.child.as_mut().unwrap().try_wait().unwrap().is_none());
    let session: Value =
        serde_json::from_slice(&std::fs::read(f.directory().join("session.json")).unwrap())
            .unwrap();
    assert_eq!(session["renewal"], "on");
    assert_eq!(
        f.wait("quiet_window", "deferred")["restart_deferred_total"],
        recorded
    );
    assert_eq!(f.journal().len(), journal_len);
    let run = f.run();
    assert_eq!(run["settings"]["crossSessionInbound"], "accept");
    assert_eq!(run["settings"]["isolatePeerMachines"], true);
    assert_eq!(
        run["settings"]["hooks"]["Stop"].as_array().unwrap().len(),
        1
    );
    f.finish();
}

#[test]
fn every_deferred_session_warns_and_blocks_without_monitor_teardown() {
    for (mode, reason) in [
        ("busy", "running_turn"),
        ("task", "background_task"),
        ("hold", "explicit_hold"),
        ("no_hooks", "evidence_unknown"),
        ("hook_error", "evidence_unknown"),
        ("damaged", "evidence_unknown"),
    ] {
        // Cross the missing-hook timeout before expiry, rather than only its startup path.
        let life_ms = if mode == "no_hooks" { 6_500 } else { 2_500 };
        let mut f = Fixture::start(mode, life_ms, false);
        let warn = f.wait(reason, "warn");
        assert_eq!(warn["attention_required"], true);
        let hold = f.home.path().join(".claudectl/server/holds").join(format!(
            "{}.json",
            f.directory().file_name().unwrap().to_str().unwrap()
        ));
        let held = std::fs::read(&hold).ok();
        let blocked = f.wait(reason, "blocked");
        assert_eq!(blocked["attention_required"], true);
        assert!(f.child.as_mut().unwrap().try_wait().unwrap().is_none());
        for stage in ["warn", "blocked"] {
            let rows = f.journal();
            let matching: Vec<_> = rows.iter().filter(|r| r["stage"] == stage).collect();
            assert!(!matching.is_empty(), "each session needs its {stage} event");
            assert_eq!(matching[0]["metric"]["labels"]["stage"], stage);
        }
        let mut command = Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", f.home.path())
            .env("CLAUDECTL_SERVER_RUN", f.directory())
            .arg("statusline");
        let output = command.output().unwrap();
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains(&format!("restart deferred: {reason} (blocked)"))
        );
        if mode == "task" {
            assert!(f.home.path().join("task-progress").exists());
        }
        let output = f.finish();
        if mode == "no_hooks" {
            assert!(String::from_utf8_lossy(&output.stderr).contains("sent no hook events"));
        }
        if mode == "task" {
            assert!(f.home.path().join("task-done").exists());
        }
        if let Some(held) = held {
            assert_eq!(std::fs::read(hold).unwrap(), held);
        }
    }
}

#[test]
fn later_prompts_and_non_task_helpers_do_not_bypass_the_quiet_window() {
    for mode in ["idle", "extra"] {
        let mut f = Fixture::start(mode, 600_000, false);
        f.wait("quiet_window", "deferred");
        std::fs::write(f.home.path().join("submit"), "").unwrap();
        f.wait("running_turn", "deferred");
        std::fs::write(f.home.path().join("turn-done"), "").unwrap();
        f.wait("quiet_window", "deferred");
        f.finish();
    }
}

#[test]
fn an_idle_terminal_session_keeps_foreground_until_its_owner_exits() {
    let mut f = Fixture::start("idle", 600_000, true);
    f.wait("quiet_window", "deferred");
    assert_eq!(f.run()["tty"], true);
    assert_eq!(f.run()["foreground"], true);
    f.finish();
}
