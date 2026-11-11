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
    reject_once: bool,
    pause_observe: bool,
    observe_pending: bool,
    token_failures: usize,
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
async fn token(State(shared): State<Shared>, Json(body): Json<Value>) -> (StatusCode, Json<Value>) {
    let response = {
        let mut fake = shared.lock().unwrap();
        fake.requests.push(body);
        if fake.token_failures > 0 && fake.requests.last().unwrap()["previous_revision"].is_string()
        {
            fake.token_failures -= 1;
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"synthetic failure"})),
            );
        }
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
    (StatusCode::OK, Json(response))
}
async fn provider(State(shared): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let mut fake = shared.lock().unwrap();
    let now = chrono::Utc::now().timestamp_millis();
    let current = format!("Bearer token-{}", fake.generation);
    let revoked = fake.current_revoked
        || headers.get("authorization").and_then(|h| h.to_str().ok()) != Some(current.as_str());
    let transient = std::mem::take(&mut fake.reject_once);
    let status = if revoked || transient || now >= fake.expires_at {
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
import fcntl, json, os, select, signal, subprocess, sys, time, tty, urllib.error, urllib.request
from pathlib import Path
home=Path(os.environ['HOME'])
log=home/'claude.log'
first_launch=not log.exists()
mode=os.environ['FAKE_MODE']
if mode=='auth_typing': tty.setraw(0)
args=sys.argv[1:]
settings=json.load(open(args[args.index('--settings')+1]))
run=Path(os.environ['CLAUDECTL_SERVER_RUN'])
with log.open('a') as out:
    out.write(json.dumps({'token':os.environ['CLAUDE_CODE_OAUTH_TOKEN'],'args':args,'settings':settings,'run':str(run),'session':json.load(open(run/'session.json')),'pid':os.getpid(),'tty':os.isatty(0),'foreground':not os.isatty(0) or os.tcgetpgrp(0)==os.getpgrp()})+'\n')
if mode=='auth_resume_fails' and not first_launch: sys.exit(7)
def term(*_):
    if mode=='exit_race' and first_launch:
        admission=(run/'restart.lock').open('r+')
        fcntl.flock(admission,fcntl.LOCK_EX)
        ended=int((home/'exit-at').read_text())
        with (run/'events').open('a') as out:
            out.write(json.dumps({'at':ended,'event':'SessionEnd','session_id':'s'})+'\n'+'broken record\n')
        if os.fork()==0:
            signal.signal(signal.SIGTERM,signal.SIG_DFL)
            time.sleep(.25)
            os._exit(0)
        sys.exit(23)
    if mode=='ignore_term' and first_launch:
        (home/'term-received').touch()
        return
    (home/'terminated').touch()
    sys.exit(143)
signal.signal(signal.SIGTERM,term)
command=settings['hooks']['Stop'][0]['hooks'][0]['command']
def hook(event, **details):
    subprocess.run(['/bin/sh','-c',command],input=json.dumps({'hook_event_name':event,'session_id':'s',**details}).encode(),check=True)
def provider_status():
    request=urllib.request.Request(os.environ['FAKE_PROVIDER_URL'],headers={'Authorization':'Bearer '+os.environ['CLAUDE_CODE_OAUTH_TOKEN']})
    try:
        with urllib.request.urlopen(request,timeout=2) as response: return response.status
    except urllib.error.HTTPError as error: return error.code
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
deadline=time.monotonic()+(60 if os.isatty(0) or mode=='ignore_term' else 15)
prompted=False
probed=False
retried=False
became_idle=False
typed=0
while not (home/'release').exists() and time.monotonic()<deadline:
    if mode=='auth_typing' and select.select([0],[],[],0)[0]:
        typed+=len(os.read(0,4096))
        (home/'typed-progress.next').write_text(str(typed))
        os.replace(home/'typed-progress.next',home/'typed-progress')
    if mode in ('auth_recovery','auth_prompt','auth_resume_fails','auth_typing','auth_revoked','auth_expired','auth_login','task','busy') and (home/'provider-probe').exists() and not probed:
        status=provider_status()
        if mode!='busy' or not first_launch:
            details={'auth_revoked':'OAuth token revoked','auth_expired':'401 OAuth access token has expired','auth_login':'Please run /login'}.get(mode)
            hook('StopFailure',error='unknown' if details else 'authentication_failed',error_details=details) if status==401 else hook('Stop')
        probed=True
    if (home/'provider-retry').exists() and not retried:
        status=provider_status()
        hook('StopFailure',error='authentication_failed') if status==401 else hook('Stop')
        retried=True
    if (home/'become-idle').exists() and not became_idle:
        status=provider_status() if probed else 200
        hook('StopFailure',error='authentication_failed') if status==401 else hook('Stop')
        became_idle=True
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
            .stdin(if mode == "auth_typing" {
                Stdio::piped()
            } else {
                Stdio::null()
            })
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
        let wait = if self.run()["tty"] == true { 30 } else { 4 };
        let end = Instant::now() + Duration::from_secs(wait);
        while Instant::now() < end {
            let runs = self.runs();
            if runs.len() >= 2 {
                return runs;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!(
            "the child did not automatically resume; last restart status: {}",
            std::fs::read_to_string(self.directory().join("restart-status.json"))
                .unwrap_or_default()
        );
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
        assert!(
            self.state.lock().unwrap().requests.iter().skip(1)
                .all(|request| request["observe"] == true && request["previous_revision"].is_null()),
            "busy sessions may observe the server but must not force-refresh a live token"
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
fn revoked_token_restarts_despite_background_task() {
    let mut f = Fixture::start("task", 600_000, false);
    f.wait("background_task", "deferred");
    assert!(f.home.path().join("task-progress").exists());
    assert!(!f.home.path().join("task-done").exists());
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    f.wait_recovered();
    assert!(
        f.state
            .lock()
            .unwrap()
            .provider_requests
            .iter()
            .any(|request| { request["status"] == 401 && request["revoked"] == true })
    );
    assert!(f.home.path().join("terminated").exists());
    assert!(
        !f.home.path().join("task-done").exists(),
        "tK case: recovery must stop the revoked child and its task before natural task completion"
    );
    let forced: Vec<_> = f
        .journal()
        .into_iter()
        .filter(|event| event["event"] == "restart_forced")
        .collect();
    assert_eq!(forced.len(), 1, "count each actual forced restart once");
    assert_eq!(
        forced[0]["metric"]["name"],
        "claudectl_restart_forced_total"
    );
    assert_eq!(forced[0]["metric"]["value"], 1);
    assert_eq!(forced[0]["route"], "voice_inbox");
    std::thread::sleep(Duration::from_millis(450));
    f.finish_recovered();
}

#[test]
fn expiry_restarts_even_after_hook_failure() {
    let mut f = Fixture::start("hook_error", 1_500, false);
    f.wait("evidence_unknown", "warn");
    f.state.lock().unwrap().life_ms = 600_000;
    f.wait_recovered();
    f.finish_recovered();
}

#[test]
fn a_corrupt_log_cannot_hide_a_later_revoked_token_failure() {
    use std::io::Write;
    for damaged in [b"broken record\n".as_slice(), b"partial record".as_slice()] {
        let mut f = Fixture::start("auth_recovery", 600_000, false);
        f.wait("quiet_window", "deferred");
        std::fs::OpenOptions::new()
            .append(true)
            .open(f.directory().join("events"))
            .unwrap()
            .write_all(damaged)
            .unwrap();
        f.revoke();
        std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
        f.wait_recovered();
        f.finish_recovered();
    }
}

#[test]
fn a_child_ignoring_sigterm_is_killed_after_the_save_grace_and_resumed() {
    let mut f = Fixture::start("ignore_term", 1_500, false);
    f.wait("quiet_window", "warn");
    f.state.lock().unwrap().life_ms = 600_000;
    let start = Instant::now();
    let end = start + Duration::from_secs(25);
    while f.runs().len() < 2 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(f.home.path().join("term-received").exists());
    assert!(
        start.elapsed() >= Duration::from_secs(20),
        "allow Claude to save before SIGKILL"
    );
    assert_eq!(
        f.runs().len(),
        2,
        "a leader ignoring SIGTERM must not strand recovery"
    );
    f.finish_recovered();
}

#[test]
fn an_explicit_exit_during_forced_shutdown_is_not_resumed() {
    let mut f = Fixture::start("exit_race", 1_500, false);
    f.wait("quiet_window", "warn");
    f.state.lock().unwrap().life_ms = 600_000;
    std::fs::write(
        f.home.path().join("exit-at"),
        chrono::Utc::now().timestamp_millis().to_string(),
    )
    .unwrap();
    let end = Instant::now() + Duration::from_secs(4);
    while f.child.as_mut().unwrap().try_wait().unwrap().is_none() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        f.child.as_mut().unwrap().try_wait().unwrap().is_some(),
        "do not reopen an explicitly ended conversation"
    );
    let output = f.child.take().unwrap().wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(f.runs().len(), 1);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("resuming session"));
}

#[test]
fn failed_recovery_attempt_is_counted_once_then_recovers() {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    {
        let mut state = f.state.lock().unwrap();
        state.current_revoked = true;
        state.token_failures = 1;
    }
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    f.wait_recovered();
    let failures: Vec<_> = f
        .journal()
        .into_iter()
        .filter(|event| event["event"] == "recovery_failed")
        .collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["reason"], "acquire");
    assert_eq!(
        failures[0]["metric"]["name"],
        "claudectl_recovery_failed_total"
    );
    assert_eq!(failures[0]["metric"]["value"], 1);
    assert_eq!(failures[0]["route"], "voice_inbox");
    f.finish_recovered();
}

#[test]
fn unavailable_throttle_storage_does_not_drop_a_recovery_failure() {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    let streak = f.directory().join("recovery-failures.json");
    if streak.exists() {
        std::fs::remove_file(&streak).unwrap();
    }
    std::fs::create_dir(&streak).unwrap();
    {
        let mut state = f.state.lock().unwrap();
        state.current_revoked = true;
        state.token_failures = 21;
    }
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    f.wait_recovered();
    let failures: Vec<_> = f
        .journal()
        .into_iter()
        .filter(|event| event["metric"]["name"] == "claudectl_recovery_failed_total")
        .collect();
    assert_eq!(failures.len(), 21);
    assert!(
        failures.iter().all(
            |event| event["reason"] == "acquire" && event["throttle_state_unavailable"] == true
        )
    );
    assert_eq!(
        failures
            .iter()
            .filter(|event| event["route"] == "voice_inbox")
            .count(),
        11
    );
    f.finish_recovered();
}

#[test]
fn auth_failure_messages_trigger_recovery_without_logging_raw_details() {
    for mode in ["auth_revoked", "auth_expired", "auth_login"] {
        let mut f = Fixture::start(mode, 600_000, false);
        f.wait("quiet_window", "deferred");
        f.state.lock().unwrap().pause_observe = true;
        f.revoke();
        std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
        let end = Instant::now() + Duration::from_secs(3);
        let events = loop {
            let events = std::fs::read_to_string(f.directory().join("events")).unwrap_or_default();
            if events.contains("authentication_failed") || Instant::now() >= end {
                assert!(events.contains("authentication_failed"));
                break events;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!events.contains("error_details"));
        f.state.lock().unwrap().pause_observe = false;
        f.wait_recovered();
        assert!(
            !f.journal()
                .iter()
                .any(|event| event.to_string().contains("token-"))
        );
        f.finish_recovered();
    }
}

#[test]
fn a_held_restart_lock_cannot_block_expired_token_recovery() {
    let mut f = Fixture::start("busy", 1_500, false);
    f.wait("running_turn", "warn");
    f.state.lock().unwrap().life_ms = 600_000;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.directory().join("restart.lock"))
        .unwrap();
    lock.lock().unwrap();
    f.wait_recovered();
    drop(lock);
    f.finish_recovered();
}

#[test]
fn ordinary_restart_lock_contention_does_not_poison_admission() {
    let mut f = Fixture::start("idle", 3_600_000, false);
    f.wait("quiet_window", "deferred");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.directory().join("restart.lock"))
        .unwrap();
    lock.lock().unwrap();
    std::thread::sleep(Duration::from_millis(350));
    drop(lock);
    f.wait("quiet_window", "deferred");
    std::fs::write(f.home.path().join("submit"), "").unwrap();
    f.wait("running_turn", "deferred");
    f.finish();
}

#[test]
fn a_busy_journal_does_not_drop_a_forced_restart_metric() {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    let journal = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(
            f.home
                .path()
                .join(".claudectl/server/restart-decisions.jsonl"),
        )
        .unwrap();
    journal.lock().unwrap();
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    f.wait_recovered();
    assert_eq!(
        f.journal()
            .iter()
            .filter(|event| event["event"] == "restart_forced")
            .count(),
        1
    );
    drop(journal);
    f.finish_recovered();
}

#[test]
fn a_failed_recovery_spawn_is_counted_once() {
    use std::os::unix::fs::PermissionsExt;
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    std::fs::set_permissions(
        f.directory().join("claude"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(4);
    while f.child.as_mut().unwrap().try_wait().unwrap().is_none() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(f.child.as_mut().unwrap().try_wait().unwrap().is_some());
    let output = f.child.take().unwrap().wait_with_output().unwrap();
    assert!(!output.status.success());
    let failures: Vec<_> = f
        .journal()
        .into_iter()
        .filter(|event| event["event"] == "recovery_failed")
        .collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["reason"], "spawn");
}

#[test]
fn repeated_failures_keep_all_metrics_and_throttle_voice_notices() {
    let mut f = Fixture::start("auth_recovery", 600_000, false);
    f.wait("quiet_window", "deferred");
    {
        let mut state = f.state.lock().unwrap();
        state.current_revoked = true;
        state.token_failures = 21;
    }
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    f.wait_recovered();
    let events = f.journal();
    let failures: Vec<_> = events
        .iter()
        .filter(|event| event["metric"]["name"] == "claudectl_recovery_failed_total")
        .collect();
    assert_eq!(
        failures.len(),
        21,
        "retain a counter increment for every failed attempt"
    );
    assert_eq!(
        failures
            .iter()
            .filter(|event| event["route"] == "voice_inbox")
            .count(),
        11
    );
    assert_eq!(
        failures
            .iter()
            .filter(|event| event["event"] == "recovery_failed")
            .count(),
        11
    );
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
fn terminal_input_does_not_defer_auth_recovery() {
    use std::io::Write;
    let mut f = Fixture::start("auth_typing", 600_000, true);
    f.wait("quiet_window", "deferred");
    f.child
        .as_mut()
        .unwrap()
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"x")
        .unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    while !f.home.path().join("typed-progress").exists() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        f.home.path().join("typed-progress").exists(),
        "owned PTY must deliver input"
    );
    let start = Instant::now();
    f.revoke();
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let runs = f.wait_recovered();
    assert!(
        start.elapsed() < Duration::from_secs(4),
        "typing cannot add a terminal observation delay"
    );
    assert!(
        runs.iter()
            .all(|run| run["tty"] == true && run["foreground"] == true)
    );
    f.finish_recovered();
}

#[test]
fn a_naturally_expired_busy_child_resumes_before_its_turn_finishes() {
    let mut f = Fixture::start("busy", 1_500, false);
    f.wait("running_turn", "warn");
    assert!(f.home.path().join("busy-progress").exists());
    f.state.lock().unwrap().life_ms = 600_000;
    f.wait_recovered();
    assert!(!f.home.path().join("become-idle").exists());
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
    let failures: Vec<_> = f
        .journal()
        .into_iter()
        .filter(|event| event["event"] == "recovery_failed")
        .collect();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0]["reason"], "resume");
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

#[test]
fn a_successful_retry_clears_stale_auth_failure_without_rotating_the_shared_grant() {
    let mut f = Fixture::start("task", 600_000, false);
    f.wait("background_task", "deferred");
    let first = f.run();
    {
        let mut state = f.state.lock().unwrap();
        state.reject_once = true;
        state.pause_observe = true;
    }
    std::fs::write(f.home.path().join("provider-probe"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    while f.state.lock().unwrap().provider_requests.is_empty() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(f.state.lock().unwrap().provider_requests[0]["status"], 401);
    std::fs::write(f.home.path().join("provider-retry"), "").unwrap();
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        let events = std::fs::read_to_string(f.directory().join("events")).unwrap_or_default();
        let stops = events
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["event"] == "Stop")
            .count();
        if stops >= 2 || Instant::now() >= end {
            assert!(stops >= 2);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    f.state.lock().unwrap().pause_observe = false;
    assert_eq!(f.state.lock().unwrap().provider_requests[1]["status"], 200);
    f.wait("background_task", "deferred");
    assert_eq!(f.runs(), vec![first]);
    assert!(!f.home.path().join("terminated").exists());
    assert_eq!(f.state.lock().unwrap().generation, 1);
    assert!(
        f.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .all(|r| r["previous_revision"].is_null())
    );
    f.finish();
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
fn a_prompt_hook_reading_input_cannot_block_the_auth_recovery_signal() {
    hook_input_blocks_recovery(false);
}

#[test]
fn a_prompt_hook_cannot_block_refreshing_the_rejected_current_grant() {
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
    f.wait_recovered();
    assert!(f.home.path().join("terminated").exists());
    assert_eq!(
        f.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|r| r["previous_revision"] == "revision-1")
            .count(),
        usize::from(reject_current),
    );
    hook.submit();
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
fn a_pending_replacement_does_not_wait_on_further_server_reads() {
    let mut f = Fixture::start("busy", 3_600_000, false);
    f.wait("running_turn", "deferred");
    let before = f.state.lock().unwrap().requests.len();
    f.revoke();
    let end = Instant::now() + Duration::from_secs(3);
    while f.state.lock().unwrap().requests.len() <= before && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(f.state.lock().unwrap().requests.len() > before);
    // Let the observing response reach the wrapper, then verify admission keeps
    // progressing from its snapshot instead of depending on another HTTP request.
    std::thread::sleep(Duration::from_millis(150));
    let observed = f.state.lock().unwrap().requests.len();
    std::thread::sleep(Duration::from_millis(350));
    let after = f.state.lock().unwrap().requests.len();
    assert_eq!(after, observed);
    f.finish();
}

#[test]
fn expired_sessions_recover_despite_each_workload_blocker() {
    for mode in ["busy", "task", "hold", "hook_error", "damaged"] {
        let mut f = Fixture::start(mode, 1_500, false);
        let end = Instant::now() + Duration::from_secs(3);
        while !f.home.path().join("ready").exists() && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(f.home.path().join("ready").exists());
        let hold = f.home.path().join(".claudectl/server/holds").join(format!(
            "{}.json",
            f.directory().file_name().unwrap().to_str().unwrap()
        ));
        let held = std::fs::read(&hold).ok();
        f.state.lock().unwrap().life_ms = 600_000;
        f.wait_recovered();
        if let Some(held) = held {
            assert_eq!(std::fs::read(hold).unwrap(), held);
        }
        f.finish_recovered();
    }
}

#[test]
fn an_expired_child_without_a_session_id_reports_one_failed_recovery() {
    let mut f = Fixture::start("no_hooks", 1_500, false);
    f.wait("evidence_unknown", "warn");
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        let count = f
            .journal()
            .iter()
            .filter(|event| event["event"] == "recovery_failed" && event["reason"] == "no_session")
            .count();
        if count > 0 || Instant::now() >= end {
            assert_eq!(count, 1);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        f.journal()
            .iter()
            .filter(|event| event["event"] == "recovery_failed")
            .count(),
        1
    );
    f.finish();
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
