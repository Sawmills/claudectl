#![cfg(all(feature = "server", target_os = "linux"))]
//! Synthetic CLI coverage for fail-closed input admission. Recovery parsing lives at its
//! module interface; no fixture bypasses the automatic signal guard.
use axum::{
    Json, Router,
    extract::State,
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
    let mut fake = shared.lock().unwrap();
    fake.requests.push(body);
    Json(
        json!({"provider":"anthropic","account_id":ACCOUNT,"user_id":"person","identity":identity(),
        "access_token":format!("token-{}",fake.generation),"expires_at":chrono::Utc::now().timestamp_millis()+fake.life_ms,
        "scopes":["user:inference","user:profile"],"revision":format!("revision-{}",fake.generation),"generation":fake.generation}),
    )
}
fn private_write(path: &Path, value: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
const FAKE_CLAUDE: &str = r#"#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
from pathlib import Path
home=Path(os.environ['HOME'])
log=home/'claude.log'
mode=os.environ['FAKE_MODE']
args=sys.argv[1:]
settings=json.load(open(args[args.index('--settings')+1]))
run=Path(os.environ['CLAUDECTL_SERVER_RUN'])
with log.open('a') as out:
    out.write(json.dumps({'token':os.environ['CLAUDE_CODE_OAUTH_TOKEN'],'args':args,'settings':settings,'run':str(run),'pid':os.getpid(),'tty':os.isatty(0),'foreground':not os.isatty(0) or os.tcgetpgrp(0)==os.getpgrp()})+'\n')
def term(*_):
    (home/'terminated').touch()
    sys.exit(143)
signal.signal(signal.SIGTERM,term)
command=settings['hooks']['Stop'][0]['hooks'][0]['command']
def hook(event):
    subprocess.run(['/bin/sh','-c',command],input=json.dumps({'hook_event_name':event,'session_id':'s'}).encode(),check=True)
if mode != 'no_hooks':
    hook('SessionStart'); hook('UserPromptSubmit')
    if mode != 'busy': hook('Stop')
task=None
if mode=='task':
    folder=Path(os.environ['TMPDIR'])/('claude-'+str(os.getuid()))/'project/tasks'
    folder.mkdir(parents=True)
    with (folder/'task.output').open('w') as out:
        task=subprocess.Popen([sys.executable,'-c',"import os,time; from pathlib import Path; h=Path(os.environ['HOME']); end=time.monotonic()+15\nwhile not (h/'release').exists() and time.monotonic()<end:\n (h/'task-progress').write_text(str(time.monotonic())); time.sleep(.02)\n(h/'task-done').touch()"],stdout=out,stderr=out)
if mode=='hold':
    subprocess.run([os.environ['FAKE_WRAPPER_BIN'],'hold','start','--reason','FLT-553 synthetic step'],check=True)
if mode=='hook_error': (run/'hook-error').touch()
if mode=='damaged':
    with (run/'events').open('a') as out: out.write('broken record\n')
if mode=='extra': task=subprocess.Popen(['sleep','15'])
(home/'ready').touch()
deadline=time.monotonic()+15
prompted=False
while not (home/'release').exists() and time.monotonic()<deadline:
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
        command
            .env_clear()
            .env("HOME", home.path())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("TERM", "xterm")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .env("CLAUDECTL_TEST_RENEW_FAST", "1")
            .env("TMPDIR", home.path().join("tmp"))
            .env("FAKE_MODE", mode)
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
impl Drop for Fixture {
    fn drop(&mut self) {
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

#[test]
fn idle_hook_only_renewal_preserves_child_token_settings_and_accounting() {
    let mut f = Fixture::start("idle", 600_000, false);
    let status = f.wait("evidence_unknown", "deferred");
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
        f.wait("evidence_unknown", "deferred")["restart_deferred_total"],
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
        ("idle", "evidence_unknown"),
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
fn later_prompts_and_non_task_helpers_do_not_bypass_unknown_admission() {
    for mode in ["idle", "extra"] {
        let mut f = Fixture::start(mode, 600_000, false);
        f.wait("evidence_unknown", "deferred");
        std::fs::write(f.home.path().join("submit"), "").unwrap();
        f.wait("running_turn", "deferred");
        std::fs::write(f.home.path().join("turn-done"), "").unwrap();
        f.wait("evidence_unknown", "deferred");
        f.finish();
    }
}

#[test]
fn an_idle_terminal_session_keeps_foreground_until_its_owner_exits() {
    let mut f = Fixture::start("idle", 600_000, true);
    f.wait("evidence_unknown", "deferred");
    assert_eq!(f.run()["tty"], true);
    assert_eq!(f.run()["foreground"], true);
    f.finish();
}
