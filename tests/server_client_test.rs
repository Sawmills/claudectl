#![cfg(feature = "server")]
//! The claudectl client against the real server code and a synthetic Anthropic API.
use assert_cmd::Command;
use axum::{
    Json, Router,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use claudectl::server::{app, engine::Endpoints};
use serde_json::json;
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

const AMIR: &str = "amir@sawmills.ai";

struct Running {
    origin: String,
    api: String,
    refreshes: Arc<AtomicUsize>,
    server: Arc<app::Server>,
    runtime: tokio::runtime::Runtime,
}
impl Running {
    fn register(&self, name: &str) -> (String, String) {
        self.runtime
            .block_on(app::register(self.server.store(), AMIR, name))
            .unwrap()
    }
}

fn start(state: &Path, key: &Path) -> Running {
    start_with_lifetime(state, key, 3600)
}

fn start_with_lifetime(state: &Path, key: &Path, lifetime: i64) -> Running {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let refreshes = Arc::new(AtomicUsize::new(0));
    let counter = refreshes.clone();
    let inference_counter = refreshes.clone();
    let (origin, server, api) = runtime.block_on(async {
        let provider = Router::new()
            .route(
                "/api/oauth/profile",
                get(|| async { Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})) }),
            )
            .route(
                "/token",
                post(move || {
                    let n = counter.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Json(json!({"access_token":format!("synthetic-{n}"),"refresh_token":format!("synthetic-refresh-{n}"),"expires_in":lifetime,"scope":"user:inference user:profile"}))
                    }
                }),
            )
            .route(
                "/api/oauth/usage",
                get(|| async { Json(json!({"five_hour":{"utilization":1},"seven_day":{"utilization":3},"extra_usage":{"is_enabled":false}})) }),
            )
            .route(
                "/synthetic/inference",
                get(move |headers: HeaderMap| {
                    let counter = inference_counter.clone();
                    async move {
                        let generation = counter.load(Ordering::SeqCst);
                        let current = match generation.checked_sub(1) {
                            Some(n) => format!("Bearer synthetic-{n}"),
                            None => "Bearer synthetic-seed".into(),
                        };
                        if headers.get("authorization").and_then(|h| h.to_str().ok())
                            == Some(current.as_str())
                        {
                            return Json(json!({"ok":true})).into_response();
                        }
                        (StatusCode::UNAUTHORIZED, Json(json!({"error":{"type":"authentication_error","message":"OAuth token revoked · Please run /login"}}))).into_response()
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
        let server = app::Server::open(app::Config {
            store: app::StoreConfig::File(state.into()),
            key: key.into(),
            allowed_users: vec![AMIR.into()],
            sso: None,
            metrics_token_hash: None,
            endpoints: Endpoints {
                api: api.clone(),
                token: format!("{api}/token"),
            },
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let router = app::router(server.clone());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        (origin, server, api)
    });
    Running {
        origin,
        api,
        refreshes,
        server,
        runtime,
    }
}

#[cfg(unix)]
const LIVE_TOKEN_CHILD: &str = r#"#!/usr/bin/env python3
import hashlib, json, os, signal, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path
control=Path(os.environ['D3_CONTROL'])
name=os.environ['D3_CHILD']
args=sys.argv[1:]
settings=json.load(open(args[args.index('--settings')+1]))
command=settings['hooks']['Stop'][0]['hooks'][0]['command']
def hook(event):
    subprocess.run(['/bin/sh','-c',command],input=json.dumps({'hook_event_name':event,'session_id':'synthetic-'+name}).encode(),check=True)
def sample(stage):
    request=urllib.request.Request(os.environ['D3_PROVIDER']+'/synthetic/inference',headers={'Authorization':'Bearer '+os.environ['CLAUDE_CODE_OAUTH_TOKEN']})
    try:
        with urllib.request.urlopen(request,timeout=3) as response: status=response.status
    except urllib.error.HTTPError as error: status=error.code
    result={'pid':os.getpid(),'status':status,'token_sha256':hashlib.sha256(os.environ['CLAUDE_CODE_OAUTH_TOKEN'].encode()).hexdigest()}
    (control/(name+'-'+stage+'.json')).write_text(json.dumps(result))
def terminated(*_):
    (control/(name+'-terminated')).touch()
    sys.exit(143)
signal.signal(signal.SIGTERM,terminated)
hook('SessionStart'); hook('UserPromptSubmit')
sample('before')
if name=='live':
    deadline=time.monotonic()+20
    sampled=False
    while not (control/'release').exists() and time.monotonic()<deadline:
        if (control/'sample-again').exists() and not sampled:
            sample('after'); sampled=True
        time.sleep(.02)
hook('Stop'); hook('SessionEnd')
"#;

#[cfg(unix)]
struct LiveTokenChild {
    process: Option<std::process::Child>,
    release: std::path::PathBuf,
}

#[cfg(unix)]
impl Drop for LiveTokenChild {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.release, "");
        if let Some(child) = self.process.take() {
            let _ = child.wait_with_output();
        }
    }
}

#[cfg(unix)]
fn live_token_command(
    home: &Path,
    binary: &Path,
    control: &Path,
    api: &str,
    name: &str,
) -> std::process::Command {
    use std::os::unix::fs::PermissionsExt;
    let qualified = home.join(".claudectl/server/qualified-host-config-builds.json");
    std::fs::write(&qualified, json!([{"sha256":claudectl::exec::sha256_file(binary).unwrap(),"platform":std::env::consts::OS,"qualified_at":"test","check":"supervised_host_config"}]).to_string()).unwrap();
    std::fs::set_permissions(&qualified, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl"));
    command
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .env("CLAUDECTL_TEST_RENEW_FAST", "1")
        .env("D3_CONTROL", control)
        .env("D3_PROVIDER", api)
        .env("D3_CHILD", name)
        .args(["server", "run", "work", "--claude"])
        .arg(binary)
        .args(["--", "--resume", "synthetic-session"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    command
}

#[cfg(unix)]
fn wait_for_token_sample(path: &Path) -> serde_json::Value {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while std::time::Instant::now() < end {
        if let Ok(bytes) = std::fs::read(path)
            && let Ok(result) = serde_json::from_slice(&bytes)
        {
            return result;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("synthetic child did not publish {}", path.display());
}

#[cfg(unix)]
fn live_child_token_case(lifetime: i64) {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    app::setup(&state, &key).unwrap();
    let server = start_with_lifetime(&state, &key, lifetime);
    let (_, machine) = server.register("synthetic-live-child");
    let http = reqwest::blocking::Client::new();
    let me: serde_json::Value = http
        .get(format!("{}/v1/me", server.origin))
        .bearer_auth(&machine)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let receipt = server
        .runtime
        .block_on(server.server.engine().admit(
            me["id"].as_str().unwrap(),
            "work",
            "synthetic-login",
            claudectl::server::engine::Grant {
                access_token: "synthetic-seed".into(),
                refresh_token: "synthetic-seed-refresh".into(),
                expires_at: chrono::Utc::now().timestamp_millis() + lifetime * 1_000,
                scopes: vec!["user:inference".into(), "user:profile".into()],
            },
            None,
        ))
        .unwrap();
    let live_home = tempfile::tempdir().unwrap();
    let next_home = tempfile::tempdir().unwrap();
    connect(live_home.path(), &server.origin, &machine);
    connect(next_home.path(), &server.origin, &machine);
    let binary = root.path().join("synthetic-claude");
    std::fs::write(&binary, LIVE_TOKEN_CHILD).unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
    let control = root.path().join("control");
    std::fs::create_dir(&control).unwrap();
    let mut live = LiveTokenChild {
        process: Some(
            live_token_command(live_home.path(), &binary, &control, &server.api, "live")
                .spawn()
                .unwrap(),
        ),
        release: control.join("release"),
    };
    let before = wait_for_token_sample(&control.join("live-before.json"));
    assert_eq!(before["status"], 200);
    let exchanges_after_start = server.refreshes.load(Ordering::SeqCst);
    let observe = || -> serde_json::Value {
        http.post(format!("{}/v2/anthropic/token", server.origin))
            .bearer_auth(&machine)
            .json(&json!({"account_id":receipt.account_id,"observe":true}))
            .send()
            .unwrap()
            .json()
            .unwrap()
    };
    let held = observe();
    std::thread::sleep(std::time::Duration::from_millis(350));
    assert_eq!(
        server.refreshes.load(Ordering::SeqCst),
        exchanges_after_start,
        "an observing request or the busy monitor refreshed the grant"
    );
    let next = live_token_command(next_home.path(), &binary, &control, &server.api, "next")
        .output()
        .unwrap();
    assert!(
        next.status.success(),
        "{}",
        String::from_utf8_lossy(&next.stderr)
    );
    let exchanges_after_next = server.refreshes.load(Ordering::SeqCst);
    let current = observe();
    std::fs::write(control.join("sample-again"), "").unwrap();
    let after = wait_for_token_sample(&control.join("live-after.json"));
    let status = claudectl(live_home.path(), &["server", "status", "work", "--json"]);
    let status: serde_json::Value = serde_json::from_str(&ok(&status)).unwrap();
    assert_eq!(status.get("error"), Some(&serde_json::Value::Null));
    assert_eq!(status["stale"], false);
    assert_eq!(status["data"]["seven_day"]["utilization"], 3);
    assert_eq!(
        server.refreshes.load(Ordering::SeqCst),
        exchanges_after_next,
        "status or observing a successor refreshed the grant"
    );
    assert!(live.process.as_mut().unwrap().try_wait().unwrap().is_none());
    assert_eq!(before["pid"], after["pid"]);
    assert_eq!(before["token_sha256"], after["token_sha256"]);
    assert!(!control.join("live-terminated").exists());
    let latest = wait_for_token_sample(&control.join("next-before.json"));
    assert_eq!(latest["status"], 200);
    let revision_changed = held["revision"] != current["revision"];
    let metrics = http
        .get(format!("{}/metrics", server.origin))
        .send()
        .unwrap()
        .text()
        .unwrap();
    let rotations: Vec<_> = metrics
        .lines()
        .filter(|line| line.starts_with("claudectl_token_rotations_total{"))
        .collect();
    for reason in ["forced", "migration", "expired"] {
        assert!(rotations.contains(
            &format!("claudectl_token_rotations_total{{reason=\"{reason}\"}} 0").as_str()
        ));
    }
    drop(live); // Release the synthetic child normally before the RED assertion.
    assert_eq!(
        after["status"], 200,
        "a normal new session invalidated a still-live child's grant while server status remained OK: lifetime={lifetime}, revision_changed={revision_changed}, exchanges={exchanges_after_start}->{exchanges_after_next}, rotations={rotations:?}"
    );
}

#[test]
#[cfg(unix)]
fn a_new_session_does_not_revoke_the_grant_a_live_child_holds() {
    live_child_token_case(120);
}

#[test]
#[cfg(unix)]
fn a_new_session_outside_the_margin_keeps_the_live_child_usable() {
    live_child_token_case(3600);
}

/// Write the files `claudectl server connect` leaves behind, without the browser step.
fn connect(home: &Path, origin: &str, token: &str) {
    let me: serde_json::Value = reqwest::blocking::Client::new()
        .get(format!("{origin}/v1/me"))
        .bearer_auth(token)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let dir = home.join(".claudectl").join("server");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("connection.json"),
        json!({"server":origin,"user_id":me["id"],"token_file":dir.join("machine.json")})
            .to_string(),
    )
    .unwrap();
    std::fs::write(dir.join("machine.json"), json!(token).to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["connection.json", "machine.json"] {
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
}

fn claudectl(home: &Path, args: &[&str]) -> std::process::Output {
    Command::cargo_bin("claudectl")
        .unwrap()
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .args(args)
        .output()
        .unwrap()
}

fn ok(output: &std::process::Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn service_issue_refuses_an_enabled_user_outside_the_server_allow_list() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    app::setup(&state, &key).unwrap();
    let server = start(&state, &key);
    let (_, human) = server.register("human-machine");
    let (_, other) = server
        .runtime
        .block_on(app::register(
            server.server.store(),
            "other@sawmills.ai",
            "other-machine",
        ))
        .unwrap();
    let http = reqwest::blocking::Client::new();
    let me: serde_json::Value = http
        .get(format!("{}/v1/me", server.origin))
        .bearer_auth(&human)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let refused_access = http
        .get(format!("{}/v1/devices", server.origin))
        .bearer_auth(&other)
        .send()
        .unwrap()
        .status();
    assert_eq!(refused_access, 403);
    // Registration returns the machine ID; company-user IDs come from the admin list.
    drop(server);
    let users = Command::cargo_bin("claudectl-server")
        .unwrap()
        .arg("users")
        .arg("--state")
        .arg(&state)
        .arg("--key-file")
        .arg(&key)
        .env_remove("DATABASE_URL")
        .output()
        .unwrap();
    let users = ok(&users);
    let other_user = users
        .lines()
        .find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.get(1) == Some(&"other@sawmills.ai")).then_some(fields)
        })
        .unwrap();
    assert_eq!(other_user[2], "true");
    let issue = |user: &str| {
        Command::cargo_bin("claudectl-server")
            .unwrap()
            .args([
                "service-account",
                "issue",
                user,
                "--allow-user",
                "AMIR@SAWMILLS.AI",
                "--state",
            ])
            .arg(&state)
            .arg("--key-file")
            .arg(&key)
            .env_remove("DATABASE_URL")
            .output()
            .unwrap()
    };
    let good = issue(me["id"].as_str().unwrap());
    let token = ok(&good).trim().to_owned();
    let refused = issue(other_user[0]);
    assert!(!refused.status.success());
    assert!(
        refused.stdout.is_empty(),
        "refused issuance emitted a bearer"
    );
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("company user is not allowed by --allow-user")
    );
    let server = start(&state, &key);
    assert_eq!(
        http.get(format!("{}/v1/me", server.origin))
            .bearer_auth(token)
            .send()
            .unwrap()
            .status(),
        200,
        "refused issuance rotated the valid shared bearer"
    );
}

#[test]
fn shared_service_issue_rotates_the_only_job_credential_without_a_token_file() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    app::setup(&state, &key).unwrap();
    let server = start(&state, &key);
    let (_, human) = server.register("human-machine");
    let me: serde_json::Value = reqwest::blocking::Client::new()
        .get(format!("{}/v1/me", server.origin))
        .bearer_auth(&human)
        .send()
        .unwrap()
        .json()
        .unwrap();
    let user = me["id"].as_str().unwrap().to_owned();
    drop(server); // File-store administration holds the ordinary exclusive process lock.
    let issue = |user: &str| {
        Command::cargo_bin("claudectl-server")
            .unwrap()
            .args(["service-account", "issue", user, "--state"])
            .arg(&state)
            .arg("--key-file")
            .arg(&key)
            .args(["--allow-user", AMIR])
            .env_remove("DATABASE_URL")
            .output()
            .unwrap()
    };
    let first = issue(&user);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        first
            .stdout
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        1
    );
    let first = String::from_utf8(first.stdout).unwrap().trim().to_owned();
    assert_eq!(first.len(), 64);
    let refused = issue("missing-company-user");
    assert!(!refused.status.success());
    assert!(
        refused.stdout.is_empty(),
        "failed issuance emitted a credential"
    );
    let server = start(&state, &key);
    let status = |server: &Running, token: &str| {
        reqwest::blocking::Client::new()
            .get(format!("{}/v1/me", server.origin))
            .bearer_auth(token)
            .send()
            .unwrap()
            .status()
    };
    assert_eq!(status(&server, &first), 200);
    assert_eq!(server.refreshes.load(Ordering::SeqCst), 0);
    drop(server);
    let second = issue(&user);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        second
            .stdout
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        1
    );
    let second = String::from_utf8(second.stdout).unwrap().trim().to_owned();
    assert_eq!(second.len(), 64);
    assert!(
        first != second,
        "rotation retained the old shared credential"
    );
    let server = start(&state, &key);
    assert_eq!(status(&server, &first), 401);
    assert_eq!(status(&server, &second), 200);
    assert_eq!(status(&server, &human), 200);
    assert_eq!(server.refreshes.load(Ordering::SeqCst), 0);
    let sealed = std::fs::read(state.join("state.enc")).unwrap();
    for token in [&first, &second] {
        assert!(
            !sealed
                .windows(token.len())
                .any(|bytes| bytes == token.as_bytes())
        );
    }
}

#[test]
fn a_machine_lists_refreshes_removes_and_revokes_through_the_server() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    app::setup(&state, &key).unwrap();
    let server = start(&state, &key);
    let (_mac_id, mac) = server.register("mac");
    let (devbox_id, devbox) = server.register("devbox");
    let expires_at = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let receipt: serde_json::Value = reqwest::blocking::Client::new()
        .post(format!("{}/v2/anthropic/migrations", server.origin))
        .bearer_auth(&mac)
        .json(&json!({"alias":"work","migration_id":"m-1","exclusive_owner":true,
            "grant":{"access_token":"migrated","refresh_token":"migrated-refresh","expires_at":expires_at,"scopes":["user:inference","user:profile"]}}))
        .send()
        .unwrap()
        .json()
        .unwrap();
    assert!(receipt["account_id"].is_string(), "{receipt}");
    assert_eq!(server.refreshes.load(Ordering::SeqCst), 1);

    let mac_home = tempfile::tempdir().unwrap();
    let devbox_home = tempfile::tempdir().unwrap();
    connect(mac_home.path(), &server.origin, &mac);
    connect(devbox_home.path(), &server.origin, &devbox);

    let accounts = ok(&claudectl(
        devbox_home.path(),
        &["server", "accounts", "--json"],
    ));
    assert!(accounts.contains("\"alias\":\"work\""), "{accounts}");
    // Without --json: a table.
    let table = ok(&claudectl(devbox_home.path(), &["server", "accounts"]));
    assert!(
        table.contains("work") && table.contains("Account"),
        "{table}"
    );
    ok(&claudectl(
        mac_home.path(),
        &["server", "refresh-access", "work"],
    ));
    assert_eq!(server.refreshes.load(Ordering::SeqCst), 2);

    ok(&claudectl(
        mac_home.path(),
        &["server", "revoke", &devbox_id],
    ));
    assert!(
        !claudectl(devbox_home.path(), &["server", "accounts"])
            .status
            .success()
    );

    ok(&claudectl(mac_home.path(), &["server", "remove", "work"]));
    let accounts = ok(&claudectl(
        mac_home.path(),
        &["server", "accounts", "--json"],
    ));
    assert_eq!(accounts.trim(), "[]");
    assert!(
        !claudectl(mac_home.path(), &["server", "refresh-access", "work"])
            .status
            .success()
    );
}
