#![cfg(feature = "server")]
//! The claudectl client against the real server code and a synthetic Anthropic API.
use assert_cmd::Command;
use axum::{
    Json, Router,
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
    refreshes: Arc<AtomicUsize>,
    _runtime: tokio::runtime::Runtime,
}

fn start(state: &Path, key: &Path) -> Running {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let refreshes = Arc::new(AtomicUsize::new(0));
    let counter = refreshes.clone();
    let origin = runtime.block_on(async {
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
                        Json(json!({"access_token":format!("synthetic-{n}"),"refresh_token":format!("synthetic-refresh-{n}"),"expires_in":3600,"scope":"user:inference user:profile"}))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, provider).await.unwrap() });
        let server = app::Server::open(app::Config {
            state: state.into(),
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
        tokio::spawn(async move { axum::serve(listener, app::router(server)).await.unwrap() });
        origin
    });
    Running {
        origin,
        refreshes,
        _runtime: runtime,
    }
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
        .env("HOME", home)
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
fn a_machine_lists_refreshes_removes_and_revokes_through_the_server() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    app::setup(&state, &key).unwrap();
    let (_mac_id, mac) = app::register(&state, AMIR, "mac").unwrap();
    let (devbox_id, devbox) = app::register(&state, AMIR, "devbox").unwrap();
    let server = start(&state, &key);
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

    let accounts = ok(&claudectl(devbox_home.path(), &["server", "accounts"]));
    assert!(accounts.contains("\"alias\":\"work\""), "{accounts}");
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
    let accounts = ok(&claudectl(mac_home.path(), &["server", "accounts"]));
    assert_eq!(accounts.trim(), "[]");
    assert!(
        !claudectl(mac_home.path(), &["server", "refresh-access", "work"])
            .status
            .success()
    );
}
