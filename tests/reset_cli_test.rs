#![cfg(feature = "server")]
//! Public CLI against a synthetic provider; no live credentials or redemption.
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};

async fn cli(home: &Path, origin: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_claudectl"));
    command
        .env("HOME", home)
        .env_remove("CLAUDECTL_SERVICE_TOKEN")
        .env_remove("CLAUDECTL_SERVER_URL")
        .env("CLAUDECTL_TEST_USAGE_URL", format!("{origin}/usage"))
        .env("CLAUDECTL_TEST_RESET_URL", format!("{origin}/reset"))
        .stdin(Stdio::null())
        .args(args);
    tokio::task::spawn_blocking(move || command.output().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn reset_cli_replays_pending_requests_and_enforces_local_authority() {
    let home = tempfile::tempdir().unwrap();
    let paths = claudectl::config::Paths::from_home(home.path().to_owned());
    let credentials =
        json!({"claudeAiOauth":{"accessToken":"synthetic-access", "expiresAt":4102444800000_i64}});
    let credentials: claudectl::api::CredentialsFile =
        serde_json::from_value(credentials.clone()).unwrap();
    let profile = claudectl::profile::save_profile_to(
        &paths,
        "work",
        &credentials,
        Some(json!({"accountUuid":"a", "organizationUuid":"o"})),
    )
    .unwrap();
    let full = Arc::new(AtomicBool::new(true));
    let status = Arc::new(AtomicU16::new(502));
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let usage_full = full.clone();
    let reset_status = status.clone();
    let captured = requests.clone();
    let router = Router::new()
        .route("/v1/me", get(|| async { Json(json!({"id":"company-user"})) }))
        .route("/v2/anthropic/accounts", get(|| async { Json(json!([{
            "provider":"anthropic", "account_id":"server-account", "alias":"work", "available":true,
            "identity":{"account_uuid":"a", "organization_uuid":"o"}
        }])) }))
        .route("/v2/anthropic/usage", get(|| async { Json(json!({"data":null,"observed_at":null,"next_retry_at":0,"stale":true,"error":null})) }))
        .route("/v2/anthropic/resets", get(|| async { (StatusCode::FORBIDDEN, Json(json!({"error":"service_account_reset_refused"}))) }))
        .route("/usage", get(move |Query(query): Query<std::collections::HashMap<String, String>>| {
            let full = usage_full.clone();
            async move {
                assert_eq!(query.get("cedar_ember").map(String::as_str), Some("1"));
                Json(if full.load(Ordering::SeqCst) { json!({
                    "five_hour":{"utilization":100}, "cedar_ember":{"at_limit":true,"grants":[
                        {"id":"later-private-grant", "resets_left":1,"clears":["five_hour"],"ends_at":"2099-02-01T00:00:00Z"},
                        {"resets_left":7,"clears":["five_hour"]},
                        {"id":"sooner-private-grant", "resets_left":2,"clears":["five_hour"],"ends_at":"2099-01-01T00:00:00Z"}
                    ]}
                }) } else { json!({"five_hour":{"utilization":0},"cedar_ember":{"at_limit":false,"grants":[]}}) })
            }
        }))
        .route("/reset", post(move |Json(body): Json<Value>| {
            let captured = captured.clone(); let status = reset_status.clone();
            async move {
                captured.lock().unwrap().push(body);
                (StatusCode::from_u16(status.load(Ordering::SeqCst)).unwrap(), Json(json!({"result":"reset"})))
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let provider = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    let list = cli(home.path(), &origin, &["resets", "--json"]).await;
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list: Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(list["accounts"][0]["offers"].as_array().unwrap().len(), 2);
    assert!(!list.to_string().contains("private-grant"));
    let text = cli(home.path(), &origin, &["resets"]).await;
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("2099-01-01"), "{text}");
    assert!(text.contains("five_hour"), "{text}");
    let unconfirmed = cli(home.path(), &origin, &["reset", "wo"]).await;
    assert!(!unconfirmed.status.success());
    assert!(String::from_utf8_lossy(&unconfirmed.stderr).contains("--yes"));
    assert!(requests.lock().unwrap().is_empty());
    let failed = cli(home.path(), &origin, &["reset", "wo", "--yes"]).await;
    assert!(!failed.status.success());
    let pending = profile.dir.join("reset-pending.json");
    assert!(pending.exists());
    full.store(false, Ordering::SeqCst);
    status.store(200, Ordering::SeqCst);
    let resumed = cli(home.path(), &origin, &["reset", "work", "--yes"]).await;
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(!pending.exists());
    {
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0]["grant_id"], "sooner-private-grant");
        assert_eq!(requests[0]["request_id"], requests[1]["request_id"]);
    }
    full.store(true, Ordering::SeqCst);
    status.store(400, Ordering::SeqCst);
    let rejected = cli(home.path(), &origin, &["reset", "work", "--yes"]).await;
    assert!(!rejected.status.success());
    assert!(!pending.exists());
    let lock = std::fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(profile.dir.join("reset.lock"))
        .unwrap();
    lock.try_lock().unwrap();
    let busy = cli(home.path(), &origin, &["reset", "work", "--yes"]).await;
    assert!(!busy.status.success());
    assert!(String::from_utf8_lossy(&busy.stderr).contains("already in progress"));
    drop(lock);
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::write(
        paths.claude_credentials_file(),
        serde_json::to_vec(&credentials).unwrap(),
    )
    .unwrap();
    std::fs::write(
        paths.claude_json(),
        json!({"oauthAccount":{"accountUuid":"different-account"}}).to_string(),
    )
    .unwrap();
    claudectl::profile::set_active_from(&paths, "work").unwrap();
    let mismatch = cli(home.path(), &origin, &["reset", "work", "--yes"]).await;
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("does not match"));
    assert_eq!(requests.lock().unwrap().len(), 3);
    let mut service = Command::new(env!("CARGO_BIN_EXE_claudectl"));
    service
        .env("HOME", home.path())
        .env("CLAUDECTL_SERVICE_TOKEN", "synthetic-service-token")
        .env("CLAUDECTL_SERVER_URL", &origin)
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .env("CLAUDECTL_TEST_RESET_URL", format!("{origin}/reset"))
        .stdin(Stdio::null())
        .args(["reset", "work", "--yes"]);
    let refused = tokio::task::spawn_blocking(move || service.output().unwrap())
        .await
        .unwrap();
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("service_account_reset_refused"));
    assert_eq!(requests.lock().unwrap().len(), 3);
    provider.abort();
}
