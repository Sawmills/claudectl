#![cfg(feature = "server")]
//! Public CLI against a synthetic provider; no live credentials or redemption.
use axum::{
    Json, Router,
    extract::Query,
    http::{HeaderMap, StatusCode},
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
        .route("/usage", get(move |Query(query): Query<std::collections::HashMap<String, String>>, headers: HeaderMap| {
            let full = usage_full.clone();
            async move {
                assert_eq!(query.get("cedar_ember").map(String::as_str), Some("1"));
                assert_eq!(
                    headers.get("user-agent").and_then(|v| v.to_str().ok()),
                    Some(claudectl::api::CLAUDE_CLI_USER_AGENT)
                );
                Json(if full.load(Ordering::SeqCst) { json!({
                    "five_hour":{"utilization":100}, "cedar_ember":{"at_limit":true,"grants":[
                        {"id":"later-private-grant", "resets_left":1,"clears":["five_hour"],"ends_at":"2099-02-01T00:00:00Z"},
                        {"resets_left":7,"clears":["five_hour"]},
                        {"id":"sooner-private-grant", "resets_left":2,"clears":["five_hour"],"ends_at":"2099-01-01T00:00:00Z"}
                    ]}
                }) } else { json!({"five_hour":{"utilization":0},"cedar_ember":{"at_limit":false,"grants":[]}}) })
            }
        }))
        .route("/reset", post(move |headers: HeaderMap, Json(body): Json<Value>| {
            let captured = captured.clone(); let status = reset_status.clone();
            async move {
                assert_eq!(
                    headers.get("user-agent").and_then(|v| v.to_str().ok()),
                    Some(claudectl::api::CLAUDE_CLI_USER_AGENT)
                );
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

#[tokio::test]
async fn reset_cli_dry_run_shows_live_shape_offers_and_sends_nothing() {
    let home = tempfile::tempdir().unwrap();
    let paths = claudectl::config::Paths::from_home(home.path().to_owned());
    let credentials: claudectl::api::CredentialsFile = serde_json::from_value(
        json!({"claudeAiOauth":{"accessToken":"synthetic-access", "expiresAt":4102444800000_i64}}),
    )
    .unwrap();
    let profile = claudectl::profile::save_profile_to(
        &paths,
        "amir3",
        &credentials,
        Some(json!({"accountUuid":"a", "organizationUuid":"org-secret-sentinel"})),
    )
    .unwrap();
    let reset_posts = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured_posts = reset_posts.clone();
    let token_posts = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured_token_posts = token_posts.clone();
    let server_usage_gets = Arc::new(Mutex::new(0usize));
    let captured_server_usage = server_usage_gets.clone();
    let server_posts = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured_server_posts = server_posts.clone();
    let router = Router::new()
        .route(
            "/token",
            post(move |Json(body): Json<Value>| {
                let captured_token_posts = captured_token_posts.clone();
                async move {
                    captured_token_posts.lock().unwrap().push(body);
                    Json(json!({"access_token": "should-never-happen"}))
                }
            }),
        )
        .route(
            "/usage",
            get(move |headers: HeaderMap| async move {
                let ua = headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if ua != claudectl::api::CLAUDE_CLI_USER_AGENT {
                    return Json(json!({
                        "seven_day": {"utilization": 100.0},
                        "cedar_ember": {
                            "eligible": false,
                            "ineligible_reason": "surface",
                            "at_limit": false,
                            "exhausted": [],
                            "grants": []
                        }
                    }));
                }
                Json(
                    serde_json::from_str::<Value>(include_str!(
                        "fixtures/limit-reset-offers-v2.json"
                    ))
                    .unwrap(),
                )
            }),
        )
        .route(
            "/reset",
            post(move |Json(body): Json<Value>| {
                let captured_posts = captured_posts.clone();
                async move {
                    captured_posts.lock().unwrap().push(body);
                    Json(json!({"result": "reset"}))
                }
            }),
        )
        .route(
            "/v2/anthropic/accounts",
            get(|| async {
                Json(json!([{
                    "provider": "anthropic",
                    "account_id": "srv-acct-1",
                    "alias": "amir3@sawmills.ai",
                    "available": true,
                    "identity": {"account_uuid": "a", "organization_uuid": "o"}
                }]))
            }),
        )
        .route(
            "/v2/anthropic/usage",
            get(move || {
                let captured_server_usage = captured_server_usage.clone();
                async move {
                    *captured_server_usage.lock().unwrap() += 1;
                    Json(json!({
                        "data": serde_json::from_str::<Value>(include_str!(
                            "fixtures/limit-reset-offers-v2.json"
                        ))
                        .unwrap(),
                        "observed_at": chrono::Utc::now().timestamp_millis(),
                        "next_retry_at": chrono::Utc::now().timestamp_millis() + 300_000,
                        "stale": false,
                        "error": null
                    }))
                }
            }),
        )
        .route(
            "/v2/anthropic/resets",
            get(|| async {
                Json(json!({
                    "accounts": [{
                        "alias": "amir3@sawmills.ai",
                        "account_id": "srv-acct-1",
                        "available": true,
                        "stale": false,
                        "exhausted": ["seven_day"],
                        "offers": [
                            {
                                "resets_left": 1,
                                "clears": ["seven_day", "seven_day_overage_included"],
                                "ends_at": "2099-12-10T22:00:00Z",
                                "use_requires_limit": false
                            },
                            {
                                "resets_left": 1,
                                "clears": ["seven_day_overage_included"],
                                "ends_at": "2100-03-09T07:59:00Z",
                                "gives_back_weekly": true,
                                "use_requires_limit": false
                            }
                        ]
                    }]
                }))
            }),
        )
        .route(
            "/v2/anthropic/resets/redeem",
            post(move |Json(body): Json<Value>| {
                let captured_server_posts = captured_server_posts.clone();
                async move {
                    captured_server_posts.lock().unwrap().push(body);
                    Json(json!({"result": "reset"}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let provider = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // Dry-run before any `resets` call must not create usage/auth/reset locks or cache files.
    for args in [
        &["reset", "amir3", "--dry-run"][..],
        &["reset", "amir3", "--dry-run", "--yes"][..],
    ] {
        let dry = cli(home.path(), &origin, args).await;
        assert!(
            dry.status.success(),
            "{}",
            String::from_utf8_lossy(&dry.stderr)
        );
        let stdout = String::from_utf8(dry.stdout).unwrap();
        assert!(stdout.contains("Dry run: no request sent"), "{stdout}");
        assert!(stdout.contains("2099-12-10 22:00 UTC"), "{stdout}");
        assert!(stdout.contains("weekly + Fable weekly"), "{stdout}");
        assert!(stdout.contains("POST "), "{stdout}");
        assert!(stdout.contains("cedar_ember"), "{stdout}");
        assert!(!stdout.contains("not-for-display"), "{stdout}");
        assert!(!stdout.contains("org-secret-sentinel"), "{stdout}");
        assert!(!stdout.contains("synthetic-access"), "{stdout}");
    }
    assert!(reset_posts.lock().unwrap().is_empty());
    assert!(!profile.dir.join("reset-pending.json").exists());
    assert!(!profile.dir.join("reset.lock").exists());
    assert!(!home.path().join(".claudectl/usage").exists());
    assert!(!home.path().join(".claudectl/auth-state.lock").exists());

    // Expired non-active local profile under --dry-run must NOT POST to refresh credentials
    // or create lock files.
    let expired_home = tempfile::tempdir().unwrap();
    let expired_paths = claudectl::config::Paths::from_home(expired_home.path().to_owned());
    let expired_creds: claudectl::api::CredentialsFile = serde_json::from_value(json!({
        "claudeAiOauth": {
            "accessToken": "expired-access",
            "refreshToken": "synthetic-refresh",
            "expiresAt": 1000_i64
        }
    }))
    .unwrap();
    claudectl::profile::save_profile_to(
        &expired_paths,
        "expired",
        &expired_creds,
        Some(json!({"accountUuid": "b", "organizationUuid": "org-secret-sentinel"})),
    )
    .unwrap();
    let mut expired_cmd = Command::new(env!("CARGO_BIN_EXE_claudectl"));
    expired_cmd
        .env("HOME", expired_home.path())
        .env_remove("CLAUDECTL_SERVICE_TOKEN")
        .env_remove("CLAUDECTL_SERVER_URL")
        .env("CLAUDECTL_TEST_USAGE_URL", format!("{origin}/usage"))
        .env("CLAUDECTL_TEST_TOKEN_URL", format!("{origin}/token"))
        .env("CLAUDECTL_TEST_RESET_URL", format!("{origin}/reset"))
        .stdin(Stdio::null())
        .args(["reset", "expired", "--dry-run"]);
    let expired_out = tokio::task::spawn_blocking(move || expired_cmd.output().unwrap())
        .await
        .unwrap();
    assert!(!expired_out.status.success());
    assert!(
        String::from_utf8_lossy(&expired_out.stderr).contains("expired"),
        "{}",
        String::from_utf8_lossy(&expired_out.stderr)
    );
    assert!(token_posts.lock().unwrap().is_empty());
    assert!(!expired_home.path().join(".claudectl/usage").exists());
    assert!(
        !expired_home
            .path()
            .join(".claudectl/auth-state.lock")
            .exists()
    );

    // Now test `resets --json` on amir3 (normal read).
    let listed = cli(home.path(), &origin, &["resets", "--json"]).await;
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: Value = serde_json::from_slice(&listed.stdout).unwrap();
    let amir3_row = listed["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["alias"] == "amir3")
        .unwrap();
    assert_eq!(amir3_row["offers"].as_array().unwrap().len(), 2);
    assert!(!listed.to_string().contains("not-for-display"));

    // Provider connection error on local reset must not leak organization UUID in stderr.
    let mut dead_cmd = Command::new(env!("CARGO_BIN_EXE_claudectl"));
    dead_cmd
        .env("HOME", home.path())
        .env_remove("CLAUDECTL_SERVICE_TOKEN")
        .env_remove("CLAUDECTL_SERVER_URL")
        .env("CLAUDECTL_TEST_USAGE_URL", format!("{origin}/usage"))
        .env(
            "CLAUDECTL_TEST_RESET_URL",
            "http://127.0.0.1:1/api/organizations/org-secret-sentinel/reset_rate_limits",
        )
        .stdin(Stdio::null())
        .args(["reset", "amir3", "--yes"]);
    let dead_out = tokio::task::spawn_blocking(move || dead_cmd.output().unwrap())
        .await
        .unwrap();
    assert!(!dead_out.status.success());
    let dead_err = String::from_utf8_lossy(&dead_out.stderr);
    assert!(
        dead_err.contains("limit reset provider request failed"),
        "{dead_err}"
    );
    assert!(
        !dead_err.contains("org-secret-sentinel"),
        "organization UUID leaked in error: {dead_err}"
    );

    // Server-backed dry-run: connect a synthetic server in a clean HOME and prove zero POSTs
    // and zero /v2/anthropic/usage refresh triggers.
    let srv_home = tempfile::tempdir().unwrap();
    let srv_dir = srv_home.path().join(".claudectl/server");
    std::fs::create_dir_all(&srv_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&srv_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let machine_file = srv_dir.join("machine.json");
    std::fs::write(&machine_file, r#""synthetic-machine-token""#).unwrap();
    let conn_file = srv_dir.join("connection.json");
    std::fs::write(
        &conn_file,
        serde_json::to_vec(&json!({
            "server": origin,
            "user_id": "company-user",
            "token_file": machine_file
        }))
        .unwrap(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for f in [&machine_file, &conn_file] {
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let mut srv_cmd = Command::new(env!("CARGO_BIN_EXE_claudectl"));
    srv_cmd
        .env("HOME", srv_home.path())
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .env_remove("CLAUDECTL_SERVICE_TOKEN")
        .env_remove("CLAUDECTL_SERVER_URL")
        .stdin(Stdio::null())
        .args(["reset", "amir3", "--dry-run"]);
    let srv_dry = tokio::task::spawn_blocking(move || srv_cmd.output().unwrap())
        .await
        .unwrap();
    assert!(
        srv_dry.status.success(),
        "{}",
        String::from_utf8_lossy(&srv_dry.stderr)
    );
    let stdout = String::from_utf8(srv_dry.stdout).unwrap();
    assert!(stdout.contains("Dry run: no request sent"), "{stdout}");
    assert!(
        stdout.contains("Account: amir3@sawmills.ai (server)"),
        "{stdout}"
    );
    assert!(stdout.contains("2099-12-10 22:00 UTC"), "{stdout}");
    assert!(
        stdout.contains(&format!("POST {origin}/v2/anthropic/resets/redeem")),
        "{stdout}"
    );
    assert!(stdout.contains(r#""account_id":"srv-acct-1""#), "{stdout}");
    assert!(!stdout.contains("synthetic-machine-token"), "{stdout}");
    assert!(server_posts.lock().unwrap().is_empty());
    assert_eq!(*server_usage_gets.lock().unwrap(), 0);

    provider.abort();
}
