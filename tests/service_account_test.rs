#![cfg(feature = "server")]
//! Public service-job CLI and ordinary machine HTTP routes; synthetic only.
use axum::{Json, Router, http::HeaderMap, routing::get};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_status_refuses_bad_auth_without_refreshing_or_showing_human_profiles() {
    let human_calls = Arc::new(AtomicUsize::new(0));
    let calls = human_calls.clone();
    let app = Router::new()
        .route(
            "/v1/me",
            get(|| async {
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(json!({"error":"machine_revoked"})),
                )
            }),
        )
        .route(
            "/human/token",
            axum::routing::post(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    (
                        axum::http::StatusCode::UNAUTHORIZED,
                        Json(json!({"error":"invalid_grant"})),
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let home = tempfile::tempdir().unwrap();
    let paths = claudectl::config::Paths::from_home(home.path().into());
    let credentials = serde_json::from_value(json!({"claudeAiOauth":{
        "accessToken":"synthetic-human-access", "refreshToken":"synthetic-human-refresh",
        "expiresAt":1,"scopes":["user:profile","user:inference"]
    }}))
    .unwrap();
    claudectl::profile::save_profile_to(&paths, "human", &credentials, None).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_claudectl"))
        .args(["status", "--json"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.path())
        .env("CLAUDECTL_SERVICE_TOKEN", "synthetic-revoked")
        .env("CLAUDECTL_SERVER_URL", &origin)
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .env("CLAUDECTL_TEST_TOKEN_URL", format!("{origin}/human/token"))
        .env("CLAUDECTL_TEST_USAGE_URL", format!("{origin}/human/usage"))
        .output()
        .unwrap();
    server.abort();
    assert_eq!(
        human_calls.load(Ordering::SeqCst),
        0,
        "service status refreshed a human profile"
    );
    assert!(!output.status.success(), "revoked service status succeeded");
    assert!(
        output.stdout.is_empty(),
        "refused service status displayed human results"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("machine_revoked"));
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_job_rejection_never_falls_back_to_a_saved_human_machine_or_starts_claude() {
    use std::os::unix::fs::PermissionsExt;
    let human_reads = Arc::new(AtomicUsize::new(0));
    let human = human_reads.clone();
    let app = Router::new().route(
        "/v1/me",
        get(move |headers: HeaderMap| {
            let human = human.clone();
            async move {
                if headers
                    .get("authorization")
                    .is_some_and(|h| h == "Bearer synthetic-human")
                {
                    human.fetch_add(1, Ordering::SeqCst);
                }
                (
                    axum::http::StatusCode::UNAUTHORIZED,
                    Json(json!({"error":"machine_revoked"})),
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let home = tempfile::tempdir().unwrap();
    let saved = home.path().join(".claudectl/server");
    std::fs::create_dir_all(&saved).unwrap();
    let machine = saved.join("machine.json");
    std::fs::write(&machine, json!("synthetic-human").to_string()).unwrap();
    std::fs::write(
        saved.join("connection.json"),
        json!({"server":origin,"user_id":"human","token_file":machine}).to_string(),
    )
    .unwrap();
    for name in ["machine.json", "connection.json"] {
        std::fs::set_permissions(saved.join(name), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let marker = home.path().join("child-started");
    let binary = home.path().join("claude");
    std::fs::write(
        &binary,
        format!(
            "#!/bin/sh\ntouch {}\n",
            claudectl::shell::arg(marker.to_str().unwrap())
        ),
    )
    .unwrap();
    std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    for (token, url, error) in [
        (
            Some("synthetic-revoked"),
            Some(origin.as_str()),
            "machine_revoked",
        ),
        (
            Some("synthetic-service"),
            None,
            "CLAUDECTL_SERVER_URL is required",
        ),
        (
            None,
            Some(origin.as_str()),
            "CLAUDECTL_SERVICE_TOKEN is required",
        ),
        (
            Some("  \n"),
            Some(origin.as_str()),
            "CLAUDECTL_SERVICE_TOKEN is empty",
        ),
        (
            Some("synthetic-service"),
            Some("http://example.com"),
            "HTTPS origin",
        ),
    ] {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_claudectl"));
        command
            .args(["run", "work", "--claude"])
            .arg(&binary)
            .args(["--", "-p", "synthetic prompt"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", home.path())
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1");
        if let Some(token) = token {
            command.env("CLAUDECTL_SERVICE_TOKEN", token);
        }
        if let Some(url) = url {
            command.env("CLAUDECTL_SERVER_URL", url);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(error),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!marker.exists(), "refused service job executed a child");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-revoked"));
    }
    assert_eq!(human_reads.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read_to_string(machine).unwrap(),
        json!("synthetic-human").to_string()
    );
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_claudectl"))
        .args(["server", "disconnect"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.path())
        .env("CLAUDECTL_SERVICE_TOKEN", "synthetic-service")
        .env("CLAUDECTL_SERVER_URL", &origin)
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "service mode disconnected the human machine"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("service jobs cannot disconnect the human machine")
    );
    assert_eq!(
        std::fs::read_to_string(saved.join("machine.json")).unwrap(),
        json!("synthetic-human").to_string()
    );
    assert!(saved.join("connection.json").exists());
    server.abort();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_jobs_keep_billing_guard_without_automatic_pick_headroom_cutoff() {
    use std::os::unix::fs::PermissionsExt;
    for (billed, week, should_acquire) in [(true, 20.0, false), (false, 96.0, true)] {
        let grants = Arc::new(AtomicUsize::new(0));
        let posted = grants.clone();
        let app = Router::new()
        .route("/v1/me", get(|| async { Json(json!({"id":"company-user"})) }))
        .route("/v2/anthropic/accounts", get(|| async { Json(json!([{
            "provider":"anthropic", "account_id":"a".repeat(64), "alias":"work",
            "identity":{"account_uuid":"account","organization_uuid":"org"}, "available":true
        }])) }))
        .route("/v2/anthropic/usage", get(move || async move {
            let now = chrono::Utc::now().timestamp_millis();
            Json(json!({"data":{"five_hour":{"utilization":10.0},"seven_day":{"utilization":week},
                "extra_usage":{"is_enabled":billed}}, "observed_at":now,
                "next_retry_at":now+300000,"stale":false,"error":null}))
        }))
        .route("/v2/anthropic/token", axum::routing::post(move || {
            let grants = posted.clone();
            async move { grants.fetch_add(1, Ordering::SeqCst); axum::http::StatusCode::UNAUTHORIZED }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let home = tempfile::tempdir().unwrap();
        let marker = home.path().join("child-started");
        let binary = home.path().join("claude");
        std::fs::write(
            &binary,
            format!(
                "#!/bin/sh\ntouch {}\nprintf 'fixture-unqualified\\n'\n",
                claudectl::shell::arg(marker.to_str().unwrap())
            ),
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        let qualified = home
            .path()
            .join(".claudectl/server/qualified-host-config-builds.json");
        std::fs::create_dir_all(qualified.parent().unwrap()).unwrap();
        std::fs::write(&qualified, json!([{
            "sha256": claudectl::exec::sha256_file(&binary).unwrap(),
            "platform": std::env::consts::OS, "qualified_at":"test", "check":"supervised_host_config"
        }]).to_string()).unwrap();
        std::fs::set_permissions(&qualified, std::fs::Permissions::from_mode(0o600)).unwrap();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_claudectl"))
            .args(["server", "run", "work", "--claude"])
            .arg(&binary)
            .args(["--", "-p", "synthetic prompt"])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap())
            .env("HOME", home.path())
            .env("CLAUDECTL_SERVICE_TOKEN", "synthetic-claude-service")
            .env("CLAUDECTL_SERVER_URL", origin)
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .output()
            .unwrap();
        server.abort();
        assert!(!marker.exists(), "billed={billed}, week={week}: {output:?}");
        assert!(!output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stderr)
                .contains("service job requires fresh included capacity"),
            billed
        );
        assert_eq!(grants.load(Ordering::SeqCst), usize::from(should_acquire));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_status_uses_its_live_catalog_without_saved_human_metadata() {
    let app = Router::new()
        .route("/v1/me", get(|| async { Json(json!({"id":"company-user"})) }))
        .route("/v2/anthropic/accounts", get(|| async { Json(json!([{
            "provider":"anthropic", "account_id":"a".repeat(64), "alias":"work",
            "identity":{"account_uuid":"account","organization_uuid":"org"}, "available":true
        }])) }))
        .route("/v2/anthropic/usage", get(|| async {
            let now = chrono::Utc::now().timestamp_millis();
            Json(json!({"data":{"five_hour":{"utilization":10.0},"seven_day":{"utilization":20.0},
                "extra_usage":{"is_enabled":false}}, "observed_at":now,
                "next_retry_at":now+300000,"stale":false,"error":null}))
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_claudectl"))
        .args(["status", "--json"])
        .env("HOME", home.path())
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("CLAUDECTL_SERVICE_TOKEN", "synthetic-claude-service")
        .env("CLAUDECTL_SERVER_URL", origin)
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .output()
        .unwrap();
    server.abort();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["server"]["state"], "connected");
    assert_eq!(report["server"]["accounts"][0]["alias"], "work");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-claude-service"));
    assert!(!home.path().join(".claudectl/server/machine.json").exists());
    assert!(
        !home
            .path()
            .join(".claudectl/server/connection.json")
            .exists()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn service_token_lists_machines_without_a_saved_human_login() {
    let reads = Arc::new(AtomicUsize::new(0));
    let identities = reads.clone();
    let machines = reads.clone();
    let app = Router::new()
        .route(
            "/v1/me",
            get(move |headers: HeaderMap| {
                let reads = identities.clone();
                async move {
                    assert_eq!(
                        headers.get("authorization").unwrap(),
                        "Bearer synthetic-claude-service"
                    );
                    reads.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"id":"company-user","enabled":true}))
                }
            }),
        )
        .route(
            "/v1/devices",
            get(move |headers: HeaderMap| {
                let reads = machines.clone();
                async move {
                    assert_eq!(
                        headers.get("authorization").unwrap(),
                        "Bearer synthetic-claude-service"
                    );
                    reads.fetch_add(1, Ordering::SeqCst);
                    Json(json!([{"id":"shared-job-machine","revoked":false}]))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let home = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_claudectl"))
        .args(["server", "devices", "--json"])
        .env("HOME", home.path())
        .env_remove("CLAUDE_CONFIG_DIR")
        .env("CLAUDECTL_SERVICE_TOKEN", "synthetic-claude-service\n")
        .env("CLAUDECTL_SERVER_URL", origin)
        .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
        .output()
        .unwrap();
    server.abort();
    assert!(
        output.status.success(),
        "env-only service client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("shared-job-machine"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-claude-service"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("synthetic-claude-service"));
    assert!(!home.path().join(".claudectl/server/machine.json").exists());
    assert!(
        !home
            .path()
            .join(".claudectl/server/connection.json")
            .exists()
    );
    assert_eq!(reads.load(Ordering::SeqCst), 2);
}
