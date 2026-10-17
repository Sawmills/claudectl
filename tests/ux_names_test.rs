#![cfg(all(feature = "server", target_os = "linux"))]
//! SAW-12677: the short names the compact view shows work in `renew` and `status`.
//! A scripted account server; synthetic data only.
use assert_cmd::Command;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

const ACCOUNT: &str = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";

/// The body of every login start request.
type Logins = Arc<Mutex<Vec<Value>>>;

async fn accounts() -> Json<Value> {
    Json(json!([{"provider": "anthropic", "account_id": ACCOUNT,
        "alias": "amir2@sawmills.ai",
        "identity": {"account_uuid": "claude-account", "organization_uuid": "claude-org"},
        "available": true}]))
}

async fn usage() -> Json<Value> {
    Json(json!({
        "data": {"five_hour": {"utilization": 3}, "seven_day": {"utilization": 1},
            "extra_usage": {"is_enabled": false}},
        "observed_at": chrono::Utc::now().timestamp_millis(),
        "next_retry_at": 0, "stale": false, "error": null,
    }))
}

async fn remove() -> StatusCode {
    StatusCode::NO_CONTENT
}

/// Records the request, then refuses it: the test needs only what the CLI asked for.
async fn login_start(
    State(logins): State<Logins>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    logins.lock().unwrap().push(body);
    (StatusCode::CONFLICT, Json(json!({"error": "test_stop"})))
}

fn private_write(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Env {
    home: tempfile::TempDir,
    logins: Logins,
}

impl Env {
    fn new() -> Self {
        Self::with_usage(None)
    }
    fn with_usage(observation: Option<Value>) -> Self {
        let home = tempfile::tempdir().unwrap();
        let logins = Logins::default();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let usage_route = match observation {
            Some(body) => get(move || {
                let body = body.clone();
                async move { Json(body) }
            }),
            None => get(usage),
        };
        let app = Router::new()
            .route("/v2/anthropic/accounts", get(accounts))
            .route("/v2/anthropic/usage", usage_route)
            .route("/v2/anthropic/login/start", post(login_start))
            .route("/v2/anthropic/accounts/{id}", axum::routing::delete(remove))
            .with_state(logins.clone());
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
        Self { home, logins }
    }
    fn claudectl(&self, args: &[&str]) -> std::process::Output {
        Command::cargo_bin("claudectl")
            .unwrap()
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .args(args)
            .output()
            .unwrap()
    }
}

#[test]
fn status_shows_read_only_limit_reset_offers_from_the_server() {
    let data: Value =
        serde_json::from_str(include_str!("fixtures/limit-reset-offers.json")).unwrap();
    let env = Env::with_usage(Some(json!({
        "data": data,
        "observed_at": chrono::Utc::now().timestamp_millis(),
        "next_retry_at": 0, "stale": false, "error": null
    })));
    for args in [&["status"][..], &["status", "--details"]] {
        let output = env.claudectl(args);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("2 resets"), "{text}");
        assert!(text.contains("5-hour + weekly"), "{text}");
        assert!(text.contains("2099-10-22"), "{text}");
        assert!(text.contains("/limit-reset"), "{text}");
        assert!(!text.contains("synthetic-grant-not-for-display"));
        assert!(!text.contains("provider-label-not-for-display"));
    }
    let output = env.claudectl(&["status", "--json"]);
    assert!(output.status.success());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!report["next"].as_str().unwrap().is_empty());
    assert_eq!(
        report["server"]["accounts"][0]["limit_reset_offers"][0]["resets_left"],
        2
    );
}

#[test]
fn status_labels_paused_future_and_currently_unusable_reset_offers() {
    let mut data: Value =
        serde_json::from_str(include_str!("fixtures/limit-reset-offers.json")).unwrap();
    data["cedar_ember"]["grants"][0]["paused"] = json!(true);
    data["cedar_ember"]["grants"][0]["usable_now"] = json!(false);
    data["cedar_ember"]["grants"][0]["starts_at"] = json!("2099-01-01T00:00:00Z");
    let env = Env::with_usage(Some(
        json!({"data":data,"observed_at":chrono::Utc::now().timestamp_millis(),"next_retry_at":0,"stale":false,"error":null}),
    ));
    for args in [&["status"][..], &["status", "--details"]] {
        let output = env.claudectl(args);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        for label in ["2 resets", "paused", "not usable now", "starts 2099-01-01"] {
            assert!(text.contains(label), "missing {label}: {text}");
        }
    }
}

#[test]
fn status_ignores_absent_empty_malformed_and_expired_reset_metadata() {
    for cedar in [
        None,
        Some(Value::Null),
        Some(json!("unexpected")),
        Some(json!({"grants": "unexpected"})),
        Some(json!({"eligible": false, "grants": [{"resets_left": 2}]})),
        Some(json!({"grants": [{"resets_left": 0}, {"resets_left": "two"}, null]})),
        Some(json!({"grants": [{"resets_left": 2, "ends_at": "2000-01-01T00:00:00Z"}]})),
    ] {
        let mut data = json!({"five_hour": {"utilization": 3}, "seven_day": {"utilization": 1}, "extra_usage": {"is_enabled": false}});
        if let Some(cedar) = cedar {
            data["cedar_ember"] = cedar;
        }
        let env = Env::with_usage(Some(
            json!({"data":data, "observed_at":chrono::Utc::now().timestamp_millis(), "next_retry_at":0, "stale":false, "error":null}),
        ));
        let output = env.claudectl(&["status"]);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("ready"), "{text}");
        assert!(!text.contains("Limit resets"), "{text}");
        assert!(!text.contains("/limit-reset"), "{text}");
        let output = env.claudectl(&["status", "--json"]);
        assert!(output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report["server"]["accounts"][0]["limit_reset_offers"].is_array());
        assert!(
            report["server"]["accounts"][0]["limit_reset_offers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            report["server"]["accounts"][0]["windows"]["five_hour"]["used_percent"],
            3.0
        );
    }
}

#[test]
fn renew_resolves_the_short_name_before_it_starts_the_login() {
    let env = Env::new();
    let output = env.claudectl(&["renew", "amir2", "--no-browser"]);
    let logins = env.logins.lock().unwrap().clone();
    assert_eq!(
        logins.len(),
        1,
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(logins[0]["alias"], "amir2@sawmills.ai");
    assert_eq!(logins[0]["renew"], true);
}

#[test]
fn status_resolves_the_short_name_of_a_server_account() {
    let env = Env::new();
    let output = env.claudectl(&["status", "amir2"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout
            .lines()
            .any(|l| l.contains("amir2") && l.contains("ready")),
        "{stdout}"
    );
    // The cached view, from the usage the live read saved, resolves the same name.
    let output = env.claudectl(&["status", "amir2", "--cached"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("amir2"), "{stdout}");
}

#[test]
fn rm_names_the_resolved_account_before_and_after_it_removes_it() {
    let env = Env::new();
    // A prefix: the confirmation names the account it would remove, never the typed text.
    let output = env.claudectl(&["rm", "am"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("Try: claudectl rm amir2@sawmills.ai --yes"),
        "{stderr}"
    );
    let output = env.claudectl(&["rm", "am", "--yes"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("amir2@sawmills.ai removed"), "{stdout}");
}

#[test]
fn cached_server_status_resolves_the_short_name() {
    let env = Env::new();
    // A live read saves the usage on this machine.
    assert!(
        env.claudectl(&["server", "status", "amir2"])
            .status
            .success()
    );
    let output = env.claudectl(&["server", "status", "amir2", "--cached", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(usage["data"]["five_hour"]["utilization"], 3, "{usage}");
}
