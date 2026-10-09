#![cfg(all(feature = "server", target_os = "linux"))]
//! SAW-12694: `claudectl add` reads the pasted `code#state` visibly (or from stdin without a
//! terminal) and checks it before anything is sent. A scripted account server; synthetic data.
use assert_cmd::Command;
use axum::{Json, Router, extract::State, http::StatusCode, routing::post};
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

/// The body of every login completion request.
type Completions = Arc<Mutex<Vec<Value>>>;

async fn start() -> Json<Value> {
    Json(json!({
        "id": "login-1",
        "authorize_url": "https://claude.ai/oauth/authorize?code=true&client_id=c&state=st-1",
        "expires_at": chrono::Utc::now().timestamp_millis() + 300_000,
    }))
}

async fn complete(
    State(completions): State<Completions>,
    Json(body): Json<Value>,
) -> (StatusCode, Json<Value>) {
    completions.lock().unwrap().push(body);
    (
        StatusCode::OK,
        Json(json!({"account_id": "a".repeat(64),
            "identity": {"account_uuid": "u", "organization_uuid": "o"},
            "migration_id": "m-1"})),
    )
}

fn private_write(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

struct Env {
    home: tempfile::TempDir,
    completions: Completions,
}

impl Env {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let completions = Completions::default();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/v2/anthropic/login/start", post(start))
            .route("/v2/anthropic/login/complete", post(complete))
            .with_state(completions.clone());
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
        Self { home, completions }
    }
    fn add(&self, stdin: &str) -> std::process::Output {
        Command::cargo_bin("claudectl")
            .unwrap()
            .env_clear()
            .env("HOME", self.home.path())
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .args(["add", "work", "--no-browser"])
            .write_stdin(stdin)
            .output()
            .unwrap()
    }
}

#[test]
fn a_piped_code_of_this_sign_in_completes_the_login() {
    let env = Env::new();
    let output = env.add("secret-code#st-1\n");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let completions = env.completions.lock().unwrap().clone();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0]["code"], "secret-code#st-1");
}

#[test]
fn a_wrong_paste_fails_here_and_sends_nothing() {
    for paste in ["secret-code\n", "secret-code#st-9\n", "\n"] {
        let env = Env::new();
        let output = env.add(paste);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{paste:?}: {stderr}");
        assert!(stderr.contains("Try:"), "{paste:?}: {stderr}");
        assert!(!stderr.contains("secret-code"), "{paste:?}: {stderr}");
        assert!(env.completions.lock().unwrap().is_empty(), "{paste:?}");
    }
}
