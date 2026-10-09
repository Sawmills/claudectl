#![cfg(feature = "server")]
//! The account server's HTTP contract, with a synthetic Anthropic API. No real credential.
use axum::{
    Json, Router,
    routing::{get, post},
};
use claudectl::server::{app, engine::Endpoints};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Notify;

const AMIR: &str = "amir@sawmills.ai";

async fn serve(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (origin, task)
}

/// A synthetic Anthropic API. Each refresh waits for `release` when one is given.
async fn provider(release: Option<Arc<Notify>>) -> (Endpoints, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/api/oauth/profile",
            get(|| async { Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})) }),
        )
        .route(
            "/token",
            post(move || {
                let release = release.clone();
                async move {
                    if let Some(release) = release {
                        release.notified().await;
                    }
                    Json(json!({"access_token":"successor","refresh_token":"successor-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
                }
            }),
        );
    let (origin, task) = serve(app).await;
    (
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/token"),
        },
        task,
    )
}

struct Fixture {
    _root: tempfile::TempDir,
    state: PathBuf,
    server: Arc<app::Server>,
    origin: String,
    http: reqwest::Client,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn register(&self, email: &str, name: &str) -> (String, String) {
        app::register(self.server.store(), email, name)
            .await
            .unwrap()
    }
    fn file_store(&self) -> bool {
        matches!(
            self.server.store(),
            claudectl::server::store::Store::File(_)
        )
    }
    async fn new(release: Option<Arc<Notify>>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let key = root.path().join("key");
        app::setup(&state, &key).unwrap();
        let store = match claudectl::server::testing::fresh_database().await.unwrap() {
            Some(url) => app::StoreConfig::Postgres(url),
            None => app::StoreConfig::File(state.clone()),
        };
        let (endpoints, provider) = provider(release).await;
        let server = app::Server::open(app::Config {
            store,
            key,
            allowed_users: vec![AMIR.into()],
            sso: None,
            metrics_token_hash: None,
            endpoints,
        })
        .await
        .unwrap();
        let (origin, task) = serve(app::router(server.clone())).await;
        Self {
            _root: root,
            state,
            server,
            origin,
            http: reqwest::Client::new(),
            tasks: vec![provider, task],
        }
    }
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (u16, Value) {
        let mut request = self.http.request(method, format!("{}{path}", self.origin));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    }
    async fn migrate(&self, token: &str) -> String {
        let expires_at = chrono::Utc::now().timestamp_millis() + 3_600_000;
        let (status, receipt) = self
            .call(
                reqwest::Method::POST,
                "/v2/anthropic/migrations",
                Some(token),
                Some(json!({"alias":"work","migration_id":"m-1","exclusive_owner":true,
                    "grant":{"access_token":"migrated","refresh_token":"migrated-refresh","expires_at":expires_at,"scopes":["user:inference","user:profile"]}})),
            )
            .await;
        assert_eq!(status, 200, "{receipt}");
        receipt["account_id"].as_str().unwrap().into()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort());
    }
}

#[tokio::test]
async fn only_an_enrolled_machine_of_an_allowed_user_gets_access() {
    let f = Fixture::new(None).await;
    let (_mac, mac) = f.register(AMIR, "mac").await;
    let (_other_id, other) = f.register("teammate@sawmills.ai", "laptop").await;
    let get = reqwest::Method::GET;

    assert_eq!(
        f.call(get.clone(), "/v2/anthropic/accounts", None, None)
            .await
            .0,
        401
    );
    assert_eq!(
        f.call(get.clone(), "/v2/anthropic/accounts", Some("guess"), None)
            .await
            .0,
        401
    );
    let (status, body) = f
        .call(get.clone(), "/v2/anthropic/accounts", Some(&other), None)
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (403, Some("user_not_allowed"))
    );

    let id = f.migrate(&mac).await;
    let (status, access) = f
        .call(
            reqwest::Method::POST,
            "/v2/anthropic/token",
            Some(&mac),
            Some(json!({"account_id":id})),
        )
        .await;
    assert_eq!(status, 200, "{access}");
    assert_eq!(access["provider"], "anthropic");
    assert_eq!(access["access_token"], "successor");
    assert!(!access.to_string().contains("refresh"));
    let (status, _) = f
        .call(
            reqwest::Method::POST,
            "/v2/anthropic/token",
            Some(&other),
            Some(json!({"account_id":id})),
        )
        .await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn a_deleted_account_answers_gone_and_a_revoked_machine_is_refused() {
    let f = Fixture::new(None).await;
    let (mac_id, mac) = f.register(AMIR, "mac").await;
    let (_devbox_id, devbox) = f.register(AMIR, "devbox").await;
    let id = f.migrate(&mac).await;
    let (status, _) = f
        .call(
            reqwest::Method::DELETE,
            &format!("/v2/anthropic/accounts/{id}"),
            Some(&devbox),
            None,
        )
        .await;
    assert_eq!(status, 204);
    let (status, body) = f
        .call(
            reqwest::Method::POST,
            "/v2/anthropic/token",
            Some(&mac),
            Some(json!({"account_id":id})),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (410, Some("account_deleted"))
    );

    let (status, _) = f
        .call(
            reqwest::Method::POST,
            "/v1/devices/revoke",
            Some(&devbox),
            Some(json!({"id":mac_id})),
        )
        .await;
    assert_eq!(status, 204);
    assert_eq!(
        f.call(reqwest::Method::GET, "/v1/me", Some(&mac), None)
            .await
            .0,
        401
    );
    assert_eq!(
        f.call(reqwest::Method::GET, "/v1/me", Some(&devbox), None)
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn a_machine_revoked_during_a_refresh_gets_no_token() {
    let release = Arc::new(Notify::new());
    let f = Fixture::new(Some(release.clone())).await;
    let (mac_id, mac) = f.register(AMIR, "mac").await;
    let (_devbox_id, devbox) = f.register(AMIR, "devbox").await;
    // The migration's forced refresh waits for one release.
    let migrate = {
        let release = release.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            release.notify_one();
        })
    };
    let id = f.migrate(&devbox).await;
    migrate.await.unwrap();
    let (status, access) = f
        .call(
            reqwest::Method::POST,
            "/v2/anthropic/token",
            Some(&mac),
            Some(json!({"account_id":id})),
        )
        .await;
    assert_eq!(status, 200, "{access}");

    let previous = access["revision"].as_str().unwrap().to_owned();
    let token = {
        let http = f.http.clone();
        let url = format!("{}/v2/anthropic/token", f.origin);
        let mac = mac.clone();
        let id = id.clone();
        tokio::spawn(async move {
            let response = http
                .post(url)
                .bearer_auth(mac)
                .json(&json!({"account_id":id,"previous_revision":previous}))
                .send()
                .await
                .unwrap();
            (response.status().as_u16(), response.text().await.unwrap())
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, _) = f
        .call(
            reqwest::Method::POST,
            "/v1/devices/revoke",
            Some(&devbox),
            Some(json!({"id":mac_id})),
        )
        .await;
    assert_eq!(status, 204);
    release.notify_one();
    let (status, body) = token.await.unwrap();
    assert_eq!(status, 401, "{body}");
    assert!(!body.contains("successor"));
}

#[tokio::test]
async fn metrics_count_failures_by_reason_with_the_last_failure_time() {
    let f = Fixture::new(None).await;
    let (_mac_id, mac) = f.register(AMIR, "mac").await;
    assert_eq!(
        f.call(reqwest::Method::GET, "/v1/me", Some("guess"), None)
            .await
            .0,
        401
    );
    let text = f
        .http
        .get(format!("{}/metrics", f.origin))
        .bearer_auth(&mac)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("claudectl_server_failed_requests_total{reason=\"unauthorized\"} 1\n"),
        "{text}"
    );
    let now = chrono::Utc::now().timestamp();
    let last: i64 = text
        .lines()
        .find_map(|l| {
            l.strip_prefix(
                "claudectl_server_last_failure_timestamp_seconds{reason=\"unauthorized\"} ",
            )
        })
        .expect("last failure gauge")
        .parse()
        .unwrap();
    assert!((now - 5..=now).contains(&last));
    // Every rotation reason is exported before its first event.
    for reason in ["expired", "forced", "margin", "migration"] {
        for series in [
            "claudectl_token_rotations_total",
            "claudectl_token_last_rotation_timestamp_seconds",
        ] {
            let line = format!("{series}{{reason=\"{reason}\"}} 0\n");
            assert!(text.contains(&line), "{line} in {text}");
        }
    }
}

#[tokio::test]
async fn a_delete_that_cannot_persist_answers_503_and_an_unknown_account_404() {
    let f = Fixture::new(None).await;
    let (_mac_id, mac) = f.register(AMIR, "mac").await;
    let id = f.migrate(&mac).await;
    if f.file_store() {
        // A directory where the state file goes makes every write fail.
        let (file, saved) = (f.state.join("state.enc"), f.state.join("state.saved"));
        std::fs::rename(&file, &saved).unwrap();
        std::fs::create_dir(&file).unwrap();
        let (status, body) = f
            .call(
                reqwest::Method::DELETE,
                &format!("/v2/anthropic/accounts/{id}"),
                Some(&mac),
                None,
            )
            .await;
        std::fs::remove_dir(&file).unwrap();
        std::fs::rename(&saved, &file).unwrap();
        assert_eq!(
            (status, body["error"].as_str()),
            (503, Some("persistence_failed"))
        );
        let (status, _) = f
            .call(
                reqwest::Method::POST,
                "/v2/anthropic/token",
                Some(&mac),
                Some(json!({"account_id":id})),
            )
            .await;
        assert_eq!(status, 200);
    }
    let missing = "0".repeat(64);
    let (status, body) = f
        .call(
            reqwest::Method::DELETE,
            &format!("/v2/anthropic/accounts/{missing}"),
            Some(&mac),
            None,
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (404, Some("account_not_found"))
    );
}

#[tokio::test]
async fn shutdown_lets_a_refresh_in_progress_finish_and_persist() {
    let release = Arc::new(Notify::new());
    let root = tempfile::tempdir().unwrap();
    let (state, key) = (root.path().join("state"), root.path().join("key"));
    app::setup(&state, &key).unwrap();
    let store = match claudectl::server::testing::fresh_database().await.unwrap() {
        Some(url) => app::StoreConfig::Postgres(url),
        None => app::StoreConfig::File(state.clone()),
    };
    let (endpoints, _provider) = provider(Some(release.clone())).await;
    let server = app::Server::open(app::Config {
        store,
        key,
        allowed_users: vec![AMIR.into()],
        sso: None,
        metrics_token_hash: None,
        endpoints,
    })
    .await
    .unwrap();
    let (_mac_id, mac) = app::register(server.store(), AMIR, "mac").await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let serving = tokio::spawn(app::serve_until(server.clone(), listener, async {
        let _ = stopped.await;
    }));
    let http = reqwest::Client::new();
    // The migration's forced refresh waits for one release.
    release.notify_one();
    let expires_at = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let receipt: Value = http
        .post(format!("{origin}/v2/anthropic/migrations"))
        .bearer_auth(&mac)
        .json(&json!({"alias":"work","migration_id":"m-1","exclusive_owner":true,
            "grant":{"access_token":"migrated","refresh_token":"migrated-refresh","expires_at":expires_at,"scopes":["user:inference","user:profile"]}}))
        .send().await.unwrap().json().await.unwrap();
    let id = receipt["account_id"].as_str().unwrap().to_owned();
    let access: Value = http
        .post(format!("{origin}/v2/anthropic/token"))
        .bearer_auth(&mac)
        .json(&json!({"account_id":id}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let pending = {
        let (http, origin, mac, id) = (http.clone(), origin.clone(), mac.clone(), id.clone());
        let previous = access["revision"].as_str().unwrap().to_owned();
        tokio::spawn(async move {
            http.post(format!("{origin}/v2/anthropic/token"))
                .bearer_auth(mac)
                .json(&json!({"account_id":id,"previous_revision":previous}))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    stop.send(()).unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !serving.is_finished(),
        "shutdown did not wait for the refresh"
    );
    release.notify_one();
    assert_eq!(pending.await.unwrap(), 200);
    tokio::time::timeout(Duration::from_secs(10), serving)
        .await
        .expect("drain finished")
        .unwrap()
        .unwrap();
    let accounts = server
        .store()
        .accounts(&receipt_user(&server).await)
        .await
        .unwrap();
    assert_eq!(accounts.len(), 1);
}

async fn receipt_user(server: &app::Server) -> String {
    server.store().users().await.unwrap()[0].id.clone()
}

#[tokio::test]
async fn a_server_without_sso_offers_no_home_page_or_dashboard() {
    let f = Fixture::new(None).await;
    for path in ["/", "/accounts", "/accounts/sign-in"] {
        let (status, _) = f.call(reqwest::Method::GET, path, None, None).await;
        assert_eq!(status, 404, "{path}");
    }
    let (status, _) = f
        .call(reqwest::Method::POST, "/accounts/sign-out", None, None)
        .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn the_receipt_route_reports_the_admission_state() {
    let f = Fixture::new(None).await;
    let (_mac, mac) = f.register(AMIR, "mac").await;
    let get = reqwest::Method::GET;
    let (status, body) = f
        .call(
            get.clone(),
            "/v2/anthropic/migrations?migration_id=m-1",
            Some(&mac),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "none");
    assert!(body["receipt"].is_null());
    f.migrate(&mac).await;
    let (status, body) = f
        .call(
            get,
            "/v2/anthropic/migrations?migration_id=m-1",
            Some(&mac),
            None,
        )
        .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["state"], "complete");
    assert_eq!(body["receipt"]["migration_id"], "m-1");
}

#[tokio::test]
async fn a_migration_retried_after_its_account_was_deleted_answers_410() {
    let f = Fixture::new(None).await;
    let (_mac_id, mac) = f.register(AMIR, "mac").await;
    let id = f.migrate(&mac).await;
    let (status, _) = f
        .call(
            reqwest::Method::DELETE,
            &format!("/v2/anthropic/accounts/{id}"),
            Some(&mac),
            None,
        )
        .await;
    assert_eq!(status, 204);
    // A lost reply makes the client retry the same migration ID.
    let expires_at = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let (status, body) = f
        .call(
            reqwest::Method::POST,
            "/v2/anthropic/migrations",
            Some(&mac),
            Some(json!({"alias":"work","migration_id":"m-1","exclusive_owner":true,
                "grant":{"access_token":"migrated","refresh_token":"migrated-refresh","expires_at":expires_at,"scopes":["user:inference","user:profile"]}})),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (410, Some("account_deleted")),
        "{body}"
    );
}

#[tokio::test]
async fn the_cancel_route_blocks_later_imports_and_refuses_after_commit() {
    let f = Fixture::new(None).await;
    let (_mac_id, mac) = f.register(AMIR, "mac").await;
    let post = reqwest::Method::POST;
    let (status, body) = f
        .call(
            post.clone(),
            "/v2/anthropic/migrations/cancel",
            Some(&mac),
            Some(json!({"alias":"work","migration_id":"m-9"})),
        )
        .await;
    assert_eq!(
        (status, body["state"].as_str()),
        (200, Some("cancelled")),
        "{body}"
    );
    let expires_at = chrono::Utc::now().timestamp_millis() + 3_600_000;
    let (status, body) = f
        .call(post.clone(), "/v2/anthropic/migrations", Some(&mac),
            Some(json!({"alias":"work","migration_id":"m-9","exclusive_owner":true,
                "grant":{"access_token":"migrated","refresh_token":"migrated-refresh","expires_at":expires_at,"scopes":["user:inference","user:profile"]}})))
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (409, Some("migration_cancelled")),
        "{body}"
    );
    f.migrate(&mac).await;
    let (status, body) = f
        .call(
            post,
            "/v2/anthropic/migrations/cancel",
            Some(&mac),
            Some(json!({"alias":"work","migration_id":"m-1"})),
        )
        .await;
    assert_eq!(
        (status, body["error"].as_str()),
        (409, Some("migration_admitted")),
        "{body}"
    );
}

// ---------- Machine last-seen (SAW-12696 A) ----------

async fn last_seen(f: &Fixture, token: &str) -> Option<i64> {
    f.server
        .store()
        .machine_by_token(&claudectl::server::vault::digest(token.as_bytes()))
        .await
        .unwrap()
        .unwrap()
        .last_seen_at
}

/// The last-seen write runs off the request path: wait for it a little.
async fn wait_seen(f: &Fixture, token: &str) -> Option<i64> {
    for _ in 0..40 {
        if let Some(at) = last_seen(f, token).await {
            return Some(at);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn a_machine_request_records_last_seen_at_most_every_five_minutes() {
    let f = Fixture::new(None).await;
    let (_mac_id, mac) = f.register(AMIR, "mac").await;
    assert_eq!(last_seen(&f, &mac).await, None);
    let before = chrono::Utc::now().timestamp_millis();
    assert_eq!(
        f.call(reqwest::Method::GET, "/v1/me", Some(&mac), None)
            .await
            .0,
        200
    );
    let first = wait_seen(&f, &mac).await.expect("last seen recorded");
    assert!(first >= before, "{first} < {before}");
    // A second request within 5 minutes writes nothing.
    assert_eq!(
        f.call(reqwest::Method::GET, "/v1/me", Some(&mac), None)
            .await
            .0,
        200
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(last_seen(&f, &mac).await, Some(first));
    // The machine list shows it.
    let (status, devices) = f
        .call(reqwest::Method::GET, "/v1/devices", Some(&mac), None)
        .await;
    assert_eq!(status, 200);
    assert_eq!(devices[0]["last_seen_at"], first, "{devices}");
    // A revoked machine's token is refused and records nothing.
    let (old_id, old) = f.register(AMIR, "old").await;
    f.server
        .store()
        .revoke_machine(&old_id, None)
        .await
        .unwrap();
    assert_eq!(
        f.call(reqwest::Method::GET, "/v1/me", Some(&old), None)
            .await
            .0,
        401
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(last_seen(&f, &old).await, None);
}

#[tokio::test]
async fn a_failed_last_seen_write_still_serves_the_request_and_is_counted() {
    let f = Fixture::new(None).await;
    if !f.file_store() {
        return;
    }
    let (_mac_id, mac) = f.register(AMIR, "mac").await;
    // A directory where the state file goes makes every write fail.
    let (file, saved) = (f.state.join("state.enc"), f.state.join("state.saved"));
    std::fs::rename(&file, &saved).unwrap();
    std::fs::create_dir(&file).unwrap();
    let status = f
        .call(reqwest::Method::GET, "/v1/me", Some(&mac), None)
        .await
        .0;
    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&saved, &file).unwrap();
    assert_eq!(status, 200);
    let text = f
        .http
        .get(format!("{}/metrics", f.origin))
        .bearer_auth(&mac)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(
        text.contains("claudectl_server_failed_requests_total{reason=\"machine_seen_store\"} 1\n"),
        "{text}"
    );
}
