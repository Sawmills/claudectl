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
    origin: String,
    http: reqwest::Client,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Fixture {
    async fn new(release: Option<Arc<Notify>>) -> Self {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let key = root.path().join("key");
        app::setup(&state, &key).unwrap();
        let (endpoints, provider) = provider(release).await;
        let server = app::Server::open(app::Config {
            state: state.clone(),
            key,
            allowed_users: vec![AMIR.into()],
            sso: None,
            metrics_token_hash: None,
            endpoints,
        })
        .await
        .unwrap();
        let (origin, task) = serve(app::router(server)).await;
        Self {
            _root: root,
            state,
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
    let (_mac, mac) = app::register(&f.state, AMIR, "mac").unwrap();
    let (_other_id, other) = app::register(&f.state, "teammate@sawmills.ai", "laptop").unwrap();
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
    let (mac_id, mac) = app::register(&f.state, AMIR, "mac").unwrap();
    let (_devbox_id, devbox) = app::register(&f.state, AMIR, "devbox").unwrap();
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
    let (mac_id, mac) = app::register(&f.state, AMIR, "mac").unwrap();
    let (_devbox_id, devbox) = app::register(&f.state, AMIR, "devbox").unwrap();
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
    let (_mac_id, mac) = app::register(&f.state, AMIR, "mac").unwrap();
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
}
