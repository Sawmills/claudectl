#![cfg(feature = "server")]
//! Machine reset HTTP contract against a synthetic provider and either store.
use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use claudectl::server::{
    app, audit,
    engine::{Endpoints, Grant},
    testing,
};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

async fn serve(router: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (url, task)
}

// This binary has one test, so the reset gate cannot race other tests' environment.
#[tokio::test]
async fn reset_machine_contract_preserves_initiator_and_refuses_service_authority() {
    unsafe { std::env::set_var("CLAUDECTL_CENTRAL_BROWSER_RESETS", "1") };
    let requests = Arc::new(Mutex::new(Vec::<Value>::new()));
    let captured = requests.clone();
    let provider = Router::new()
        .route("/api/oauth/profile", get(|| async { Json(json!({"account":{"uuid":"a"}, "organization":{"uuid":"o"}})) }))
        .route("/api/oauth/usage", get(|| async { Json(json!({
            "five_hour":{"utilization":100},
            "cedar_ember":{"at_limit":true, "grants":[
                {"resets_left":7,"clears":["five_hour"]},
                {"id":"later-private-grant","resets_left":1,"clears":["five_hour"],"ends_at":"2099-02-01T00:00:00Z"},
                {"id":"sooner-private-grant","resets_left":2,"clears":["five_hour"],"ends_at":"2099-01-01T00:00:00Z"}
            ]}
        })) }))
        .route("/api/organizations/o/reset_rate_limits", post(move |Json(body): Json<Value>| {
            let captured = captured.clone();
            async move {
                let mut captured = captured.lock().unwrap();
                captured.push(body);
                if captured.len() == 1 {
                    (axum::http::StatusCode::BAD_GATEWAY, Json(json!({"error":"lost reply"}))).into_response()
                } else { Json(json!({"result":"reset"})).into_response() }
            }
        }));
    let (provider_url, provider_task) = serve(provider).await;
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    let state = root.path().join("state");
    app::setup(&state, &key).unwrap();
    let backend = match testing::fresh_database().await.unwrap() {
        Some(url) => app::StoreConfig::Postgres(url),
        None => app::StoreConfig::File(state),
    };
    let server = app::Server::open(app::Config {
        store: backend,
        key: key.clone(),
        allowed_users: vec!["a@sawmills.ai".into(), "b@sawmills.ai".into()],
        sso: None,
        metrics_token_hash: None,
        endpoints: Endpoints {
            api: provider_url.clone(),
            token: format!("{provider_url}/token"),
        },
    })
    .await
    .unwrap();
    let (machine, token) = app::register(server.store(), "a@sawmills.ai", "initiator")
        .await
        .unwrap();
    let (_, resumer) = app::register(server.store(), "a@sawmills.ai", "resumer")
        .await
        .unwrap();
    let (_, other) = app::register(server.store(), "b@sawmills.ai", "other")
        .await
        .unwrap();
    let user = server
        .store()
        .machine_by_token(&claudectl::server::vault::digest(token.as_bytes()))
        .await
        .unwrap()
        .unwrap()
        .user;
    let account = server
        .engine()
        .admit(
            &user,
            &machine,
            "work",
            Grant {
                access_token: "synthetic-access".into(),
                refresh_token: "synthetic-refresh".into(),
                expires_at: chrono::Utc::now().timestamp_millis() + 3_600_000,
                scopes: vec!["user:profile".into(), "user:inference".into()],
            },
            None,
        )
        .await
        .unwrap();
    let service = claudectl::central::service_account::issue(
        server.store(),
        &user,
        &["a@sawmills.ai".into()],
    )
    .await
    .unwrap();
    let (url, task) = serve(app::router(server.clone())).await;
    let http = reqwest::Client::new();
    let list_url = format!("{url}/v2/anthropic/resets");
    let redeem_url = format!("{list_url}/redeem");
    for (method, path) in [
        (reqwest::Method::GET, &list_url),
        (reqwest::Method::POST, &redeem_url),
    ] {
        let reply = http
            .request(method, path)
            .bearer_auth(&service)
            .json(&json!({"account_id": account.account_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), 403);
        assert_eq!(
            reply.json::<Value>().await.unwrap()["error"],
            "service_account_reset_refused"
        );
    }
    let other_list: Value = http
        .get(&list_url)
        .bearer_auth(&other)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(other_list["accounts"], json!([]));
    let refused = http
        .post(&redeem_url)
        .bearer_auth(&other)
        .json(&json!({"account_id":account.account_id}))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 404);
    assert!(requests.lock().unwrap().is_empty());
    let cold: Value = http
        .get(&list_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cold["accounts"][0]["stale"], true);
    assert_eq!(cold["accounts"][0]["offers"], json!([]));
    let usage = http
        .get(format!("{url}/v2/anthropic/usage"))
        .query(&[("account_id", account.account_id.as_str())])
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(usage.status().is_success());
    let listed: Value = http
        .get(&list_url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(listed["accounts"][0]["stale"], false);
    assert_eq!(listed["accounts"][0]["offers"].as_array().unwrap().len(), 2);
    assert_eq!(listed["accounts"][0]["offers"][0]["resets_left"], 2);
    assert!(!listed.to_string().contains("private-grant"));
    for (bearer, expected) in [(&token, 503), (&resumer, 200)] {
        let reply = http
            .post(&redeem_url)
            .bearer_auth(bearer)
            .json(&json!({"account_id":account.account_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), expected);
    }
    let requests = requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["grant_id"], "sooner-private-grant");
    assert_eq!(requests[0]["request_id"], requests[1]["request_id"]);
    let events = audit::read(server.store(), &key).await.unwrap();
    let events = events
        .iter()
        .filter(|event| event["operation"] == "account_reset")
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["machine"], machine);
    assert_eq!(events[0]["actor"], format!("machine:{machine}"));
    task.abort();
    provider_task.abort();
}
