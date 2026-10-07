use super::*;
use axum::{
    Json, Router,
    routing::{get, post},
};
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn cached_usage_never_acquires_a_token_and_machines_share_polling() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app=Router::new()
        .route("/api/oauth/profile",get(||async{Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}}))}))
        .route("/api/oauth/usage",get(move||{let calls=calls.clone();async move{calls.fetch_add(1,Ordering::SeqCst);Json(json!({"five_hour":{"utilization":42,"resets_at":"2099-01-01T00:00:00Z"},"seven_day":null}))}}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[8; 32]).unwrap();
    let engine = Engine::open_at(
        &root.path().join("store"),
        &key,
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/v1/oauth/token"),
        },
    )
    .unwrap();
    let receipt = engine
        .admit(
            "person",
            "work",
            "first",
            Grant {
                access_token: "fake-a".into(),
                refresh_token: "fake-ra".into(),
                expires_at: now() + 3600000,
                scopes: vec!["user:inference".into(), "user:profile".into()],
            },
            None,
        )
        .await
        .unwrap();
    assert!(
        engine
            .usage("person", &receipt.account_id, true)
            .await
            .unwrap()
            .data
            .is_none()
    );
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let (a, b) = tokio::join!(
        engine.usage("person", &receipt.account_id, false),
        engine.usage("person", &receipt.account_id, false)
    );
    assert_eq!(a.unwrap().data.unwrap()["five_hour"]["utilization"], 42);
    assert!(b.unwrap().data.unwrap()["seven_day"].is_null());
    assert_eq!(count.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn concurrent_rejections_refresh_once_and_restart_preserves_the_successor() {
    let count = Arc::new(AtomicUsize::new(0));
    let refresh_count = count.clone();
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { Json(json!({"account":{"uuid":"account-a"},"organization":{"uuid":"organization-a"}})) }))
        .route("/v1/oauth/token", post(move || { let count = refresh_count.clone(); async move {
            count.fetch_add(1, Ordering::SeqCst);
            Json(json!({"access_token":"synthetic-b","refresh_token":"synthetic-rb","expires_in":3600,"scope":"user:inference user:profile"}))
        }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[7; 32]).unwrap();
    let store = root.path().join("provider");
    let engine = Engine::open_at(
        &store,
        &key,
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/v1/oauth/token"),
        },
    )
    .unwrap();
    let grant = Grant {
        access_token: "synthetic-a".into(),
        refresh_token: "synthetic-ra".into(),
        expires_at: now() + 3600000,
        scopes: vec!["user:inference".into(), "user:profile".into()],
    };
    let receipt = engine
        .admit("person-a", "work", "migration-1", grant, None)
        .await
        .unwrap();
    let current = engine
        .acquire("person-a", &receipt.account_id, None)
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        engine.acquire("person-a", &receipt.account_id, Some(&current.revision)),
        engine.acquire("person-a", &receipt.account_id, Some(&current.revision))
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_eq!(left.access_token, "synthetic-b");
    assert_eq!(right.revision, left.revision);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(
        engine
            .acquire("person-b", &receipt.account_id, None)
            .await
            .is_err()
    );
    drop(engine);
    let engine = Engine::open_at(
        &store,
        &key,
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/v1/oauth/token"),
        },
    )
    .unwrap();
    let restarted = engine
        .acquire("person-a", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(restarted.revision, left.revision);
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let serialized = serde_json::to_string(&restarted).unwrap();
    assert!(!serialized.contains("refresh"));
    assert!(!serialized.contains("synthetic-rb"));
    task.abort();
}

#[tokio::test]
async fn lost_refresh_response_is_never_replayed_after_restart() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app = Router::new()
        .route(
            "/api/oauth/profile",
            get(|| async { Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})) }),
        )
        .route(
            "/v1/oauth/token",
            post(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::BAD_GATEWAY
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[9; 32]).unwrap();
    let open = || {
        Engine::open_at(
            &root.path().join("store"),
            &key,
            Endpoints {
                api: origin.clone(),
                token: format!("{origin}/v1/oauth/token"),
            },
        )
        .unwrap()
    };
    let engine = open();
    let receipt = engine
        .admit(
            "person",
            "work",
            "first",
            Grant {
                access_token: "fake-a".into(),
                refresh_token: "fake-ra".into(),
                expires_at: now() + 3600000,
                scopes: vec!["user:inference".into(), "user:profile".into()],
            },
            None,
        )
        .await
        .unwrap();
    let access = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert!(
        engine
            .acquire("person", &receipt.account_id, Some(&access.revision))
            .await
            .is_err()
    );
    drop(engine);
    let engine = open();
    assert!(
        engine
            .acquire("person", &receipt.account_id, None)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(!engine.accounts("person").await[0].available);
    task.abort();
}

#[tokio::test]
async fn admission_retry_verifies_the_retained_grant_without_replacing_it() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app = Router::new().route(
        "/api/oauth/profile",
        get(move |headers: axum::http::HeaderMap| {
            let calls = calls.clone();
            async move {
                use axum::response::IntoResponse;
                assert_eq!(headers["authorization"], "Bearer original-access");
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                } else {
                    Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}}))
                        .into_response()
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[11; 32]).unwrap();
    let open = || {
        Engine::open_at(
            &root.path().join("store"),
            &key,
            Endpoints {
                api: origin.clone(),
                token: format!("{origin}/token"),
            },
        )
        .unwrap()
    };
    let grant = |access: &str| Grant {
        access_token: access.into(),
        refresh_token: "refresh".into(),
        expires_at: now() + 3600000,
        scopes: vec!["user:inference".into(), "user:profile".into()],
    };
    let engine = open();
    assert!(
        engine
            .admit(
                "person",
                "work",
                "migration",
                grant("original-access"),
                None
            )
            .await
            .is_err()
    );
    drop(engine);
    let engine = open();
    let receipt = engine
        .admit(
            "person",
            "work",
            "migration",
            grant("retry-must-not-replace"),
            None,
        )
        .await
        .unwrap();
    let access = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "original-access");
    assert_eq!(count.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn successor_verification_recovers_after_restart_without_another_refresh() {
    let profiles = Arc::new(AtomicUsize::new(0));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let calls = profiles.clone();
    let exchanges = refreshes.clone();
    let app = Router::new()
        .route("/api/oauth/profile", get(move || {let calls=calls.clone(); async move {
            use axum::response::IntoResponse;
            if calls.fetch_add(1,Ordering::SeqCst)==1 {axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()}
            else {Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})).into_response()}
        }}))
        .route("/token", post(move || {let exchanges=exchanges.clone(); async move {
            exchanges.fetch_add(1,Ordering::SeqCst);
            Json(json!({"access_token":"successor","refresh_token":"successor-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
        }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[12; 32]).unwrap();
    let open = || {
        Engine::open_at(
            &root.path().join("store"),
            &key,
            Endpoints {
                api: origin.clone(),
                token: format!("{origin}/token"),
            },
        )
        .unwrap()
    };
    let engine = open();
    let receipt = engine
        .admit(
            "person",
            "work",
            "migration",
            Grant {
                access_token: "initial".into(),
                refresh_token: "initial-refresh".into(),
                expires_at: now() + 3600000,
                scopes: vec!["user:inference".into(), "user:profile".into()],
            },
            None,
        )
        .await
        .unwrap();
    let current = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert!(
        engine
            .acquire("person", &receipt.account_id, Some(&current.revision))
            .await
            .is_err()
    );
    drop(engine);
    let engine = open();
    let successor = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(successor.access_token, "successor");
    assert_eq!(successor.generation, 2);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn login_retries_retained_response_without_reusing_authorization_code() {
    use axum::response::IntoResponse;
    let exchanges = Arc::new(AtomicUsize::new(0));
    let profiles = Arc::new(AtomicUsize::new(0));
    let tokens = exchanges.clone();
    let ids = profiles.clone();
    let app=Router::new().route("/token",post(move || {let tokens=tokens.clone();async move {
        tokens.fetch_add(1,Ordering::SeqCst);
        Json(json!({"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
    }})).route("/api/oauth/profile",get(move || {let ids=ids.clone();async move {
        if ids.fetch_add(1,Ordering::SeqCst)==0 {axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()}
        else {Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})).into_response()}
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[13; 32]).unwrap();
    let open = || {
        Engine::open_at(
            &root.path().join("store"),
            &key,
            Endpoints {
                api: origin.clone(),
                token: format!("{origin}/token"),
            },
        )
        .unwrap()
    };
    let engine = open();
    let challenge = engine
        .start_login("person", "machine", "work", false)
        .await
        .unwrap();
    let url = reqwest::Url::parse(&challenge.authorize_url).unwrap();
    let state = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .unwrap()
        .1
        .into_owned();
    let code = format!("fake-code#{state}");
    assert!(
        engine
            .finish_login("person", "other-machine", &challenge.id, &code)
            .await
            .is_err()
    );
    assert!(
        engine
            .finish_login("person", "machine", &challenge.id, "fake-code#wrong")
            .await
            .is_err()
    );
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    assert!(
        engine
            .finish_login("person", "machine", &challenge.id, &code)
            .await
            .is_err()
    );
    drop(engine);
    let engine = open();
    let receipt = engine
        .finish_login("person", "machine", &challenge.id, &code)
        .await
        .unwrap();
    assert_eq!(
        engine
            .acquire("person", &receipt.account_id, None)
            .await
            .unwrap()
            .access_token,
        "new-access"
    );
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
    task.abort();
}

fn grant_until(access: &str, expires_at: i64) -> Grant {
    Grant {
        access_token: access.into(),
        refresh_token: format!("{access}-refresh"),
        expires_at,
        scopes: vec!["user:inference".into(), "user:profile".into()],
    }
}

/// A synthetic Anthropic API: a fixed identity and a counted refresh that returns `expires_in`.
async fn synthetic_provider(
    expires_in: i64,
) -> (
    tempfile::TempDir,
    Engine,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let count = Arc::new(AtomicUsize::new(0));
    let refreshes = count.clone();
    let app = Router::new()
        .route(
            "/api/oauth/profile",
            get(|| async { Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})) }),
        )
        .route(
            "/token",
            post(move || {
                let refreshes = refreshes.clone();
                async move {
                    let n = refreshes.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"access_token":format!("successor-{n}"),"refresh_token":format!("successor-refresh-{n}"),"expires_in":expires_in,"scope":"user:inference user:profile"}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[21; 32]).unwrap();
    let engine = Engine::open_at(
        &root.path().join("store"),
        &key,
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/token"),
        },
    )
    .unwrap();
    (root, engine, count, task)
}

#[tokio::test]
async fn the_server_refreshes_inside_five_minutes_of_expiry_and_not_before() {
    let (_root, engine, refreshes, task) = synthetic_provider(3600).await;
    let early = engine
        .admit(
            "person",
            "early",
            "m-early",
            grant_until("early", now() + 360_000),
            None,
        )
        .await
        .unwrap();
    let access = engine
        .acquire("person", &early.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "early");
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
    task.abort();

    let (_root, engine, refreshes, task) = synthetic_provider(3600).await;
    let due = engine
        .admit(
            "person",
            "due",
            "m-due",
            grant_until("due", now() + 240_000),
            None,
        )
        .await
        .unwrap();
    let access = engine
        .acquire("person", &due.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "successor-0");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn a_refresh_reads_expires_in_as_seconds() {
    let (_root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "m",
            grant_until("first", now() + 240_000),
            None,
        )
        .await
        .unwrap();
    let before = now();
    let access = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    // One hour: 3,600 seconds is 3,600,000 milliseconds.
    assert!(
        access.expires_at >= before + 3_590_000,
        "{}",
        access.expires_at - before
    );
    assert!(access.expires_at <= now() + 3_600_000);
    task.abort();
}

#[tokio::test]
async fn a_migration_refreshes_once_so_copies_of_the_old_grant_go_stale() {
    let (_root, engine, refreshes, task) = synthetic_provider(3600).await;
    let receipt = engine
        .migrate(
            "person",
            "machine",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .unwrap();
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    let access = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "successor-0");
    assert_eq!(access.generation, 2);

    let retry = engine
        .migrate(
            "person",
            "machine",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .unwrap();
    assert_eq!(retry.account_id, receipt.account_id);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn the_audit_log_records_migration_and_refresh_without_any_token() {
    let (root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let receipt = engine
        .migrate(
            "person",
            "mac-1",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .unwrap();
    let events =
        crate::server::audit::read(&root.path().join("store"), &root.path().join("key")).unwrap();
    let operations: Vec<_> = events
        .iter()
        .map(|e| {
            (
                e["operation"].as_str().unwrap(),
                e["result"].as_str().unwrap(),
            )
        })
        .collect();
    assert_eq!(operations, [("refresh", "ok"), ("migrate", "ok")]);
    assert_eq!(events[0]["machine"], "mac-1");
    assert_eq!(events[0]["account"], receipt.account_id);
    assert_eq!(events[0]["rotated"], true);
    let mut sealed = Vec::new();
    for entry in std::fs::read_dir(root.path().join("store").join("audit")).unwrap() {
        sealed.extend(std::fs::read(entry.unwrap().path()).unwrap());
    }
    let plain = serde_json::to_string(&events).unwrap();
    for secret in ["migrated", "successor-0", "successor-refresh-0"] {
        assert!(!plain.contains(secret), "audit event contains {secret}");
        assert!(!String::from_utf8_lossy(&sealed).contains(secret));
    }
    task.abort();
}

#[tokio::test]
async fn a_deleted_account_keeps_no_grant_and_answers_gone_after_restart() {
    let (root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    assert!(
        engine
            .remove("other-person", "mac-1", &receipt.account_id)
            .await
            .is_err()
    );
    engine
        .remove("person", "mac-1", &receipt.account_id)
        .await
        .unwrap();
    let error = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    assert!(engine.accounts("person").await.is_empty());
    let store = root.path().join("store");
    assert!(!store.join("accounts").join(&receipt.account_id).exists());
    drop(engine);
    let engine = Engine::open_at(&store, &root.path().join("key"), Endpoints::default()).unwrap();
    let error = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    let events = crate::server::audit::read(&store, &root.path().join("key")).unwrap();
    let last = events.last().unwrap();
    assert_eq!(
        (last["operation"].as_str(), last["result"].as_str()),
        (Some("revoke"), Some("ok"))
    );
    assert_eq!(last["machine"], "mac-1");
    task.abort();
}

#[tokio::test]
async fn a_migration_stopped_before_its_refresh_shows_no_receipt_until_it_rotates() {
    let (_root, engine, refreshes, task) = synthetic_provider(3600).await;
    // A stop after admission, before the forced refresh.
    let admitted = engine
        .admit_migration(
            "person",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .unwrap();
    assert!(engine.receipt("person", "m-1").await.unwrap().is_none());
    // Even a token request rotates first, so it never hands out the migrated token.
    let access = engine
        .acquire("person", &admitted.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "successor-0");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    let receipt = engine
        .migrate(
            "person",
            "machine",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .unwrap();
    assert_eq!(receipt.account_id, admitted.account_id);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert!(engine.receipt("person", "m-1").await.unwrap().is_some());
    task.abort();
}

#[tokio::test]
async fn a_near_expiry_migration_refreshes_exactly_once() {
    let (_root, engine, refreshes, task) = synthetic_provider(3600).await;
    engine
        .migrate(
            "person",
            "machine",
            "work",
            "m-1",
            grant_until("migrated", now() + 240_000),
        )
        .await
        .unwrap();
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn a_renewal_started_before_a_delete_cannot_recreate_the_account() {
    let (_root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let identity = receipt.identity.clone();
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    assert!(
        engine
            .admit(
                "person",
                "work",
                "renewal",
                grant_until("renewed", now() + 3_600_000),
                Some(&identity)
            )
            .await
            .is_err()
    );
    assert!(engine.accounts("person").await.is_empty());
    let error = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    task.abort();
}

#[tokio::test]
async fn a_usage_read_reports_a_failed_refresh_once() {
    let app = Router::new()
        .route(
            "/api/oauth/profile",
            get(|| async { Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})) }),
        )
        .route(
            "/token",
            post(|| async { axum::http::StatusCode::BAD_REQUEST }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[22; 32]).unwrap();
    let engine = Engine::open_at(
        &root.path().join("store"),
        &key,
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/token"),
        },
    )
    .unwrap();
    let receipt = engine
        .admit(
            "person",
            "work",
            "m",
            grant_until("due", now() + 120_000),
            None,
        )
        .await
        .unwrap();
    let usage = engine
        .usage("person", &receipt.account_id, false)
        .await
        .unwrap();
    assert_eq!(usage.error.as_deref(), Some("login_required"));
    assert_eq!(usage.failure, Some("usage_login_required"));
    let cached = engine
        .usage("person", &receipt.account_id, true)
        .await
        .unwrap();
    assert_eq!(cached.failure, None);
    task.abort();
}

#[tokio::test]
async fn a_delete_whose_tombstone_cannot_be_saved_leaves_the_account_usable_and_retryable() {
    let (root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let blocker = root.path().join("store").join("deleted.json");
    std::fs::create_dir(&blocker).unwrap();
    assert!(
        engine
            .remove("person", "mac", &receipt.account_id)
            .await
            .is_err()
    );
    assert!(
        engine
            .acquire("person", &receipt.account_id, None)
            .await
            .is_ok()
    );
    std::fs::remove_dir(&blocker).unwrap();
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    let error = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    task.abort();
}

#[tokio::test]
async fn a_delete_drops_the_cached_usage_of_that_account() {
    let (_root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let first = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    // The synthetic provider has no usage route; any fresh read stores a result.
    engine
        .usage("person", &first.account_id, false)
        .await
        .unwrap();
    engine
        .remove("person", "mac", &first.account_id)
        .await
        .unwrap();
    let second = engine
        .admit(
            "person",
            "work",
            "m-2",
            grant_until("second", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    assert_eq!(second.account_id, first.account_id);
    let cached = engine
        .usage("person", &second.account_id, true)
        .await
        .unwrap();
    assert!(cached.error.is_none() && cached.observed_at.is_none() && cached.next_retry_at == 0);
    task.abort();
}

#[tokio::test]
async fn a_migration_completes_only_after_its_successor_is_verified() {
    let profiles = Arc::new(AtomicUsize::new(0));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let (calls, exchanges) = (profiles.clone(), refreshes.clone());
    let app = Router::new()
        .route("/api/oauth/profile", get(move || {
            let calls = calls.clone();
            async move {
                use axum::response::IntoResponse;
                // Admission check passes; the first successor check fails.
                if calls.fetch_add(1, Ordering::SeqCst) == 1 {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                } else {
                    Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})).into_response()
                }
            }
        }))
        .route("/token", post(move || {
            let exchanges = exchanges.clone();
            async move {
                exchanges.fetch_add(1, Ordering::SeqCst);
                Json(json!({"access_token":"successor","refresh_token":"successor-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[23; 32]).unwrap();
    let engine = Engine::open_at(
        &root.path().join("store"),
        &key,
        Endpoints {
            api: origin.clone(),
            token: format!("{origin}/token"),
        },
    )
    .unwrap();
    let grant = || grant_until("migrated", now() + 3_600_000);
    assert!(
        engine
            .migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    assert!(engine.receipt("person", "m-1").await.unwrap().is_none());
    engine
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .unwrap();
    assert!(engine.receipt("person", "m-1").await.unwrap().is_some());
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    task.abort();
}

#[tokio::test]
async fn a_delete_and_a_usage_read_waiting_on_the_same_account_do_not_deadlock() {
    let release = Arc::new(tokio::sync::Notify::new());
    let gate = release.clone();
    let app = Router::new()
        .route(
            "/api/oauth/profile",
            get(|| async { Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}})) }),
        )
        .route(
            "/token",
            post(move || {
                let gate = gate.clone();
                async move {
                    gate.notified().await;
                    Json(json!({"access_token":"successor","refresh_token":"successor-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let root = tempfile::tempdir().unwrap();
    let key = root.path().join("key");
    vault::create_secret(&key, &[24; 32]).unwrap();
    let engine = Arc::new(
        Engine::open_at(
            &root.path().join("store"),
            &key,
            Endpoints {
                api: origin.clone(),
                token: format!("{origin}/token"),
            },
        )
        .unwrap(),
    );
    let receipt = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let id = receipt.account_id.clone();
    let current = engine.acquire("person", &id, None).await.unwrap();
    // 1. A forced refresh holds the account lock.
    let refresh = {
        let (engine, id) = (engine.clone(), id.clone());
        tokio::spawn(async move { engine.acquire("person", &id, Some(&current.revision)).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    // 2. A delete queues for the account lock first, 3. then a usage read holding the cache.
    let remove = {
        let (engine, id) = (engine.clone(), id.clone());
        tokio::spawn(async move { engine.remove("person", "mac", &id).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let usage = {
        let (engine, id) = (engine.clone(), id.clone());
        tokio::spawn(async move { engine.usage("person", &id, false).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    release.notify_one();
    let all = async {
        let _ = refresh.await.unwrap();
        remove.await.unwrap().unwrap();
        let _ = usage.await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), all)
        .await
        .expect("delete and usage read deadlocked");
    task.abort();
}

#[tokio::test]
async fn startup_drops_cached_usage_of_an_account_deleted_before_a_stop() {
    let (root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let store = root.path().join("store");
    let first = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    engine
        .usage("person", &first.account_id, false)
        .await
        .unwrap();
    let cached = std::fs::read(store.join("usage.json")).unwrap();
    engine
        .remove("person", "mac", &first.account_id)
        .await
        .unwrap();
    drop(engine);
    // A stop after the tombstone, before the cache cleanup.
    crate::server::fs::atomic_write(&store.join("usage.json"), &cached).unwrap();
    let engine = Engine::open_at(&store, &root.path().join("key"), Endpoints::default()).unwrap();
    let cached = engine.usage("person", &first.account_id, true).await;
    assert!(cached.is_err(), "a deleted account has no usage");
    let usage: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.join("usage.json")).unwrap()).unwrap();
    assert!(
        usage["accounts"].get(&first.account_id).is_none(),
        "{usage}"
    );
    task.abort();
}

#[tokio::test]
async fn a_new_account_survives_restart_after_a_failed_tombstone_cleanup() {
    let (root, engine, _refreshes, task) = synthetic_provider(3600).await;
    let store = root.path().join("store");
    let first = engine
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    engine.remove("person", "mac", &first.account_id).await.unwrap();
    let tombstones = store.join("deleted.json");
    let saved = store.join("deleted.saved");
    std::fs::rename(&tombstones, &saved).unwrap();
    std::fs::create_dir(&tombstones).unwrap();
    assert!(
        engine
            .admit("person", "work", "m-2", grant_until("second", now() + 3_600_000), None)
            .await
            .is_err()
    );
    std::fs::remove_dir(&tombstones).unwrap();
    std::fs::rename(&saved, &tombstones).unwrap();
    let second = engine
        .admit("person", "work", "m-2", grant_until("second", now() + 3_600_000), None)
        .await
        .unwrap();
    drop(engine);
    let engine = Engine::open_at(&store, &root.path().join("key"), Endpoints::default()).unwrap();
    assert_eq!(engine.accounts("person").await.len(), 1);
    assert!(engine.receipt("person", "m-2").await.unwrap().is_some());
    assert_eq!(second.account_id, first.account_id);
    task.abort();
}
