//! Engine behavior on both stores. With CLAUDECTL_TEST_DATABASE_URL set, every fixture uses
//! a fresh PostgreSQL database; otherwise the file store. Tests marked "PostgreSQL only"
//! need two replicas and skip without a database.
use super::*;
use crate::server::{store::PostgresStore, testing};
use axum::{
    Json, Router,
    response::IntoResponse,
    routing::{get, post},
};
use std::sync::atomic::{AtomicUsize, Ordering};

const KEY: [u8; 32] = [7; 32];

enum Backend {
    File(PathBuf),
    Postgres(String),
}
struct Fixture {
    _root: tempfile::TempDir,
    key: PathBuf,
    backend: Backend,
    origin: String,
    _provider: tokio::task::JoinHandle<()>,
}
impl Fixture {
    async fn new(app: Router) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let provider = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let root = tempfile::tempdir().unwrap();
        let key = root.path().join("key");
        vault::create_secret(&key, &KEY).unwrap();
        let backend = match testing::fresh_database().await.unwrap() {
            Some(url) => Backend::Postgres(url),
            None => Backend::File(root.path().join("store")),
        };
        Self {
            _root: root,
            key,
            backend,
            origin,
            _provider: provider,
        }
    }
    fn endpoints(&self) -> Endpoints {
        Endpoints {
            api: self.origin.clone(),
            token: format!("{}/token", self.origin),
        }
    }
    /// A new engine on this fixture's state, as after a restart or on another replica.
    async fn engine(&self) -> Engine {
        match &self.backend {
            Backend::File(path) => Engine::open_at(path, &self.key, self.endpoints()).unwrap(),
            Backend::Postgres(url) => {
                let store = Store::Postgres(PostgresStore::connect(url).await.unwrap());
                Engine::with_store(Arc::new(store), &self.key, self.endpoints()).unwrap()
            }
        }
    }
    fn postgres(&self) -> Option<&str> {
        match &self.backend {
            Backend::Postgres(url) => Some(url),
            Backend::File(_) => None,
        }
    }
    /// Run raw SQL against this fixture's database.
    async fn sql(&self, statement: &str) {
        let url = self.postgres().expect("PostgreSQL fixture");
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(connection);
        client.batch_execute(statement).await.unwrap();
    }
}

fn grant_until(access: &str, expires_at: i64) -> Grant {
    Grant {
        access_token: access.into(),
        refresh_token: format!("{access}-refresh"),
        expires_at,
        scopes: vec!["user:inference".into(), "user:profile".into()],
    }
}
fn profile() -> Json<Value> {
    Json(json!({"account":{"uuid":"a"},"organization":{"uuid":"o"}}))
}
fn token_body(n: usize, expires_in: i64) -> Json<Value> {
    Json(
        json!({"access_token":format!("successor-{n}"),"refresh_token":format!("successor-refresh-{n}"),"expires_in":expires_in,"scope":"user:inference user:profile"}),
    )
}
/// A fixed identity, and a counted refresh that waits for `gate` when given.
fn provider(
    refreshes: Arc<AtomicUsize>,
    expires_in: i64,
    gate: Option<Arc<tokio::sync::Notify>>,
) -> Router {
    Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(move || {
                let (refreshes, gate) = (refreshes.clone(), gate.clone());
                async move {
                    if let Some(gate) = gate {
                        gate.notified().await;
                    }
                    token_body(refreshes.fetch_add(1, Ordering::SeqCst), expires_in)
                }
            }),
        )
}
async fn synthetic(expires_in: i64) -> (Fixture, Engine, Arc<AtomicUsize>) {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let f = Fixture::new(provider(refreshes.clone(), expires_in, None)).await;
    let engine = f.engine().await;
    (f, engine, refreshes)
}
fn pasted(login: &Login) -> String {
    let url = reqwest::Url::parse(&login.authorize_url).unwrap();
    let state = url
        .query_pairs()
        .find(|(n, _)| n == "state")
        .unwrap()
        .1
        .into_owned();
    format!("fake-code#{state}")
}
/// A profile route that fails on call number `fail_on` (0-based) and passes otherwise.
fn flaky_profile(fail_on: usize) -> axum::routing::MethodRouter {
    let calls = Arc::new(AtomicUsize::new(0));
    get(move || {
        let calls = calls.clone();
        async move {
            if calls.fetch_add(1, Ordering::SeqCst) == fail_on {
                axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
            } else {
                profile().into_response()
            }
        }
    })
}
fn counted_token(count: Arc<AtomicUsize>) -> axum::routing::MethodRouter {
    post(move || {
        let count = count.clone();
        async move { token_body(count.fetch_add(1, Ordering::SeqCst), 3600) }
    })
}

#[tokio::test]
async fn dashboard_usage_is_one_owner_scoped_read_without_the_poll_lock() {
    let app = Router::new()
        .route(
            "/api/oauth/profile",
            // One Claude identity per access token, so two users can hold accounts.
            get(|headers: axum::http::HeaderMap| async move {
                let token = headers["authorization"].to_str().unwrap().to_owned();
                Json(json!({"account":{"uuid":token},"organization":{"uuid":"o"}}))
            }),
        )
        .route(
            "/api/oauth/usage",
            get(|| async {
                Json(json!({"five_hour":{"utilization":42,"resets_at":"2099-01-01T00:00:00Z"}}))
            }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let mine = engine
        .admit(
            "person",
            "work",
            "first",
            grant_until("a", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let theirs = engine
        .admit(
            "other",
            "work",
            "second",
            grant_until("b", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    assert!(engine.cached_usages("person").await.unwrap().is_empty());
    engine
        .usage("person", &mine.account_id, false)
        .await
        .unwrap();
    engine
        .usage("other", &theirs.account_id, false)
        .await
        .unwrap();
    // A poll in progress holds the poll lock; the dashboard read must not wait for it.
    let _poll = engine.usage_poll.lock().await;
    let read = tokio::time::timeout(Duration::from_secs(2), engine.cached_usages("person"))
        .await
        .expect("dashboard read waited for the poll lock")
        .unwrap();
    // Only the caller's own account, never another user's cached usage.
    assert_eq!(read.len(), 1);
    let usage = read[&mine.account_id].as_ref().unwrap();
    assert_eq!(usage.data.as_ref().unwrap()["five_hour"]["utilization"], 42);
    assert!(usage.observed_at.is_some());
    // A deleted account's usage is gone from the read.
    engine
        .remove("person", "machine", &mine.account_id)
        .await
        .unwrap();
    assert!(engine.cached_usages("person").await.unwrap().is_empty());
}

#[tokio::test]
async fn cached_usage_never_contacts_the_provider_and_reads_share_polling() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/api/oauth/usage",
            get(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"five_hour":{"utilization":42,"resets_at":"2099-01-01T00:00:00Z"},"seven_day":null}))
                }
            }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "first",
            grant_until("a", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let cached = engine
        .usage("person", &receipt.account_id, true)
        .await
        .unwrap();
    assert!(cached.data.is_none());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let (a, b) = tokio::join!(
        engine.usage("person", &receipt.account_id, false),
        engine.usage("person", &receipt.account_id, false)
    );
    assert_eq!(a.unwrap().data.unwrap()["five_hour"]["utilization"], 42);
    assert!(b.unwrap().data.unwrap()["seven_day"].is_null());
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_rejections_refresh_once_and_restart_preserves_the_successor() {
    let (f, engine, refreshes) = synthetic(3600).await;
    let receipt = engine
        .admit(
            "person-a",
            "work",
            "migration-1",
            grant_until("a", now() + 3_600_000),
            None,
        )
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
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left.access_token, "successor-0");
    assert_eq!(right.revision, left.revision);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert!(
        engine
            .acquire("person-b", &receipt.account_id, None)
            .await
            .is_err()
    );
    drop(engine);
    let engine = f.engine().await;
    let restarted = engine
        .acquire("person-a", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(restarted.revision, left.revision);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    let serialized = serde_json::to_string(&restarted).unwrap();
    assert!(!serialized.contains("refresh"));
}

#[tokio::test]
async fn a_lost_refresh_response_is_never_replayed_after_restart() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::BAD_GATEWAY
                }
            }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "first",
            grant_until("a", now() + 3_600_000),
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
    let engine = f.engine().await;
    assert!(
        engine
            .acquire("person", &receipt.account_id, None)
            .await
            .is_err()
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert!(!engine.accounts("person").await.unwrap()[0].available);
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
                assert_eq!(headers["authorization"], "Bearer original-access");
                if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response()
                } else {
                    profile().into_response()
                }
            }
        }),
    );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let first = grant_until("original-access", now() + 3_600_000);
    assert!(
        engine
            .admit("person", "work", "migration", first, None)
            .await
            .is_err()
    );
    drop(engine);
    let engine = f.engine().await;
    let retry = grant_until("retry-must-not-replace", now() + 3_600_000);
    let receipt = engine
        .admit("person", "work", "migration", retry, None)
        .await
        .unwrap();
    let access = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "original-access");
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn successor_verification_recovers_after_restart_without_another_refresh() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/api/oauth/profile", flaky_profile(1))
        .route("/token", counted_token(refreshes.clone()));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "migration",
            grant_until("initial", now() + 3_600_000),
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
    let engine = f.engine().await;
    let successor = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(successor.access_token, "successor-0");
    assert_eq!(successor.generation, 2);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn login_retries_a_kept_response_without_reusing_the_authorization_code() {
    let exchanges = Arc::new(AtomicUsize::new(0));
    let tokens = exchanges.clone();
    let app = Router::new()
        .route(
            "/token",
            post(move || {
                let tokens = tokens.clone();
                async move {
                    tokens.fetch_add(1, Ordering::SeqCst);
                    Json(json!({"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
                }
            }),
        )
        .route("/api/oauth/profile", flaky_profile(0));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let challenge = engine
        .start_login("person", "machine", "work", false)
        .await
        .unwrap();
    let code = pasted(&challenge);
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
    let engine = f.engine().await;
    let receipt = engine
        .finish_login("person", "machine", &challenge.id, &code)
        .await
        .unwrap();
    let access = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "new-access");
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_server_refreshes_inside_five_minutes_of_expiry_and_not_before() {
    let (_f, engine, refreshes) = synthetic(3600).await;
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

    let (_f, engine, refreshes) = synthetic(3600).await;
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
}

#[tokio::test]
async fn an_observing_request_never_refreshes_a_usable_token() {
    // Inside the refresh margin a normal request refreshes; an observing one returns the
    // held token, so it can never revoke the token a running session uses (SAW-12610).
    let (_f, engine, refreshes) = synthetic(3600).await;
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
    let seen = engine
        .observe_for("person", "server", &due.account_id)
        .await
        .unwrap();
    assert_eq!(seen.access_token, "due");
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
    // In its last minute the token is too short for a new launch, but running sessions still
    // use it until it expires: observing must not refresh it.
    let (_f, engine, refreshes) = synthetic(3600).await;
    let ending = engine
        .admit(
            "person",
            "end",
            "m-end",
            grant_until("end", now() + 61_000),
            None,
        )
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1_500)).await;
    let seen = engine
        .observe_for("person", "server", &ending.account_id)
        .await
        .unwrap();
    assert_eq!(seen.access_token, "end");
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_observing_request_refreshes_an_expired_token() {
    // An expired token is dead for every holder, so observing may refresh it.
    let (_f, engine, refreshes) = synthetic(1).await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "m",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let held = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    // Forced: the successor lives one second.
    let short = engine
        .acquire("person", &receipt.account_id, Some(&held.revision))
        .await
        .unwrap();
    assert_eq!(short.access_token, "successor-0");
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    let seen = engine
        .observe_for("person", "server", &receipt.account_id)
        .await
        .unwrap();
    assert_eq!(seen.access_token, "successor-1");
    assert_eq!(refreshes.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_refresh_reads_expires_in_as_seconds() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
}

#[tokio::test]
async fn a_migration_refreshes_once_so_copies_of_the_old_grant_go_stale() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    let receipt = engine
        .migrate("person", "machine", "work", "m-1", grant())
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
        .migrate("person", "machine", "work", "m-1", grant())
        .await
        .unwrap();
    assert_eq!(retry.account_id, receipt.account_id);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_near_expiry_migration_refreshes_exactly_once() {
    let (_f, engine, refreshes) = synthetic(3600).await;
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
}

#[tokio::test]
async fn a_migration_stopped_before_its_refresh_shows_no_receipt_until_it_rotates() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    // A stop after admission, before the forced refresh.
    let admitted = engine
        .admit_migration("person", "work", "m-1", grant())
        .await
        .unwrap();
    assert!(engine.receipt("person", "m-1").await.unwrap().is_none());
    // Even a token request rotates first, so it never hands out the migrated token.
    let access = engine
        .acquire("person", &admitted.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "successor-0");
    let receipt = engine
        .migrate("person", "machine", "work", "m-1", grant())
        .await
        .unwrap();
    assert_eq!(receipt.account_id, admitted.account_id);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert!(engine.receipt("person", "m-1").await.unwrap().is_some());
}

#[tokio::test]
async fn a_migration_completes_only_after_its_successor_is_verified() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    // Admission check passes; the first successor check fails.
    let app = Router::new()
        .route("/api/oauth/profile", flaky_profile(1))
        .route("/token", counted_token(refreshes.clone()));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
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
}

#[tokio::test]
async fn the_audit_log_records_migration_and_refresh_without_any_token() {
    let (f, engine, _refreshes) = synthetic(3600).await;
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
    let events = crate::server::audit::read(engine.store(), &f.key)
        .await
        .unwrap();
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
    let sealed: Vec<u8> = engine.store().audit().await.unwrap().concat();
    let plain = serde_json::to_string(&events).unwrap();
    for secret in ["migrated", "successor-0", "successor-refresh-0"] {
        assert!(!plain.contains(secret), "audit event contains {secret}");
        assert!(!String::from_utf8_lossy(&sealed).contains(secret));
    }
}

#[tokio::test]
async fn a_deleted_account_keeps_no_grant_and_answers_gone_after_restart() {
    let (f, engine, _refreshes) = synthetic(3600).await;
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
    assert!(engine.accounts("person").await.unwrap().is_empty());
    assert!(
        engine
            .store()
            .account("person", &receipt.account_id)
            .await
            .unwrap()
            .is_none()
    );
    drop(engine);
    let engine = f.engine().await;
    let error = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    let events = crate::server::audit::read(engine.store(), &f.key)
        .await
        .unwrap();
    let last = events.last().unwrap();
    assert_eq!(
        (last["operation"].as_str(), last["result"].as_str()),
        (Some("revoke"), Some("ok"))
    );
    assert_eq!(last["machine"], "mac-1");
}

#[tokio::test]
async fn a_renewal_started_before_a_delete_cannot_recreate_the_account() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
    let renewal = grant_until("renewed", now() + 3_600_000);
    assert!(
        engine
            .admit("person", "work", "renewal", renewal, Some(&identity))
            .await
            .is_err()
    );
    assert!(engine.accounts("person").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_renewal_from_before_a_delete_cannot_overwrite_a_recreated_account() {
    let app = Router::new()
        .route("/token", counted_token(Arc::default()))
        // Admission passes; the renewal's first verification fails, so its response is kept.
        .route("/api/oauth/profile", flaky_profile(1));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
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
    let renewal = engine
        .start_login("person", "machine", "work", true)
        .await
        .unwrap();
    let code = pasted(&renewal);
    assert!(
        engine
            .finish_login("person", "machine", &renewal.id, &code)
            .await
            .is_err()
    );
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
    // The renewal started before the delete; the delete cancelled its flow.
    assert!(
        engine
            .finish_login("person", "machine", &renewal.id, &code)
            .await
            .is_err()
    );
    let access = engine
        .acquire("person", &second.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "second");
}

#[tokio::test]
async fn a_migration_retried_after_a_delete_is_refused() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    let receipt = engine
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .unwrap();
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    // A lost reply makes the client retry the same migration ID; it must not recreate.
    let retry = engine
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .err()
        .unwrap();
    assert!(retry.downcast_ref::<Gone>().is_some());
    assert!(engine.accounts("person").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_provider_that_keeps_the_refresh_token_leaves_the_migration_incomplete() {
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(|| async {
                Json(json!({"access_token":"successor","refresh_token":"migrated-refresh","expires_in":3600,"scope":"user:inference user:profile"}))
            }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    let error = engine
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<Unrotated>().is_some());
    assert!(engine.receipt("person", "m-1").await.is_err());
    // The account works; only the migration proof is missing.
    let id = account_id("person", "work");
    let access = engine.acquire("person", &id, None).await.unwrap();
    assert_eq!(access.access_token, "successor");
}

#[tokio::test]
async fn store_reads_stay_inside_the_user_scope() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
    let store = engine.store();
    assert!(
        store
            .account("intruder", &receipt.account_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(store.accounts("intruder").await.unwrap().is_empty());
    assert!(store.admission("intruder", "m-1").await.unwrap().is_none());
    assert!(
        engine
            .acquire("intruder", &receipt.account_id, None)
            .await
            .is_err()
    );
    assert!(
        engine
            .remove("intruder", "mac", &receipt.account_id)
            .await
            .is_err()
    );
    assert!(
        store
            .account("person", &receipt.account_id)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn an_enrollment_swap_never_overwrites_a_newer_payload() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let store = engine.store();
    let row = store::EnrollmentRow {
        lookup: None,
        sealed: b"pending".to_vec(),
        expires_at: now() + 60_000,
        consumed: false,
    };
    store.put_enrollment("device", "d", &row).await.unwrap();
    // An approval lands first; a poll that read the old payload must not undo it.
    assert!(
        store
            .swap_enrollment("device", "d", b"pending", b"granted")
            .await
            .unwrap()
    );
    assert!(
        !store
            .swap_enrollment("device", "d", b"pending", b"polled")
            .await
            .unwrap()
    );
    let stored = store
        .enrollment("device", "d", now())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.sealed, b"granted");
}

#[tokio::test]
async fn a_follower_never_returns_the_revision_the_caller_rejected() {
    let Some((f, a, _b)) = replicas(provider(Arc::default(), 3600, None)).await else {
        return;
    };
    let receipt = a
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let current = a
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    // Another holder took the lease and stalled before writing anything.
    f.sql(&format!(
        "INSERT INTO refresh_leases VALUES ('{}', 'stalled', 1, now() + interval '1 hour')",
        receipt.account_id
    ))
    .await;
    let error = a
        .acquire("person", &receipt.account_id, Some(&current.revision))
        .await
        .err()
        .unwrap();
    assert!(error.downcast_ref::<RefreshInProgress>().is_some());
}

#[tokio::test]
async fn two_replicas_reading_usage_poll_the_provider_once() {
    let count = Arc::new(AtomicUsize::new(0));
    let calls = count.clone();
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/api/oauth/usage",
            get(move || {
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Json(json!({"five_hour":{"utilization":1}}))
                }
            }),
        );
    let Some((_f, a, b)) = replicas(app).await else {
        return;
    };
    let receipt = a
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let (left, right) = tokio::join!(
        a.usage("person", &receipt.account_id, false),
        b.usage("person", &receipt.account_id, false)
    );
    left.unwrap();
    right.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_usage_read_never_refreshes_and_reports_login_required_once() {
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(|| async { axum::http::StatusCode::BAD_REQUEST }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let receipt = engine
        .admit(
            "person",
            "work",
            "m",
            grant_until("due", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let current = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    // A rejected refresh leaves the account waiting for login renewal.
    assert!(
        engine
            .acquire("person", &receipt.account_id, Some(&current.revision))
            .await
            .is_err()
    );
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
}

#[tokio::test]
async fn a_delete_drops_the_cached_usage_of_that_account() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
    // The synthetic provider has no usage route; a fresh read stores an error result.
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
}

#[tokio::test]
async fn a_delete_purges_pending_admission_grants_for_the_alias() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
    let wrong = Identity {
        account_uuid: "other".into(),
        organization_uuid: "o".into(),
    };
    let renewal = grant_until("renewed", now() + 3_600_000);
    assert!(
        engine
            .admit("person", "work", "renewal", renewal, Some(&wrong))
            .await
            .is_err()
    );
    let pending = engine
        .store()
        .pending("person", "renewal")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.state, store::PendingState::Live);
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    let pending = engine
        .store()
        .pending("person", "renewal")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.state, store::PendingState::Cancelled);
    assert!(
        pending.sealed.is_empty(),
        "a cancelled admission kept its grant"
    );
}

#[tokio::test]
async fn a_kept_login_response_cannot_restore_a_deleted_account() {
    let app = Router::new()
        .route("/token", counted_token(Arc::default()))
        // Admission passes; the renewal's first verification fails.
        .route("/api/oauth/profile", flaky_profile(1));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let existing = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let renewal = engine
        .start_login("person", "machine", "work", true)
        .await
        .unwrap();
    let code = pasted(&renewal);
    assert!(
        engine
            .finish_login("person", "machine", &renewal.id, &code)
            .await
            .is_err()
    );
    let kept = engine
        .store()
        .flow("person", &renewal.id)
        .await
        .unwrap()
        .unwrap();
    assert!(kept.retained.is_some());
    engine
        .remove("person", "mac", &existing.account_id)
        .await
        .unwrap();
    let cancelled = engine
        .store()
        .flow("person", &renewal.id)
        .await
        .unwrap()
        .unwrap();
    assert!(cancelled.cancelled && cancelled.retained.is_none());
    assert!(
        engine
            .finish_login("person", "machine", &renewal.id, &code)
            .await
            .is_err()
    );
    assert!(engine.accounts("person").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_login_exchange_in_flight_during_a_delete_cannot_recreate_the_account() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let exchanges = Arc::new(AtomicUsize::new(0));
    let (g, e) = (gate.clone(), exchanges.clone());
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(move || {
                let (gate, exchanges) = (g.clone(), e.clone());
                async move {
                    if exchanges.fetch_add(1, Ordering::SeqCst) == 1 {
                        gate.notified().await;
                    }
                    token_body(9, 3600)
                }
            }),
        );
    let f = Fixture::new(app).await;
    let engine = Arc::new(f.engine().await);
    let first = engine
        .start_login("person", "machine", "work", false)
        .await
        .unwrap();
    let second = engine
        .start_login("person", "machine", "work", false)
        .await
        .unwrap();
    let receipt = engine
        .finish_login("person", "machine", &first.id, &pasted(&first))
        .await
        .unwrap();
    let late = {
        let engine = engine.clone();
        let code = pasted(&second);
        tokio::spawn(async move {
            engine
                .finish_login("person", "machine", &second.id, &code)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    gate.notify_one();
    assert!(late.await.unwrap().is_err());
    assert!(engine.accounts("person").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_delete_during_a_refresh_leaves_no_account_and_issues_no_token() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let f = Fixture::new(provider(refreshes.clone(), 3600, Some(gate.clone()))).await;
    let engine = Arc::new(f.engine().await);
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
    let current = engine
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    let refresh = {
        let (engine, id, previous) = (engine.clone(), receipt.account_id.clone(), current.revision);
        tokio::spawn(async move { engine.acquire("person", &id, Some(&previous)).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    gate.notify_one();
    assert!(refresh.await.unwrap().is_err());
    assert!(
        engine
            .store()
            .account("person", &receipt.account_id)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_delete_and_a_usage_read_on_the_same_account_do_not_deadlock() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let f = Fixture::new(provider(Arc::default(), 3600, Some(gate.clone()))).await;
    let engine = Arc::new(f.engine().await);
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
    let refresh = {
        let (engine, id) = (engine.clone(), id.clone());
        tokio::spawn(async move { engine.acquire("person", &id, Some(&current.revision)).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let remove = {
        let (engine, id) = (engine.clone(), id.clone());
        tokio::spawn(async move { engine.remove("person", "mac", &id).await })
    };
    let usage = {
        let (engine, id) = (engine.clone(), id.clone());
        tokio::spawn(async move { engine.usage("person", &id, false).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    gate.notify_one();
    let all = async {
        let _ = refresh.await.unwrap();
        remove.await.unwrap().unwrap();
        let _ = usage.await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), all)
        .await
        .expect("delete and usage read deadlocked");
}

#[tokio::test]
async fn a_file_store_write_failure_changes_nothing() {
    let (f, engine, _refreshes) = synthetic(3600).await;
    let Backend::File(state) = &f.backend else {
        return;
    };
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
    // A directory where the state file goes makes every write fail.
    let (file, saved) = (state.join("state.enc"), state.join("state.saved"));
    std::fs::rename(&file, &saved).unwrap();
    std::fs::create_dir(&file).unwrap();
    let result = engine.remove("person", "mac", &receipt.account_id).await;
    std::fs::remove_dir(&file).unwrap();
    std::fs::rename(&saved, &file).unwrap();
    assert!(result.is_err());
    assert!(
        engine
            .acquire("person", &receipt.account_id, None)
            .await
            .is_ok()
    );
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn enrollment_state_is_consumed_once() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let store = engine.store();
    let row = store::EnrollmentRow {
        lookup: Some("CODE".into()),
        sealed: b"x".to_vec(),
        expires_at: now() + 60_000,
        consumed: false,
    };
    store.put_enrollment("sso", "state", &row).await.unwrap();
    let (first, second) = tokio::join!(
        store.consume_enrollment("sso", "state", now()),
        store.consume_enrollment("sso", "state", now())
    );
    let consumed = [first.unwrap().is_some(), second.unwrap().is_some()];
    assert_eq!(consumed.iter().filter(|c| **c).count(), 1);
}

// PostgreSQL only: several replicas on one database.

async fn replicas(app: Router) -> Option<(Fixture, Engine, Engine)> {
    let f = Fixture::new(app).await;
    f.postgres()?;
    let (a, b) = (f.engine().await, f.engine().await);
    Some((f, a, b))
}

#[tokio::test]
async fn two_replicas_refresh_once_and_the_follower_gets_the_successor() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let Some((_f, a, b)) = replicas(provider(refreshes.clone(), 3600, Some(gate.clone()))).await
    else {
        return;
    };
    let receipt = a
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let current = a
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    let (a, b) = (Arc::new(a), Arc::new(b));
    let left = {
        let (a, id, rev) = (
            a.clone(),
            receipt.account_id.clone(),
            current.revision.clone(),
        );
        tokio::spawn(async move { a.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    let right = {
        let (b, id, rev) = (
            b.clone(),
            receipt.account_id.clone(),
            current.revision.clone(),
        );
        tokio::spawn(async move { b.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    gate.notify_one();
    let (left, right) = (left.await.unwrap().unwrap(), right.await.unwrap().unwrap());
    assert_eq!(left.access_token, "successor-0");
    assert_eq!(right.revision, left.revision);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_replica_that_lost_its_lease_to_another_keeps_nothing_and_issues_no_token() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let Some((f, a, _b)) = replicas(provider(refreshes.clone(), 3600, Some(gate.clone()))).await
    else {
        return;
    };
    let receipt = a
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let current = a
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    let a = Arc::new(a);
    let refresh = {
        let (a, id, rev) = (a.clone(), receipt.account_id.clone(), current.revision);
        tokio::spawn(async move { a.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Another holder takes the lease over.
    f.sql("UPDATE refresh_leases SET holder_id = 'other', epoch = epoch + 1")
        .await;
    gate.notify_one();
    assert!(refresh.await.unwrap().is_err());
    let stored = a.selected("person", &receipt.account_id).await.unwrap();
    assert!(
        stored.record.retained.is_none(),
        "an old holder kept a response"
    );
}

#[tokio::test]
async fn a_lease_that_lapsed_mid_exchange_keeps_the_response_without_a_replay() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let refreshes = Arc::new(AtomicUsize::new(0));
    let Some((f, a, b)) = replicas(provider(refreshes.clone(), 3600, Some(gate.clone()))).await
    else {
        return;
    };
    let receipt = a
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let current = a
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    let a = Arc::new(a);
    let refresh = {
        let (a, id, rev) = (a.clone(), receipt.account_id.clone(), current.revision);
        tokio::spawn(async move { a.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The lease lapses, but nobody takes it over.
    f.sql("UPDATE refresh_leases SET expires_at = now() - interval '1 second'")
        .await;
    gate.notify_one();
    // This replica cannot finish without its lease, but it kept the response.
    let _ = refresh.await.unwrap();
    let next = b
        .acquire("person", &receipt.account_id, None)
        .await
        .unwrap();
    assert_eq!(next.access_token, "successor-0");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn two_replicas_admitting_the_same_grant_create_one_account() {
    let Some((_f, a, b)) = replicas(provider(Arc::default(), 3600, None)).await else {
        return;
    };
    let grant = grant_until("first", now() + 3_600_000);
    let (left, right) = tokio::join!(
        a.admit("person", "work", "m-1", grant.clone(), None),
        b.admit("person", "Work", "m-2", grant.clone(), None)
    );
    assert_eq!(
        [left.is_ok(), right.is_ok()]
            .iter()
            .filter(|ok| **ok)
            .count(),
        1
    );
    assert_eq!(a.accounts("person").await.unwrap().len(), 1);
}

#[tokio::test]
async fn serve_refuses_a_schema_it_cannot_read() {
    let Some(url) = testing::fresh_database().await.unwrap() else {
        return;
    };
    let store = PostgresStore::connect(&url).await.unwrap();
    store.check_schema().await.unwrap();
    store.migrate().await.unwrap();
    store.check_schema().await.unwrap();
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
        .batch_execute("UPDATE schema_info SET min_reader = 99")
        .await
        .unwrap();
    assert!(store.check_schema().await.is_err());
    client
        .batch_execute("DELETE FROM schema_info")
        .await
        .unwrap();
    assert!(store.check_schema().await.is_err());
}

#[tokio::test]
async fn an_old_migration_receipt_never_resolves_to_a_recreated_account() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    // The migration's forced refresh fails, so m-1 never completes.
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(|| async { axum::http::StatusCode::BAD_GATEWAY }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    assert!(
        engine
            .migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    let id = account_id("person", "work");
    engine.remove("person", "mac", &id).await.unwrap();
    engine
        .admit(
            "person",
            "work",
            "login-2",
            grant_until("second", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    // m-1 belonged to the deleted account; the recreated one must not complete it.
    assert!(engine.receipt("person", "m-1").await.is_err());
    assert!(
        engine
            .migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_pending_grant_is_never_stored_for_a_cancelled_login() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
    let renewal = engine
        .start_login("person", "machine", "work", true)
        .await
        .unwrap();
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    // A completion that kept its response before the delete reaches admission afterwards.
    let late = engine
        .admit_with(
            "person",
            "work",
            &renewal.id,
            grant_until("late", now() + 3_600_000),
            Some(&receipt.identity),
            false,
            Some(&renewal.id),
        )
        .await;
    assert!(late.is_err());
    assert!(
        engine
            .store()
            .pending("person", &renewal.id)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn the_runtime_role_needs_no_delete_privilege() {
    let Some(url) = testing::fresh_database().await.unwrap() else {
        return;
    };
    let role = format!("rt_{}", &vault::secret()[..12]);
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "CREATE ROLE {role} LOGIN;
             GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO {role};
             GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role};"
        ))
        .await
        .unwrap();
    let runtime_url = url.replacen("postgres://postgres@", &format!("postgres://{role}@"), 1);
    let f = Fixture::new(provider(Arc::default(), 3600, None)).await;
    let store = Store::Postgres(PostgresStore::connect(&runtime_url).await.unwrap());
    let engine = Engine::with_store(Arc::new(store), &f.key, f.endpoints()).unwrap();
    let grant = || grant_until("first", now() + 3_600_000);
    let receipt = engine
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .unwrap();
    engine
        .usage("person", &receipt.account_id, false)
        .await
        .unwrap();
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
    let again = engine
        .admit(
            "person",
            "work",
            "m-2",
            grant_until("second", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let access = engine
        .acquire("person", &again.account_id, None)
        .await
        .unwrap();
    assert_eq!(access.access_token, "second");
    let cached = engine
        .usage("person", &again.account_id, true)
        .await
        .unwrap();
    assert!(
        cached.observed_at.is_none(),
        "a deleted account's usage came back"
    );
}

/// A provider whose refresh always fails, so a migration stays pending.
fn failing_refresh() -> Router {
    Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post(|| async { axum::http::StatusCode::BAD_GATEWAY }),
        )
}

#[tokio::test]
async fn a_login_renewal_never_completes_a_pending_migration() {
    let f = Fixture::new(failing_refresh()).await;
    let engine = f.engine().await;
    assert!(
        engine
            .migrate(
                "person",
                "mac",
                "work",
                "m-1",
                grant_until("migrated", now() + 3_600_000)
            )
            .await
            .is_err()
    );
    let identity = Identity {
        account_uuid: "a".into(),
        organization_uuid: "o".into(),
    };
    // A login renewal replaces the pending grant; its rotation is NotMigrated.
    engine
        .admit(
            "person",
            "work",
            "renew-1",
            grant_until("renewed", now() + 3_600_000),
            Some(&identity),
        )
        .await
        .unwrap();
    // The copies m-1 left on its holders were never made stale: no receipt.
    assert!(!matches!(
        engine.receipt("person", "m-1").await,
        Ok(Some(_))
    ));
    assert!(
        engine
            .migrate(
                "person",
                "mac",
                "work",
                "m-1",
                grant_until("migrated", now() + 3_600_000)
            )
            .await
            .is_err()
    );
    // The renewal's own receipt stands.
    assert!(matches!(
        engine.receipt("person", "renew-1").await,
        Ok(Some(_))
    ));
}

#[tokio::test]
async fn a_recreated_account_is_a_new_row_and_the_deleted_row_stays_deleted() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let id = account_id("person", "work");
    engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    engine.remove("person", "mac", &id).await.unwrap();
    engine
        .admit(
            "person",
            "work",
            "m-2",
            grant_until("second", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    let rows = engine.store().account_rows(&id).await.unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows.iter().filter(|(_, deleted)| *deleted).count(), 1);
    assert_ne!(rows[0].0, rows[1].0, "a recreate needs a new incarnation");
    assert!(engine.receipt("person", "m-1").await.is_err());
    assert!(matches!(engine.receipt("person", "m-2").await, Ok(Some(_))));
}

/// PostgreSQL only: replica A holds a stale admission marker while replica B deletes and
/// recreates the alias. The marker binds the incarnation, so even a revoked flag that A
/// read before the delete cannot resolve to the new account.
#[tokio::test]
async fn a_stale_migration_marker_resolves_gone_across_replicas() {
    let f = Fixture::new(failing_refresh()).await;
    if f.postgres().is_none() {
        return;
    }
    let (a, b) = (f.engine().await, f.engine().await);
    let grant = || grant_until("migrated", now() + 3_600_000);
    assert!(
        a.migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    let id = account_id("person", "work");
    b.remove("person", "mac", &id).await.unwrap();
    b.admit(
        "person",
        "work",
        "login-2",
        grant_until("second", now() + 3_600_000),
        None,
    )
    .await
    .unwrap();
    // The state A sees when it read the marker before B's delete committed.
    f.sql("UPDATE admissions SET revoked = false").await;
    let receipt = a.receipt("person", "m-1").await.err().unwrap();
    assert!(receipt.downcast_ref::<Gone>().is_some(), "{receipt}");
    let retry = a
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .err()
        .unwrap();
    assert!(retry.downcast_ref::<Gone>().is_some(), "{retry}");
    assert!(matches!(b.receipt("person", "login-2").await, Ok(Some(_))));
}

#[tokio::test]
async fn an_oversized_refresh_response_is_not_kept_and_the_account_stays_readable() {
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route("/token", post(|| async { "x".repeat(MAX_RESPONSE + 1) }));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    // An access token close to expiry, so the next acquire refreshes.
    let receipt = engine
        .admit(
            "person",
            "work",
            "m-1",
            grant_until("first", now() + USABLE + 1_000),
            None,
        )
        .await
        .unwrap();
    assert!(
        engine
            .acquire("person", &receipt.account_id, None)
            .await
            .is_err()
    );
    // The record still loads: the oversized body was never sealed into it.
    assert_eq!(engine.accounts("person").await.unwrap().len(), 1);
}

/// PostgreSQL only. Replica A resolved m-1 as Pending; before its refresh runs, replica B deletes the alias,
/// re-admits the same identity, and rotates the replacement. A must not publish m-1's
/// receipt for the replacement incarnation.
#[tokio::test]
async fn a_pending_migration_never_returns_a_receipt_for_a_rotated_replacement() {
    let refreshes = Arc::new(AtomicUsize::new(0));
    let fail_first = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/token",
            post({
                let (refreshes, fail_first) = (refreshes.clone(), fail_first.clone());
                move || {
                    let (refreshes, fail_first) = (refreshes.clone(), fail_first.clone());
                    async move {
                        // The first refresh (m-1's) fails, so m-1 stays pending.
                        if fail_first.fetch_add(1, Ordering::SeqCst) == 0 {
                            return axum::http::StatusCode::BAD_GATEWAY.into_response();
                        }
                        token_body(refreshes.fetch_add(1, Ordering::SeqCst), 3600).into_response()
                    }
                }
            }),
        );
    let f = Fixture::new(app).await;
    if f.postgres().is_none() {
        return;
    }
    let (a, b) = (f.engine().await, f.engine().await);
    let grant = || grant_until("migrated", now() + 3_600_000);
    assert!(
        a.migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    // A read m-1 as Pending: this is the receipt it holds when B acts.
    let held = Receipt {
        account_id: account_id("person", "work"),
        identity: Identity {
            account_uuid: "a".into(),
            organization_uuid: "o".into(),
        },
        migration_id: "m-1".into(),
    };
    b.remove("person", "mac", &held.account_id).await.unwrap();
    b.migrate(
        "person",
        "mac",
        "work",
        "m-2",
        grant_until("other", now() + 3_600_000),
    )
    .await
    .unwrap();
    let late = a.finish_migration("person", "mac", "m-1", held).await;
    assert!(late.is_err(), "m-1 published a receipt for the replacement");
    assert!(late.err().unwrap().downcast_ref::<Gone>().is_some());
}

fn flow_row(alias: &str) -> store::FlowRow {
    store::FlowRow {
        user: "person".into(),
        alias: alias.into(),
        sealed: vec![1],
        exchanging: false,
        retained: None,
        cancelled: false,
        consumed: false,
    }
}

/// start_login reads its renewal target, then a delete commits, then the flow is written:
/// the write must see the delete under the alias lock and refuse.
#[tokio::test]
async fn a_login_flow_written_after_a_delete_of_its_target_is_refused() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
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
    let target = engine
        .store()
        .account("person", &receipt.account_id)
        .await
        .unwrap()
        .unwrap();
    engine
        .remove("person", "mac", &receipt.account_id)
        .await
        .unwrap();
    let renewal = store::FlowTarget::Renew {
        account: &target.id,
        incarnation: &target.incarnation,
    };
    assert!(
        !engine
            .store()
            .put_flow("late", &flow_row("work"), renewal)
            .await
            .unwrap()
    );
    assert!(
        engine
            .store()
            .flow("person", "late")
            .await
            .unwrap()
            .is_none()
    );
    // A recreated alias is a new incarnation: the old target still does not match.
    engine
        .admit(
            "person",
            "work",
            "m-2",
            grant_until("second", now() + 3_600_000),
            None,
        )
        .await
        .unwrap();
    assert!(
        !engine
            .store()
            .put_flow("late-2", &flow_row("work"), renewal)
            .await
            .unwrap()
    );
    // A new login for an alias that now exists is refused too.
    assert!(
        !engine
            .store()
            .put_flow("new", &flow_row("work"), store::FlowTarget::New)
            .await
            .unwrap()
    );
    assert!(
        engine
            .store()
            .put_flow("fresh", &flow_row("home"), store::FlowTarget::New)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn an_oversized_usage_response_is_refused_and_never_stored() {
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route(
            "/api/oauth/usage",
            get(|| async {
                Json(json!({"five_hour":{"utilization":42,"pad":"x".repeat(MAX_RESPONSE)}}))
            }),
        );
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
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
    let usage = engine
        .usage("person", &receipt.account_id, false)
        .await
        .unwrap();
    assert!(usage.data.is_none());
    assert_eq!(usage.error.as_deref(), Some("invalid_usage"));
}

#[tokio::test]
async fn a_receipt_state_tells_no_admission_from_pending_and_complete() {
    let f = Fixture::new(failing_refresh()).await;
    let engine = f.engine().await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    let (receipt, state) = engine.receipt_state("person", "m-1").await.unwrap();
    assert!(receipt.is_none());
    assert_eq!(state, "none");
    // The forced refresh fails: admitted, rotation not verified.
    assert!(
        engine
            .migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    let (receipt, state) = engine.receipt_state("person", "m-1").await.unwrap();
    assert!(receipt.is_none());
    assert_eq!(state, "pending");
    // A completed migration on a working provider.
    let (_f2, ok, _refreshes) = synthetic(3600).await;
    ok.migrate("person", "mac", "home", "m-2", grant())
        .await
        .unwrap();
    let (receipt, state) = ok.receipt_state("person", "m-2").await.unwrap();
    assert!(receipt.is_some());
    assert_eq!(state, "complete");
}

/// An admission in flight (its grant kept, not yet committed) is not "none": a client must
/// not restore its fenced grant while the server may still admit it.
#[tokio::test]
async fn a_receipt_state_is_pending_while_an_admission_is_in_flight() {
    let app = Router::new()
        .route("/token", counted_token(Arc::default()))
        // The identity check fails once: the grant is kept, nothing is committed.
        .route("/api/oauth/profile", flaky_profile(0));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    assert!(
        engine
            .migrate(
                "person",
                "mac",
                "work",
                "m-1",
                grant_until("migrated", now() + 3_600_000)
            )
            .await
            .is_err()
    );
    let (receipt, state) = engine.receipt_state("person", "m-1").await.unwrap();
    assert!(receipt.is_none());
    assert_eq!(state, "pending");
}

/// The admission and its pending row are separate reads; a commit between them leaves a
/// committed pending row, which must not read as "none".
#[tokio::test]
async fn a_committed_pending_row_without_a_visible_admission_is_not_none() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let row = store::PendingRow {
        user: "person".into(),
        alias: "work".into(),
        state: store::PendingState::Live,
        sealed: vec![1],
    };
    engine.store().put_pending("m-9", &row, None).await.unwrap();
    // Model the reader that saw no admission, then a committed row.
    assert_eq!(
        engine.receipt_state("person", "m-9").await.unwrap().1,
        "pending"
    );
    assert_eq!(
        state_without_admission(Some(store::PendingState::Committed)),
        "pending"
    );
    assert_eq!(
        state_without_admission(Some(store::PendingState::Cancelled)),
        "none"
    );
    assert_eq!(state_without_admission(None), "none");
}

#[tokio::test]
async fn an_import_arriving_after_a_cancel_is_rejected() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    assert_eq!(
        engine
            .cancel_migration("person", "work", "m-1")
            .await
            .unwrap(),
        store::CancelOutcome::Cancelled
    );
    let late = engine
        .migrate(
            "person",
            "mac",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .err()
        .unwrap();
    assert!(
        late.downcast_ref::<AdmissionCancelled>().is_some(),
        "{late}"
    );
    assert!(engine.accounts("person").await.unwrap().is_empty());
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);
    // A second cancel is harmless.
    assert_eq!(
        engine
            .cancel_migration("person", "work", "m-1")
            .await
            .unwrap(),
        store::CancelOutcome::Cancelled
    );
}

#[tokio::test]
async fn a_cancel_after_the_commit_is_refused() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    engine
        .migrate(
            "person",
            "mac",
            "work",
            "m-1",
            grant_until("migrated", now() + 3_600_000),
        )
        .await
        .unwrap();
    assert_eq!(
        engine
            .cancel_migration("person", "work", "m-1")
            .await
            .unwrap(),
        store::CancelOutcome::Admitted
    );
    assert_eq!(
        engine.receipt_state("person", "m-1").await.unwrap().1,
        "complete"
    );
}

#[tokio::test]
async fn a_cancel_beats_an_import_that_kept_its_grant_but_did_not_commit() {
    let app = Router::new()
        .route("/token", counted_token(Arc::default()))
        // The first identity check fails: the grant is kept (live pending row), not admitted.
        .route("/api/oauth/profile", flaky_profile(0));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    assert!(
        engine
            .migrate("person", "mac", "work", "m-1", grant())
            .await
            .is_err()
    );
    assert_eq!(
        engine
            .cancel_migration("person", "work", "m-1")
            .await
            .unwrap(),
        store::CancelOutcome::Cancelled
    );
    let retry = engine
        .migrate("person", "mac", "work", "m-1", grant())
        .await
        .err()
        .unwrap();
    assert!(
        retry.downcast_ref::<AdmissionCancelled>().is_some(),
        "{retry}"
    );
    assert!(engine.accounts("person").await.unwrap().is_empty());
}
