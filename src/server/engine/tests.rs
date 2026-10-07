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
    Json(json!({"access_token":format!("successor-{n}"),"refresh_token":format!("successor-refresh-{n}"),"expires_in":expires_in,"scope":"user:inference user:profile"}))
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
    let state = url.query_pairs().find(|(n, _)| n == "state").unwrap().1.into_owned();
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
        .admit("person", "work", "first", grant_until("a", now() + 3_600_000), None)
        .await
        .unwrap();
    let cached = engine.usage("person", &receipt.account_id, true).await.unwrap();
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
        .admit("person-a", "work", "migration-1", grant_until("a", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = engine.acquire("person-a", &receipt.account_id, None).await.unwrap();
    let (left, right) = tokio::join!(
        engine.acquire("person-a", &receipt.account_id, Some(&current.revision)),
        engine.acquire("person-a", &receipt.account_id, Some(&current.revision))
    );
    let (left, right) = (left.unwrap(), right.unwrap());
    assert_eq!(left.access_token, "successor-0");
    assert_eq!(right.revision, left.revision);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    assert!(engine.acquire("person-b", &receipt.account_id, None).await.is_err());
    drop(engine);
    let engine = f.engine().await;
    let restarted = engine.acquire("person-a", &receipt.account_id, None).await.unwrap();
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
        .admit("person", "work", "first", grant_until("a", now() + 3_600_000), None)
        .await
        .unwrap();
    let access = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    assert!(
        engine
            .acquire("person", &receipt.account_id, Some(&access.revision))
            .await
            .is_err()
    );
    drop(engine);
    let engine = f.engine().await;
    assert!(engine.acquire("person", &receipt.account_id, None).await.is_err());
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
    assert!(engine.admit("person", "work", "migration", first, None).await.is_err());
    drop(engine);
    let engine = f.engine().await;
    let retry = grant_until("retry-must-not-replace", now() + 3_600_000);
    let receipt = engine.admit("person", "work", "migration", retry, None).await.unwrap();
    let access = engine.acquire("person", &receipt.account_id, None).await.unwrap();
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
        .admit("person", "work", "migration", grant_until("initial", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    assert!(
        engine
            .acquire("person", &receipt.account_id, Some(&current.revision))
            .await
            .is_err()
    );
    drop(engine);
    let engine = f.engine().await;
    let successor = engine.acquire("person", &receipt.account_id, None).await.unwrap();
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
    let challenge = engine.start_login("person", "machine", "work", false).await.unwrap();
    let code = pasted(&challenge);
    assert!(engine.finish_login("person", "other-machine", &challenge.id, &code).await.is_err());
    assert!(engine.finish_login("person", "machine", &challenge.id, "fake-code#wrong").await.is_err());
    assert_eq!(exchanges.load(Ordering::SeqCst), 0);
    assert!(engine.finish_login("person", "machine", &challenge.id, &code).await.is_err());
    drop(engine);
    let engine = f.engine().await;
    let receipt = engine
        .finish_login("person", "machine", &challenge.id, &code)
        .await
        .unwrap();
    let access = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    assert_eq!(access.access_token, "new-access");
    assert_eq!(exchanges.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_server_refreshes_inside_five_minutes_of_expiry_and_not_before() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    let early = engine
        .admit("person", "early", "m-early", grant_until("early", now() + 360_000), None)
        .await
        .unwrap();
    let access = engine.acquire("person", &early.account_id, None).await.unwrap();
    assert_eq!(access.access_token, "early");
    assert_eq!(refreshes.load(Ordering::SeqCst), 0);

    let (_f, engine, refreshes) = synthetic(3600).await;
    let due = engine
        .admit("person", "due", "m-due", grant_until("due", now() + 240_000), None)
        .await
        .unwrap();
    let access = engine.acquire("person", &due.account_id, None).await.unwrap();
    assert_eq!(access.access_token, "successor-0");
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refresh_reads_expires_in_as_seconds() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let receipt = engine
        .admit("person", "work", "m", grant_until("first", now() + 240_000), None)
        .await
        .unwrap();
    let before = now();
    let access = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    // One hour: 3,600 seconds is 3,600,000 milliseconds.
    assert!(access.expires_at >= before + 3_590_000, "{}", access.expires_at - before);
    assert!(access.expires_at <= now() + 3_600_000);
}

#[tokio::test]
async fn a_migration_refreshes_once_so_copies_of_the_old_grant_go_stale() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    let receipt = engine.migrate("person", "machine", "work", "m-1", grant()).await.unwrap();
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    let access = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    assert_eq!(access.access_token, "successor-0");
    assert_eq!(access.generation, 2);
    let retry = engine.migrate("person", "machine", "work", "m-1", grant()).await.unwrap();
    assert_eq!(retry.account_id, receipt.account_id);
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_near_expiry_migration_refreshes_exactly_once() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    engine
        .migrate("person", "machine", "work", "m-1", grant_until("migrated", now() + 240_000))
        .await
        .unwrap();
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_migration_stopped_before_its_refresh_shows_no_receipt_until_it_rotates() {
    let (_f, engine, refreshes) = synthetic(3600).await;
    let grant = || grant_until("migrated", now() + 3_600_000);
    // A stop after admission, before the forced refresh.
    let admitted = engine.admit_migration("person", "work", "m-1", grant()).await.unwrap();
    assert!(engine.receipt("person", "m-1").await.unwrap().is_none());
    // Even a token request rotates first, so it never hands out the migrated token.
    let access = engine.acquire("person", &admitted.account_id, None).await.unwrap();
    assert_eq!(access.access_token, "successor-0");
    let receipt = engine.migrate("person", "machine", "work", "m-1", grant()).await.unwrap();
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
    assert!(engine.migrate("person", "mac", "work", "m-1", grant()).await.is_err());
    assert!(engine.receipt("person", "m-1").await.unwrap().is_none());
    engine.migrate("person", "mac", "work", "m-1", grant()).await.unwrap();
    assert!(engine.receipt("person", "m-1").await.unwrap().is_some());
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_audit_log_records_migration_and_refresh_without_any_token() {
    let (f, engine, _refreshes) = synthetic(3600).await;
    let receipt = engine
        .migrate("person", "mac-1", "work", "m-1", grant_until("migrated", now() + 3_600_000))
        .await
        .unwrap();
    let events = crate::server::audit::read(engine.store(), &f.key).await.unwrap();
    let operations: Vec<_> = events
        .iter()
        .map(|e| (e["operation"].as_str().unwrap(), e["result"].as_str().unwrap()))
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    assert!(engine.remove("other-person", "mac-1", &receipt.account_id).await.is_err());
    engine.remove("person", "mac-1", &receipt.account_id).await.unwrap();
    let error = engine.acquire("person", &receipt.account_id, None).await.err().unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    assert!(engine.accounts("person").await.unwrap().is_empty());
    assert!(engine.store().account(&receipt.account_id).await.unwrap().is_none());
    drop(engine);
    let engine = f.engine().await;
    let error = engine.acquire("person", &receipt.account_id, None).await.err().unwrap();
    assert!(error.downcast_ref::<Gone>().is_some());
    let events = crate::server::audit::read(engine.store(), &f.key).await.unwrap();
    let last = events.last().unwrap();
    assert_eq!((last["operation"].as_str(), last["result"].as_str()), (Some("revoke"), Some("ok")));
    assert_eq!(last["machine"], "mac-1");
}

#[tokio::test]
async fn a_renewal_started_before_a_delete_cannot_recreate_the_account() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let receipt = engine
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let identity = receipt.identity.clone();
    engine.remove("person", "mac", &receipt.account_id).await.unwrap();
    let renewal = grant_until("renewed", now() + 3_600_000);
    assert!(engine.admit("person", "work", "renewal", renewal, Some(&identity)).await.is_err());
    assert!(engine.accounts("person").await.unwrap().is_empty());
}

#[tokio::test]
async fn a_renewal_from_before_a_delete_cannot_overwrite_a_recreated_account() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let first = engine
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let before_delete = now() - 1;
    engine.remove("person", "mac", &first.account_id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let second = engine
        .admit("person", "work", "m-2", grant_until("second", now() + 3_600_000), None)
        .await
        .unwrap();
    let options = Admission {
        rotation_pending: false,
        started_at: before_delete,
    };
    let stale = grant_until("stale", now() + 3_600_000);
    let late = engine
        .admit_with("person", "work", "old-renewal", stale, Some(&second.identity), options, None)
        .await;
    assert!(late.is_err());
    let access = engine.acquire("person", &second.account_id, None).await.unwrap();
    assert_eq!(access.access_token, "second");
}

#[tokio::test]
async fn a_usage_read_never_refreshes_and_reports_login_required_once() {
    let app = Router::new()
        .route("/api/oauth/profile", get(|| async { profile() }))
        .route("/token", post(|| async { axum::http::StatusCode::BAD_REQUEST }));
    let f = Fixture::new(app).await;
    let engine = f.engine().await;
    let receipt = engine
        .admit("person", "work", "m", grant_until("due", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    // A rejected refresh leaves the account waiting for login renewal.
    assert!(
        engine
            .acquire("person", &receipt.account_id, Some(&current.revision))
            .await
            .is_err()
    );
    let usage = engine.usage("person", &receipt.account_id, false).await.unwrap();
    assert_eq!(usage.error.as_deref(), Some("login_required"));
    assert_eq!(usage.failure, Some("usage_login_required"));
    let cached = engine.usage("person", &receipt.account_id, true).await.unwrap();
    assert_eq!(cached.failure, None);
}

#[tokio::test]
async fn a_delete_drops_the_cached_usage_of_that_account() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let first = engine
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    // The synthetic provider has no usage route; a fresh read stores an error result.
    engine.usage("person", &first.account_id, false).await.unwrap();
    engine.remove("person", "mac", &first.account_id).await.unwrap();
    let second = engine
        .admit("person", "work", "m-2", grant_until("second", now() + 3_600_000), None)
        .await
        .unwrap();
    assert_eq!(second.account_id, first.account_id);
    let cached = engine.usage("person", &second.account_id, true).await.unwrap();
    assert!(cached.error.is_none() && cached.observed_at.is_none() && cached.next_retry_at == 0);
}

#[tokio::test]
async fn a_delete_purges_pending_admission_grants_for_the_alias() {
    let (_f, engine, _refreshes) = synthetic(3600).await;
    let receipt = engine
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let wrong = Identity {
        account_uuid: "other".into(),
        organization_uuid: "o".into(),
    };
    let renewal = grant_until("renewed", now() + 3_600_000);
    assert!(engine.admit("person", "work", "renewal", renewal, Some(&wrong)).await.is_err());
    let key = vault::digest(b"person\0renewal");
    assert!(engine.store().pending(&key).await.unwrap().is_some());
    engine.remove("person", "mac", &receipt.account_id).await.unwrap();
    assert!(engine.store().pending(&key).await.unwrap().is_none());
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let renewal = engine.start_login("person", "machine", "work", true).await.unwrap();
    let code = pasted(&renewal);
    assert!(engine.finish_login("person", "machine", &renewal.id, &code).await.is_err());
    assert!(engine.store().flow(&renewal.id).await.unwrap().unwrap().retained.is_some());
    engine.remove("person", "mac", &existing.account_id).await.unwrap();
    assert!(engine.store().flow(&renewal.id).await.unwrap().is_none());
    assert!(engine.finish_login("person", "machine", &renewal.id, &code).await.is_err());
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
    let first = engine.start_login("person", "machine", "work", false).await.unwrap();
    let second = engine.start_login("person", "machine", "work", false).await.unwrap();
    let receipt = engine
        .finish_login("person", "machine", &first.id, &pasted(&first))
        .await
        .unwrap();
    let late = {
        let engine = engine.clone();
        let code = pasted(&second);
        tokio::spawn(async move { engine.finish_login("person", "machine", &second.id, &code).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine.remove("person", "mac", &receipt.account_id).await.unwrap();
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = engine.acquire("person", &receipt.account_id, None).await.unwrap();
    let refresh = {
        let (engine, id, previous) = (engine.clone(), receipt.account_id.clone(), current.revision);
        tokio::spawn(async move { engine.acquire("person", &id, Some(&previous)).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    engine.remove("person", "mac", &receipt.account_id).await.unwrap();
    gate.notify_one();
    assert!(refresh.await.unwrap().is_err());
    assert!(engine.store().account(&receipt.account_id).await.unwrap().is_none());
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_delete_and_a_usage_read_on_the_same_account_do_not_deadlock() {
    let gate = Arc::new(tokio::sync::Notify::new());
    let f = Fixture::new(provider(Arc::default(), 3600, Some(gate.clone()))).await;
    let engine = Arc::new(f.engine().await);
    let receipt = engine
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
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
    assert!(engine.acquire("person", &receipt.account_id, None).await.is_ok());
    engine.remove("person", "mac", &receipt.account_id).await.unwrap();
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = a.acquire("person", &receipt.account_id, None).await.unwrap();
    let (a, b) = (Arc::new(a), Arc::new(b));
    let left = {
        let (a, id, rev) = (a.clone(), receipt.account_id.clone(), current.revision.clone());
        tokio::spawn(async move { a.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    let right = {
        let (b, id, rev) = (b.clone(), receipt.account_id.clone(), current.revision.clone());
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = a.acquire("person", &receipt.account_id, None).await.unwrap();
    let a = Arc::new(a);
    let refresh = {
        let (a, id, rev) = (a.clone(), receipt.account_id.clone(), current.revision);
        tokio::spawn(async move { a.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Another holder takes the lease over.
    f.sql("UPDATE refresh_leases SET holder_id = 'other', epoch = epoch + 1").await;
    gate.notify_one();
    assert!(refresh.await.unwrap().is_err());
    let stored = a.selected("person", &receipt.account_id).await.unwrap();
    assert!(stored.record.retained.is_none(), "an old holder kept a response");
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
        .admit("person", "work", "m-1", grant_until("first", now() + 3_600_000), None)
        .await
        .unwrap();
    let current = a.acquire("person", &receipt.account_id, None).await.unwrap();
    let a = Arc::new(a);
    let refresh = {
        let (a, id, rev) = (a.clone(), receipt.account_id.clone(), current.revision);
        tokio::spawn(async move { a.acquire("person", &id, Some(&rev)).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    // The lease lapses, but nobody takes it over.
    f.sql("UPDATE refresh_leases SET expires_at = now() - interval '1 second'").await;
    gate.notify_one();
    // This replica cannot finish without its lease, but it kept the response.
    let _ = refresh.await.unwrap();
    let next = b.acquire("person", &receipt.account_id, None).await.unwrap();
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
    assert_eq!([left.is_ok(), right.is_ok()].iter().filter(|ok| **ok).count(), 1);
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
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await.unwrap();
    tokio::spawn(connection);
    client.batch_execute("UPDATE schema_info SET min_reader = 99").await.unwrap();
    assert!(store.check_schema().await.is_err());
    client.batch_execute("DELETE FROM schema_info").await.unwrap();
    assert!(store.check_schema().await.is_err());
}
