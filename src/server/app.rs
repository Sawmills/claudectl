//! HTTP contract, machine authorization, and the company-user allow list.
use super::{
    audit, dashboard,
    engine::{self, Endpoints, Engine, Gone, NotFound, RefreshInProgress, Superseded, Unrotated},
    enrollment,
    store::{self, Machine, Store},
    vault,
};
use anyhow::{Result, bail};
use axum::{
    Json, Router,
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::Semaphore;

pub struct Sso {
    pub config: PathBuf,
    pub public_url: String,
}

/// Where server state lives.
#[derive(Clone)]
pub enum StoreConfig {
    /// One sealed file; one process. For tests and single-machine use.
    File(PathBuf),
    /// PostgreSQL; several replicas.
    Postgres(String),
}

pub struct Config {
    pub store: StoreConfig,
    pub key: PathBuf,
    /// Company email addresses that may use this server. Nobody else gets access.
    pub allowed_users: Vec<String>,
    pub sso: Option<Sso>,
    /// SHA-256 of the Prometheus scrape token. Without it, `/metrics` needs a machine token.
    pub metrics_token_hash: Option<String>,
    pub endpoints: Endpoints,
}

pub struct Server {
    key: PathBuf,
    engine: Arc<Engine>,
    pub(super) sso: Option<enrollment::Sso>,
    allowed: Vec<String>,
    metrics_token_hash: Option<String>,
    /// Per reason: failure count and the Unix time of the last one.
    failures: StdMutex<BTreeMap<&'static str, (u64, i64)>>,
    work: Arc<Semaphore>,
    /// Set on shutdown: readiness fails while in-flight work finishes.
    draining: AtomicBool,
}

pub struct HttpError {
    pub(super) status: StatusCode,
    pub(super) reason: &'static str,
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.reason}))).into_response()
    }
}

/// Open a store. A database must already have this binary's schema (run `migrate`).
pub async fn open_store(config: &StoreConfig, key: &Path) -> Result<Arc<Store>> {
    Ok(Arc::new(match config {
        StoreConfig::File(state) => Store::File(Box::new(store::FileStore::open(state, key)?)),
        StoreConfig::Postgres(url) => {
            let store = store::PostgresStore::connect(url).await?;
            store.check_schema().await?;
            Store::Postgres(store)
        }
    }))
}

/// Create a new vault key when absent, and an empty file store.
pub fn setup(state: &Path, key: &Path) -> Result<()> {
    if key.try_exists()? {
        if vault::private_read(key)?.len() != 32 {
            bail!("vault key must contain exactly 32 bytes");
        }
    } else {
        vault::create_secret(key, &vault::random_bytes())?;
    }
    store::FileStore::create(state, key)
}

/// Apply the database schema. The migration job runs this; `serve` never does.
pub async fn migrate(url: &str) -> Result<()> {
    store::PostgresStore::connect(url).await?.migrate().await
}

fn user_id(email: &str) -> String {
    vault::digest(format!("admin\0{}", email.to_ascii_lowercase()).as_bytes())
}

pub(super) async fn add_machine(store: &Store, user: &str, name: &str) -> Result<(String, String)> {
    let token = vault::secret();
    let id = format!("{name}-{}", &vault::secret()[..12]);
    store
        .add_machine(&Machine {
            id: id.clone(),
            user: user.into(),
            token_hash: vault::digest(token.as_bytes()),
            revoked: false,
        })
        .await?;
    Ok((id, token))
}

/// Enroll a machine without SSO, for an operator on the server host. Returns the machine ID
/// and its bearer token, which is shown once.
pub async fn register(store: &Store, email: &str, name: &str) -> Result<(String, String)> {
    let id = user_id(email);
    if !store.record_user(&id, &email.to_ascii_lowercase()).await? {
        bail!("user is disabled");
    }
    add_machine(store, &id, name).await
}

/// Revoke a machine from the server host, with an audit line.
pub async fn revoke(store: &Store, key: &Path, machine: &str) -> Result<()> {
    if !store.revoke_machine(machine, None).await? {
        bail!("machine not found");
    }
    audit::record(
        store,
        key,
        &audit::Event {
            operation: "revoke",
            machine: "operator",
            account: "-",
            result: "ok",
            rotated: None,
            target: Some(machine),
            reason: None,
            actor: None,
        },
    )
    .await
}

pub async fn set_user(store: &Store, email: &str, enabled: bool) -> Result<()> {
    if !store.set_user_enabled(email, enabled).await? {
        bail!("user not found");
    }
    Ok(())
}

impl Server {
    pub async fn open(config: Config) -> Result<Arc<Self>> {
        if config.allowed_users.is_empty()
            || config
                .allowed_users
                .iter()
                .any(|u| !u.contains('@') || u.trim() != u)
        {
            bail!("at least one allowed company email is required");
        }
        let store = open_store(&config.store, &config.key).await?;
        let engine = Engine::with_store(store, &config.key, config.endpoints)?;
        let sso = match config.sso {
            Some(sso) => Some(enrollment::Sso::load(&sso.config, &sso.public_url).await?),
            None => None,
        };
        Ok(Arc::new(Self {
            key: config.key,
            engine: Arc::new(engine),
            sso,
            allowed: config
                .allowed_users
                .iter()
                .map(|u| u.to_ascii_lowercase())
                .collect(),
            metrics_token_hash: config.metrics_token_hash,
            failures: StdMutex::new(BTreeMap::new()),
            work: Arc::new(Semaphore::new(64)),
            draining: AtomicBool::new(false),
        }))
    }
    pub fn store(&self) -> &Store {
        self.engine.store()
    }
    /// Ready for new work: not draining, and the store answers. `/ready` and the home page
    /// badge both use this, so they never disagree.
    pub(super) async fn ready(&self) -> bool {
        !self.draining.load(Ordering::Acquire) && self.store().ready().await.is_ok()
    }
    #[cfg(test)]
    pub(super) fn begin_drain(&self) {
        self.draining.store(true, Ordering::Release);
    }
    pub fn engine(&self) -> &Arc<Engine> {
        &self.engine
    }
    /// The public origin, when company SSO is configured.
    pub(super) fn public_url(&self) -> Option<&str> {
        self.sso.as_ref().map(enrollment::Sso::public_url)
    }
    pub(super) fn seal<T: serde::Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        vault::encrypt(&self.key, &serde_json::to_vec(value)?)
    }
    pub(super) fn unseal<T: serde::de::DeserializeOwned>(&self, bytes: &[u8]) -> Result<T> {
        Ok(serde_json::from_slice(&vault::decrypt(&self.key, bytes)?)?)
    }
    pub(super) fn error(&self, status: StatusCode, reason: &'static str) -> HttpError {
        self.record_failure(status, reason);
        HttpError { status, reason }
    }
    /// Count one failed attempt and log it. The request itself may still succeed.
    fn record_failure(&self, status: StatusCode, reason: &'static str) {
        {
            let mut failures = self.failures.lock().expect("metrics lock");
            let failure = failures.entry(reason).or_default();
            failure.0 += 1;
            failure.1 = chrono::Utc::now().timestamp();
        }
        eprintln!(
            "{}",
            json!({"operation":"request","stage":"http","reason":reason,"status":status.as_u16()})
        );
    }
    pub(super) fn allowed(&self, email: &str) -> bool {
        self.allowed.iter().any(|a| a.eq_ignore_ascii_case(email))
    }
    async fn authorize(&self, headers: &HeaderMap) -> Result<Machine, HttpError> {
        let bearer = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| self.error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
        let unavailable = |_| self.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable");
        let machine = self
            .store()
            .machine_by_token(&vault::digest(bearer.as_bytes()))
            .await
            .map_err(unavailable)?
            .filter(|m| !m.revoked)
            .ok_or_else(|| self.error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
        let user = self
            .store()
            .user(&machine.user)
            .await
            .map_err(unavailable)?
            .filter(|u| u.enabled)
            .ok_or_else(|| self.error(StatusCode::FORBIDDEN, "user_disabled"))?;
        if !self.allowed(&user.email) {
            return Err(self.error(StatusCode::FORBIDDEN, "user_not_allowed"));
        }
        Ok(machine)
    }
    fn engine_error(&self, error: &anyhow::Error, fallback: &'static str) -> HttpError {
        if error.downcast_ref::<Gone>().is_some() {
            self.error(StatusCode::GONE, "account_deleted")
        } else if error.downcast_ref::<RefreshInProgress>().is_some() {
            self.error(StatusCode::SERVICE_UNAVAILABLE, "refresh_in_progress")
        } else if error.downcast_ref::<Unrotated>().is_some() {
            self.error(StatusCode::CONFLICT, "refresh_token_not_rotated")
        } else if error.downcast_ref::<Superseded>().is_some() {
            self.error(StatusCode::CONFLICT, "migration_superseded")
        } else if error.downcast_ref::<NotFound>().is_some() {
            self.error(StatusCode::NOT_FOUND, "account_not_found")
        } else {
            self.error(StatusCode::SERVICE_UNAVAILABLE, fallback)
        }
    }
    async fn audit(&self, event: &audit::Event<'_>) -> Result<(), HttpError> {
        self.engine
            .audit(event)
            .await
            .map_err(|_| self.error(StatusCode::SERVICE_UNAVAILABLE, "audit_unavailable"))
    }
    /// Run engine work on its own task so a dropped request cannot cancel a refresh midway.
    async fn run<T: Send + 'static>(
        &self,
        work: impl Future<Output = Result<T>> + Send + 'static,
    ) -> Result<Result<T>, HttpError> {
        let permit = self
            .work
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| self.error(StatusCode::SERVICE_UNAVAILABLE, "server_stopping"))?;
        tokio::spawn(async move {
            let _permit = permit;
            work.await
        })
        .await
        .map_err(|_| self.error(StatusCode::SERVICE_UNAVAILABLE, "owner_unavailable"))
    }
    /// Wait until every running engine task has finished.
    async fn drain(&self) {
        let _all = self.work.acquire_many(64).await;
    }
}

type Shared = State<Arc<Server>>;
type Body<T> = Result<Json<T>, axum::extract::rejection::JsonRejection>;

fn private<T: serde::Serialize>(value: T) -> Response {
    ([("cache-control", "no-store")], Json(value)).into_response()
}
fn body<T>(server: &Server, body: Body<T>) -> Result<T, HttpError> {
    body.map(|Json(v)| v)
        .map_err(|_| server.error(StatusCode::BAD_REQUEST, "invalid_request"))
}

async fn me(State(server): Shared, headers: HeaderMap) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    Ok(private(json!({"id": machine.user, "machine": machine.id})))
}
async fn machines(State(server): Shared, headers: HeaderMap) -> Result<Response, HttpError> {
    let current = server.authorize(&headers).await?;
    let machines = server
        .store()
        .machines(&current.user)
        .await
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable"))?;
    Ok(private(
        machines
            .into_iter()
            .map(|(id, revoked)| json!({"id": id, "revoked": revoked}))
            .collect::<Vec<_>>(),
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevokeMachine {
    id: String,
}
async fn revoke_machine(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<RevokeMachine>,
) -> Result<StatusCode, HttpError> {
    let current = server.authorize(&headers).await?;
    let input = body(&server, input)?;
    if !server
        .store()
        .revoke_machine(&input.id, Some(&current.user))
        .await
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "persistence_failed"))?
    {
        return Err(server.error(StatusCode::NOT_FOUND, "machine_not_found"));
    }
    server
        .audit(&audit::Event {
            operation: "revoke",
            machine: &current.id,
            account: "-",
            result: "ok",
            rotated: None,
            target: Some(&input.id),
            reason: None,
            actor: None,
        })
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn accounts(State(server): Shared, headers: HeaderMap) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let accounts = server
        .engine
        .accounts(&machine.user)
        .await
        .map_err(|e| server.engine_error(&e, "registry_unavailable"))?;
    Ok(private(accounts))
}
async fn delete_account(
    State(server): Shared,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Result<StatusCode, HttpError> {
    let machine = server.authorize(&headers).await?;
    server
        .engine
        .remove(&machine.user, &machine.id, &id)
        .await
        .map_err(|e| {
            if e.downcast_ref::<Gone>().is_some() {
                server.error(StatusCode::GONE, "account_deleted")
            } else if e.downcast_ref::<NotFound>().is_some() {
                server.error(StatusCode::NOT_FOUND, "account_not_found")
            } else {
                server.error(StatusCode::SERVICE_UNAVAILABLE, "persistence_failed")
            }
        })?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Token {
    account_id: String,
    #[serde(default)]
    previous_revision: Option<String>,
    /// Watch for a new revision without refreshing a usable token (SAW-12610).
    #[serde(default)]
    observe: bool,
}
async fn token(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<Token>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let input = body(&server, input)?;
    let engine = server.engine.clone();
    let (user, machine_id) = (machine.user.clone(), machine.id.clone());
    let account = input.account_id.clone();
    let access = server
        .run(async move {
            if input.observe {
                engine.observe_for(&user, &machine_id, &account).await
            } else {
                engine
                    .acquire_for(
                        &user,
                        &machine_id,
                        &account,
                        input.previous_revision.as_deref(),
                    )
                    .await
            }
        })
        .await?
        .map_err(|e| server.engine_error(&e, "account_unavailable_or_login_required"))?;
    // A machine revoked while the refresh ran gets nothing.
    let authorized = server.authorize(&headers).await;
    server
        .audit(&audit::Event {
            operation: "issue",
            machine: &machine.id,
            account: &input.account_id,
            result: if authorized.is_ok() {
                "ok"
            } else {
                "refused_revoked"
            },
            rotated: None,
            target: None,
            reason: None,
            actor: None,
        })
        .await?;
    authorized?;
    Ok(private(access))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Migration {
    alias: String,
    migration_id: String,
    grant: engine::Grant,
    exclusive_owner: bool,
}
async fn migrate_account(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<Migration>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let input = body(&server, input)?;
    if !input.exclusive_owner {
        return Err(server.error(StatusCode::CONFLICT, "exclusive_owner_required"));
    }
    let engine = server.engine.clone();
    let (user, machine_id) = (machine.user.clone(), machine.id.clone());
    let receipt = server
        .run(async move {
            engine
                .migrate(
                    &user,
                    &machine_id,
                    &input.alias,
                    &input.migration_id,
                    input.grant,
                )
                .await
        })
        .await?
        .map_err(|e| {
            if e.downcast_ref::<Unrotated>().is_some() {
                server.error(StatusCode::CONFLICT, "refresh_token_not_rotated")
            } else if e.downcast_ref::<Superseded>().is_some() {
                server.error(StatusCode::CONFLICT, "migration_superseded")
            } else if e.downcast_ref::<Gone>().is_some() {
                server.error(StatusCode::GONE, "account_deleted")
            } else if e.downcast_ref::<engine::AdmissionCancelled>().is_some() {
                server.error(StatusCode::CONFLICT, "migration_cancelled")
            } else {
                server.error(StatusCode::CONFLICT, "admission_refused_reconcile_receipt")
            }
        })?;
    server.authorize(&headers).await?;
    Ok(private(receipt))
}
#[derive(Deserialize)]
struct ReceiptQuery {
    migration_id: String,
}
async fn receipt(
    State(server): Shared,
    headers: HeaderMap,
    Query(input): Query<ReceiptQuery>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let (receipt, state) = server
        .engine
        .receipt_state(&machine.user, &input.migration_id)
        .await
        .map_err(|e| server.engine_error(&e, "receipt_unavailable"))?;
    Ok(private(json!({"receipt": receipt, "state": state})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelInput {
    alias: String,
    migration_id: String,
}
/// Cancel a migration ID before it commits. A client restores its fenced grant only after
/// this answers `cancelled`; a later import with the ID is rejected.
async fn cancel_migration(
    State(server): Shared,
    headers: HeaderMap,
    body: Body<CancelInput>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let input = self::body(&server, body)?;
    match server
        .engine
        .cancel_migration(&machine.user, &input.alias, &input.migration_id)
        .await
        .map_err(|e| server.engine_error(&e, "cancel_unavailable"))?
    {
        crate::server::store::CancelOutcome::Cancelled => {
            Ok(private(json!({"state": "cancelled"})))
        }
        crate::server::store::CancelOutcome::Admitted => {
            Err(server.error(StatusCode::CONFLICT, "migration_admitted"))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageQuery {
    account_id: String,
    #[serde(default)]
    cached: bool,
}
async fn usage(
    State(server): Shared,
    headers: HeaderMap,
    Query(input): Query<UsageQuery>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let engine = server.engine.clone();
    let result = server
        .run(async move {
            engine
                .usage(&machine.user, &input.account_id, input.cached)
                .await
        })
        .await?
        .map_err(|e| server.engine_error(&e, "usage_unavailable"))?;
    if let Some(reason) = result.failure {
        server.record_failure(StatusCode::SERVICE_UNAVAILABLE, reason);
    }
    server.authorize(&headers).await?;
    Ok(private(result))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginStart {
    alias: String,
    #[serde(default)]
    renew: bool,
}
async fn login_start(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<LoginStart>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let input = body(&server, input)?;
    let login = server
        .engine
        .start_login(&machine.user, &machine.id, &input.alias, input.renew)
        .await
        .map_err(|_| server.error(StatusCode::CONFLICT, "login_refused"))?;
    Ok(private(login))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginComplete {
    id: String,
    code: String,
}
async fn login_complete(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<LoginComplete>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers).await?;
    let input = body(&server, input)?;
    let engine = server.engine.clone();
    let result = server
        .run(async move {
            engine
                .finish_login(&machine.user, &machine.id, &input.id, &input.code)
                .await
        })
        .await?
        .map_err(|error| {
            let reason = engine::login_reason(&error);
            // Engine errors are fixed texts; no token or code reaches them.
            eprintln!(
                "{}",
                json!({"operation":"login_complete","reason":reason,"error":format!("{error:#}")})
            );
            server.error(StatusCode::CONFLICT, reason)
        })?;
    server.authorize(&headers).await?;
    Ok(private(result))
}

async fn health() -> StatusCode {
    StatusCode::OK
}
async fn ready(State(server): Shared) -> StatusCode {
    if server.ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
async fn metrics(State(server): Shared, headers: HeaderMap) -> Result<Response, HttpError> {
    if let Some(expected) = &server.metrics_token_hash {
        let actual = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| vault::digest(v.as_bytes()));
        if actual.as_ref() != Some(expected) {
            return Err(server.error(StatusCode::UNAUTHORIZED, "metrics_unauthorized"));
        }
    } else {
        server.authorize(&headers).await?;
    }
    let output: String = server
        .failures
        .lock()
        .expect("metrics lock")
        .iter()
        .map(|(reason, (count, last))| {
            format!(
                "claudectl_server_failed_requests_total{{reason=\"{reason}\"}} {count}\nclaudectl_server_last_failure_timestamp_seconds{{reason=\"{reason}\"}} {last}\n"
            )
        })
        .collect();
    let rotations: String = server
        .engine
        .rotations()
        .iter()
        .zip(server.engine.last_rotations())
        .map(|((reason, count), (_, last))| {
            format!(
                "claudectl_token_rotations_total{{reason=\"{reason}\"}} {count}\nclaudectl_token_last_rotation_timestamp_seconds{{reason=\"{reason}\"}} {last}\n"
            )
        })
        .collect();
    let output = output + &rotations;
    Ok((
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        output,
    )
        .into_response())
}

pub fn router(server: Arc<Server>) -> Router {
    let routes = Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/metrics", get(metrics))
        .route("/v1/me", get(me))
        .route("/v1/devices", get(machines))
        .route("/v1/devices/revoke", post(revoke_machine))
        .route("/v2/anthropic/accounts", get(accounts))
        .route("/v2/anthropic/accounts/{id}", delete(delete_account))
        .route("/v2/anthropic/token", post(token))
        .route("/v2/anthropic/usage", get(usage))
        .route("/v2/anthropic/login/start", post(login_start))
        .route("/v2/anthropic/login/complete", post(login_complete))
        .route(
            "/v2/anthropic/migrations",
            post(migrate_account).get(receipt),
        )
        .route("/v2/anthropic/migrations/cancel", post(cancel_migration));
    let routes = enrollment::routes(routes);
    // The home page and dashboard sign in through company SSO; without it they do not exist.
    let routes = if server.sso.is_some() {
        dashboard::routes(routes)
    } else {
        routes
    };
    routes.with_state(server)
}

/// Serve until SIGTERM or Ctrl-C. A network listener needs an HTTPS public origin and
/// company SSO.
pub async fn serve(config: Config, listen: std::net::SocketAddr) -> Result<()> {
    let public_url = config.sso.as_ref().map(|s| s.public_url.clone());
    if !listen.ip().is_loopback() {
        let Some(public_url) = public_url else {
            bail!("a network listener requires company SSO configuration");
        };
        if reqwest::Url::parse(&public_url)?.scheme() != "https" {
            bail!("a network listener requires an HTTPS public origin");
        }
    }
    let server = Server::open(config).await?;
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!(
        "{}",
        json!({"operation":"serve","stage":"listening","address":listener.local_addr()?.to_string()})
    );
    serve_until(server, listener, async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    })
    .await
}

/// Serve until `stop` resolves, then drain: readiness fails, new connections stop, and
/// in-flight requests and engine work finish and persist before this returns. Each refresh
/// releases its lease when it finishes.
pub async fn serve_until(
    server: Arc<Server>,
    listener: tokio::net::TcpListener,
    stop: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let draining = server.clone();
    axum::serve(listener, router(server.clone()))
        .with_graceful_shutdown(async move {
            stop.await;
            draining.draining.store(true, Ordering::Release);
            eprintln!("{}", json!({"operation":"serve","stage":"draining"}));
        })
        .await?;
    server.drain().await;
    Ok(())
}
