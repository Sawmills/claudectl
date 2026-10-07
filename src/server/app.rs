//! HTTP contract, machine authorization, and the company-user allow list.
use super::{
    audit,
    engine::{self, Endpoints, Engine, Gone, NotFound},
    enrollment, fs, vault,
};
use anyhow::{Context, Result, bail};
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
    sync::{Arc, Mutex as StdMutex},
};
use tokio::sync::Semaphore;

pub struct Sso {
    pub config: PathBuf,
    pub public_url: String,
}

pub struct Config {
    pub state: PathBuf,
    pub key: PathBuf,
    /// Company email addresses that may use this server. Nobody else gets access.
    pub allowed_users: Vec<String>,
    pub sso: Option<Sso>,
    /// SHA-256 of the Prometheus scrape token. Without it, `/metrics` needs a machine token.
    pub metrics_token_hash: Option<String>,
    pub endpoints: Endpoints,
}

pub struct Server {
    pub(super) state: PathBuf,
    engine: Arc<Engine>,
    pub(super) sso: Option<enrollment::Sso>,
    allowed: Vec<String>,
    metrics_token_hash: Option<String>,
    /// Per reason: failure count and the Unix time of the last one.
    failures: StdMutex<BTreeMap<&'static str, (u64, i64)>>,
    work: Arc<Semaphore>,
}

pub struct HttpError {
    status: StatusCode,
    reason: &'static str,
}
impl IntoResponse for HttpError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.reason}))).into_response()
    }
}

/// Create empty registries and, when absent, a new vault key.
pub fn setup(state: &Path, key: &Path) -> Result<()> {
    fs::ensure_private_dir(state)?;
    let _lock = vault::lock(state, "owner.lock")?;
    if state.join("users.json").try_exists()? {
        bail!("server state already initialized");
    }
    if key.try_exists()? {
        if vault::private_read(key)?.len() != 32 {
            bail!("vault key must contain exactly 32 bytes");
        }
    } else {
        vault::create_secret(key, &vault::random_bytes())?;
    }
    vault::save_machines(state, &[])?;
    // The pod initializer treats this registry as the completion marker.
    vault::save_users(state, &[])
}

fn user_id(email: &str) -> String {
    vault::digest(format!("admin\0{}", email.to_ascii_lowercase()).as_bytes())
}

/// Record a company user from SSO. A disabled user stays disabled.
pub(super) fn record_user(state: &Path, id: &str, email: &str) -> Result<bool> {
    let _lock = vault::registry_lock(state, "registry.lock")?;
    let mut users = vault::users(state)?;
    if let Some(user) = users.iter_mut().find(|u| u.id == id) {
        if !user.enabled {
            return Ok(false);
        }
        user.email = email.into();
    } else {
        users.push(vault::User {
            id: id.into(),
            email: email.into(),
            enabled: true,
        });
    }
    vault::save_users(state, &users)?;
    Ok(true)
}

pub(super) fn add_machine(state: &Path, user: &str, name: &str) -> Result<(String, String)> {
    let _lock = vault::registry_lock(state, "registry.lock")?;
    let mut machines = vault::machines(state)?;
    let token = vault::secret();
    let id = format!("{name}-{}", &vault::secret()[..12]);
    machines.push(vault::Machine {
        id: id.clone(),
        user: user.into(),
        token_hash: vault::digest(token.as_bytes()),
        revoked: false,
    });
    vault::save_machines(state, &machines)?;
    Ok((id, token))
}

/// Enroll a machine without SSO, for an operator on the server host. Returns the machine ID
/// and its bearer token, which is shown once.
pub fn register(state: &Path, email: &str, name: &str) -> Result<(String, String)> {
    let id = user_id(email);
    if !record_user(state, &id, &email.to_ascii_lowercase())? {
        bail!("user is disabled");
    }
    add_machine(state, &id, name)
}

/// Revoke a machine from the server host, with an audit line.
pub fn revoke(state: &Path, key: &Path, machine: &str) -> Result<()> {
    {
        let _lock = vault::registry_lock(state, "registry.lock")?;
        let mut machines = vault::machines(state)?;
        machines
            .iter_mut()
            .find(|m| m.id == machine)
            .context("machine not found")?
            .revoked = true;
        vault::save_machines(state, &machines)?;
    }
    audit::record(
        state,
        key,
        &audit::Event {
            operation: "revoke",
            machine: "operator",
            account: "-",
            result: "ok",
            rotated: None,
            target: Some(machine),
        },
    )
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
        vault::users(&config.state)?;
        vault::machines(&config.state)?;
        // The engine holds the process lock: one server per state directory.
        let engine = Engine::open_at(&config.state, &config.key, config.endpoints)?;
        let sso = match config.sso {
            Some(sso) => Some(enrollment::Sso::load(&sso.config, &sso.public_url).await?),
            None => None,
        };
        Ok(Arc::new(Self {
            state: config.state,
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
        }))
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
    fn authorize(&self, headers: &HeaderMap) -> Result<vault::Machine, HttpError> {
        let bearer = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
            .ok_or_else(|| self.error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
        let unavailable = |_| self.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable");
        let hash = vault::digest(bearer.as_bytes());
        let machine = vault::machines(&self.state)
            .map_err(unavailable)?
            .into_iter()
            .find(|m| m.token_hash == hash && !m.revoked)
            .ok_or_else(|| self.error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
        let user = vault::users(&self.state)
            .map_err(unavailable)?
            .into_iter()
            .find(|u| u.id == machine.user && u.enabled)
            .ok_or_else(|| self.error(StatusCode::FORBIDDEN, "user_disabled"))?;
        if !self.allowed(&user.email) {
            return Err(self.error(StatusCode::FORBIDDEN, "user_not_allowed"));
        }
        Ok(machine)
    }
    fn engine_error(&self, error: &anyhow::Error, fallback: &'static str) -> HttpError {
        if error.downcast_ref::<Gone>().is_some() {
            self.error(StatusCode::GONE, "account_deleted")
        } else {
            self.error(StatusCode::SERVICE_UNAVAILABLE, fallback)
        }
    }
    fn audit(&self, event: &audit::Event) -> Result<(), HttpError> {
        self.engine
            .audit(event)
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
    let machine = server.authorize(&headers)?;
    Ok(private(json!({"id": machine.user, "machine": machine.id})))
}
async fn machines(State(server): Shared, headers: HeaderMap) -> Result<Response, HttpError> {
    let current = server.authorize(&headers)?;
    let machines = vault::machines(&server.state)
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable"))?;
    Ok(private(
        machines
            .into_iter()
            .filter(|m| m.user == current.user)
            .map(|m| json!({"id": m.id, "revoked": m.revoked}))
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
    let current = server.authorize(&headers)?;
    let input = body(&server, input)?;
    {
        let _lock = vault::registry_lock(&server.state, "registry.lock")
            .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "registry_busy"))?;
        let mut machines = vault::machines(&server.state)
            .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable"))?;
        machines
            .iter_mut()
            .find(|m| m.id == input.id && m.user == current.user)
            .ok_or_else(|| server.error(StatusCode::NOT_FOUND, "machine_not_found"))?
            .revoked = true;
        vault::save_machines(&server.state, &machines)
            .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "persistence_failed"))?;
    }
    server.audit(&audit::Event {
        operation: "revoke",
        machine: &current.id,
        account: "-",
        result: "ok",
        rotated: None,
        target: Some(&input.id),
    })?;
    Ok(StatusCode::NO_CONTENT)
}

async fn accounts(State(server): Shared, headers: HeaderMap) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers)?;
    Ok(private(server.engine.accounts(&machine.user).await))
}
async fn delete_account(
    State(server): Shared,
    headers: HeaderMap,
    UrlPath(id): UrlPath<String>,
) -> Result<StatusCode, HttpError> {
    let machine = server.authorize(&headers)?;
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
}
async fn token(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<Token>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers)?;
    let input = body(&server, input)?;
    let engine = server.engine.clone();
    let (user, machine_id) = (machine.user.clone(), machine.id.clone());
    let account = input.account_id.clone();
    let access = server
        .run(async move {
            engine
                .acquire_for(
                    &user,
                    &machine_id,
                    &account,
                    input.previous_revision.as_deref(),
                )
                .await
        })
        .await?
        .map_err(|e| server.engine_error(&e, "account_unavailable_or_login_required"))?;
    // A machine revoked while the refresh ran gets nothing.
    let authorized = server.authorize(&headers);
    server.audit(&audit::Event {
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
    })?;
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
async fn migrate(
    State(server): Shared,
    headers: HeaderMap,
    input: Body<Migration>,
) -> Result<Response, HttpError> {
    let machine = server.authorize(&headers)?;
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
        .map_err(|_| server.error(StatusCode::CONFLICT, "admission_refused_reconcile_receipt"))?;
    server.authorize(&headers)?;
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
    let machine = server.authorize(&headers)?;
    let receipt = server
        .engine
        .receipt(&machine.user, &input.migration_id)
        .await
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "receipt_unavailable"))?;
    Ok(private(json!({"receipt": receipt})))
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
    let machine = server.authorize(&headers)?;
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
    server.authorize(&headers)?;
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
    let machine = server.authorize(&headers)?;
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
    let machine = server.authorize(&headers)?;
    let input = body(&server, input)?;
    let engine = server.engine.clone();
    let result = server
        .run(async move {
            engine
                .finish_login(&machine.user, &machine.id, &input.id, &input.code)
                .await
        })
        .await?
        .map_err(|_| server.error(StatusCode::CONFLICT, "login_incomplete_grant_retained"))?;
    server.authorize(&headers)?;
    Ok(private(result))
}

async fn health() -> StatusCode {
    StatusCode::OK
}
async fn ready(State(server): Shared) -> StatusCode {
    if vault::users(&server.state).is_ok() && vault::machines(&server.state).is_ok() {
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
        server.authorize(&headers)?;
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
        .route("/v2/anthropic/migrations", post(migrate).get(receipt));
    enrollment::routes(routes).with_state(server)
}

/// Serve until SIGTERM or Ctrl-C. A network listener needs an HTTPS public origin and company SSO.
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
    axum::serve(listener, router(server))
        .with_graceful_shutdown(async {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        })
        .await?;
    Ok(())
}

pub fn set_user(state: &Path, email: &str, enabled: bool) -> Result<()> {
    let _lock = vault::registry_lock(state, "registry.lock")?;
    let mut users = vault::users(state)?;
    let user = users
        .iter_mut()
        .find(|u| u.email.eq_ignore_ascii_case(email))
        .context("user not found")?;
    user.enabled = enabled;
    vault::save_users(state, &users)
}
