//! Account-server client. This module never exchanges provider refresh tokens.
use crate::{config::Paths, profile};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[path = "central_migration.rs"]
mod migration;
#[path = "central_qualify.rs"]
mod qualify;
#[path = "central_renew.rs"]
mod renew;
#[path = "central_session.rs"]
pub mod session;
pub use migration::{
    ensure_local, ensure_local_grant, ensure_login_unfenced, ensure_removable, is_migrated, migrate,
};

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub account_uuid: String,
    pub organization_uuid: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Access {
    pub provider: String,
    pub account_id: String,
    pub user_id: String,
    pub identity: Identity,
    pub access_token: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    pub revision: String,
    pub generation: u64,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Account {
    pub provider: String,
    pub account_id: String,
    pub alias: String,
    pub identity: Identity,
    pub available: bool,
}
#[derive(Clone, Deserialize, Serialize)]
pub struct Usage {
    pub data: Option<Value>,
    pub observed_at: Option<i64>,
    pub next_retry_at: i64,
    pub stale: bool,
    pub error: Option<String>,
}
#[derive(Deserialize, Serialize)]
pub struct Receipt {
    pub account_id: String,
    pub identity: Identity,
    pub migration_id: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Connection {
    pub server: String,
    pub user_id: String,
    token_file: PathBuf,
}
#[derive(Clone)]
pub struct Client {
    pub connection: Connection,
    token: String,
    http: reqwest::blocking::Client,
}

pub(super) fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
pub(super) fn root(paths: &Paths) -> PathBuf {
    paths.claudectl_dir().join("server")
}
pub(super) fn private_dir(path: &Path) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_dir() || m.file_type().is_symlink()) {
        bail!("server directory must be a real directory");
    }
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
pub(super) fn atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("file has no parent")?;
    private_dir(parent)?;
    if std::fs::symlink_metadata(path).is_ok_and(|m| !m.is_file() || m.file_type().is_symlink()) {
        bail!("server state must be a regular file");
    }
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    tmp.write_all(&serde_json::to_vec(value)?)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .map_err(|_| anyhow::anyhow!("server state publication failed"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub(super) fn private_read(path: &Path) -> Result<Vec<u8>> {
    let m = std::fs::symlink_metadata(path)?;
    if !m.is_file() || m.file_type().is_symlink() {
        bail!("server credential must be a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if m.permissions().mode() & 0o077 != 0 {
            bail!("server credentials must have mode 0600");
        }
    }
    Ok(std::fs::read(path)?)
}
pub(super) fn lock(paths: &Paths) -> Result<File> {
    let dir = root(paths);
    private_dir(&dir)?;
    let path = dir.join("state.lock");
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!("server lock must not be a symlink");
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let file = opts.open(path)?;
    file.try_lock()
        .context("another account-server operation is running")?;
    Ok(file)
}
pub fn origin(server: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(server)
        .map_err(|_| anyhow::anyhow!("invalid account-server origin"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"));
    let test = std::env::var("CLAUDECTL_ALLOW_INSECURE_LOOPBACK").as_deref() == Ok("1");
    if !(url.scheme() == "https" || (test && loopback && url.scheme() == "http"))
        || url.host_str().is_none()
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("account server must be an HTTPS origin");
    }
    Ok(url)
}
fn http() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(40))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()?)
}
/// The account server answered with an error status; `reason` is its `error` field.
#[derive(Debug)]
pub struct ServerError {
    pub status: u16,
    pub reason: String,
}
impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "account server returned HTTP {} ({}); credentials were not changed",
            self.status, self.reason
        )
    }
}
impl std::error::Error for ServerError {}
/// The account server could not be reached, or its reply was lost.
#[derive(Debug)]
pub struct Unavailable;
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("account server unavailable; reconcile pending operations")
    }
}
impl std::error::Error for Unavailable {}
/// True when the server cannot serve now: unreachable, a lost reply, or HTTP 5xx.
pub fn server_down(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Unavailable>().is_some()
        || error
            .downcast_ref::<ServerError>()
            .is_some_and(|e| e.status >= 500)
}
fn checked(response: reqwest::blocking::Response) -> Result<reqwest::blocking::Response> {
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let reason = response
            .json::<Value>()
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".into());
        return Err(ServerError { status, reason }.into());
    }
    Ok(response)
}
impl Client {
    pub fn load(paths: &Paths) -> Result<Self> {
        let dir = root(paths);
        let connection: Connection =
            serde_json::from_slice(&private_read(&dir.join("connection.json"))?)
                .map_err(|_| anyhow::anyhow!("invalid account-server connection"))?;
        if connection.token_file != dir.join("machine.json") {
            bail!("unexpected machine credential path");
        }
        let token: String = serde_json::from_slice(&private_read(&connection.token_file)?)
            .map_err(|_| anyhow::anyhow!("invalid machine credential"))?;
        origin(&connection.server)?;
        Ok(Self {
            connection,
            token,
            http: http()?,
        })
    }
    fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T> {
        checked(
            self.http
                .get(format!("{}{path}", self.connection.server))
                .bearer_auth(&self.token)
                .send()
                .map_err(|_| Unavailable)?,
        )?
        .json()
        // A broken reply is a broken server: callers stop instead of continuing blind.
        .map_err(|_| anyhow::Error::from(Unavailable))
    }
    pub(super) fn post<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T> {
        checked(
            self.http
                .post(format!("{}{path}", self.connection.server))
                .bearer_auth(&self.token)
                .json(body)
                .send()
                .map_err(|_| Unavailable)?,
        )?
        .json()
        // A reply that cannot be read is a lost reply: the server may have acted.
        .map_err(|_| anyhow::Error::from(Unavailable))
    }
    pub fn accounts(&self) -> Result<Vec<Account>> {
        let accounts: Vec<Account> = self.get("/v2/anthropic/accounts")?;
        if accounts.iter().any(|a| a.provider != "anthropic") {
            bail!("unexpected account provider");
        }
        Ok(accounts)
    }
    pub fn account(&self, alias: &str) -> Result<Account> {
        let alias = profile::validate_alias(alias)?;
        let mut selected = self
            .accounts()?
            .into_iter()
            .filter(|a| a.alias.eq_ignore_ascii_case(alias));
        let account = selected.next().context("server account not found")?;
        if selected.next().is_some() {
            bail!("ambiguous server alias");
        }
        Ok(account)
    }
    pub fn acquire(&self, id: &str, previous: Option<&str>) -> Result<Access> {
        let access: Access = self.post(
            "/v2/anthropic/token",
            &json!({"account_id":id,"previous_revision":previous}),
        )?;
        if access.provider != "anthropic"
            || access.account_id != id
            || access.user_id != self.connection.user_id
            || access.access_token.is_empty()
            || access.expires_at <= now()
            || access.revision.is_empty()
            || access.generation == 0
        {
            bail!("invalid or mismatched access grant");
        }
        Ok(access)
    }
    pub fn usage(&self, id: &str, cached: bool) -> Result<Usage> {
        self.get(&format!(
            "/v2/anthropic/usage?account_id={}&cached={cached}",
            urlencoding::encode(id)
        ))
    }
    /// The machine's company user; a preflight that the server is reachable and accepts us.
    pub fn me(&self) -> Result<String> {
        let me: Value = self.get("/v1/me")?;
        let id = me["id"].as_str().context("invalid company-user identity")?;
        if id != self.connection.user_id {
            bail!("machine belongs to another company user");
        }
        Ok(id.into())
    }
    pub(super) fn receipt(&self, id: &str) -> Result<Option<Receipt>> {
        Ok(self.receipt_state(id)?.0)
    }
    /// Ask the server to cancel a migration ID that has not committed.
    pub(super) fn cancel_migration(&self, alias: &str, id: &str) -> Result<()> {
        let reply: Value = self.post(
            "/v2/anthropic/migrations/cancel",
            &json!({"alias": alias, "migration_id": id}),
        )?;
        if reply["state"] != "cancelled" {
            bail!("the server did not confirm the cancel");
        }
        Ok(())
    }
    /// The receipt and the server's admission state: `none`, `pending` or `complete`.
    pub(super) fn receipt_state(&self, id: &str) -> Result<(Option<Receipt>, String)> {
        #[derive(Deserialize)]
        struct Reply {
            receipt: Option<Receipt>,
            /// Servers before the state field answer without it.
            state: Option<String>,
        }
        let reply: Reply = self.get(&format!(
            "/v2/anthropic/migrations?migration_id={}",
            urlencoding::encode(id)
        ))?;
        let state = reply.state.unwrap_or_else(|| {
            if reply.receipt.is_some() {
                "complete"
            } else {
                "unknown"
            }
            .into()
        });
        Ok((reply.receipt, state))
    }
}
pub fn connect(paths: &Paths, server: &str, name: &str, no_browser: bool) -> Result<()> {
    let _lock = lock(paths)?;
    let dir = root(paths);
    if dir.join("connection.json").exists() || dir.join("machine.json").exists() {
        bail!("machine already connected or enrollment incomplete; disconnect before retrying");
    }
    let url = origin(server)?;
    let server = server.trim_end_matches('/');
    let http = http()?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Challenge {
        device_code: String,
        user_code: String,
        verification_url: String,
        expires_in: u64,
        interval: u64,
    }
    let challenge: Challenge = checked(
        http.post(format!("{server}/v1/enrollment/start"))
            .json(&json!({"name":name,"providers":["anthropic"]}))
            .send()?,
    )?
    .json()?;
    let verification = reqwest::Url::parse(&challenge.verification_url)?;
    if verification.origin() != url.origin()
        || verification.path() != "/enroll"
        || challenge.expires_in > 600
        || !(1..=10).contains(&challenge.interval)
    {
        bail!("invalid enrollment challenge");
    }
    println!(
        "Company sign-in: {}\nConfirm code: {}",
        challenge.verification_url, challenge.user_code
    );
    if !no_browser {
        open::that(&challenge.verification_url)
            .context("open the displayed company sign-in link")?;
    }
    let deadline = Instant::now() + Duration::from_secs(challenge.expires_in);
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Grant {
        device_token: String,
    }
    let token = loop {
        if Instant::now() >= deadline {
            bail!("enrollment expired");
        }
        let r = http
            .post(format!("{server}/v1/enrollment/poll"))
            .json(&json!({"device_code":challenge.device_code}))
            .send()?;
        if matches!(r.status().as_u16(), 202 | 429) {
            std::thread::sleep(Duration::from_secs(challenge.interval));
            continue;
        }
        break checked(r)?.json::<Grant>()?.device_token;
    };
    let me: Value = checked(
        http.get(format!("{server}/v1/me"))
            .bearer_auth(&token)
            .send()?,
    )?
    .json()?;
    let user = me["id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("invalid company-user identity")?;
    if token.len() < 32 {
        bail!("invalid machine credential");
    }
    let connection = Connection {
        server: server.into(),
        user_id: user.into(),
        token_file: dir.join("machine.json"),
    };
    atomic(&connection.token_file, &token)?;
    atomic(&dir.join("connection.json"), &connection)?;
    println!("Machine connected for Claude accounts.");
    Ok(())
}
/// A newly acquired login must survive a later local persistence/activation failure.
pub fn retain_login(
    paths: &Paths,
    alias: &str,
    creds: &crate::api::CredentialsFile,
    account: &Option<Value>,
) -> Result<PathBuf> {
    ensure_login_unfenced(&paths.claudectl_dir(), alias, creds, account)?;
    let path = paths
        .claudectl_dir()
        .join("retained-logins")
        .join(format!("{}.json", crate::oauth::generate_state()));
    atomic(&path, &json!({"credentials":creds,"oauth_account":account}))?;
    Ok(path)
}
pub fn disconnect(paths: &Paths) -> Result<()> {
    let _lock = lock(paths)?;
    let dir = root(paths);
    for name in ["connection.json", "machine.json"] {
        let p = dir.join(name);
        if p.exists() {
            std::fs::remove_file(p)?;
        }
    }
    File::open(dir)?.sync_all()?;
    println!("Machine disconnected; migrated accounts remain on the server.");
    Ok(())
}
pub fn login(client: &Client, alias: &str, renew: bool, no_browser: bool) -> Result<()> {
    #[derive(Deserialize)]
    struct Login {
        id: String,
        authorize_url: String,
        expires_at: i64,
    }
    let login: Login = client.post(
        "/v2/anthropic/login/start",
        &json!({"alias":alias,"renew":renew}),
    )?;
    let url = reqwest::Url::parse(&login.authorize_url)?;
    if url.scheme() != "https"
        || url.host_str() != Some("claude.ai")
        || url.path() != "/oauth/authorize"
        || login.expires_at <= now()
    {
        bail!("invalid Claude login challenge");
    }
    println!("Claude sign-in: {}", login.authorize_url);
    if !no_browser {
        open::that(&login.authorize_url)?;
    }
    let code = dialoguer::Password::new()
        .with_prompt("Paste code#state from the Claude sign-in page")
        .interact()?;
    let receipt: Receipt = client.post(
        "/v2/anthropic/login/complete",
        &json!({"id":login.id,"code":code}),
    ).with_context(|| format!("login result retained if acquired; retry verification with claudectl server complete-login {} --resume", login.id))?;
    println!("Server account saved: {} ({})", alias, receipt.account_id);
    Ok(())
}
#[derive(Serialize, Deserialize)]
struct CachedUsage {
    server: String,
    user_id: String,
    account: Account,
    usage: Usage,
}
fn cache_path(paths: &Paths, alias: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let hash = format!(
        "{:x}",
        Sha256::digest(alias.to_ascii_lowercase().as_bytes())
    );
    root(paths).join("status").join(format!("{hash}.json"))
}
fn cached_connection(paths: &Paths) -> Option<Connection> {
    private_read(&root(paths).join("connection.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
}
pub(super) fn usage_path(paths: &Paths, connection: &Connection, id: &str) -> PathBuf {
    use sha2::{Digest, Sha256};
    let scope = format!(
        "{:x}",
        Sha256::digest(format!("{}\0{}", connection.server, connection.user_id).as_bytes())
    );
    root(paths)
        .join("usage")
        .join(scope)
        .join(format!("{id}.json"))
}
fn stale(usage: &Usage) -> bool {
    usage.stale
        || usage.error.is_some()
        || usage.next_retry_at <= now()
        || usage
            .observed_at
            .is_none_or(|at| at > now() || at.saturating_add(300_000) <= now())
}
/// A saved server read, if it belongs to the current server and user.
fn cached_entry(paths: &Paths, connection: &Connection, file: &Path) -> Option<CachedUsage> {
    let mut cache = private_read(file)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CachedUsage>(&bytes).ok())
        .filter(|cache| connection.server == cache.server && connection.user_id == cache.user_id)?;
    // The file name is the alias digest: a renamed copy is not this alias.
    (cache_path(paths, &cache.account.alias) == file).then(|| {
        cache.usage.stale = stale(&cache.usage);
        cache
    })
}
/// The last usage this machine read for `alias` from its current server, if any.
fn cached_usage(paths: &Paths, alias: &str) -> Option<Usage> {
    let connection = cached_connection(paths)?;
    cached_entry(paths, &connection, &cache_path(paths, alias))
        .filter(|cache| cache.account.alias.eq_ignore_ascii_case(alias))
        .map(|cache| cache.usage)
}
fn save_usage(paths: &Paths, client: &Client, account: &Account, usage: &Usage) -> Result<()> {
    atomic(
        &cache_path(paths, &account.alias),
        &CachedUsage {
            server: client.connection.server.clone(),
            user_id: client.connection.user_id.clone(),
            account: account.clone(),
            usage: usage.clone(),
        },
    )
}
fn read_usage(paths: &Paths, alias: &str, cached: bool) -> Result<Usage> {
    let alias = profile::validate_alias(alias)?;
    if cached {
        return Ok(cached_usage(paths, alias).unwrap_or(Usage {
            data: None,
            observed_at: None,
            next_retry_at: 0,
            stale: true,
            error: Some("no saved usage".into()),
        }));
    }
    let client = Client::load(paths)?;
    let account = client.account(alias)?;
    let usage = client.usage(&account.account_id, false)?;
    save_usage(paths, &client, &account, &usage)?;
    Ok(usage)
}
pub fn status(paths: &Paths, alias: &str, cached: bool, json: bool) -> Result<()> {
    let usage = read_usage(paths, alias, cached)?;
    if json {
        println!("{}", serde_json::to_string(&usage)?);
        return Ok(());
    }
    let windows: Option<crate::api::UsageResponse> = usage
        .data
        .clone()
        .and_then(|data| serde_json::from_value(data).ok());
    let mut table = table(&["Window", "Used", "Resets"]);
    if let Some(windows) = &windows {
        for (name, window) in [
            ("5h", &windows.five_hour),
            ("week", &windows.seven_day),
            ("week Opus", &windows.seven_day_opus),
            ("week Sonnet", &windows.seven_day_sonnet),
        ] {
            if let Some(window) = window {
                table.add_row(vec![
                    name.to_string(),
                    window
                        .utilization
                        .map_or("-".into(), |used| format!("{used:.0}%")),
                    window.resets_at.clone().unwrap_or_else(|| "-".into()),
                ]);
            }
        }
    }
    println!("{alias} (account server)");
    if table.row_count() > 0 {
        println!("{table}");
    }
    match usage.observed_at {
        Some(at) => println!(
            "Observed {} ago{}.",
            ago(now().saturating_sub(at)),
            if usage.stale { "; stale" } else { "" }
        ),
        None => println!("No usage observed yet."),
    }
    if let Some(error) = &usage.error {
        println!("Server reports: {error}");
    }
    Ok(())
}
fn ago(ms: i64) -> String {
    let seconds = (ms / 1000).max(0);
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        _ => format!("{}h", seconds / 3600),
    }
}
/// A plain table; colour is left to callers that give it meaning.
fn table(header: &[&str]) -> comfy_table::Table {
    let mut table = comfy_table::Table::new();
    table.load_preset(comfy_table::presets::UTF8_FULL);
    table.apply_modifier(comfy_table::modifiers::UTF8_ROUND_CORNERS);
    table.set_header(header.to_vec());
    table
}
/// One server account as `claudectl status` shows it.
pub struct ServerRow {
    pub alias: String,
    pub available: bool,
    pub usage: std::result::Result<Usage, String>,
}
/// What the account server reports for `claudectl status`.
pub enum ServerView {
    NotConnected,
    Unreachable(String),
    Rows(Vec<ServerRow>),
}
/// Every server account with its usage. The server answers usage from its cache and polls
/// the provider at most once per 5 minutes, so the reads run in parallel. `cached` reads
/// only this machine's saved copies of the `known` aliases and sends nothing.
pub fn server_view(paths: &Paths, cached: bool, known: &[String]) -> ServerView {
    let Some(connection) = cached_connection(paths) else {
        return ServerView::NotConnected;
    };
    if cached {
        // Every account this machine last read from the server, with what the server said.
        let mut rows: Vec<ServerRow> = std::fs::read_dir(root(paths).join("status"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| cached_entry(paths, &connection, &entry.path()))
            .map(|cache| ServerRow {
                alias: cache.account.alias,
                available: cache.account.available,
                usage: Ok(cache.usage),
            })
            .collect();
        for alias in known {
            if !rows.iter().any(|r| r.alias.eq_ignore_ascii_case(alias)) {
                rows.push(ServerRow {
                    alias: alias.clone(),
                    available: true,
                    usage: Err("no saved usage".into()),
                });
            }
        }
        rows.sort_by(|a, b| a.alias.cmp(&b.alias));
        return ServerView::Rows(rows);
    }
    let client = match Client::load(paths) {
        Ok(client) => client,
        Err(error) => return ServerView::Unreachable(format!("{error:#}")),
    };
    let accounts = match client.accounts() {
        Ok(accounts) => accounts,
        Err(error) => return ServerView::Unreachable(format!("{error:#}")),
    };
    let client = &client;
    ServerView::Rows(std::thread::scope(|scope| {
        let reads: Vec<_> = accounts
            .into_iter()
            .map(|account| {
                scope.spawn(move || {
                    let usage = client.usage(&account.account_id, false);
                    if let Ok(usage) = &usage
                        && let Err(error) = save_usage(paths, client, &account, usage)
                    {
                        eprintln!(
                            "warning: server usage of {} not saved: {error:#}",
                            account.alias
                        );
                    }
                    ServerRow {
                        alias: account.alias,
                        available: account.available,
                        usage: usage.map_err(|error| format!("{error:#}")),
                    }
                })
            })
            .collect();
        reads
            .into_iter()
            .map(|read| read.join().expect("server usage read panicked"))
            .collect()
    }))
}
pub fn statusline(paths: &Paths, id: &str) -> Result<()> {
    if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid server account identifier");
    }
    let usage = cached_connection(paths)
        .and_then(|connection| private_read(&usage_path(paths, &connection, id)).ok())
        .and_then(|v| serde_json::from_slice::<Usage>(&v).ok());
    match usage {
        Some(u) if !stale(&u) => {
            let data = u.data.unwrap_or(Value::Null);
            let value = |name: &str| {
                data.get(name)
                    .and_then(|v| v.get("utilization"))
                    .and_then(Value::as_f64)
                    .map(|n| format!("{n:.0}%"))
                    .unwrap_or_else(|| "Unknown".into())
            };
            println!(
                "Claude 5h {} · 7d {}",
                value("five_hour"),
                value("seven_day")
            );
        }
        _ => println!("Claude usage Unknown (stale or unavailable)"),
    }
    Ok(())
}

/// Account-server operations are separate from local profile switching.
#[derive(clap::Subcommand)]
pub enum Command {
    /// Enroll this machine with company SSO
    Connect {
        server: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        no_browser: bool,
    },
    /// List accounts belonging to the enrolled company user
    Accounts {
        /// Print the raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Sign in directly on the server; refresh credentials never reach this client
    Login {
        alias: String,
        #[arg(long)]
        no_browser: bool,
    },
    /// Complete a browser login, or retry verification of its retained result
    CompleteLogin {
        id: String,
        #[arg(long)]
        resume: bool,
    },
    /// Force a new access token; every running server session of this account loses its
    /// token (a refresh revokes the previous one) and must be relaunched with --resume
    RefreshAccess { alias: String },
    /// Repair an existing server grant through identity-pinned sign-in
    Renew {
        alias: String,
        #[arg(long)]
        no_browser: bool,
    },
    /// Run the tested Claude build with access-only credentials
    Run {
        alias: String,
        #[arg(long, default_value = "claude")]
        claude: PathBuf,
        #[arg(last = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Qualify a Claude build: run the synthetic renewal handoff check, record it only on a pass
    Qualify {
        #[arg(long, default_value = "claude")]
        claude: PathBuf,
    },
    /// Read subscription usage; --cached works entirely offline
    Status {
        alias: String,
        #[arg(long)]
        cached: bool,
        /// Print the raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Read the local session usage cache without network access
    Statusline { account_id: String },
    /// Record a Claude hook event for a running server session (internal; never fails)
    #[command(hide = true)]
    Hook { dir: PathBuf },
    /// Transfer a profile, or every saved account with --all, after stopping every previous
    /// grant holder
    Migrate {
        #[arg(required_unless_present_any = ["all", "abort"], conflicts_with_all = ["all", "abort"])]
        alias: Option<String>,
        /// Every saved account: inactive ones first, the live login last
        #[arg(long, conflicts_with = "abort")]
        all: bool,
        /// Declare all other copies and sessions retired, including backups and other machines
        #[arg(long)]
        exclusive_owner: bool,
        /// Drop a fence the server never admitted (restores the grant), or whose server
        /// account is gone
        #[arg(long, value_name = "ALIAS")]
        abort: Option<String>,
    },
    /// List enrolled machines for the current company user
    Devices {
        /// Print the raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Stop a machine from acquiring further access tokens
    Revoke { machine_id: String },
    /// Delete a server account and its refresh grant; tokens already issued expire on their own
    Remove { alias: String },
    /// Remove this machine's local connection; does not revoke it on the server
    Disconnect,
}
pub fn dispatch(command: Command) -> Result<()> {
    let paths = crate::config::default_paths()?;
    match command {
        Command::Connect {
            server,
            name,
            no_browser,
        } => connect(&paths, &server, &name, no_browser),
        Command::Disconnect => disconnect(&paths),
        Command::Status {
            alias,
            cached,
            json,
        } => status(&paths, &alias, cached, json),
        Command::Statusline { account_id } => statusline(&paths, &account_id),
        Command::Hook { dir } => {
            // A hook never blocks or talks to Claude: no output, exit 0 whatever happens. A
            // failure leaves the session's error marker, so renewal stops (fail closed).
            let _ = renew::hook_from(
                &root(&paths).join("sessions"),
                &dir,
                std::io::stdin(),
                now(),
            );
            Ok(())
        }
        Command::Qualify { claude } => qualify::qualify(&paths, &claude),
        command => {
            let client = Client::load(&paths)?;
            match command {
                Command::CompleteLogin { id, resume } => {
                    let code = if resume {
                        String::new()
                    } else {
                        dialoguer::Password::new()
                            .with_prompt("Paste code#state")
                            .interact()?
                    };
                    let receipt: Receipt = client.post(
                        "/v2/anthropic/login/complete",
                        &json!({"id":id,"code":code}),
                    )?;
                    println!("Server account saved: {}", receipt.account_id);
                    Ok(())
                }
                Command::RefreshAccess { alias } => {
                    let account = client.account(&alias)?;
                    let current = client.acquire(&account.account_id, None)?;
                    client.acquire(&account.account_id, Some(&current.revision))?;
                    println!(
                        "Access token refreshed. The previous token is revoked: relaunch every running `server run` of {alias} with --resume."
                    );
                    Ok(())
                }
                Command::Accounts { json } => {
                    let accounts = client.accounts()?;
                    if json {
                        println!("{}", serde_json::to_string(&accounts)?);
                        return Ok(());
                    }
                    let mut table = table(&["Account", "Available", "Claude account"]);
                    for account in &accounts {
                        table.add_row(vec![
                            account.alias.clone(),
                            if account.available { "yes" } else { "no" }.into(),
                            account.identity.account_uuid.chars().take(8).collect(),
                        ]);
                    }
                    println!("{table}");
                    Ok(())
                }
                Command::Login { alias, no_browser } => login(&client, &alias, false, no_browser),
                Command::Renew { alias, no_browser } => login(&client, &alias, true, no_browser),
                Command::Migrate {
                    alias,
                    all,
                    exclusive_owner,
                    abort,
                } => match (alias, all, abort) {
                    (_, _, Some(alias)) => migration::abort(&paths, &client, &alias),
                    (_, true, None) => {
                        if !migration::migrate_all(&paths, &client, exclusive_owner)? {
                            std::process::exit(1);
                        }
                        Ok(())
                    }
                    (Some(alias), false, None) => migrate(&paths, &client, &alias, exclusive_owner),
                    (None, false, None) => unreachable!("clap requires an alias, --all or --abort"),
                },
                Command::Run {
                    alias,
                    claude,
                    args,
                } => {
                    let code = session::run(&paths, &client, &alias, &claude, &args)?;
                    std::process::exit(code)
                }
                Command::Devices { json } => {
                    let devices: Value = client.get("/v1/devices")?;
                    if json {
                        println!("{devices}");
                        return Ok(());
                    }
                    let mut table = table(&["Machine", "Revoked"]);
                    for device in devices.as_array().into_iter().flatten() {
                        table.add_row(vec![
                            device["id"].as_str().unwrap_or("-").to_string(),
                            if device["revoked"].as_bool() == Some(true) {
                                "yes"
                            } else {
                                "no"
                            }
                            .into(),
                        ]);
                    }
                    println!("{table}");
                    Ok(())
                }
                Command::Revoke { machine_id } => {
                    checked(
                        client
                            .http
                            .post(format!("{}/v1/devices/revoke", client.connection.server))
                            .bearer_auth(&client.token)
                            .json(&json!({"id":machine_id}))
                            .send()
                            .map_err(|_| Unavailable)?,
                    )?;
                    println!("Machine revoked.");
                    Ok(())
                }
                Command::Remove { alias } => {
                    let account = client.account(&alias)?;
                    checked(
                        client
                            .http
                            .delete(format!(
                                "{}/v2/anthropic/accounts/{}",
                                client.connection.server, account.account_id
                            ))
                            .bearer_auth(&client.token)
                            .send()
                            .map_err(|_| Unavailable)?,
                    )?;
                    println!(
                        "Server account removed. Access tokens already issued stay valid until they expire."
                    );
                    Ok(())
                }
                _ => unreachable!(),
            }
        }
    }
}
