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

#[path = "central_failover.rs"]
mod failover;
#[path = "central_migration.rs"]
mod migration;
#[path = "central_qualify.rs"]
mod qualify;
#[path = "central_renew.rs"]
mod renew;
#[path = "central_session.rs"]
pub mod session;
#[cfg(unix)]
#[path = "central_shim.rs"]
pub mod shim;
pub use migration::{
    ensure_local, ensure_local_grant, ensure_login_unfenced, ensure_removable, is_fenced,
    is_migrated, migrate,
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
/// A token grant from the server, refused unless it is for this account and user, complete,
/// and still valid now (a grant can cross expiry in transit).
fn checked_access(access: Access, id: &str, user_id: &str) -> Result<Access> {
    if access.provider != "anthropic"
        || access.account_id != id
        || access.user_id != user_id
        || access.access_token.is_empty()
        || access.expires_at <= now()
        || access.revision.is_empty()
        || access.generation == 0
    {
        bail!("invalid or mismatched access grant");
    }
    Ok(access)
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
    /// The server account `name` names: the full alias, its email local part (`amir2`),
    /// or a unique prefix (`crate::accounts::resolve`).
    pub fn account(&self, name: &str) -> Result<Account> {
        let name = profile::validate_alias(name)?;
        let accounts = self.accounts()?;
        let aliases: Vec<&str> = accounts.iter().map(|a| a.alias.as_str()).collect();
        let alias = crate::accounts::resolve(name, &aliases)?.to_owned();
        let mut selected = accounts
            .into_iter()
            .filter(|a| a.alias.eq_ignore_ascii_case(&alias));
        let account = selected.next().context("server account not found")?;
        if selected.next().is_some() {
            bail!("ambiguous server alias\nTry: claudectl status");
        }
        Ok(account)
    }
    pub fn acquire(&self, id: &str, previous: Option<&str>) -> Result<Access> {
        checked_access(
            self.post(
                "/v2/anthropic/token",
                &json!({"account_id":id,"previous_revision":previous}),
            )?,
            id,
            &self.connection.user_id,
        )
    }
    /// The current token without refreshing an unexpired one (SAW-12657): a session that
    /// watches for a new revision must never revoke the token another session's turn uses.
    pub fn observe(&self, id: &str) -> Result<Access> {
        checked_access(
            self.post(
                "/v2/anthropic/token",
                &json!({"account_id":id,"observe":true}),
            )?,
            id,
            &self.connection.user_id,
        )
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
/// The Claude sign-in pages a server may send: the one before Claude Code 2.1.295, and the one it uses.
fn claude_authorize(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && matches!(
            (url.host_str(), url.path()),
            (Some("claude.ai"), "/oauth/authorize") | (Some("claude.com"), "/cai/oauth/authorize")
        )
}
/// The pasted `code#state`, checked before any network call: the server's own format, and
/// the state of the sign-in this command opened (`url`). Errors never repeat the paste.
fn check_code(pasted: &str, url: &reqwest::Url) -> Result<String> {
    let pasted = pasted.trim();
    let Some((_, state)) = pasted
        .split_once('#')
        .filter(|(code, state)| !code.is_empty() && !state.is_empty())
    else {
        bail!(
            "the pasted text is not the code#state from the Claude sign-in page\nTry: copy the whole code from the page (it has a # in the middle) and run the command again"
        );
    };
    let expected = url
        .query_pairs()
        .find(|(name, _)| name == "state")
        .map(|(_, value)| value.into_owned());
    if expected.as_deref() != Some(state) {
        bail!(
            "the pasted code is from another sign-in, not the one this command opened\nTry: run the command again and paste the code from the page it opens"
        );
    }
    Ok(pasted.to_string())
}
/// The `code#state` from the Claude sign-in page: a visible prompt on a terminal, otherwise
/// one line from `input`, so `add` also works from a script. `add`, `renew` and `server login`
/// all come here, so the Try line names no command.
fn read_code(mut input: impl std::io::BufRead, terminal: bool) -> Result<String> {
    let prompt = "Paste the code from the Claude sign-in page (code#state)";
    if terminal {
        return Ok(dialoguer::Input::<String>::new()
            .with_prompt(prompt)
            .interact_text()?);
    }
    eprintln!("{prompt}:");
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        bail!(
            "no code on standard input\nTry: echo '<code#state>' | <the same command> --no-browser"
        );
    }
    Ok(line.trim_end().to_string())
}
/// A failed login completion in plain words, by the server's reason. `id` is the login,
/// for the reasons where the server kept the acquired grant and the login can resume.
fn login_failure(reason: &str, id: &str) -> Option<String> {
    Some(match reason {
        "login_identity_changed" => "this sign-in is a different Claude account or organization than the saved one (a plan change can move the account to a new organization). Renewal never changes identity: run claudectl server remove <alias>, then claudectl server login <alias>".into(),
        "login_exchange_rejected" => "Claude rejected the sign-in code. Start again and paste the newest code#state within a few minutes".into(),
        "login_state_mismatch" => "the pasted code belongs to another sign-in. Paste the code#state shown for this login".into(),
        "login_expired" => "this sign-in expired. Start the login again".into(),
        "login_identity_lookup_failed" => format!("Claude did not confirm which account signed in; the server kept the sign-in result. Retry verification with claudectl server complete-login {id} --resume; if it repeats, the account may be blocked"),
        _ => return None,
    })
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
    if !claude_authorize(&url) || login.expires_at <= now() {
        bail!(
            "invalid Claude login challenge from the account server\nTry: claudectl add <name> again in a minute; if it repeats, check claudectl status"
        );
    }
    println!("Claude sign-in: {}", login.authorize_url);
    if !no_browser {
        open::that(&login.authorize_url)?;
    }
    // The prompt reads the terminal and draws on stderr: both must be the terminal.
    let terminal = {
        use std::io::IsTerminal;
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
    };
    let code = check_code(&read_code(std::io::stdin().lock(), terminal)?, &url)?;
    let receipt: Receipt = client
        .post(
            "/v2/anthropic/login/complete",
            &json!({"id":login.id,"code":code}),
        )
        .map_err(|error| {
            let plain = error
                .downcast_ref::<ServerError>()
                .and_then(|e| login_failure(&e.reason, &login.id));
            match plain {
                Some(plain) => error.context(plain),
                None => error.context(format!("login result retained if acquired; retry verification with claudectl server complete-login {} --resume", login.id)),
            }
        })?;
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
        let aliases = server_aliases(paths, true);
        let alias = match aliases.is_empty() {
            true => alias,
            false => crate::accounts::resolve(alias, &aliases)?,
        };
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
    print!("{}", status_text(alias, &usage, now()));
    Ok(())
}
/// The `server status` summary. Its lines and table are a contract: the capacity guard reads
/// them (SAW-12710; `server_status_text_keeps_its_lines_and_table`).
fn status_text(alias: &str, usage: &Usage, now: i64) -> String {
    let windows: Option<crate::api::UsageResponse> = usage
        .data
        .clone()
        .and_then(|data| serde_json::from_value(data).ok());
    let mut table = table(&["Window", "Used", "Resets"]);
    if let Some(windows) = &windows {
        // Every window the compact status shows (Fable included), with human reset times.
        for row in crate::accounts::detail_rows(windows, now / 1000) {
            table.add_row(row.to_vec());
        }
    }
    let mut out = format!("{alias} (account server)\n");
    if table.row_count() > 0 {
        out.push_str(&format!("{table}\n"));
    }
    match usage.observed_at {
        Some(at) => out.push_str(&format!(
            "Observed {} ago{}.\n",
            ago(now.saturating_sub(at)),
            if usage.stale { "; stale" } else { "" }
        )),
        None => out.push_str("No usage observed yet.\n"),
    }
    if let Some(error) = &usage.error {
        out.push_str(&format!("Server reports: {error}\n"));
    }
    out
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
    /// The server did not answer, or (`rejected`) answered with a 4xx refusal such as a
    /// revoked machine. `aliases`: every account this machine read from it before, and the
    /// `known` aliases.
    Unreachable {
        error: String,
        rejected: bool,
        aliases: Vec<String>,
    },
    Rows(Vec<ServerRow>),
}
/// Every account this machine last read from the server, with what the server said, plus
/// the `known` aliases it never read.
fn cached_rows(
    paths: &Paths,
    connection: &Connection,
    known: &[String],
    wanted: &dyn Fn(&str) -> bool,
) -> Vec<ServerRow> {
    let mut rows: Vec<ServerRow> = std::fs::read_dir(root(paths).join("status"))
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| cached_entry(paths, connection, &entry.path()))
        .filter(|cache| wanted(&cache.account.alias))
        .map(|cache| ServerRow {
            alias: cache.account.alias,
            available: cache.account.available,
            usage: Ok(cache.usage),
        })
        .collect();
    for alias in known.iter().filter(|alias| wanted(alias)) {
        if !rows.iter().any(|r| r.alias.eq_ignore_ascii_case(alias)) {
            rows.push(ServerRow {
                alias: alias.clone(),
                // Never read from the server: its availability is unknown.
                available: false,
                usage: Err("no saved usage".into()),
            });
        }
    }
    rows.sort_by(|a, b| a.alias.cmp(&b.alias));
    rows
}
/// Every server account with its usage. The server answers usage from its cache and polls
/// the provider at most once per 5 minutes, so the reads run in parallel. `cached` reads
/// only this machine's saved copies of the `known` aliases and sends nothing. `only` limits
/// every read to one alias.
/// A server account as the picker sees it. Fresh only with current usage from an
/// available account. Never billed only when the usage says extra usage is off: missing
/// data is not proof.
pub fn candidate(row: &ServerRow) -> crate::accounts::Candidate {
    let usage = row.usage.as_ref().ok();
    let parsed = usage
        .and_then(|u| u.data.clone())
        .and_then(|d| serde_json::from_value::<crate::api::UsageResponse>(d).ok());
    crate::accounts::Candidate {
        name: row.alias.clone(),
        windows: parsed
            .as_ref()
            .map(crate::accounts::windows)
            .unwrap_or_default(),
        fresh: row.available && usage.is_some_and(|u| !u.stale) && parsed.is_some(),
        billed: parsed
            .as_ref()
            .and_then(|u| u.extra_usage.as_ref())
            .and_then(|e| e.is_enabled)
            != Some(false),
    }
}

const NOT_CONNECTED: &str = "this machine is not connected to an account server\nTry: claudectl server connect <server-url> --name <machine>";

/// The server account `claudectl run` starts on when none is named: `accounts::best`
/// over live usage. Refuses with the account list when none has room.
pub fn pick_account(paths: &Paths) -> Result<String> {
    let rows = match server_view(paths, false, &[], None) {
        ServerView::Rows(rows) => rows,
        ServerView::NotConnected => bail!(NOT_CONNECTED),
        ServerView::Unreachable { error, .. } => {
            bail!("the account server did not answer: {error}\nTry: claudectl status")
        }
    };
    let candidates: Vec<_> = rows.iter().map(candidate).collect();
    match crate::accounts::best(&candidates) {
        Some(i) => Ok(candidates[i].name.clone()),
        None if candidates.is_empty() => {
            bail!("the account server has no accounts for you\nTry: claudectl add <name>")
        }
        None => bail!(
            "no account has room now (every one is at a limit, billed, or without fresh usage): {}\nTry: claudectl status",
            candidates
                .iter()
                .map(|c| c.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// The server account names, for name resolution: live, else this machine's saved copies.
pub fn server_aliases(paths: &Paths, cached: bool) -> Vec<String> {
    let Some(connection) = cached_connection(paths) else {
        return vec![];
    };
    let saved = || {
        cached_rows(paths, &connection, &[], &|_| true)
            .into_iter()
            .map(|row| row.alias)
            .collect()
    };
    if cached {
        return saved();
    }
    match Client::load(paths).and_then(|client| client.accounts()) {
        Ok(accounts) => accounts.into_iter().map(|a| a.alias).collect(),
        Err(_) => saved(),
    }
}

pub fn server_view(
    paths: &Paths,
    cached: bool,
    known: &[String],
    only: Option<&str>,
) -> ServerView {
    let wanted = |alias: &str| only.is_none_or(|only| only.eq_ignore_ascii_case(alias));
    let Some(connection) = cached_connection(paths) else {
        return ServerView::NotConnected;
    };
    if cached {
        return ServerView::Rows(cached_rows(paths, &connection, known, &wanted));
    }
    let unreachable = |error: anyhow::Error| ServerView::Unreachable {
        rejected: error
            .downcast_ref::<ServerError>()
            .is_some_and(|e| (400..500).contains(&e.status)),
        error: format!("{error:#}"),
        aliases: cached_rows(paths, &connection, known, &wanted)
            .into_iter()
            .map(|row| row.alias)
            .collect(),
    };
    let client = match Client::load(paths) {
        Ok(client) => client,
        Err(error) => return unreachable(error),
    };
    let accounts: Vec<Account> = match client.accounts() {
        Ok(accounts) => accounts.into_iter().filter(|a| wanted(&a.alias)).collect(),
        Err(error) => return unreachable(error),
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
        /// Account server URL (shown on the server's home page)
        server: String,
        /// Name for this machine, as it shows in `claudectl server devices`
        #[arg(long)]
        name: String,
        /// Print the sign-in link instead of opening a browser
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
        /// Name for the new account
        alias: String,
        /// Print the sign-in link instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Complete a browser login, or retry verification of its retained result
    #[command(hide = true)]
    CompleteLogin {
        /// Login ID that `server login` printed
        id: String,
        /// Retry the verification of a sign-in the server already kept
        #[arg(long)]
        resume: bool,
    },
    /// Force a new access token; every running server session of this account loses its
    /// token (a refresh revokes the previous one) and must be relaunched with --resume
    #[command(hide = true)]
    RefreshAccess { alias: String },
    /// Repair an existing server grant through identity-pinned sign-in
    Renew {
        /// Account to repair: full name, email name, or a unique prefix
        alias: String,
        /// Print the sign-in link instead of opening a browser
        #[arg(long)]
        no_browser: bool,
    },
    /// Run the tested Claude build with access-only credentials
    Run {
        /// Account to use: full name, email name, or a unique prefix
        alias: String,
        /// Claude executable to run (default: `claude` on PATH)
        #[arg(long, default_value = "claude")]
        claude: PathBuf,
        /// On a usage limit, resume the session on another account
        #[arg(long)]
        failover: bool,
        /// Arguments for Claude, after `--`
        #[arg(last = true)]
        args: Vec<std::ffi::OsString>,
    },
    /// Qualify a Claude build: run the synthetic renewal handoff check, record it only on a pass
    #[command(hide = true)]
    Qualify {
        /// Claude executable to check (default: `claude` on PATH)
        #[arg(long, default_value = "claude")]
        claude: PathBuf,
    },
    /// Read subscription usage; --cached works entirely offline
    Status {
        /// Account to show: full name, email name, or a unique prefix
        alias: String,
        /// Use the saved usage only; no network
        #[arg(long)]
        cached: bool,
        /// Print the raw JSON instead of a table
        #[arg(long)]
        json: bool,
    },
    /// Read the local session usage cache without network access
    #[command(hide = true)]
    Statusline { account_id: String },
    /// Record a Claude hook event for a running server session (internal; never fails)
    #[command(hide = true)]
    Hook { dir: PathBuf },
    /// Transfer a profile, or every saved account with --all, after stopping every previous
    /// grant holder
    Migrate {
        /// Saved profile to move to the server
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
    Revoke {
        /// Machine ID from `claudectl server devices`
        machine_id: String,
    },
    /// Delete a server account and its refresh grant; tokens already issued expire on their own
    Remove {
        /// Account to remove: full name, email name, or a unique prefix
        alias: String,
    },
    /// Remove this machine's local connection; does not revoke it on the server
    Disconnect,
}
/// `claudectl run`: `server run` on the named account, or on `pick_account` when none is
/// named. The account name resolves like every other (`accounts::resolve`).
pub fn run(
    account: Option<&str>,
    claude: PathBuf,
    failover: bool,
    args: Vec<std::ffi::OsString>,
) -> Result<()> {
    let paths = crate::config::default_paths()?;
    let alias = match account {
        Some(name) => name.to_owned(),
        None => {
            let picked = pick_account(&paths)?;
            eprintln!("claudectl: starting Claude on {picked} (most room)");
            picked
        }
    };
    dispatch(Command::Run {
        alias,
        claude,
        failover,
        args,
    })
}

/// `claudectl rm`: `server remove` after a confirmation, or with `--yes`.
pub fn remove_confirmed(account: &str, yes: bool) -> Result<()> {
    use std::io::IsTerminal;
    let paths = crate::config::default_paths()?;
    if cached_connection(&paths).is_none() {
        bail!(NOT_CONNECTED);
    }
    // The confirmation names the account a prefix or short name resolves to.
    let account = Client::load(&paths)?.account(account)?.alias;
    if !yes {
        if !std::io::stdin().is_terminal() {
            bail!(
                "removing an account needs a confirmation\nTry: claudectl rm {} --yes",
                crate::shell::arg(&account)
            );
        }
        let confirmed = dialoguer::Confirm::new()
            .with_prompt(format!(
                "Remove {account} from the account server? Running sessions stop at their next token renewal."
            ))
            .default(false)
            .interact()?;
        if !confirmed {
            bail!("not removed");
        }
    }
    dispatch(Command::Remove { alias: account })
}

pub fn dispatch(command: Command) -> Result<()> {
    let paths = crate::config::default_paths()?;
    // Before any connection is loaded: a shim passed as Claude would run itself.
    #[cfg(unix)]
    if let Command::Run { claude, .. } | Command::Qualify { claude } = &command {
        shim::refuse_shim_program(claude)?;
    }
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
                Command::Renew { alias, no_browser } => {
                    let alias = client.account(&alias)?.alias;
                    login(&client, &alias, true, no_browser)
                }
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
                    failover,
                    args,
                } => {
                    let code = session::run(&paths, &client, &alias, &claude, &args, failover)?;
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
                        "Server account {} removed. Access tokens already issued stay valid until they expire.",
                        account.alias
                    );
                    Ok(())
                }
                _ => unreachable!(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ServerRow, Usage, candidate, check_code, read_code};

    /// `server status <account> --json` (SAW-12696): the server's usage record as is. Readers
    /// (the capacity guard, SAW-12710) rely on these keys and types; keys are only added.
    #[test]
    fn server_status_json_keeps_every_key_and_type() {
        let usage = Usage {
            data: Some(serde_json::json!({"five_hour": {"utilization": 12.0}})),
            observed_at: Some(1_000),
            next_retry_at: 0,
            stale: false,
            error: None,
        };
        let v = serde_json::to_value(&usage).unwrap();
        assert!(v["data"].is_object(), "{v}");
        assert!(v["observed_at"].is_number(), "{v}");
        assert!(v["next_retry_at"].is_number(), "{v}");
        assert!(v["stale"].is_boolean(), "{v}");
        assert!(v.get("error").is_some_and(|e| e.is_null()), "{v}");
        assert_eq!(v["data"]["five_hour"]["utilization"], 12.0);
    }

    /// `server status <account>` text (SAW-12696): the first line names the account, the
    /// table has Window | Used | Resets with "N%" used cells, then the observed line.
    #[test]
    fn server_status_text_keeps_its_lines_and_table() {
        let now = 1_800_000_000_000;
        let usage = Usage {
            data: Some(serde_json::json!({
                "five_hour": {"utilization": 12.0},
                "seven_day": {"utilization": 40.0},
                "limits": [{"kind": "weekly_scoped", "percent": 100,
                    "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}]
            })),
            observed_at: Some(now - 120_000),
            next_retry_at: 0,
            stale: true,
            error: Some("usage_unavailable".into()),
        };
        let text = super::status_text("amir2@sawmills.ai", &usage, now);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "amir2@sawmills.ai (account server)", "{text}");
        let rows: Vec<Vec<String>> = lines
            .iter()
            .filter(|l| l.starts_with('│'))
            .map(|l| {
                l.trim_matches('│')
                    .split('┆')
                    .map(|c| c.trim().to_string())
                    .collect()
            })
            .collect();
        assert_eq!(rows[0], ["Window", "Used", "Resets"], "{text}");
        let used = |name: &str| {
            rows.iter()
                .find(|r| r[0] == name)
                .unwrap_or_else(|| panic!("{name} row: {text}"))[1]
                .clone()
        };
        assert_eq!(used("5h"), "12%");
        assert_eq!(used("week"), "40%");
        assert_eq!(used("Fable"), "100%");
        assert!(lines.contains(&"Observed 2m ago; stale."), "{text}");
        assert_eq!(
            *lines.last().unwrap(),
            "Server reports: usage_unavailable",
            "{text}"
        );
        let none = Usage {
            data: None,
            observed_at: None,
            next_retry_at: 0,
            stale: true,
            error: None,
        };
        assert_eq!(
            super::status_text("work", &none, now),
            "work (account server)\nNo usage observed yet.\n"
        );
    }

    #[test]
    fn a_pasted_code_is_checked_against_this_sign_in_before_it_is_sent() {
        let url = reqwest::Url::parse(
            "https://claude.ai/oauth/authorize?code=true&client_id=c&state=st-1&code_challenge=x",
        )
        .unwrap();
        assert_eq!(check_code("  abc#st-1 \n", &url).unwrap(), "abc#st-1");
        for bad in ["", "abc", "#st-1", "abc#", "abc#st-2"] {
            let error = format!("{:#}", check_code(bad, &url).unwrap_err());
            assert!(error.contains("Try:"), "{bad}: {error}");
            // The paste is never repeated (it is a secret).
            assert!(bad.is_empty() || !error.contains(bad), "{bad}: {error}");
        }
        let other = format!("{:#}", check_code("abc#st-2", &url).unwrap_err());
        assert!(other.contains("another sign-in"), "{other}");
        let no_state = reqwest::Url::parse("https://claude.ai/oauth/authorize?code=true").unwrap();
        assert!(check_code("abc#st-1", &no_state).is_err());
    }

    #[test]
    fn without_a_terminal_the_code_is_one_line_of_input() {
        let input = std::io::Cursor::new("abc#st-1\r\nnext line\n");
        assert_eq!(read_code(input, false).unwrap(), "abc#st-1");
        // add, renew and server login share this path: the Try line names no command.
        let error = format!(
            "{:#}",
            read_code(std::io::Cursor::new(""), false).unwrap_err()
        );
        assert!(
            error.contains("Try: echo '<code#state>' | <the same command> --no-browser"),
            "{error}"
        );
        assert!(!error.contains("claudectl add"), "{error}");
    }

    fn row(alias: &str, data: serde_json::Value, stale: bool) -> ServerRow {
        ServerRow {
            alias: alias.into(),
            available: true,
            usage: Ok(Usage {
                data: Some(data),
                observed_at: Some(1),
                next_retry_at: i64::MAX,
                stale,
                error: None,
            }),
        }
    }

    #[test]
    fn a_server_account_is_picked_only_when_extra_usage_is_known_off() {
        let off = serde_json::json!({"five_hour": {"utilization": 5.0},
            "extra_usage": {"is_enabled": false}});
        let on = serde_json::json!({"five_hour": {"utilization": 5.0},
            "extra_usage": {"is_enabled": true}});
        let missing = serde_json::json!({"five_hour": {"utilization": 5.0}});
        assert!(!candidate(&row("a", off.clone(), false)).billed);
        assert!(candidate(&row("a", on, false)).billed);
        assert!(
            candidate(&row("a", missing, false)).billed,
            "unknown is not safe"
        );
        // Stale, unavailable, or failed usage is never fresh.
        assert!(candidate(&row("a", off.clone(), false)).fresh);
        assert!(!candidate(&row("a", off.clone(), true)).fresh);
        let mut down = row("a", off, false);
        down.available = false;
        assert!(!candidate(&down).fresh);
        let failed = ServerRow {
            alias: "a".into(),
            available: true,
            usage: Err("429".into()),
        };
        assert!(!candidate(&failed).fresh);
    }
    #[test]
    fn a_partial_usage_response_is_never_picked() {
        let partial = serde_json::json!({"limits": [{"kind": "weekly_scoped", "percent": 1,
            "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}],
            "extra_usage": {"is_enabled": false}});
        let full = serde_json::json!({"five_hour": {"utilization": 50.0},
            "seven_day": {"utilization": 50.0}, "extra_usage": {"is_enabled": false}});
        let candidates = [
            candidate(&row("partial", partial, false)),
            candidate(&row("full", full, false)),
        ];
        assert_eq!(crate::accounts::best(&candidates), Some(1));
        assert_eq!(
            crate::accounts::state(&candidates[0].windows),
            crate::accounts::State::Unknown
        );
    }
    #[test]
    fn a_grant_that_expired_in_transit_is_refused() {
        // An observing read returns a grant valid at the server's read time; one that
        // crossed expiry on the way is dead and goes to the retry path.
        let access = |expires_at| super::Access {
            provider: "anthropic".into(),
            account_id: "a".into(),
            user_id: "u".into(),
            identity: super::Identity {
                account_uuid: "x".into(),
                organization_uuid: "o".into(),
            },
            access_token: "t".into(),
            expires_at,
            scopes: vec![],
            revision: "r".into(),
            generation: 1,
        };
        let now = super::now();
        assert!(super::checked_access(access(now + 60_000), "a", "u").is_ok());
        assert!(super::checked_access(access(now - 1), "a", "u").is_err());
        assert!(super::checked_access(access(now + 60_000), "b", "u").is_err());
    }
    #[test]
    fn login_accepts_the_old_and_the_claude_code_2_1_295_sign_in_pages() {
        let ok = |u: &str| super::claude_authorize(&reqwest::Url::parse(u).unwrap());
        assert!(ok("https://claude.ai/oauth/authorize?x=1"));
        assert!(ok("https://claude.com/cai/oauth/authorize?x=1"));
        assert!(!ok("http://claude.com/cai/oauth/authorize"));
        assert!(!ok("https://evil.example/cai/oauth/authorize"));
        assert!(!ok("https://claude.com/oauth/authorize"));
    }
    #[test]
    fn a_login_failure_reason_is_explained_in_plain_words() {
        for reason in [
            "login_identity_changed",
            "login_exchange_rejected",
            "login_state_mismatch",
            "login_expired",
            "login_identity_lookup_failed",
        ] {
            assert!(super::login_failure(reason, "L1").is_some(), "{reason}");
        }
        assert!(super::login_failure("login_incomplete_grant_retained", "L1").is_none());
        assert!(
            super::login_failure("login_identity_changed", "L1")
                .unwrap()
                .contains("claudectl server remove")
        );
        // The server kept the grant: the user can resume this login.
        assert!(
            super::login_failure("login_identity_lookup_failed", "L1")
                .unwrap()
                .contains("claudectl server complete-login L1 --resume")
        );
    }
}
