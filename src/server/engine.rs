//! Claude's single refresh owner across replicas. Machines receive access-only snapshots.
//! A refresh runs only under the account's lease; every write it makes is fenced by it.
use super::{
    audit,
    fs::validate_alias,
    store::{self, AdmitOutcome, Fence, Lease, PendingRow, Store, StoredAccount},
    vault,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};
use tokio::sync::Mutex;

mod usage;
pub use usage::Usage;
mod login;
pub use login::Login;

const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const BETA: &str = "oauth-2025-04-20";
const PROVIDER: &str = "anthropic";
/// Refresh when less than this remains, so machines always hold a token with room to work.
const MARGIN: i64 = 300_000;
/// A grant must stay valid this long for admission and identity verification.
const USABLE: i64 = 60_000;
/// Refresh lease length. Each provider call needs `CALL_BUDGET` of it left.
const LEASE_TTL: i64 = 120_000;
/// The provider call timeout (30 s) plus a margin (10 s).
const CALL_BUDGET: i64 = 40_000;
/// How long a replica waits for another replica's refresh before answering 503.
const FOLLOW_WAIT: Duration = Duration::from_secs(35);

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn revision() -> String {
    vault::secret()
}
fn account_id(user: &str, alias: &str) -> String {
    vault::digest(format!("anthropic\0{user}\0{}", alias.to_ascii_lowercase()).as_bytes())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
}
impl Grant {
    fn validate(&self) -> Result<()> {
        if self.access_token.is_empty()
            || self.refresh_token.is_empty()
            || self.access_token.len() > 16384
            || self.refresh_token.len() > 16384
            || !self.scopes.iter().any(|s| s == "user:inference")
            || !self.scopes.iter().any(|s| s == "user:profile")
        {
            bail!("invalid Claude grant or missing scopes");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub account_uuid: String,
    pub organization_uuid: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Access {
    pub provider: &'static str,
    pub account_id: String,
    pub user_id: String,
    pub identity: Identity,
    pub access_token: String,
    pub expires_at: i64,
    pub scopes: Vec<String>,
    pub revision: String,
    pub generation: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub account_id: String,
    pub identity: Identity,
    pub migration_id: String,
}
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Ready,
    Refreshing,
    Unverified,
}
/// The sealed part of an account.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    grant: Grant,
    /// The token revision machines see; it changes with every new access token.
    revision: String,
    generation: u64,
    phase: Phase,
    admissions: Vec<String>,
    /// A migrated grant may still exist on other holders until its first verified refresh.
    rotation_pending: bool,
    /// The refresh attempt that wrote `Refreshing`.
    attempt: Option<String>,
    /// A provider response kept before parsing, so a stop never forces a replay.
    retained: Option<Retained>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Retained {
    received_at: i64,
    body: Vec<u8>,
}
/// An account as read: its routing row and its unsealed record.
struct Loaded {
    row: StoredAccount,
    record: Record,
}
impl Loaded {
    fn identity(&self) -> Identity {
        Identity {
            account_uuid: self.row.account_uuid.clone(),
            organization_uuid: self.row.organization_uuid.clone(),
        }
    }
    fn needs_refresh(&self, previous: Option<&str>) -> bool {
        let r = &self.record;
        r.phase != Phase::Ready
            || r.rotation_pending
            || r.grant.expires_at <= now() + MARGIN
            || previous == Some(r.revision.as_str())
    }
    fn access(&self) -> Access {
        Access {
            provider: PROVIDER,
            account_id: self.row.id.clone(),
            user_id: self.row.user.clone(),
            identity: self.identity(),
            access_token: self.record.grant.access_token.clone(),
            expires_at: self.record.grant.expires_at,
            scopes: self.record.grant.scopes.clone(),
            revision: self.record.revision.clone(),
            generation: self.record.generation,
        }
    }
}
#[derive(Clone, Serialize)]
pub struct Account {
    pub provider: &'static str,
    pub account_id: String,
    pub alias: String,
    pub identity: Identity,
    pub available: bool,
}
/// Anthropic API origins. Tests point them at a synthetic provider.
pub struct Endpoints {
    pub api: String,
    pub token: String,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            api: "https://api.anthropic.com".into(),
            token: "https://console.anthropic.com/v1/oauth/token".into(),
        }
    }
}
/// How an admission was started.
#[derive(Clone, Copy)]
pub(super) struct Admission {
    /// A migrated grant stays pending until its first verified refresh.
    pub rotation_pending: bool,
    /// When the admission's work began: a login flow's start, or now.
    pub started_at: i64,
}
macro_rules! marker_error {
    ($name:ident, $text:literal) => {
        #[derive(Debug)]
        pub struct $name;
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str($text)
            }
        }
        impl std::error::Error for $name {}
    };
}
marker_error!(Gone, "server account was deleted");
marker_error!(NotFound, "server account not found");
marker_error!(
    RefreshInProgress,
    "another replica is refreshing this account; retry"
);

pub struct Engine {
    store: Arc<Store>,
    key: PathBuf,
    http: reqwest::Client,
    endpoints: Endpoints,
    /// One task per account in this process; the lease covers other replicas.
    local: StdMutex<BTreeMap<String, Arc<Mutex<()>>>>,
    usage_poll: Mutex<()>,
}
impl Engine {
    /// A file-store engine at `state`; it takes the state directory's process lock.
    pub fn open_at(state: &Path, key: &Path, endpoints: Endpoints) -> Result<Self> {
        if !store::FileStore::exists(state)? {
            store::FileStore::create(state, key)?;
        }
        Self::with_store(
            Arc::new(Store::File(Box::new(store::FileStore::open(state, key)?))),
            key,
            endpoints,
        )
    }
    pub fn with_store(store: Arc<Store>, key: &Path, endpoints: Endpoints) -> Result<Self> {
        Ok(Self {
            store,
            key: key.into(),
            endpoints,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
            local: StdMutex::new(BTreeMap::new()),
            usage_poll: Mutex::new(()),
        })
    }
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }
    fn seal<T: Serialize>(&self, value: &T) -> Result<Vec<u8>> {
        vault::encrypt(&self.key, &serde_json::to_vec(value)?)
    }
    fn unseal<T: serde::de::DeserializeOwned>(&self, bytes: &[u8]) -> Result<T> {
        serde_json::from_slice(&vault::decrypt(&self.key, bytes)?)
            .map_err(|_| anyhow::anyhow!("invalid sealed record"))
    }
    fn local_lock(&self, id: &str) -> Arc<Mutex<()>> {
        self.local
            .lock()
            .expect("local locks")
            .entry(id.into())
            .or_default()
            .clone()
    }
    fn load_row(&self, row: StoredAccount) -> Result<Loaded> {
        let record: Record = self.unseal(&row.sealed)?;
        record.grant.validate()?;
        Ok(Loaded { row, record })
    }
    async fn selected(&self, user: &str, id: &str) -> Result<Loaded> {
        match self.store.account(id).await? {
            Some(row) if row.user == user => self.load_row(row),
            Some(_) => Err(NotFound.into()),
            None => match self.store.tombstone(id).await? {
                Some((owner, _)) if owner == user => Err(Gone.into()),
                _ => Err(NotFound.into()),
            },
        }
    }
    /// Write `record` over `loaded` under the lease. False when the fence or revision moved.
    async fn put(&self, loaded: &mut Loaded, record: Record, fence: Fence<'_>) -> Result<()> {
        let mut row = loaded.row.clone();
        row.revision = loaded.row.revision + 1;
        row.sealed = self.seal(&record)?;
        if !self
            .store
            .put_account(&row, loaded.row.revision, fence)
            .await?
        {
            bail!("the account changed or the refresh lease was lost; no token issued");
        }
        loaded.row = row;
        loaded.record = record;
        Ok(())
    }
    async fn identify(&self, access: &str) -> Result<Identity> {
        let response = self
            .http
            .get(format!("{}/api/oauth/profile", self.endpoints.api))
            .bearer_auth(access)
            .header("anthropic-beta", BETA)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Claude identity lookup unavailable"))?;
        if !response.status().is_success() {
            bail!("Claude identity lookup rejected");
        }
        let value: Value = response
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("invalid Claude identity response"))?;
        let field = |path| {
            value
                .pointer(path)
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty() && s.len() <= 256 && !s.chars().any(char::is_control))
                .map(str::to_owned)
                .context("Claude identity is incomplete")
        };
        Ok(Identity {
            account_uuid: field("/account/uuid")?,
            organization_uuid: field("/organization/uuid")?,
        })
    }
    pub async fn accounts(&self, user: &str) -> Result<Vec<Account>> {
        let mut out = Vec::new();
        for row in self.store.accounts(user).await? {
            let loaded = self.load_row(row)?;
            out.push(Account {
                provider: PROVIDER,
                account_id: loaded.row.id.clone(),
                alias: loaded.row.alias.clone(),
                identity: loaded.identity(),
                available: loaded.record.phase == Phase::Ready,
            });
        }
        Ok(out)
    }
    /// Admit only a usable, authenticated grant. Idempotent IDs never overwrite a successor.
    pub async fn admit(
        &self,
        user: &str,
        alias: &str,
        migration: &str,
        grant: Grant,
        replacement: Option<&Identity>,
    ) -> Result<Receipt> {
        let options = Admission {
            rotation_pending: false,
            started_at: now(),
        };
        self.admit_with(user, alias, migration, grant, replacement, options, None)
            .await
    }
    /// Admit a grant moved from a machine. Its receipt stays hidden until the first verified
    /// refresh, so a client keeps its fence until the copies it leaves behind are stale.
    pub async fn admit_migration(
        &self,
        user: &str,
        alias: &str,
        migration: &str,
        grant: Grant,
    ) -> Result<Receipt> {
        let options = Admission {
            rotation_pending: true,
            started_at: now(),
        };
        self.admit_with(user, alias, migration, grant, None, options, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn admit_with(
        &self,
        user: &str,
        alias: &str,
        migration: &str,
        grant: Grant,
        replacement: Option<&Identity>,
        options: Admission,
        login_id: Option<&str>,
    ) -> Result<Receipt> {
        let alias = validate_alias(alias)?;
        validate_alias(migration)?;
        grant.validate()?;
        if let Some((receipt, _)) = self.admitted(user, migration).await? {
            let stored = self.selected(user, &receipt.account_id).await?;
            if !stored.row.alias.eq_ignore_ascii_case(alias) {
                bail!("migration alias conflicts with its receipt");
            }
            return Ok(receipt);
        }
        #[derive(Serialize, Deserialize)]
        struct Pending {
            grant: Grant,
            replacement: Option<Identity>,
        }
        // Retain an acquired grant before any network verification, even if it fails.
        let pending_key = vault::digest(format!("{user}\0{migration}").as_bytes());
        let mut started_at = options.started_at;
        let grant = match self.store.pending(&pending_key).await? {
            Some(saved) => {
                let pending: Pending = self.unseal(&saved.sealed)?;
                if saved.user != user
                    || !saved.alias.eq_ignore_ascii_case(alias)
                    || pending.replacement.as_ref() != replacement
                {
                    bail!("pending admission conflicts with retry; retained grant unchanged");
                }
                started_at = started_at.min(saved.started_at);
                pending.grant
            }
            None => {
                let sealed = self.seal(&Pending {
                    grant: grant.clone(),
                    replacement: replacement.cloned(),
                })?;
                let row = PendingRow {
                    user: user.into(),
                    alias: alias.into(),
                    started_at,
                    sealed,
                };
                self.store.put_pending(&pending_key, &row).await?;
                grant
            }
        };
        let id = account_id(user, alias);
        // Refuse work that started before a delete, before any provider call.
        if self
            .store
            .tombstone(&id)
            .await?
            .is_some_and(|(_, deleted_at)| deleted_at >= started_at)
        {
            self.store.delete_pending(&pending_key).await?;
            bail!("the account was deleted after this admission started; start a new login");
        }
        grant.validate()?;
        if grant.expires_at <= now() + USABLE {
            bail!("admission requires a usable access token; grant retained for login renewal");
        }
        let identity = self.identify(&grant.access_token).await?;
        if replacement.is_some_and(|expected| expected != &identity) {
            bail!("login renewal changed Claude identity; grant retained");
        }
        let prior = self.store.account(&id).await?;
        let prior = match prior {
            Some(row) => Some(self.load_row(row)?),
            None => None,
        };
        match (&prior, replacement) {
            (None, Some(_)) => bail!("login renewal target no longer exists; start a new login"),
            (Some(p), None) if p.row.user == user => {
                bail!("Claude identity or alias already reserved")
            }
            (Some(p), Some(_)) if p.identity() != identity || p.row.user != user => {
                bail!("Claude identity or alias already reserved")
            }
            _ => {}
        }
        let mut admissions = prior
            .as_ref()
            .map(|p| p.record.admissions.clone())
            .unwrap_or_default();
        admissions.push(migration.into());
        let generation = prior
            .as_ref()
            .map(|p| {
                p.record
                    .generation
                    .checked_add(1)
                    .context("generation overflow")
            })
            .transpose()?
            .unwrap_or(1);
        let record = Record {
            grant,
            revision: revision(),
            generation,
            phase: Phase::Ready,
            admissions,
            rotation_pending: options.rotation_pending,
            attempt: None,
            retained: None,
        };
        let row = StoredAccount {
            id: id.clone(),
            user: user.into(),
            alias: alias.into(),
            account_uuid: identity.account_uuid.clone(),
            organization_uuid: identity.organization_uuid.clone(),
            revision: prior.as_ref().map_or(1, |p| p.row.revision + 1),
            sealed: self.seal(&record)?,
        };
        let admission = store::Admission {
            account: row,
            expected_revision: prior.as_ref().map(|p| p.row.revision),
            started_at,
            pending_key: pending_key.clone(),
            login_id: login_id.map(str::to_owned),
        };
        match self.store.admit(&admission).await? {
            AdmitOutcome::Committed => Ok(Receipt {
                account_id: id,
                identity,
                migration_id: migration.into(),
            }),
            AdmitOutcome::DeletedSince => {
                self.store.delete_pending(&pending_key).await?;
                bail!("the account was deleted after this admission started; start a new login")
            }
            AdmitOutcome::FlowGone => {
                self.store.delete_pending(&pending_key).await?;
                bail!("the login was cancelled by a delete; start a new login")
            }
            AdmitOutcome::Conflict => bail!("Claude identity or alias already reserved"),
        }
    }
    /// Admit a grant moved from a machine, then refresh once under the lease. A single-use
    /// refresh token makes every copy left on another holder stale. A retry with the same ID
    /// finishes a stopped rotation, or returns the receipt.
    pub async fn migrate(
        &self,
        user: &str,
        machine: &str,
        alias: &str,
        migration: &str,
        grant: Grant,
    ) -> Result<Receipt> {
        let receipt = match self.admitted(user, migration).await? {
            Some((receipt, false)) => return Ok(receipt),
            Some((receipt, true)) => receipt,
            None => match self.admit_migration(user, alias, migration, grant).await {
                Ok(receipt) => receipt,
                Err(error) => {
                    self.audit(&audit::Event {
                        operation: "migrate",
                        machine,
                        account: &account_id(user, alias),
                        result: "refused",
                        rotated: None,
                        target: None,
                    })
                    .await?;
                    return Err(error);
                }
            },
        };
        // A pending rotation always refreshes before anything is returned.
        let rotated = self
            .acquire_for(user, machine, &receipt.account_id, None)
            .await;
        self.audit(&audit::Event {
            operation: "migrate",
            machine,
            account: &receipt.account_id,
            result: if rotated.is_ok() {
                "ok"
            } else {
                "admitted_refresh_failed"
            },
            rotated: None,
            target: None,
        })
        .await?;
        rotated?;
        Ok(receipt)
    }
    /// The receipt for an admission ID and whether its rotation is still pending.
    async fn admitted(&self, user: &str, migration: &str) -> Result<Option<(Receipt, bool)>> {
        for row in self.store.accounts(user).await? {
            let loaded = self.load_row(row)?;
            if loaded.record.admissions.iter().any(|id| id == migration) {
                return Ok(Some((
                    Receipt {
                        account_id: loaded.row.id.clone(),
                        identity: loaded.identity(),
                        migration_id: migration.into(),
                    },
                    loaded.record.rotation_pending,
                )));
            }
        }
        Ok(None)
    }
    /// A completed admission. A migration counts only after its verified rotation.
    pub async fn receipt(&self, user: &str, migration: &str) -> Result<Option<Receipt>> {
        Ok(self
            .admitted(user, migration)
            .await?
            .filter(|(_, pending)| !pending)
            .map(|(receipt, _)| receipt))
    }
    /// Keep the lease long enough for one provider call; a failed renewal stops the work.
    async fn budget(&self, lease: &mut Lease, id: &str) -> Result<()> {
        if lease.left_ms() < CALL_BUDGET {
            *lease = self
                .store
                .renew_lease(lease, id, LEASE_TTL)
                .await?
                .context("refresh lease lost; stopping before the provider call")?;
        }
        Ok(())
    }
    async fn verify_successor(&self, lease: &mut Lease, loaded: &mut Loaded) -> Result<()> {
        loaded.record.grant.validate()?;
        if loaded.record.grant.expires_at <= now() {
            bail!("unverified successor expired; login renewal required");
        }
        self.budget(lease, &loaded.row.id).await?;
        if self.identify(&loaded.record.grant.access_token).await? != loaded.identity() {
            bail!("refreshed identity mismatch; successor retained");
        }
        self.budget(lease, &loaded.row.id).await?;
        let mut record = loaded.record.clone();
        // A migration counts as rotated only once its successor is verified.
        record.phase = Phase::Ready;
        record.rotation_pending = false;
        record.attempt = None;
        record.retained = None;
        self.put(loaded, record, Fence::Live(lease)).await
    }
    /// Turn a kept provider response into an unverified successor.
    async fn adopt(&self, lease: &Lease, loaded: &mut Loaded) -> Result<bool> {
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: i64,
            scope: Option<String>,
        }
        let retained = loaded
            .record
            .retained
            .clone()
            .context("refresh outcome uncertain; login renewal required")?;
        let next: Response = serde_json::from_slice(&retained.body).map_err(|_| {
            anyhow::anyhow!("refresh response invalid; retained for reconciliation")
        })?;
        let expiry = next
            .expires_in
            .checked_mul(1000)
            .and_then(|ms| retained.received_at.checked_add(ms))
            .filter(|_| next.expires_in > 0)
            .context("refresh expiry invalid")?;
        let old = &loaded.record.grant;
        let rotated = next
            .refresh_token
            .as_ref()
            .is_some_and(|t| *t != old.refresh_token);
        let grant = Grant {
            access_token: next.access_token,
            refresh_token: next
                .refresh_token
                .unwrap_or_else(|| old.refresh_token.clone()),
            expires_at: expiry,
            scopes: next
                .scope
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_else(|| old.scopes.clone()),
        };
        grant.validate()?;
        let mut record = loaded.record.clone();
        record.grant = grant;
        record.revision = revision();
        record.generation = record
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        record.phase = Phase::Unverified;
        self.put(loaded, record, Fence::Live(lease)).await?;
        Ok(rotated)
    }
    /// One refresh token exchange. Returns whether the provider rotated the refresh token.
    async fn refresh(&self, lease: &mut Lease, loaded: &mut Loaded) -> Result<bool> {
        let attempt = revision();
        let mut record = loaded.record.clone();
        record.phase = Phase::Refreshing;
        record.attempt = Some(attempt);
        record.retained = None;
        self.put(loaded, record, Fence::Live(lease)).await?;
        self.budget(lease, &loaded.row.id).await?;
        let response = self
            .http
            .post(&self.endpoints.token)
            .json(&json!({"grant_type":"refresh_token","refresh_token":loaded.record.grant.refresh_token,"client_id":CLIENT_ID}))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("refresh outcome uncertain; login renewal required"))?;
        if !response.status().is_success() {
            bail!("refresh rejected; login renewal required");
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| anyhow::anyhow!("refresh response incomplete; login renewal required"))?;
        // Keep the response before parsing. The fence ignores expiry: nobody else took the
        // lease, so nobody else refreshed (H1).
        let mut record = loaded.record.clone();
        record.retained = Some(Retained {
            received_at: now(),
            body: bytes.to_vec(),
        });
        self.put(loaded, record, Fence::Held(lease)).await?;
        let rotated = self.adopt(lease, loaded).await?;
        self.verify_successor(lease, loaded).await?;
        Ok(rotated)
    }
    /// Bring the account to Ready under the lease: verify a successor, adopt a kept
    /// response, or refresh. Never replays an uncertain exchange.
    async fn settle(
        &self,
        lease: &mut Lease,
        machine: &str,
        user: &str,
        id: &str,
        previous: Option<&str>,
    ) -> Result<Loaded> {
        let mut loaded = self.selected(user, id).await?;
        if !loaded.needs_refresh(previous) {
            return Ok(loaded);
        }
        let outcome = match loaded.record.phase {
            Phase::Unverified => self
                .verify_successor(lease, &mut loaded)
                .await
                .map(|()| None),
            Phase::Refreshing if loaded.record.retained.is_some() => {
                match self.adopt(lease, &mut loaded).await {
                    Ok(rotated) => self
                        .verify_successor(lease, &mut loaded)
                        .await
                        .map(|()| Some(rotated)),
                    Err(e) => Err(e),
                }
            }
            Phase::Refreshing => {
                bail!("refresh outcome uncertain; login renewal or reconciliation required")
            }
            Phase::Ready => self.refresh(lease, &mut loaded).await.map(Some),
        };
        self.audit(&audit::Event {
            operation: "refresh",
            machine,
            account: id,
            result: if outcome.is_ok() { "ok" } else { "failed" },
            rotated: outcome.as_ref().ok().copied().flatten(),
            target: None,
        })
        .await?;
        outcome?;
        Ok(loaded)
    }
    /// Wait for another replica's refresh to publish a newer token.
    async fn follow(&self, user: &str, id: &str, seen: &str) -> Result<Access> {
        let deadline = tokio::time::Instant::now() + FOLLOW_WAIT;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let loaded = self.selected(user, id).await?;
            if loaded.record.phase == Phase::Ready
                && (loaded.record.revision != seen || !loaded.needs_refresh(None))
            {
                return Ok(loaded.access());
            }
        }
        Err(RefreshInProgress.into())
    }
    pub async fn acquire(&self, user: &str, id: &str, previous: Option<&str>) -> Result<Access> {
        self.acquire_for(user, "server", id, previous).await
    }
    pub async fn acquire_for(
        &self,
        user: &str,
        machine: &str,
        id: &str,
        previous: Option<&str>,
    ) -> Result<Access> {
        let local = self.local_lock(id);
        let _local = local.lock().await;
        let loaded = self.selected(user, id).await?;
        if !loaded.needs_refresh(previous) {
            return Ok(loaded.access());
        }
        let Some(mut lease) = self.store.acquire_lease(id, LEASE_TTL).await? else {
            return self.follow(user, id, &loaded.record.revision).await;
        };
        // Another replica may have refreshed while this one waited for the lease.
        let previous = previous.filter(|p| *p == loaded.record.revision);
        let settled = self.settle(&mut lease, machine, user, id, previous).await;
        if let Err(error) = self.store.release_lease(&lease, id).await {
            eprintln!(
                "{}",
                json!({"operation":"release_lease","stage":"refresh","reason":"store_error","error":error.to_string()})
            );
        }
        Ok(settled?.access())
    }
    /// Delete an account and its sealed grant. Access tokens already given out stay valid
    /// until they expire; the server stops renewing them now.
    pub async fn remove(&self, user: &str, machine: &str, id: &str) -> Result<()> {
        if !self.store.delete(id, user, now()).await? {
            return match self.store.tombstone(id).await? {
                Some((owner, _)) if owner == user => Err(Gone.into()),
                _ => Err(NotFound.into()),
            };
        }
        self.audit(&audit::Event {
            operation: "revoke",
            machine,
            account: id,
            result: "ok",
            rotated: None,
            target: None,
        })
        .await
    }
    pub async fn audit(&self, event: &audit::Event<'_>) -> Result<()> {
        audit::record(&self.store, &self.key, event).await
    }
}

#[cfg(test)]
mod tests;
