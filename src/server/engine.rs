//! Claude's single refresh owner. Machines receive access-only snapshots.
use super::{audit, fs as store, vault};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{Mutex, RwLock};

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
#[derive(Serialize, Deserialize)]
struct Record {
    schema: u32,
    id: String,
    user: String,
    alias: String,
    identity: Identity,
    grant: Grant,
    revision: String,
    generation: u64,
    phase: Phase,
    admissions: Vec<String>,
    /// Set when a delete wins the lock; a waiting request must not persist the record again.
    #[serde(skip)]
    removed: bool,
}
#[derive(Clone, Serialize)]
pub struct Account {
    pub provider: &'static str,
    pub account_id: String,
    pub alias: String,
    pub identity: Identity,
    pub available: bool,
}
struct Endpoints {
    api: String,
    token: String,
}
impl Default for Endpoints {
    fn default() -> Self {
        Self {
            api: "https://api.anthropic.com".into(),
            token: "https://console.anthropic.com/v1/oauth/token".into(),
        }
    }
}
type Accounts = BTreeMap<String, Arc<Mutex<Record>>>;
/// The account was deleted. A machine must not retry with it.
#[derive(Debug)]
pub struct Gone;
impl std::fmt::Display for Gone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("server account was deleted")
    }
}
impl std::error::Error for Gone {}
/// A deleted account ID and its company user. It holds no grant.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
struct Tombstone {
    id: String,
    user: String,
}
pub struct Engine {
    state: PathBuf,
    key: PathBuf,
    http: reqwest::Client,
    endpoints: Endpoints,
    records: RwLock<Accounts>,
    deleted: Mutex<Vec<Tombstone>>,
    admissions: Mutex<()>,
    usage_state: Mutex<usage::UsageState>,
    _owner: vault::Lock,
}
impl Engine {
    pub fn open(state: &Path, key: &Path) -> Result<Self> {
        Self::open_at(state, key, Endpoints::default())
    }
    fn open_at(state: &Path, key: &Path, endpoints: Endpoints) -> Result<Self> {
        let owner = vault::lock(state, "owner.lock")?;
        store::ensure_private_dir(&state.join("accounts"))?;
        store::ensure_private_dir(&state.join("pending"))?;
        let deleted: Vec<Tombstone> = if state.join("deleted.json").try_exists()? {
            serde_json::from_slice(&vault::private_read(&state.join("deleted.json"))?)?
        } else {
            Vec::new()
        };
        // Finish a delete that stopped after its tombstone was written.
        for tombstone in &deleted {
            let dir = state.join("accounts").join(&tombstone.id);
            if dir.try_exists()? {
                std::fs::remove_dir_all(&dir)?;
                store::sync_directory(&state.join("accounts"))?;
            }
        }
        let mut records = BTreeMap::new();
        let mut identities = Vec::new();
        for entry in std::fs::read_dir(state.join("accounts"))? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                bail!("invalid provider account directory");
            }
            let record: Record = vault::unseal(&entry.path().join("vault.enc"), key)?;
            if record.schema != 2
                || record.id != account_id(&record.user, &record.alias)
                || entry.file_name() != record.id.as_str()
                || identities.contains(&record.identity)
            {
                bail!("invalid provider account inventory");
            }
            record.grant.validate()?;
            identities.push(record.identity.clone());
            records.insert(record.id.clone(), Arc::new(Mutex::new(record)));
        }
        Ok(Self {
            state: state.into(),
            key: key.into(),
            endpoints,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()?,
            records: RwLock::new(records),
            deleted: Mutex::new(deleted),
            admissions: Mutex::new(()),
            usage_state: Mutex::new(if state.join("usage.json").exists() {
                serde_json::from_slice(&vault::private_read(&state.join("usage.json"))?)?
            } else {
                Default::default()
            }),
            _owner: owner,
        })
    }
    fn persist(&self, record: &Record) -> Result<()> {
        let dir = self.state.join("accounts").join(&record.id);
        store::ensure_private_dir(&dir)?;
        vault::seal(&dir.join("vault.enc"), &self.key, record)
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
    pub async fn accounts(&self, user: &str) -> Vec<Account> {
        let records: Vec<_> = self.records.read().await.values().cloned().collect();
        let mut out = Vec::new();
        for record in records {
            let record = record.lock().await;
            if record.user == user {
                out.push(Account {
                    provider: PROVIDER,
                    account_id: record.id.clone(),
                    alias: record.alias.clone(),
                    identity: record.identity.clone(),
                    available: record.phase == Phase::Ready,
                });
            }
        }
        out
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
        let alias = store::validate_alias(alias)?;
        store::validate_alias(migration)?;
        grant.validate()?;
        let _admission = self.admissions.lock().await;
        let records: Vec<_> = self.records.read().await.values().cloned().collect();
        for record in &records {
            let r = record.lock().await;
            if r.user == user && r.admissions.iter().any(|id| id == migration) {
                if !r.alias.eq_ignore_ascii_case(alias) {
                    bail!("migration alias conflicts with its receipt");
                }
                return Ok(Receipt {
                    account_id: r.id.clone(),
                    identity: r.identity.clone(),
                    migration_id: migration.into(),
                });
            }
        }
        // Retain an acquired grant before any network verification, even if it fails.
        let pending = self.state.join("pending").join(format!(
            "{}.enc",
            vault::digest(format!("{user}\0{migration}").as_bytes())
        ));
        #[derive(Serialize, Deserialize)]
        struct Pending {
            user: String,
            alias: String,
            migration_id: String,
            grant: Grant,
            replacement: Option<Identity>,
        }
        let grant = if pending.exists() {
            let saved: Pending = vault::unseal(&pending, &self.key)?;
            if saved.user != user
                || !saved.alias.eq_ignore_ascii_case(alias)
                || saved.migration_id != migration
                || saved.replacement.as_ref() != replacement
            {
                bail!("pending admission conflicts with retry; retained grant unchanged");
            }
            saved.grant
        } else {
            vault::seal(
                &pending,
                &self.key,
                &Pending {
                    user: user.into(),
                    alias: alias.into(),
                    migration_id: migration.into(),
                    grant: grant.clone(),
                    replacement: replacement.cloned(),
                },
            )?;
            grant
        };
        grant.validate()?;
        if grant.expires_at <= now() + USABLE {
            bail!("admission requires a usable access token; grant retained for login renewal");
        }
        let identity = self.identify(&grant.access_token).await?;
        if replacement.is_some_and(|expected| expected != &identity) {
            bail!("login renewal changed Claude identity; grant retained");
        }
        let id = account_id(user, alias);
        let mut prior = None;
        for record in records {
            let r = record.lock().await;
            if r.identity == identity || r.id == id {
                if r.id != id
                    || r.user != user
                    || r.identity != identity
                    || replacement != Some(&identity)
                {
                    bail!("Claude identity or alias already reserved");
                }
                drop(r);
                prior = Some(record);
            }
        }
        let mut old = match prior.as_ref() {
            Some(r) => Some(r.lock().await),
            None => None,
        };
        let mut admissions = old
            .as_ref()
            .map(|r| r.admissions.clone())
            .unwrap_or_default();
        admissions.push(migration.into());
        let generation = old
            .as_ref()
            .map(|r| r.generation.checked_add(1).context("generation overflow"))
            .transpose()?
            .unwrap_or(1);
        let record = Record {
            schema: 2,
            id: id.clone(),
            user: user.into(),
            alias: alias.into(),
            identity: identity.clone(),
            grant,
            revision: revision(),
            generation,
            phase: Phase::Ready,
            admissions,
            removed: false,
        };
        self.persist(&record)?;
        self.forget_tombstone(&id).await?;
        if let Some(ref mut old) = old {
            **old = record;
        } else {
            self.records
                .write()
                .await
                .insert(id.clone(), Arc::new(Mutex::new(record)));
        }
        std::fs::remove_file(pending)?;
        store::sync_directory(&self.state.join("pending"))?;
        Ok(Receipt {
            account_id: id,
            identity,
            migration_id: migration.into(),
        })
    }
    /// Admit a grant moved from a machine, then refresh once. A single-use refresh token makes
    /// every copy left on another holder stale. A retry with the same ID returns the receipt.
    pub async fn migrate(
        &self,
        user: &str,
        machine: &str,
        alias: &str,
        migration: &str,
        grant: Grant,
    ) -> Result<Receipt> {
        if let Some(receipt) = self.receipt(user, migration).await? {
            return Ok(receipt);
        }
        let admitted = self.admit(user, alias, migration, grant, None).await;
        let receipt = match admitted {
            Ok(receipt) => receipt,
            Err(error) => {
                self.audit(&audit::Event {
                    operation: "migrate",
                    machine,
                    account: &account_id(user, alias),
                    result: "refused",
                    rotated: None,
                })?;
                return Err(error);
            }
        };
        let current = self
            .acquire_for(user, machine, &receipt.account_id, None)
            .await;
        let refreshed = match current {
            Ok(current) => {
                self.acquire_for(user, machine, &receipt.account_id, Some(&current.revision))
                    .await
            }
            Err(error) => Err(error),
        };
        self.audit(&audit::Event {
            operation: "migrate",
            machine,
            account: &receipt.account_id,
            result: if refreshed.is_ok() {
                "ok"
            } else {
                "admitted_refresh_failed"
            },
            rotated: None,
        })?;
        refreshed?;
        Ok(receipt)
    }
    async fn selected(&self, user: &str, id: &str) -> Result<Arc<Mutex<Record>>> {
        let record = self.records.read().await.get(id).cloned();
        let Some(record) = record else {
            let gone = self
                .deleted
                .lock()
                .await
                .iter()
                .any(|t| t.id == id && t.user == user);
            if gone {
                return Err(Gone.into());
            }
            bail!("server account not found");
        };
        if record.lock().await.user != user {
            bail!("server account not found");
        }
        Ok(record)
    }
    pub async fn receipt(&self, user: &str, migration: &str) -> Result<Option<Receipt>> {
        let records: Vec<_> = self.records.read().await.values().cloned().collect();
        for record in records {
            let record = record.lock().await;
            if record.user == user && record.admissions.iter().any(|id| id == migration) {
                return Ok(Some(Receipt {
                    account_id: record.id.clone(),
                    identity: record.identity.clone(),
                    migration_id: migration.into(),
                }));
            }
        }
        Ok(None)
    }
    async fn verify_successor(&self, record: &mut Record) -> Result<()> {
        record.grant.validate()?;
        if record.grant.expires_at <= now() {
            bail!("unverified successor expired; login renewal required");
        }
        if self.identify(&record.grant.access_token).await? != record.identity {
            bail!("refreshed identity mismatch; successor retained");
        }
        record.phase = Phase::Ready;
        if let Err(error) = self.persist(record) {
            record.phase = Phase::Unverified;
            return Err(error);
        }
        let dir = self.state.join("accounts").join(&record.id);
        let retained = dir.join("refresh-response.enc");
        if retained.try_exists()? {
            std::fs::remove_file(retained)?;
            store::sync_directory(&dir)?;
        }
        Ok(())
    }
    /// Exchange the refresh token once. Returns whether the provider rotated it.
    async fn refresh(&self, record: &mut Record) -> Result<bool> {
        record.phase = Phase::Refreshing;
        self.persist(record)?;
        let response=self.http.post(&self.endpoints.token).json(&json!({"grant_type":"refresh_token","refresh_token":record.grant.refresh_token,"client_id":CLIENT_ID})).send().await.map_err(|_|anyhow::anyhow!("refresh outcome uncertain; login renewal required"))?;
        if !response.status().is_success() {
            bail!("refresh rejected; login renewal required");
        }
        #[derive(Deserialize)]
        struct Response {
            access_token: String,
            refresh_token: Option<String>,
            expires_in: i64,
            scope: Option<String>,
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| anyhow::anyhow!("refresh response incomplete; login renewal required"))?;
        // Preserve the acquired response even when its metadata cannot be parsed.
        let retained = self
            .state
            .join("accounts")
            .join(&record.id)
            .join("refresh-response.enc");
        vault::seal(
            &retained,
            &self.key,
            &json!({"received_at":now(),"body":bytes.to_vec()}),
        )?;
        let next: Response = serde_json::from_slice(&bytes).map_err(|_| {
            anyhow::anyhow!("refresh response invalid; retained for reconciliation")
        })?;
        let expiry = next
            .expires_in
            .checked_mul(1000)
            .and_then(|ms| now().checked_add(ms))
            .filter(|_| next.expires_in > 0)
            .context("refresh expiry invalid")?;
        let rotated = next
            .refresh_token
            .as_ref()
            .is_some_and(|t| *t != record.grant.refresh_token);
        let grant = Grant {
            access_token: next.access_token,
            refresh_token: next
                .refresh_token
                .unwrap_or_else(|| record.grant.refresh_token.clone()),
            expires_at: expiry,
            scopes: next
                .scope
                .map(|s| s.split_whitespace().map(str::to_owned).collect())
                .unwrap_or_else(|| record.grant.scopes.clone()),
        };
        grant.validate()?;
        record.grant = grant;
        record.revision = revision();
        record.generation = record
            .generation
            .checked_add(1)
            .context("generation overflow")?;
        record.phase = Phase::Unverified;
        self.persist(record)?;
        self.verify_successor(record).await?;
        Ok(rotated)
    }
    async fn save_tombstones(&self, deleted: &[Tombstone]) -> Result<()> {
        store::atomic_write(
            &self.state.join("deleted.json"),
            &serde_json::to_vec(deleted)?,
        )
    }
    async fn forget_tombstone(&self, id: &str) -> Result<()> {
        let mut deleted = self.deleted.lock().await;
        if deleted.iter().any(|t| t.id == id) {
            deleted.retain(|t| t.id != id);
            self.save_tombstones(&deleted).await?;
        }
        Ok(())
    }
    /// Delete an account and its sealed grant. Access tokens already given out stay valid
    /// until they expire; the server stops renewing them now.
    pub async fn remove(&self, user: &str, machine: &str, id: &str) -> Result<()> {
        let selected = self.selected(user, id).await?;
        let mut record = selected.lock().await;
        if record.removed {
            return Err(Gone.into());
        }
        record.removed = true;
        {
            let mut deleted = self.deleted.lock().await;
            deleted.push(Tombstone {
                id: id.into(),
                user: user.into(),
            });
            self.save_tombstones(&deleted).await?;
        }
        std::fs::remove_dir_all(self.state.join("accounts").join(id))?;
        store::sync_directory(&self.state.join("accounts"))?;
        self.records.write().await.remove(id);
        self.audit(&audit::Event {
            operation: "revoke",
            machine,
            account: id,
            result: "ok",
            rotated: None,
        })
    }
    fn audit(&self, event: &audit::Event) -> Result<()> {
        audit::record(&self.state, &self.key, event)
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
        let selected = self.selected(user, id).await?;
        let mut record = selected.lock().await;
        if record.removed {
            return Err(Gone.into());
        }
        if record.phase == Phase::Unverified {
            self.verify_successor(&mut record).await?;
        }
        if record.phase != Phase::Ready {
            bail!("refresh outcome uncertain; login renewal or reconciliation required");
        }
        let refresh =
            record.grant.expires_at <= now() + MARGIN || previous == Some(record.revision.as_str());
        if refresh {
            let outcome = self.refresh(&mut record).await;
            self.audit(&audit::Event {
                operation: "refresh",
                machine,
                account: &record.id,
                result: if outcome.is_ok() { "ok" } else { "failed" },
                rotated: outcome.as_ref().ok().copied(),
            })?;
            outcome?;
        }
        Ok(Access {
            provider: PROVIDER,
            account_id: record.id.clone(),
            user_id: record.user.clone(),
            identity: record.identity.clone(),
            access_token: record.grant.access_token.clone(),
            expires_at: record.grant.expires_at,
            scopes: record.grant.scopes.clone(),
            revision: record.revision.clone(),
            generation: record.generation,
        })
    }
}

#[cfg(test)]
mod tests;
