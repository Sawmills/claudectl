//! Claude's single refresh owner across replicas. Machines receive access-only snapshots.
//! A refresh runs only under the account's lease; every write it makes is fenced by it.
use super::{
    audit,
    fs::validate_alias,
    store::{
        self, AdmissionKind, AdmitOutcome, Admitted, Fence, Lease, PendingRow, PendingState, Store,
        StoredAccount,
    },
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
/// Keep it short: a refresh revokes the token every `server run` of the account holds, and
/// the client avoids asking inside this window (claudectl renew::NO_POLL_MS, SAW-12610).
const MARGIN: i64 = 300_000;

/// Every value `rotation_reason` returns. `/metrics` exports each from startup, so the first
/// refresh of a reason shows as an increase.
pub(crate) const ROTATION_REASONS: [&str; 4] = ["expired", "forced", "margin", "migration"];
/// Why a refresh ran: a client that sent the current revision forced it; a token that had
/// already expired revoked nothing; a pending migration rotates a token that may have hours
/// left; otherwise the held token was inside the margin.
pub(crate) fn rotation_reason(
    previous: Option<&str>,
    revision: &str,
    pending_migration: bool,
    expires_at: i64,
    now: i64,
) -> &'static str {
    if previous == Some(revision) {
        "forced"
    } else if expires_at <= now {
        "expired"
    } else if pending_migration {
        "migration"
    } else {
        "margin"
    }
}
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
/// Where a migrated grant stands. Copies left on other holders are stale only once the
/// provider has issued a distinct refresh token.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Rotation {
    /// Admitted by login; nothing to rotate.
    NotMigrated,
    /// Migrated; `migrated` is the digest of the migrated refresh token.
    Pending { migrated: String },
    /// Refreshed and verified, but the provider kept the refresh token: copies stay valid.
    Unrotated,
    /// Refreshed and verified with a distinct refresh token.
    Rotated,
}
/// The sealed part of an account.
#[derive(Clone, Serialize, Deserialize)]
struct Record {
    /// Envelope version of this record.
    v: u32,
    grant: Grant,
    /// The token revision machines see; it changes with every new access token.
    revision: String,
    generation: u64,
    phase: Phase,
    rotation: Rotation,
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
            || matches!(r.rotation, Rotation::Pending { .. })
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
    /// `not_migrated` (admitted by login), `pending`, `unrotated`, or `rotated`. For the
    /// dashboard only; the machine API does not carry it.
    #[serde(skip)]
    pub migration: &'static str,
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
marker_error!(
    AdmissionCancelled,
    "this admission was cancelled (by a delete or an abort); start again"
);
marker_error!(
    Superseded,
    "a login renewal replaced this migration's grant before it rotated; its copies may still be valid"
);
marker_error!(NotFound, "server account not found");
marker_error!(
    RefreshInProgress,
    "another replica is refreshing this account; retry"
);
marker_error!(
    Unrotated,
    "the provider kept the migrated refresh token, so copies left elsewhere stay valid; migration not complete"
);
/// A sealed record larger than this is refused.
const MAX_RECORD: usize = 64 * 1024;
/// The largest provider response kept before parsing; it must fit in a record.
const MAX_RESPONSE: usize = 16 * 1024;
enum Body {
    Incomplete,
    TooLarge,
}
/// Read a provider body chunk by chunk and stop past `MAX_RESPONSE`, so an oversized body
/// is never fully buffered.
async fn capped_body(mut response: reqwest::Response) -> Result<Vec<u8>, Body> {
    if response
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE as u64)
    {
        return Err(Body::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Body::Incomplete)? {
        if body.len() + chunk.len() > MAX_RESPONSE {
            return Err(Body::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
const RECORD_VERSION: u32 = 1;
/// The usage poll lease: one replica polls the provider at a time.
const USAGE_LEASE: &str = "__usage";

pub struct Engine {
    store: Arc<Store>,
    key: PathBuf,
    http: reqwest::Client,
    endpoints: Endpoints,
    /// One task per account in this process; the lease covers other replicas.
    local: StdMutex<BTreeMap<String, Arc<Mutex<()>>>>,
    usage_poll: Mutex<()>,
    /// Refreshes run by this process, by reason: count and last time in seconds (for
    /// `/metrics`). Process memory only: a rotation followed by a restart before the next
    /// scrape (30 s) is not exported. The audit log (operation refresh, `reason`) is the
    /// durable record; the alert is best-effort.
    rotations: StdMutex<BTreeMap<&'static str, (u64, i64)>>,
}
/// The receipt state when no committed admission was visible, from the pending row read
/// after it.
pub(crate) fn state_without_admission(pending: Option<store::PendingState>) -> &'static str {
    match pending {
        // Live: an admission may still commit. Committed: it committed after the admission
        // read; the client's rerun finds the receipt.
        Some(store::PendingState::Live | store::PendingState::Committed) => "pending",
        // Cancelled by a delete, or never kept: nothing can be admitted.
        Some(store::PendingState::Cancelled) | None => "none",
    }
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
            rotations: StdMutex::new(ROTATION_REASONS.iter().map(|r| (*r, (0, 0))).collect()),
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
        if row.sealed.len() > MAX_RECORD {
            bail!("sealed account record is too large");
        }
        let record: Record = self.unseal(&row.sealed)?;
        if record.v != RECORD_VERSION {
            bail!("unknown account record version {}", record.v);
        }
        record.grant.validate()?;
        Ok(Loaded { row, record })
    }
    async fn selected(&self, user: &str, id: &str) -> Result<Loaded> {
        match self.store.account(user, id).await? {
            Some(row) => self.load_row(row),
            None if self.store.deleted(user, id).await? => Err(Gone.into()),
            None => Err(NotFound.into()),
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
                migration: match loaded.record.rotation {
                    Rotation::NotMigrated => "not_migrated",
                    Rotation::Pending { .. } => "pending",
                    Rotation::Unrotated => "unrotated",
                    Rotation::Rotated => "rotated",
                },
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
        self.admit_with(user, alias, migration, grant, replacement, false, None)
            .await
    }
    /// Admit a grant moved from a machine. Its receipt stays hidden until a verified refresh
    /// produced a distinct refresh token, so a client keeps its fence until the copies it
    /// leaves behind are stale.
    pub async fn admit_migration(
        &self,
        user: &str,
        alias: &str,
        migration: &str,
        grant: Grant,
    ) -> Result<Receipt> {
        self.admit_with(user, alias, migration, grant, None, true, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn admit_with(
        &self,
        user: &str,
        alias: &str,
        admission_id: &str,
        grant: Grant,
        replacement: Option<&Identity>,
        migrated: bool,
        login_id: Option<&str>,
    ) -> Result<Receipt> {
        let alias = validate_alias(alias)?;
        validate_alias(admission_id)?;
        grant.validate()?;
        if let Some((receipt, _, stored)) = self.admitted(user, admission_id).await? {
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
        let cancelled = || anyhow::Error::from(AdmissionCancelled);
        // Retain an acquired grant before any network verification, even if it fails. A
        // delete cancels this row, and a cancelled admission never commits.
        if self.store.pending(user, admission_id).await?.is_none() {
            let sealed = self.seal(&Pending {
                grant: grant.clone(),
                replacement: replacement.cloned(),
            })?;
            let row = PendingRow {
                user: user.into(),
                alias: alias.into(),
                state: PendingState::Live,
                sealed,
            };
            self.store.put_pending(admission_id, &row, login_id).await?;
        }
        let saved = self
            .store
            .pending(user, admission_id)
            .await?
            // No row: a delete cancelled the login before the grant could be kept.
            .ok_or_else(cancelled)?;
        if saved.state != PendingState::Live {
            return Err(cancelled());
        }
        let pending: Pending = self.unseal(&saved.sealed)?;
        if !saved.alias.eq_ignore_ascii_case(alias) || pending.replacement.as_ref() != replacement {
            bail!("pending admission conflicts with retry; retained grant unchanged");
        }
        let grant = pending.grant;
        if let Some(login) = login_id
            && self
                .store
                .flow(user, login)
                .await?
                .is_none_or(|f| f.cancelled || f.consumed)
        {
            return Err(cancelled());
        }
        grant.validate()?;
        if grant.expires_at <= now() + USABLE {
            bail!("admission requires a usable access token; grant retained for login renewal");
        }
        let identity = self.identify(&grant.access_token).await?;
        if replacement.is_some_and(|expected| expected != &identity) {
            bail!("login renewal changed Claude identity; grant retained");
        }
        let id = account_id(user, alias);
        let prior = match self.store.account(user, &id).await? {
            Some(row) => Some(self.load_row(row)?),
            None => None,
        };
        match (&prior, replacement) {
            (None, Some(_)) => bail!("login renewal target no longer exists; start a new login"),
            (Some(_), None) => bail!("Claude identity or alias already reserved"),
            (Some(p), Some(_)) if p.identity() != identity => {
                bail!("Claude identity or alias already reserved")
            }
            _ => {}
        }
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
        let rotation = if migrated {
            Rotation::Pending {
                migrated: vault::digest(grant.refresh_token.as_bytes()),
            }
        } else {
            Rotation::NotMigrated
        };
        let record = Record {
            v: RECORD_VERSION,
            grant,
            revision: revision(),
            generation,
            phase: Phase::Ready,
            rotation,
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
            // A renewal keeps its incarnation; a new account, even under a deleted ID, gets
            // a new one.
            incarnation: prior
                .as_ref()
                .map_or_else(vault::secret, |p| p.row.incarnation.clone()),
        };
        let admission = store::Admission {
            account: row,
            expected_revision: prior.as_ref().map(|p| p.row.revision),
            admission_id: admission_id.into(),
            login_id: login_id.map(str::to_owned),
            kind: if migrated {
                AdmissionKind::Migration
            } else {
                AdmissionKind::Login
            },
        };
        match self.store.admit(&admission).await? {
            AdmitOutcome::Committed => Ok(Receipt {
                account_id: id,
                identity,
                migration_id: admission_id.into(),
            }),
            AdmitOutcome::Cancelled => Err(cancelled()),
            AdmitOutcome::Conflict => bail!("Claude identity or alias already reserved"),
        }
    }
    /// Admit a grant moved from a machine, then refresh once under the lease. A rotated
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
            Some((receipt, Rotation::Rotated, _)) => return Ok(receipt),
            Some((_, Rotation::Unrotated, _)) => return Err(Unrotated.into()),
            Some((receipt, Rotation::Pending { .. }, _)) => receipt,
            // A login admission ID reused as a migration ID.
            Some((_, Rotation::NotMigrated, _)) => {
                bail!("admission ID belongs to a login, not a migration")
            }
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
                        reason: None,
                    })
                    .await?;
                    return Err(error);
                }
            },
        };
        self.finish_migration(user, machine, migration, receipt)
            .await
    }
    /// Refresh a pending migration and publish its receipt. The rotation is read again
    /// through the admission marker, so it belongs to the incarnation this migration
    /// created: a replacement admitted meanwhile answers Gone, never this receipt.
    pub(super) async fn finish_migration(
        &self,
        user: &str,
        machine: &str,
        migration: &str,
        receipt: Receipt,
    ) -> Result<Receipt> {
        // A pending rotation always refreshes before anything is returned.
        let refreshed = self
            .acquire_for(user, machine, &receipt.account_id, None)
            .await;
        let rotation = match refreshed {
            Ok(_) => match self.admitted(user, migration).await? {
                Some((_, rotation, _)) => Some(rotation),
                None => bail!("migration admission disappeared"),
            },
            Err(_) => None,
        };
        let result = match rotation {
            Some(Rotation::Rotated) => "ok",
            Some(Rotation::Unrotated) => "unrotated",
            _ => "admitted_refresh_failed",
        };
        self.audit(&audit::Event {
            operation: "migrate",
            machine,
            account: &receipt.account_id,
            result,
            rotated: None,
            target: None,
            reason: None,
        })
        .await?;
        refreshed?;
        match rotation {
            Some(Rotation::Rotated) => Ok(receipt),
            Some(Rotation::Unrotated) => Err(Unrotated.into()),
            _ => bail!("migration refresh did not complete; retry"),
        }
    }
    /// The receipt for an admission ID, its account's rotation state, and the account, all
    /// from one read bound to the incarnation the admission created. An admission whose
    /// account was deleted is Gone: a retry cannot recreate it. A migration whose grant a
    /// login renewal replaced before it rotated is Superseded.
    async fn admitted(
        &self,
        user: &str,
        admission: &str,
    ) -> Result<Option<(Receipt, Rotation, Loaded)>> {
        let (kind, row) = match self.store.admission(user, admission).await? {
            None => return Ok(None),
            Some(Admitted::Gone) => return Err(Gone.into()),
            Some(Admitted::Live { kind, account }) => (kind, account),
        };
        let loaded = self.load_row(row)?;
        let rotation = loaded.record.rotation.clone();
        if kind == AdmissionKind::Migration && rotation == Rotation::NotMigrated {
            return Err(Superseded.into());
        }
        let receipt = Receipt {
            account_id: loaded.row.id.clone(),
            identity: loaded.identity(),
            migration_id: admission.into(),
        };
        Ok(Some((receipt, rotation, loaded)))
    }
    /// A completed admission. A migration counts only after a verified, distinct rotation.
    pub async fn receipt(&self, user: &str, admission: &str) -> Result<Option<Receipt>> {
        Ok(self.receipt_state(user, admission).await?.0)
    }
    /// Cancel a migration ID that has not committed, so a delayed import can never admit it.
    pub async fn cancel_migration(
        &self,
        user: &str,
        alias: &str,
        admission: &str,
    ) -> Result<store::CancelOutcome> {
        let alias = validate_alias(alias)?;
        validate_alias(admission)?;
        self.store.cancel_admission(user, admission, alias).await
    }
    /// The receipt and where the admission stands: `none` (never admitted, so a client may
    /// restore its fenced grant), `pending` (admitted, rotation not yet verified) or
    /// `complete`. Unrotated, Superseded and Gone stay errors.
    pub async fn receipt_state(
        &self,
        user: &str,
        admission: &str,
    ) -> Result<(Option<Receipt>, &'static str)> {
        match self.admitted(user, admission).await? {
            // A kept grant not yet committed may still be admitted: never "none".
            None => Ok((
                None,
                state_without_admission(
                    self.store.pending(user, admission).await?.map(|r| r.state),
                ),
            )),
            Some((receipt, Rotation::Rotated | Rotation::NotMigrated, _)) => {
                Ok((Some(receipt), "complete"))
            }
            Some((_, Rotation::Unrotated, _)) => Err(Unrotated.into()),
            Some((_, Rotation::Pending { .. }, _)) => Ok((None, "pending")),
        }
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
        // A migration counts as rotated only once a verified successor carries a distinct
        // refresh token.
        if let Rotation::Pending { migrated } = &record.rotation {
            record.rotation = if vault::digest(record.grant.refresh_token.as_bytes()) != *migrated {
                Rotation::Rotated
            } else {
                Rotation::Unrotated
            };
        }
        record.phase = Phase::Ready;
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
    /// Exchange the refresh token. `reason` is counted once the provider accepts the
    /// exchange: that revokes the old access token even if a later step fails.
    async fn refresh(
        &self,
        lease: &mut Lease,
        loaded: &mut Loaded,
        reason: &'static str,
    ) -> Result<bool> {
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
        {
            let mut rotations = self.rotations.lock().expect("rotations lock");
            let rotation = rotations.entry(reason).or_default();
            rotation.0 += 1;
            rotation.1 = now() / 1000;
        }
        let bytes = match capped_body(response).await {
            Ok(bytes) => bytes,
            Err(Body::TooLarge) => {
                bail!("refresh response too large to keep; login renewal required")
            }
            Err(Body::Incomplete) => bail!("refresh response incomplete; login renewal required"),
        };
        // Keep the response before parsing. The fence ignores expiry: nobody else took the
        // lease, so nobody else refreshed (H1).
        let mut record = loaded.record.clone();
        record.retained = Some(Retained {
            received_at: now(),
            body: bytes,
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
        let mut reason = None;
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
            Phase::Ready => {
                let why = rotation_reason(
                    previous,
                    &loaded.record.revision,
                    matches!(loaded.record.rotation, Rotation::Pending { .. }),
                    loaded.record.grant.expires_at,
                    now(),
                );
                reason = Some(why);
                self.refresh(lease, &mut loaded, why).await.map(Some)
            }
        };
        self.audit(&audit::Event {
            operation: "refresh",
            machine,
            account: id,
            result: if outcome.is_ok() { "ok" } else { "failed" },
            rotated: outcome.as_ref().ok().copied().flatten(),
            target: None,
            reason,
        })
        .await?;
        outcome?;
        Ok(loaded)
    }
    /// Wait for another replica's refresh to publish a newer token.
    /// A rejected revision is never returned: the caller then needs a successor.
    async fn follow(&self, user: &str, id: &str, seen: &str, rejected: bool) -> Result<Access> {
        let deadline = tokio::time::Instant::now() + FOLLOW_WAIT;
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let loaded = self.selected(user, id).await?;
            let newer = loaded.record.revision != seen;
            if loaded.record.phase == Phase::Ready
                && (newer || (!rejected && !loaded.needs_refresh(None)))
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
            let rejected = previous == Some(loaded.record.revision.as_str());
            return self
                .follow(user, id, &loaded.record.revision, rejected)
                .await;
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
        if !self.store.delete(user, id).await? {
            return if self.store.deleted(user, id).await? {
                Err(Gone.into())
            } else {
                Err(NotFound.into())
            };
        }
        self.audit(&audit::Event {
            operation: "revoke",
            machine,
            account: id,
            result: "ok",
            rotated: None,
            target: None,
            reason: None,
        })
        .await
    }
    /// Refreshes run by this process, by reason.
    pub fn rotations(&self) -> Vec<(&'static str, u64)> {
        self.rotations
            .lock()
            .expect("rotations lock")
            .iter()
            .map(|(reason, (count, _))| (*reason, *count))
            .collect()
    }
    /// The last refresh run by this process, by reason, in seconds; 0 if none. The alert
    /// reads this: a rotation before the first scrape never shows as a counter increase.
    pub fn last_rotations(&self) -> Vec<(&'static str, i64)> {
        self.rotations
            .lock()
            .expect("rotations lock")
            .iter()
            .map(|(reason, (_, last))| (*reason, *last))
            .collect()
    }
    pub async fn audit(&self, event: &audit::Event<'_>) -> Result<()> {
        audit::record(&self.store, &self.key, event).await
    }
}

#[cfg(test)]
mod tests;
