//! Server state. Every multi-row change is one atomic step: one sealed file write for the
//! file store, one short transaction for PostgreSQL. No step spans a provider call.
//! Payloads arrive sealed by the caller; the store sees only routing columns.
use anyhow::Result;
use serde::{Deserialize, Serialize};

mod file;
mod postgres;
pub use file::FileStore;
pub use postgres::PostgresStore;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredAccount {
    pub id: String,
    pub user: String,
    pub alias: String,
    pub account_uuid: String,
    pub organization_uuid: String,
    /// Compare-and-swap counter; every write increments it.
    pub revision: i64,
    pub sealed: Vec<u8>,
}

/// A refresh lease. `epoch` grows on every acquisition, so an old holder's writes fail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub holder: String,
    pub epoch: i64,
    /// Milliseconds left by the store's clock when the lease was taken or renewed.
    pub remaining_ms: i64,
    /// When the request that returned `remaining_ms` started; elapsed time counts against it.
    pub taken: std::time::Instant,
}
impl Lease {
    /// Milliseconds left now, never more than the store reported.
    pub fn left_ms(&self) -> i64 {
        self.remaining_ms - self.taken.elapsed().as_millis() as i64
    }
}

/// What a fenced account write requires of the lease.
#[derive(Clone, Copy)]
pub enum Fence<'a> {
    /// Holder and epoch match and the lease has not expired.
    Live(&'a Lease),
    /// Holder and epoch match; expiry is ignored. Only for keeping an acquired provider
    /// response: nobody else took the lease, so nobody else can have refreshed.
    Held(&'a Lease),
}

pub struct Admission {
    pub account: StoredAccount,
    /// `None` for a new account; the current revision for a login renewal.
    pub expected_revision: Option<i64>,
    pub started_at: i64,
    pub pending_key: String,
    /// The login flow that produced the grant; it must still exist and is consumed.
    pub login_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdmitOutcome {
    Committed,
    /// A delete happened at or after the admission started.
    DeletedSince,
    /// Another account holds the alias or the Claude identity, or the expected predecessor
    /// is missing or moved.
    Conflict,
    /// The login flow was cancelled (a delete) or already consumed.
    FlowGone,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRow {
    pub user: String,
    pub alias: String,
    pub started_at: i64,
    pub sealed: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowRow {
    pub user: String,
    pub alias: String,
    pub sealed: Vec<u8>,
    pub exchanging: bool,
    pub retained: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Machine {
    pub id: String,
    pub user: String,
    pub token_hash: String,
    pub revoked: bool,
}

/// One-time enrollment state: a device code, an SSO login, or an approval.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrollmentRow {
    pub lookup: Option<String>,
    pub sealed: Vec<u8>,
    pub expires_at: i64,
    pub consumed: bool,
}

pub enum Store {
    File(Box<FileStore>),
    Postgres(PostgresStore),
}

macro_rules! dispatch {
    ($self:ident, $method:ident ( $($arg:expr),* )) => {
        match $self {
            Store::File(s) => s.$method($($arg),*),
            Store::Postgres(s) => s.$method($($arg),*).await,
        }
    };
}

impl Store {
    pub fn holder(&self) -> &str {
        match self {
            Store::File(s) => s.holder(),
            Store::Postgres(s) => s.holder(),
        }
    }
    pub async fn ready(&self) -> Result<()> {
        dispatch!(self, ready())
    }
    pub async fn account(&self, id: &str) -> Result<Option<StoredAccount>> {
        dispatch!(self, account(id))
    }
    pub async fn accounts(&self, user: &str) -> Result<Vec<StoredAccount>> {
        dispatch!(self, accounts(user))
    }
    /// Write `account` when its stored revision is `expected` and the fence holds.
    pub async fn put_account(
        &self,
        account: &StoredAccount,
        expected: i64,
        fence: Fence<'_>,
    ) -> Result<bool> {
        dispatch!(self, put_account(account, expected, fence))
    }
    pub async fn admit(&self, admission: &Admission) -> Result<AdmitOutcome> {
        dispatch!(self, admit(admission))
    }
    /// Delete the account and every grant or flow for its alias, and write the tombstone.
    /// False when the user owns no such account.
    pub async fn delete(&self, id: &str, user: &str, deleted_at: i64) -> Result<bool> {
        dispatch!(self, delete(id, user, deleted_at))
    }
    /// The tombstone of a deleted account: its company user and deletion time.
    pub async fn tombstone(&self, id: &str) -> Result<Option<(String, i64)>> {
        dispatch!(self, tombstone(id))
    }
    pub async fn acquire_lease(&self, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
        dispatch!(self, acquire_lease(id, ttl_ms))
    }
    /// Extend a live lease. Never re-acquires: a failed renewal returns `None`.
    pub async fn renew_lease(&self, lease: &Lease, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
        dispatch!(self, renew_lease(lease, id, ttl_ms))
    }
    pub async fn release_lease(&self, lease: &Lease, id: &str) -> Result<()> {
        dispatch!(self, release_lease(lease, id))
    }
    pub async fn pending(&self, key: &str) -> Result<Option<PendingRow>> {
        dispatch!(self, pending(key))
    }
    pub async fn put_pending(&self, key: &str, row: &PendingRow) -> Result<()> {
        dispatch!(self, put_pending(key, row))
    }
    pub async fn delete_pending(&self, key: &str) -> Result<()> {
        dispatch!(self, delete_pending(key))
    }
    pub async fn flow(&self, id: &str) -> Result<Option<FlowRow>> {
        dispatch!(self, flow(id))
    }
    pub async fn put_flow(&self, id: &str, row: &FlowRow) -> Result<()> {
        dispatch!(self, put_flow(id, row))
    }
    /// Mark a flow's exchange as started, once. False when the flow is gone or exchanging.
    pub async fn start_exchange(&self, id: &str) -> Result<bool> {
        dispatch!(self, start_exchange(id))
    }
    /// Keep an acquired login response. False when the flow is gone (a delete).
    pub async fn retain(&self, id: &str, sealed: &[u8]) -> Result<bool> {
        dispatch!(self, retain(id, sealed))
    }
    pub async fn usage(&self, id: &str) -> Result<Option<Vec<u8>>> {
        dispatch!(self, usage(id))
    }
    /// Store usage only while the account exists, so a delete cannot be undone by a poll.
    pub async fn put_usage(&self, id: &str, sealed: &[u8]) -> Result<()> {
        dispatch!(self, put_usage(id, sealed))
    }
    pub async fn append_audit(&self, sealed: &[u8]) -> Result<()> {
        dispatch!(self, append_audit(sealed))
    }
    pub async fn audit(&self) -> Result<Vec<Vec<u8>>> {
        dispatch!(self, audit())
    }
    pub async fn users(&self) -> Result<Vec<User>> {
        dispatch!(self, users())
    }
    /// Add or update a user; returns false for a disabled user and changes nothing.
    pub async fn record_user(&self, id: &str, email: &str) -> Result<bool> {
        dispatch!(self, record_user(id, email))
    }
    pub async fn set_user_enabled(&self, email: &str, enabled: bool) -> Result<bool> {
        dispatch!(self, set_user_enabled(email, enabled))
    }
    pub async fn machines(&self) -> Result<Vec<Machine>> {
        dispatch!(self, machines())
    }
    pub async fn machine_by_token(&self, token_hash: &str) -> Result<Option<Machine>> {
        dispatch!(self, machine_by_token(token_hash))
    }
    pub async fn add_machine(&self, machine: &Machine) -> Result<()> {
        dispatch!(self, add_machine(machine))
    }
    /// Revoke a machine; with `user`, only a machine of that user.
    pub async fn revoke_machine(&self, id: &str, user: Option<&str>) -> Result<bool> {
        dispatch!(self, revoke_machine(id, user))
    }
    pub async fn put_enrollment(&self, kind: &str, key: &str, row: &EnrollmentRow) -> Result<()> {
        dispatch!(self, put_enrollment(kind, key, row))
    }
    /// Find an unconsumed, unexpired row by its lookup value.
    pub async fn find_enrollment(
        &self,
        kind: &str,
        lookup: &str,
        now: i64,
    ) -> Result<Option<(String, EnrollmentRow)>> {
        dispatch!(self, find_enrollment(kind, lookup, now))
    }
    pub async fn enrollment(
        &self,
        kind: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<EnrollmentRow>> {
        dispatch!(self, enrollment(kind, key, now))
    }
    /// Replace an unconsumed row's payload. False when it is consumed or gone.
    pub async fn update_enrollment(&self, kind: &str, key: &str, sealed: &[u8]) -> Result<bool> {
        dispatch!(self, update_enrollment(kind, key, sealed))
    }
    /// Consume a row exactly once across replicas.
    pub async fn consume_enrollment(
        &self,
        kind: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<EnrollmentRow>> {
        dispatch!(self, consume_enrollment(kind, key, now))
    }
}
