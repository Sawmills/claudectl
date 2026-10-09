//! Server state. Every multi-row change is one atomic step: one sealed file write for the
//! file store, one short transaction for PostgreSQL. No step spans a provider call.
//! Payloads arrive sealed by the caller; the store sees only routing columns.
//!
//! Every read of user data is scoped by the company user in the query itself. Deletes keep
//! their markers: a deletion log, admission markers, and cancelled flows stay; only sealed
//! secret payloads are erased.
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
    /// One per creation of this ID. A recreate after a delete is a new row with a new
    /// incarnation; the deleted row stays as a marker and is never revived.
    pub incarnation: String,
}

/// A lease. `epoch` grows on every acquisition, so an old holder's writes fail.
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

/// One admission: a new account, or a login renewal of an existing one.
pub struct Admission {
    pub account: StoredAccount,
    /// `None` for a new account; the current revision for a login renewal.
    pub expected_revision: Option<i64>,
    /// The admission ID (migration ID or login ID), unique per user. Its pending row must
    /// still be live: a delete cancels it, and a cancelled admission never commits.
    pub admission_id: String,
    /// The login flow that produced the grant; it must still be live and is consumed.
    pub login_id: Option<String>,
    pub kind: AdmissionKind,
}

/// What produced an admission. Its marker keeps it, so a migration ID completes only on a
/// verified rotation, never on a grant a login wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionKind {
    Login,
    Migration,
}
impl AdmissionKind {
    pub fn name(self) -> &'static str {
        match self {
            AdmissionKind::Login => "login",
            AdmissionKind::Migration => "migration",
        }
    }
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "login" => Ok(AdmissionKind::Login),
            "migration" => Ok(AdmissionKind::Migration),
            other => anyhow::bail!("unknown admission kind {other:?}"),
        }
    }
}

/// A committed admission, resolved in one read against the incarnation it created.
#[derive(Debug)]
pub enum Admitted {
    /// The account the admission created or renewed, still live in that incarnation.
    Live {
        kind: AdmissionKind,
        account: StoredAccount,
    },
    /// A delete revoked it, or its incarnation is gone.
    Gone,
}

/// The result of cancelling an admission ID before it commits.
#[derive(Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Recorded: any later admission with this ID is rejected.
    Cancelled,
    /// The admission already committed; nothing changed.
    Admitted,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdmitOutcome {
    Committed,
    /// A delete cancelled the pending admission or the login flow.
    Cancelled,
    /// Another account holds the alias or the Claude identity, or the expected predecessor
    /// is missing or moved.
    Conflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingState {
    Live,
    Cancelled,
    Committed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRow {
    pub user: String,
    pub alias: String,
    pub state: PendingState,
    /// Erased (empty) once the admission commits or is cancelled.
    pub sealed: Vec<u8>,
}

/// What a login flow expects of its alias when it is written.
#[derive(Clone, Copy, Debug)]
pub enum FlowTarget<'a> {
    /// No live account holds the alias.
    New,
    /// This live incarnation still holds the alias.
    Renew {
        account: &'a str,
        incarnation: &'a str,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowRow {
    pub user: String,
    pub alias: String,
    pub sealed: Vec<u8>,
    pub exchanging: bool,
    pub retained: Option<Vec<u8>>,
    /// A delete cancelled the flow; its retained response is erased.
    pub cancelled: bool,
    /// The flow produced an account; its retained response is erased.
    pub consumed: bool,
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
    /// The user's account with this ID.
    pub async fn account(&self, user: &str, id: &str) -> Result<Option<StoredAccount>> {
        dispatch!(self, account(user, id))
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
    /// The committed admission with this ID, in one read. It resolves only to the
    /// incarnation it created; a revoked or recreated account is `Gone`.
    pub async fn admission(&self, user: &str, admission_id: &str) -> Result<Option<Admitted>> {
        dispatch!(self, admission(user, admission_id))
    }
    /// Delete the user's account: erase its grant, log the deletion, and cancel every
    /// pending admission and login flow for its alias. False when the user owns no such
    /// account.
    pub async fn delete(&self, user: &str, id: &str) -> Result<bool> {
        dispatch!(self, delete(user, id))
    }
    /// True when the user deleted an account with this ID and none replaced it.
    pub async fn deleted(&self, user: &str, id: &str) -> Result<bool> {
        dispatch!(self, deleted(user, id))
    }
    /// Every row ever stored under this account ID as (incarnation, deleted).
    #[cfg(test)]
    pub async fn account_rows(&self, id: &str) -> Result<Vec<(String, bool)>> {
        dispatch!(self, account_rows(id))
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
    /// Cancel an admission ID under the alias lock: mark its kept grant cancelled, or leave a
    /// cancelled tombstone when none arrived yet. Refused once the admission committed.
    pub async fn cancel_admission(
        &self,
        user: &str,
        admission_id: &str,
        alias: &str,
    ) -> Result<CancelOutcome> {
        dispatch!(self, cancel_admission(user, admission_id, alias))
    }
    pub async fn pending(&self, user: &str, admission_id: &str) -> Result<Option<PendingRow>> {
        dispatch!(self, pending(user, admission_id))
    }
    /// Keep an acquired grant before verification. Never replaces an existing row. For a
    /// login, the row is written only while its flow is live, ordered against a delete.
    pub async fn put_pending(
        &self,
        admission_id: &str,
        row: &PendingRow,
        login_id: Option<&str>,
    ) -> Result<()> {
        dispatch!(self, put_pending(admission_id, row, login_id))
    }
    pub async fn flow(&self, user: &str, id: &str) -> Result<Option<FlowRow>> {
        dispatch!(self, flow(user, id))
    }
    /// Write a login flow under the alias lock that a delete takes, only while `target`
    /// still holds: a renewal needs its live incarnation, a new login a free alias. False
    /// otherwise, so a delete either cancels the flow or the flow is never written.
    pub async fn put_flow(&self, id: &str, row: &FlowRow, target: FlowTarget<'_>) -> Result<bool> {
        dispatch!(self, put_flow(id, row, target))
    }
    /// Mark a live flow's exchange as started, once. False otherwise.
    pub async fn start_exchange(&self, user: &str, id: &str) -> Result<bool> {
        dispatch!(self, start_exchange(user, id))
    }
    /// Keep an acquired login response on a live flow. False when it was cancelled.
    pub async fn retain(&self, user: &str, id: &str, sealed: &[u8]) -> Result<bool> {
        dispatch!(self, retain(user, id, sealed))
    }
    pub async fn usage(&self, id: &str) -> Result<Option<Vec<u8>>> {
        dispatch!(self, usage(id))
    }
    /// Cached usage of `user`'s live accounts as (account ID, sealed), in one read.
    pub async fn user_usage(&self, user: &str) -> Result<Vec<(String, Vec<u8>)>> {
        dispatch!(self, user_usage(user))
    }
    /// Store usage only while the account exists, so a poll cannot outlive a delete.
    pub async fn put_usage(&self, id: &str, sealed: &[u8]) -> Result<()> {
        dispatch!(self, put_usage(id, sealed))
    }
    pub async fn append_audit(&self, sealed: &[u8]) -> Result<()> {
        dispatch!(self, append_audit(sealed))
    }
    /// The whole audit log, for the operator.
    pub async fn audit(&self) -> Result<Vec<Vec<u8>>> {
        dispatch!(self, audit())
    }
    /// Every user, for the operator.
    pub async fn users(&self) -> Result<Vec<User>> {
        dispatch!(self, users())
    }
    pub async fn user(&self, id: &str) -> Result<Option<User>> {
        dispatch!(self, user(id))
    }
    /// Add or update a user; returns false for a disabled user and changes nothing.
    pub async fn record_user(&self, id: &str, email: &str) -> Result<bool> {
        dispatch!(self, record_user(id, email))
    }
    pub async fn set_user_enabled(&self, email: &str, enabled: bool) -> Result<bool> {
        dispatch!(self, set_user_enabled(email, enabled))
    }
    /// The user's machines as (ID, revoked), without token hashes.
    pub async fn machines(&self, user: &str) -> Result<Vec<(String, bool)>> {
        dispatch!(self, machines(user))
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
    /// Revoke `user`'s machine only while it is active, in one step: true only for the call
    /// that changed it, so concurrent requests act (and audit) once.
    pub async fn revoke_active_machine(&self, id: &str, user: &str) -> Result<bool> {
        dispatch!(self, revoke_active_machine(id, user))
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
    /// Replace an unconsumed row's payload only while it still equals `expected`.
    pub async fn swap_enrollment(
        &self,
        kind: &str,
        key: &str,
        expected: &[u8],
        sealed: &[u8],
    ) -> Result<bool> {
        dispatch!(self, swap_enrollment(kind, key, expected, sealed))
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
