//! One process, one sealed file. A change is applied to a copy and published with one
//! atomic write, so a stop leaves either the old or the new state, never a mix.
use super::*;
use crate::server::{fs, vault};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Default, Serialize, Deserialize)]
struct Tables {
    /// Live accounts by ID.
    accounts: BTreeMap<String, StoredAccount>,
    /// Deleted incarnations, grant erased, kept as markers like the PostgreSQL rows.
    retired: Vec<StoredAccount>,
    /// account ID -> (holder, epoch, expires_at in ms)
    leases: BTreeMap<String, (String, i64, i64)>,
    /// Append-only: (user, account ID, alias, deleted_at).
    deletions: Vec<(String, String, String, i64)>,
    /// "user\u{1f}admission ID" -> marker
    admissions: BTreeMap<String, Marker>,
    /// "user\u{1f}admission ID" -> row
    pending: BTreeMap<String, PendingRow>,
    flows: BTreeMap<String, FlowRow>,
    usage: BTreeMap<String, Vec<u8>>,
    audit: Vec<Vec<u8>>,
    users: Vec<User>,
    machines: Vec<Machine>,
    /// "kind\u{1f}key" -> row
    enrollment: BTreeMap<String, EnrollmentRow>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Marker {
    account: String,
    incarnation: String,
    kind: AdmissionKind,
    /// Revoked by a delete of its account.
    revoked: bool,
}

pub struct FileStore {
    path: PathBuf,
    key: PathBuf,
    tables: Mutex<Tables>,
    _owner: vault::Lock,
}

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}
fn slot(a: &str, b: &str) -> String {
    format!("{a}\u{1f}{b}")
}

impl FileStore {
    /// Create an empty store. Fails when one exists.
    pub fn create(state: &Path, key: &Path) -> Result<()> {
        fs::ensure_private_dir(state)?;
        let _owner = vault::lock(state, "owner.lock")?;
        let path = state.join("state.enc");
        if path.try_exists()? {
            anyhow::bail!("server state already initialized");
        }
        vault::seal(&path, key, &Tables::default())
    }
    pub fn exists(state: &Path) -> Result<bool> {
        Ok(state.join("state.enc").try_exists()?)
    }
    /// Open the store and take the process lock: one process per state directory.
    pub fn open(state: &Path, key: &Path) -> Result<Self> {
        let owner = vault::lock(state, "owner.lock")?;
        let path = state.join("state.enc");
        let tables = vault::unseal(&path, key)?;
        Ok(Self {
            path,
            key: key.into(),
            tables: Mutex::new(tables),
            _owner: owner,
        })
    }
    pub fn holder(&self) -> &str {
        "local"
    }
    fn read<T>(&self, f: impl FnOnce(&Tables) -> T) -> T {
        f(&self.tables.lock().expect("store lock"))
    }
    /// Check and change under one lock. `f` works on a copy and returns its result and
    /// whether it changed anything; a change is published with one atomic write.
    fn transact<T>(&self, f: impl FnOnce(&mut Tables) -> (T, bool)) -> Result<T> {
        let mut tables = self.tables.lock().expect("store lock");
        let mut next = tables.clone();
        let (result, changed) = f(&mut next);
        if changed {
            vault::seal(&self.path, &self.key, &next)?;
            *tables = next;
        }
        Ok(result)
    }
    fn write(&self, f: impl FnOnce(&mut Tables)) -> Result<()> {
        self.transact(|t| (f(t), true))
    }
    pub fn ready(&self) -> Result<()> {
        Ok(())
    }
    pub fn account(&self, user: &str, id: &str) -> Result<Option<StoredAccount>> {
        Ok(self.read(|t| t.accounts.get(id).filter(|a| a.user == user).cloned()))
    }
    pub fn accounts(&self, user: &str) -> Result<Vec<StoredAccount>> {
        Ok(self.read(|t| {
            t.accounts
                .values()
                .filter(|a| a.user == user)
                .cloned()
                .collect()
        }))
    }
    fn fenced(t: &Tables, id: &str, fence: Fence<'_>) -> bool {
        let (lease, live) = match fence {
            Fence::Live(lease) => (lease, true),
            Fence::Held(lease) => (lease, false),
        };
        t.leases.get(id).is_some_and(|(holder, epoch, expires)| {
            *holder == lease.holder && *epoch == lease.epoch && (!live || *expires > now())
        })
    }
    pub fn put_account(
        &self,
        account: &StoredAccount,
        expected: i64,
        fence: Fence<'_>,
    ) -> Result<bool> {
        self.transact(|t| {
            let id = &account.id;
            let allowed = t.accounts.get(id).is_some_and(|a| {
                a.revision == expected
                    && a.user == account.user
                    && a.incarnation == account.incarnation
            }) && Self::fenced(t, id, fence);
            if allowed {
                t.accounts.insert(id.clone(), account.clone());
            }
            (allowed, allowed)
        })
    }
    pub fn admit(&self, admission: &Admission) -> Result<AdmitOutcome> {
        let a = &admission.account;
        let pending_key = slot(&a.user, &admission.admission_id);
        self.transact(|t| {
            let live = t
                .pending
                .get(&pending_key)
                .is_some_and(|p| p.state == PendingState::Live);
            let flow_live = admission.login_id.as_ref().is_none_or(|login| {
                t.flows
                    .get(login)
                    .is_some_and(|f| f.user == a.user && !f.cancelled && !f.consumed)
            });
            if !live || !flow_live {
                return (AdmitOutcome::Cancelled, false);
            }
            // A renewal writes over the live incarnation it read; a new account is new.
            let same = match t.accounts.get(&a.id) {
                Some(c) => {
                    Some(c.revision) == admission.expected_revision
                        && c.incarnation == a.incarnation
                        && c.user == a.user
                }
                None => admission.expected_revision.is_none(),
            };
            let identity_taken = t.accounts.values().any(|o| {
                o.id != a.id
                    && o.account_uuid == a.account_uuid
                    && o.organization_uuid == a.organization_uuid
            });
            let alias_taken = t.accounts.values().any(|o| {
                o.id != a.id && o.user == a.user && o.alias.eq_ignore_ascii_case(&a.alias)
            });
            if !same || identity_taken || alias_taken {
                return (AdmitOutcome::Conflict, false);
            }
            t.accounts.insert(a.id.clone(), a.clone());
            t.admissions.insert(
                pending_key.clone(),
                Marker {
                    account: a.id.clone(),
                    incarnation: a.incarnation.clone(),
                    kind: admission.kind,
                    revoked: false,
                },
            );
            if let Some(p) = t.pending.get_mut(&pending_key) {
                p.state = PendingState::Committed;
                p.sealed.clear();
            }
            if let Some(login) = &admission.login_id
                && let Some(f) = t.flows.get_mut(login)
            {
                f.consumed = true;
                f.retained = None;
            }
            (AdmitOutcome::Committed, true)
        })
    }
    pub fn admission(&self, user: &str, admission_id: &str) -> Result<Option<Admitted>> {
        Ok(self.read(|t| {
            let m = t.admissions.get(&slot(user, admission_id))?;
            let live = t
                .accounts
                .get(&m.account)
                .filter(|a| !m.revoked && a.user == user && a.incarnation == m.incarnation);
            Some(match live {
                Some(account) => Admitted::Live {
                    kind: m.kind,
                    account: account.clone(),
                },
                None => Admitted::Gone,
            })
        }))
    }
    pub fn delete(&self, user: &str, id: &str) -> Result<bool> {
        self.transact(|t| {
            if t.accounts.get(id).is_none_or(|a| a.user != user) {
                return (false, false);
            }
            // Keep the row as a marker; erase the grant.
            let mut row = t.accounts.remove(id).expect("checked above");
            row.sealed.clear();
            row.revision += 1;
            let alias = row.alias.clone();
            t.retired.push(row);
            // A new epoch fences every write of a refresh that was in flight.
            if let Some((holder, epoch, expires)) = t.leases.get_mut(id) {
                *holder = "deleted".into();
                *epoch += 1;
                *expires = now();
            }
            t.usage.remove(id);
            t.deletions
                .push((user.into(), id.into(), alias.clone(), now()));
            let prefix = slot(user, "");
            for (key, m) in t.admissions.iter_mut() {
                if key.starts_with(&prefix) && m.account == id {
                    m.revoked = true;
                }
            }
            for p in t.pending.values_mut() {
                if p.user == user
                    && p.alias.eq_ignore_ascii_case(&alias)
                    && p.state == PendingState::Live
                {
                    p.state = PendingState::Cancelled;
                    p.sealed.clear();
                }
            }
            for f in t.flows.values_mut() {
                if f.user == user && f.alias.eq_ignore_ascii_case(&alias) && !f.consumed {
                    f.cancelled = true;
                    f.retained = None;
                }
            }
            (true, true)
        })
    }
    pub fn deleted(&self, user: &str, id: &str) -> Result<bool> {
        Ok(self.read(|t| {
            !t.accounts.contains_key(id)
                && t.deletions.iter().any(|(u, i, _, _)| u == user && i == id)
        }))
    }
    #[cfg(test)]
    pub fn account_rows(&self, id: &str) -> Result<Vec<(String, bool)>> {
        Ok(self.read(|t| {
            let retired = t.retired.iter().filter(|a| a.id == id);
            retired
                .map(|a| (a.incarnation.clone(), true))
                .chain(t.accounts.get(id).map(|a| (a.incarnation.clone(), false)))
                .collect()
        }))
    }
    pub fn acquire_lease(&self, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
        let holder = self.holder().to_owned();
        self.transact(|t| {
            let now = now();
            let free = t
                .leases
                .get(id)
                .is_none_or(|(h, _, expires)| *expires <= now || *h == holder);
            if !free {
                return (None, false);
            }
            let epoch = t.leases.get(id).map_or(1, |(_, e, _)| e + 1);
            t.leases
                .insert(id.into(), (holder.clone(), epoch, now + ttl_ms));
            let lease = Lease {
                holder,
                epoch,
                remaining_ms: ttl_ms,
                taken: std::time::Instant::now(),
            };
            (Some(lease), true)
        })
    }
    pub fn renew_lease(&self, lease: &Lease, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
        self.transact(|t| {
            let now = now();
            let live = t.leases.get(id).is_some_and(|(h, e, expires)| {
                *h == lease.holder && *e == lease.epoch && *expires > now
            });
            if !live {
                return (None, false);
            }
            t.leases
                .insert(id.into(), (lease.holder.clone(), lease.epoch, now + ttl_ms));
            let renewed = Lease {
                remaining_ms: ttl_ms,
                taken: std::time::Instant::now(),
                ..lease.clone()
            };
            (Some(renewed), true)
        })
    }
    pub fn release_lease(&self, lease: &Lease, id: &str) -> Result<()> {
        self.transact(|t| match t.leases.get_mut(id) {
            Some(entry) if entry.0 == lease.holder && entry.1 == lease.epoch => {
                entry.2 = now();
                ((), true)
            }
            _ => ((), false),
        })
    }
    pub fn pending(&self, user: &str, admission_id: &str) -> Result<Option<PendingRow>> {
        Ok(self.read(|t| t.pending.get(&slot(user, admission_id)).cloned()))
    }
    pub fn put_pending(
        &self,
        admission_id: &str,
        row: &PendingRow,
        login_id: Option<&str>,
    ) -> Result<()> {
        let key = slot(&row.user, admission_id);
        self.transact(|t| {
            let flow_live = login_id.is_none_or(|login| {
                t.flows
                    .get(login)
                    .is_some_and(|f| f.user == row.user && !f.cancelled && !f.consumed)
            });
            if t.pending.contains_key(&key) || !flow_live {
                return ((), false);
            }
            t.pending.insert(key, row.clone());
            ((), true)
        })
    }
    pub fn flow(&self, user: &str, id: &str) -> Result<Option<FlowRow>> {
        Ok(self.read(|t| t.flows.get(id).filter(|f| f.user == user).cloned()))
    }
    pub fn put_flow(&self, id: &str, row: &FlowRow) -> Result<()> {
        self.write(|t| {
            t.flows.insert(id.into(), row.clone());
        })
    }
    pub fn start_exchange(&self, user: &str, id: &str) -> Result<bool> {
        self.transact(|t| match t.flows.get_mut(id) {
            Some(f) if f.user == user && !f.exchanging && !f.cancelled && !f.consumed => {
                f.exchanging = true;
                (true, true)
            }
            _ => (false, false),
        })
    }
    pub fn retain(&self, user: &str, id: &str, sealed: &[u8]) -> Result<bool> {
        self.transact(|t| match t.flows.get_mut(id) {
            Some(f) if f.user == user && !f.cancelled && !f.consumed => {
                f.retained = Some(sealed.to_vec());
                (true, true)
            }
            _ => (false, false),
        })
    }
    pub fn usage(&self, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.read(|t| t.usage.get(id).cloned()))
    }
    pub fn put_usage(&self, id: &str, sealed: &[u8]) -> Result<()> {
        self.transact(|t| {
            let keep = t.accounts.contains_key(id) || id.starts_with("__");
            if keep {
                t.usage.insert(id.into(), sealed.to_vec());
            }
            ((), keep)
        })
    }
    pub fn append_audit(&self, sealed: &[u8]) -> Result<()> {
        self.write(|t| t.audit.push(sealed.to_vec()))
    }
    pub fn audit(&self) -> Result<Vec<Vec<u8>>> {
        Ok(self.read(|t| t.audit.clone()))
    }
    pub fn users(&self) -> Result<Vec<User>> {
        Ok(self.read(|t| t.users.clone()))
    }
    pub fn user(&self, id: &str) -> Result<Option<User>> {
        Ok(self.read(|t| t.users.iter().find(|u| u.id == id).cloned()))
    }
    pub fn record_user(&self, id: &str, email: &str) -> Result<bool> {
        self.transact(|t| {
            if let Some(user) = t.users.iter_mut().find(|u| u.id == id) {
                if !user.enabled {
                    return (false, false);
                }
                user.email = email.into();
            } else {
                t.users.push(User {
                    id: id.into(),
                    email: email.into(),
                    enabled: true,
                });
            }
            (true, true)
        })
    }
    pub fn set_user_enabled(&self, email: &str, enabled: bool) -> Result<bool> {
        self.transact(|t| {
            let mut found = false;
            for user in t
                .users
                .iter_mut()
                .filter(|u| u.email.eq_ignore_ascii_case(email))
            {
                user.enabled = enabled;
                found = true;
            }
            (found, found)
        })
    }
    pub fn machines(&self, user: &str) -> Result<Vec<(String, bool)>> {
        Ok(self.read(|t| {
            t.machines
                .iter()
                .filter(|m| m.user == user)
                .map(|m| (m.id.clone(), m.revoked))
                .collect()
        }))
    }
    pub fn machine_by_token(&self, token_hash: &str) -> Result<Option<Machine>> {
        Ok(self.read(|t| {
            t.machines
                .iter()
                .find(|m| m.token_hash == token_hash)
                .cloned()
        }))
    }
    pub fn add_machine(&self, machine: &Machine) -> Result<()> {
        self.write(|t| t.machines.push(machine.clone()))
    }
    pub fn revoke_machine(&self, id: &str, user: Option<&str>) -> Result<bool> {
        self.transact(|t| {
            let mut found = false;
            for m in t
                .machines
                .iter_mut()
                .filter(|m| m.id == id && user.is_none_or(|u| m.user == u))
            {
                m.revoked = true;
                found = true;
            }
            (found, found)
        })
    }
    pub fn put_enrollment(&self, kind: &str, key: &str, row: &EnrollmentRow) -> Result<()> {
        self.write(|t| {
            t.enrollment.insert(slot(kind, key), row.clone());
        })
    }
    pub fn find_enrollment(
        &self,
        kind: &str,
        lookup: &str,
        now: i64,
    ) -> Result<Option<(String, EnrollmentRow)>> {
        Ok(self.read(|t| {
            t.enrollment.iter().find_map(|(slot, r)| {
                let (k, key) = slot.split_once('\u{1f}')?;
                (k == kind
                    && r.lookup.as_deref() == Some(lookup)
                    && !r.consumed
                    && r.expires_at > now)
                    .then(|| (key.to_owned(), r.clone()))
            })
        }))
    }
    pub fn enrollment(&self, kind: &str, key: &str, now: i64) -> Result<Option<EnrollmentRow>> {
        Ok(self.read(|t| {
            t.enrollment
                .get(&slot(kind, key))
                .filter(|r| r.expires_at > now)
                .cloned()
        }))
    }
    pub fn swap_enrollment(
        &self,
        kind: &str,
        key: &str,
        expected: &[u8],
        sealed: &[u8],
    ) -> Result<bool> {
        self.transact(|t| match t.enrollment.get_mut(&slot(kind, key)) {
            Some(r) if !r.consumed && r.sealed == expected => {
                r.sealed = sealed.to_vec();
                (true, true)
            }
            _ => (false, false),
        })
    }
    pub fn consume_enrollment(
        &self,
        kind: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<EnrollmentRow>> {
        self.transact(|t| match t.enrollment.get_mut(&slot(kind, key)) {
            Some(r) if !r.consumed && r.expires_at > now => {
                let row = r.clone();
                r.consumed = true;
                (Some(row), true)
            }
            _ => (None, false),
        })
    }
}
