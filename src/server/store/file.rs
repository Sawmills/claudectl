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
    accounts: BTreeMap<String, StoredAccount>,
    /// account ID -> (holder, epoch, expires_at in ms)
    leases: BTreeMap<String, (String, i64, i64)>,
    /// account ID -> (user, alias, deleted_at)
    tombstones: BTreeMap<String, (String, String, i64)>,
    pending: BTreeMap<String, PendingRow>,
    flows: BTreeMap<String, FlowRow>,
    usage: BTreeMap<String, Vec<u8>>,
    audit: Vec<Vec<u8>>,
    users: Vec<User>,
    machines: Vec<Machine>,
    /// (kind, key) -> row
    enrollment: BTreeMap<(String, String), EnrollmentRow>,
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
    pub fn account(&self, id: &str) -> Result<Option<StoredAccount>> {
        Ok(self.read(|t| t.accounts.get(id).cloned()))
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
            let allowed = t.accounts.get(id).is_some_and(|a| a.revision == expected)
                && Self::fenced(t, id, fence);
            if allowed {
                t.accounts.insert(id.clone(), account.clone());
            }
            (allowed, allowed)
        })
    }
    pub fn admit(&self, admission: &Admission) -> Result<AdmitOutcome> {
        let a = &admission.account;
        self.transact(|t| {
            if t
                .tombstones
                .get(&a.id)
                .is_some_and(|(_, _, deleted_at)| *deleted_at >= admission.started_at)
            {
                return (AdmitOutcome::DeletedSince, false);
            }
            if let Some(login) = &admission.login_id
                && !t.flows.contains_key(login)
            {
                return (AdmitOutcome::FlowGone, false);
            }
            let current = t.accounts.get(&a.id).map(|c| c.revision);
            let identity_taken = t.accounts.values().any(|o| {
                o.id != a.id
                    && o.account_uuid == a.account_uuid
                    && o.organization_uuid == a.organization_uuid
            });
            let alias_taken = t.accounts.values().any(|o| {
                o.id != a.id && o.user == a.user && o.alias.eq_ignore_ascii_case(&a.alias)
            });
            if current != admission.expected_revision || identity_taken || alias_taken {
                return (AdmitOutcome::Conflict, false);
            }
            t.accounts.insert(a.id.clone(), a.clone());
            t.pending.remove(&admission.pending_key);
            if let Some(login) = &admission.login_id {
                t.flows.remove(login);
            }
            (AdmitOutcome::Committed, true)
        })
    }
    pub fn delete(&self, id: &str, user: &str, deleted_at: i64) -> Result<bool> {
        self.transact(|t| {
            let Some(alias) = t
                .accounts
                .get(id)
                .filter(|a| a.user == user)
                .map(|a| a.alias.clone())
            else {
                return (false, false);
            };
            t.accounts.remove(id);
            t.leases.remove(id);
            t.usage.remove(id);
            t.tombstones
                .insert(id.into(), (user.into(), alias.clone(), deleted_at));
            t.pending
                .retain(|_, p| !(p.user == user && p.alias.eq_ignore_ascii_case(&alias)));
            t.flows
                .retain(|_, f| !(f.user == user && f.alias.eq_ignore_ascii_case(&alias)));
            (true, true)
        })
    }
    pub fn deleted(&self, id: &str, user: &str) -> Result<bool> {
        Ok(self.read(|t| t.tombstones.get(id).is_some_and(|(u, _, _)| u == user)))
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
            (
                Some(Lease {
                    holder,
                    epoch,
                    remaining_ms: ttl_ms,
                }),
                true,
            )
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
            (
                Some(Lease {
                    remaining_ms: ttl_ms,
                    ..lease.clone()
                }),
                true,
            )
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
    pub fn pending(&self, key: &str) -> Result<Option<PendingRow>> {
        Ok(self.read(|t| t.pending.get(key).cloned()))
    }
    pub fn put_pending(&self, key: &str, row: &PendingRow) -> Result<()> {
        self.write(|t| {
            t.pending.insert(key.into(), row.clone());
        })
    }
    pub fn delete_pending(&self, key: &str) -> Result<()> {
        self.transact(|t| ((), t.pending.remove(key).is_some()))
    }
    pub fn flow(&self, id: &str) -> Result<Option<FlowRow>> {
        Ok(self.read(|t| t.flows.get(id).cloned()))
    }
    pub fn put_flow(&self, id: &str, row: &FlowRow) -> Result<()> {
        self.write(|t| {
            t.flows.insert(id.into(), row.clone());
        })
    }
    pub fn start_exchange(&self, id: &str) -> Result<bool> {
        self.transact(|t| match t.flows.get_mut(id) {
            Some(flow) if !flow.exchanging => {
                flow.exchanging = true;
                (true, true)
            }
            _ => (false, false),
        })
    }
    pub fn retain(&self, id: &str, sealed: &[u8]) -> Result<bool> {
        self.transact(|t| match t.flows.get_mut(id) {
            Some(flow) => {
                flow.retained = Some(sealed.to_vec());
                (true, true)
            }
            None => (false, false),
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
            for user in t.users.iter_mut().filter(|u| u.email.eq_ignore_ascii_case(email)) {
                user.enabled = enabled;
                found = true;
            }
            (found, found)
        })
    }
    pub fn machines(&self) -> Result<Vec<Machine>> {
        Ok(self.read(|t| t.machines.clone()))
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
        let now = now();
        self.write(|t| {
            t.enrollment.retain(|_, r| r.expires_at > now);
            t.enrollment.insert((kind.into(), key.into()), row.clone());
        })
    }
    pub fn find_enrollment(
        &self,
        kind: &str,
        lookup: &str,
        now: i64,
    ) -> Result<Option<(String, EnrollmentRow)>> {
        Ok(self.read(|t| {
            t.enrollment
                .iter()
                .find(|((k, _), r)| {
                    k == kind
                        && r.lookup.as_deref() == Some(lookup)
                        && !r.consumed
                        && r.expires_at > now
                })
                .map(|((_, key), r)| (key.clone(), r.clone()))
        }))
    }
    pub fn enrollment(&self, kind: &str, key: &str, now: i64) -> Result<Option<EnrollmentRow>> {
        Ok(self.read(|t| {
            t.enrollment
                .get(&(kind.into(), key.into()))
                .filter(|r| r.expires_at > now)
                .cloned()
        }))
    }
    pub fn update_enrollment(&self, kind: &str, key: &str, sealed: &[u8]) -> Result<bool> {
        self.transact(|t| match t.enrollment.get_mut(&(kind.into(), key.into())) {
            Some(r) if !r.consumed => {
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
        self.transact(|t| match t.enrollment.get_mut(&(kind.into(), key.into())) {
            Some(r) if !r.consumed && r.expires_at > now => {
                let row = r.clone();
                r.consumed = true;
                (Some(row), true)
            }
            _ => (None, false),
        })
    }
}
