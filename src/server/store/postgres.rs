//! PostgreSQL store for several replicas. Each change is one short transaction on its own
//! pooled connection. Leases use the database clock.
use super::*;
use anyhow::{Context, bail};
use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod};
use std::time::Duration;
use tokio_postgres::{Row, error::SqlState};

/// Schema this binary writes, and the oldest schema it can read.
pub const SCHEMA_VERSION: i32 = 1;
const REQUIRED_SCHEMA: i32 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS schema_info (
    id INT PRIMARY KEY CHECK (id = 1),
    version INT NOT NULL,
    min_reader INT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT NOT NULL,
    -- A recreate after a delete inserts a new incarnation; a deleted row is never revived.
    incarnation TEXT NOT NULL,
    user_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    account_uuid TEXT NOT NULL,
    organization_uuid TEXT NOT NULL,
    revision BIGINT NOT NULL,
    sealed BYTEA NOT NULL,
    -- A delete keeps the row as a marker and erases the sealed grant; the runtime role
    -- has no DELETE privilege.
    deleted BOOLEAN NOT NULL DEFAULT false,
    PRIMARY KEY (account_id, incarnation)
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_live ON accounts (account_id) WHERE NOT deleted;
CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_alias ON accounts (user_id, lower(alias))
    WHERE NOT deleted;
CREATE UNIQUE INDEX IF NOT EXISTS accounts_identity ON accounts (account_uuid, organization_uuid)
    WHERE NOT deleted;
CREATE TABLE IF NOT EXISTS refresh_leases (
    account_id TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS deletions (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    deleted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS deletions_account ON deletions (user_id, account_id);
CREATE TABLE IF NOT EXISTS admissions (
    user_id TEXT NOT NULL,
    admission_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    -- The incarnation this admission created or renewed; it never resolves to another.
    incarnation TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('login', 'migration')),
    revoked BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, admission_id)
);
CREATE TABLE IF NOT EXISTS pending_admissions (
    user_id TEXT NOT NULL,
    admission_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('live', 'cancelled', 'committed')),
    sealed BYTEA NOT NULL,
    PRIMARY KEY (user_id, admission_id)
);
CREATE TABLE IF NOT EXISTS login_flows (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    sealed BYTEA NOT NULL,
    exchanging BOOLEAN NOT NULL DEFAULT false,
    retained BYTEA,
    cancelled BOOLEAN NOT NULL DEFAULT false,
    consumed BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS login_flows_alias ON login_flows (user_id, lower(alias));
CREATE TABLE IF NOT EXISTS usage_cache (
    account_id TEXT PRIMARY KEY,
    sealed BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,
    sealed BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    enabled BOOLEAN NOT NULL
);
CREATE TABLE IF NOT EXISTS machines (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    revoked BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS machines_user ON machines (user_id, id);
CREATE TABLE IF NOT EXISTS enrollment (
    kind TEXT NOT NULL,
    key TEXT NOT NULL,
    lookup TEXT,
    sealed BYTEA NOT NULL,
    expires_at BIGINT NOT NULL,
    consumed_at BIGINT,
    PRIMARY KEY (kind, key)
);
CREATE INDEX IF NOT EXISTS enrollment_lookup ON enrollment (kind, lookup);
"#;

pub struct PostgresStore {
    pool: Pool,
    holder: String,
}

fn tls() -> Result<tokio_postgres_rustls::MakeRustlsConnect> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    if let Ok(path) = std::env::var("CLAUDECTL_SERVER_DB_CA_FILE") {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        for certificate in CertificateDer::pem_file_iter(&path)
            .with_context(|| format!("read CLAUDECTL_SERVER_DB_CA_FILE {path:?}"))?
        {
            roots
                .add(certificate.context("parse the database CA bundle")?)
                .context("add a database CA certificate")?;
        }
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_postgres_rustls::MakeRustlsConnect::new(config))
}

/// The advisory lock that serializes admission and delete for one user and alias.
fn alias_lock(user: &str, alias: &str) -> i64 {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{user}\0{}", alias.to_ascii_lowercase()).as_bytes());
    i64::from_be_bytes(digest[..8].try_into().expect("eight bytes"))
}

fn account(row: &Row) -> StoredAccount {
    StoredAccount {
        id: row.get("account_id"),
        user: row.get("user_id"),
        alias: row.get("alias"),
        account_uuid: row.get("account_uuid"),
        organization_uuid: row.get("organization_uuid"),
        revision: row.get("revision"),
        sealed: row.get("sealed"),
        incarnation: row.get("incarnation"),
    }
}
fn state_name(state: PendingState) -> &'static str {
    match state {
        PendingState::Live => "live",
        PendingState::Cancelled => "cancelled",
        PendingState::Committed => "committed",
    }
}
fn flow(r: &Row) -> FlowRow {
    FlowRow {
        user: r.get("user_id"),
        alias: r.get("alias"),
        sealed: r.get("sealed"),
        exchanging: r.get("exchanging"),
        retained: r.get("retained"),
        cancelled: r.get("cancelled"),
        consumed: r.get("consumed"),
    }
}

impl PostgresStore {
    /// Connect with a small pool. A URL without `sslmode=require` connects without TLS,
    /// which only a loopback test database may use.
    pub async fn connect(url: &str) -> Result<Self> {
        let mut config: tokio_postgres::Config = url.parse().context("invalid database URL")?;
        config.connect_timeout(Duration::from_secs(5));
        config.keepalives_idle(Duration::from_secs(10));
        config.options(
            "-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=5000",
        );
        let manager_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let manager = match config.get_ssl_mode() {
            tokio_postgres::config::SslMode::Require => {
                Manager::from_config(config, tls()?, manager_config)
            }
            _ => {
                let loopback = config.get_hosts().iter().all(|h| match h {
                    tokio_postgres::config::Host::Tcp(host) => {
                        matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1")
                    }
                    #[cfg(unix)]
                    tokio_postgres::config::Host::Unix(_) => true,
                });
                if !loopback {
                    bail!("a remote database needs sslmode=require");
                }
                Manager::from_config(config, tokio_postgres::NoTls, manager_config)
            }
        };
        let pool = Pool::builder(manager)
            .max_size(8)
            .wait_timeout(Some(Duration::from_secs(5)))
            .create_timeout(Some(Duration::from_secs(5)))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .build()?;
        let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "server".into());
        Ok(Self {
            pool,
            holder: format!("{host}-{}", &crate::server::vault::secret()[..12]),
        })
    }
    /// Apply the schema. Only the migration job runs this; `serve` never does.
    pub async fn migrate(&self) -> Result<()> {
        let client = self.pool.get().await?;
        client.batch_execute(SCHEMA).await?;
        client
            .execute(
                "INSERT INTO schema_info (id, version, min_reader) VALUES (1, $1, $2)
                 ON CONFLICT (id) DO UPDATE SET version = GREATEST(schema_info.version, EXCLUDED.version)",
                &[&SCHEMA_VERSION, &REQUIRED_SCHEMA],
            )
            .await?;
        Ok(())
    }
    /// Refuse a schema that is too old for this binary or too new for it to read.
    pub async fn check_schema(&self) -> Result<()> {
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "SELECT version, min_reader FROM schema_info WHERE id = 1",
                &[],
            )
            .await
            .context("schema is not installed; run claudectl-server migrate")?
            .context("schema is not installed; run claudectl-server migrate")?;
        let (version, min_reader): (i32, i32) = (row.get(0), row.get(1));
        if version < REQUIRED_SCHEMA {
            bail!("schema version {version} is older than {REQUIRED_SCHEMA}; run migrate");
        }
        if min_reader > SCHEMA_VERSION {
            bail!("schema needs a server of version {min_reader} or newer");
        }
        Ok(())
    }
    pub fn holder(&self) -> &str {
        &self.holder
    }
    pub async fn ready(&self) -> Result<()> {
        self.check_schema().await
    }
    pub async fn account(&self, user: &str, id: &str) -> Result<Option<StoredAccount>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT * FROM accounts WHERE account_id = $1 AND user_id = $2 AND NOT deleted",
                &[&id, &user],
            )
            .await?
            .as_ref()
            .map(account))
    }
    pub async fn accounts(&self, user: &str) -> Result<Vec<StoredAccount>> {
        let client = self.pool.get().await?;
        Ok(client
            .query(
                "SELECT * FROM accounts WHERE user_id = $1 AND NOT deleted ORDER BY alias",
                &[&user],
            )
            .await?
            .iter()
            .map(account)
            .collect())
    }
    pub async fn put_account(
        &self,
        a: &StoredAccount,
        expected: i64,
        fence: Fence<'_>,
    ) -> Result<bool> {
        let (lease, live) = match fence {
            Fence::Live(lease) => (lease, true),
            Fence::Held(lease) => (lease, false),
        };
        let client = self.pool.get().await?;
        // Lock the lease row, so a concurrent acquisition orders against this write.
        let rows = client
            .execute(
                "WITH lease AS (
                    SELECT 1 FROM refresh_leases
                    WHERE account_id = $1 AND holder_id = $5 AND epoch = $6
                      AND (NOT $7 OR expires_at > now())
                    FOR UPDATE
                 )
                 UPDATE accounts SET revision = $3, sealed = $4
                 WHERE account_id = $1 AND user_id = $2 AND revision = $8 AND incarnation = $9
                   AND NOT deleted AND EXISTS (SELECT 1 FROM lease)",
                &[
                    &a.id,
                    &a.user,
                    &a.revision,
                    &a.sealed,
                    &lease.holder,
                    &lease.epoch,
                    &live,
                    &expected,
                    &a.incarnation,
                ],
            )
            .await?;
        Ok(rows == 1)
    }
    pub async fn admit(&self, admission: &Admission) -> Result<AdmitOutcome> {
        let a = &admission.account;
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&alias_lock(&a.user, &a.alias)],
        )
        .await?;
        // Existence fencing: a delete cancels these under the same lock, so a cancelled
        // admission never commits, whatever any clock says.
        let live = tx
            .query_opt(
                "SELECT 1 FROM pending_admissions
                 WHERE user_id = $1 AND admission_id = $2 AND state = 'live' FOR UPDATE",
                &[&a.user, &admission.admission_id],
            )
            .await?
            .is_some();
        let flow_live = match &admission.login_id {
            Some(login) => tx
                .query_opt(
                    "SELECT 1 FROM login_flows
                     WHERE id = $1 AND user_id = $2 AND NOT cancelled AND NOT consumed FOR UPDATE",
                    &[login, &a.user],
                )
                .await?
                .is_some(),
            None => true,
        };
        if !live || !flow_live {
            return Ok(AdmitOutcome::Cancelled);
        }
        let current: Option<(i64, String)> = tx
            .query_opt(
                "SELECT revision, incarnation FROM accounts
                 WHERE account_id = $1 AND user_id = $2 AND NOT deleted FOR UPDATE",
                &[&a.id, &a.user],
            )
            .await?
            .map(|r| (r.get(0), r.get(1)));
        let conflict = tx
            .query_opt(
                "SELECT 1 FROM accounts WHERE account_id <> $1 AND NOT deleted AND (
                    (account_uuid = $2 AND organization_uuid = $3)
                    OR (user_id = $4 AND lower(alias) = lower($5)))",
                &[
                    &a.id,
                    &a.account_uuid,
                    &a.organization_uuid,
                    &a.user,
                    &a.alias,
                ],
            )
            .await?
            .is_some();
        let same = match &current {
            // A renewal writes over the live incarnation it read.
            Some((revision, incarnation)) => {
                Some(*revision) == admission.expected_revision && *incarnation == a.incarnation
            }
            None => admission.expected_revision.is_none(),
        };
        if !same || conflict {
            return Ok(AdmitOutcome::Conflict);
        }
        let written = if current.is_some() {
            tx.execute(
                "UPDATE accounts SET alias = $3, account_uuid = $4, organization_uuid = $5,
                    revision = $6, sealed = $7
                 WHERE account_id = $1 AND user_id = $2 AND incarnation = $8 AND NOT deleted",
                &[
                    &a.id,
                    &a.user,
                    &a.alias,
                    &a.account_uuid,
                    &a.organization_uuid,
                    &a.revision,
                    &a.sealed,
                    &a.incarnation,
                ],
            )
            .await
        } else {
            // Always a new row: a deleted incarnation keeps its own row and stays deleted.
            tx.execute(
                "INSERT INTO accounts (account_id, incarnation, user_id, alias, account_uuid,
                    organization_uuid, revision, sealed)
                 VALUES ($1, $8, $2, $3, $4, $5, $6, $7)",
                &[
                    &a.id,
                    &a.user,
                    &a.alias,
                    &a.account_uuid,
                    &a.organization_uuid,
                    &a.revision,
                    &a.sealed,
                    &a.incarnation,
                ],
            )
            .await
        };
        match written {
            Ok(1) => {}
            Ok(_) => return Ok(AdmitOutcome::Conflict),
            // A concurrent admission of the same identity under another alias.
            Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                return Ok(AdmitOutcome::Conflict);
            }
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "INSERT INTO admissions (user_id, admission_id, account_id, incarnation, kind)
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &a.user,
                &admission.admission_id,
                &a.id,
                &a.incarnation,
                &admission.kind.name(),
            ],
        )
        .await?;
        tx.execute(
            "UPDATE pending_admissions SET state = 'committed', sealed = ''::BYTEA
             WHERE user_id = $1 AND admission_id = $2",
            &[&a.user, &admission.admission_id],
        )
        .await?;
        if let Some(login) = &admission.login_id {
            tx.execute(
                "UPDATE login_flows SET consumed = true, retained = NULL WHERE id = $1",
                &[login],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(AdmitOutcome::Committed)
    }
    pub async fn admission(&self, user: &str, admission_id: &str) -> Result<Option<Admitted>> {
        let client = self.pool.get().await?;
        // One statement: the marker and the live row of its own incarnation, or nothing.
        let Some(row) = client
            .query_opt(
                "SELECT m.kind, m.revoked, a.*
                 FROM admissions m
                 LEFT JOIN accounts a ON a.account_id = m.account_id AND a.user_id = m.user_id
                    AND a.incarnation = m.incarnation AND NOT a.deleted
                 WHERE m.user_id = $1 AND m.admission_id = $2",
                &[&user, &admission_id],
            )
            .await?
        else {
            return Ok(None);
        };
        let kind = AdmissionKind::parse(row.get("kind"))?;
        let revoked: bool = row.get("revoked");
        let live: Option<String> = row.get("account_id");
        Ok(Some(match live {
            Some(_) if !revoked => Admitted::Live {
                kind,
                account: account(&row),
            },
            _ => Admitted::Gone,
        }))
    }
    pub async fn delete(&self, user: &str, id: &str) -> Result<bool> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let Some(alias): Option<String> = tx
            .query_opt(
                "SELECT alias FROM accounts WHERE account_id = $1 AND user_id = $2 AND NOT deleted",
                &[&id, &user],
            )
            .await?
            .map(|r| r.get(0))
        else {
            return Ok(false);
        };
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&alias_lock(user, &alias)],
        )
        .await?;
        // Lock the lease row before the account row, in the same order as put_account(), so
        // a concurrent refresh write and this delete never deadlock.
        tx.execute(
            "SELECT 1 FROM refresh_leases WHERE account_id = $1 FOR UPDATE",
            &[&id],
        )
        .await?;
        // Keep the row as a marker; erase the grant. No DELETE: the runtime role has none.
        if tx
            .execute(
                "UPDATE accounts SET deleted = true, sealed = ''::BYTEA, revision = revision + 1
                 WHERE account_id = $1 AND user_id = $2 AND NOT deleted",
                &[&id, &user],
            )
            .await?
            == 0
        {
            return Ok(false);
        }
        // A new epoch fences every write of a refresh that was in flight.
        tx.execute(
            "UPDATE refresh_leases SET holder_id = 'deleted', epoch = epoch + 1, expires_at = now()
             WHERE account_id = $1",
            &[&id],
        )
        .await?;
        tx.execute(
            "UPDATE usage_cache SET sealed = ''::BYTEA WHERE account_id = $1",
            &[&id],
        )
        .await?;
        tx.execute(
            "INSERT INTO deletions (user_id, account_id, alias) VALUES ($1, $2, $3)",
            &[&user, &id, &alias],
        )
        .await?;
        tx.execute(
            "UPDATE admissions SET revoked = true WHERE user_id = $1 AND account_id = $2",
            &[&user, &id],
        )
        .await?;
        tx.execute(
            "UPDATE pending_admissions SET state = 'cancelled', sealed = ''::BYTEA
             WHERE user_id = $1 AND lower(alias) = lower($2) AND state = 'live'",
            &[&user, &alias],
        )
        .await?;
        tx.execute(
            "UPDATE login_flows SET cancelled = true, retained = NULL
             WHERE user_id = $1 AND lower(alias) = lower($2) AND NOT consumed",
            &[&user, &alias],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    pub async fn deleted(&self, user: &str, id: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT 1 FROM deletions d WHERE d.user_id = $1 AND d.account_id = $2
                 AND NOT EXISTS (SELECT 1 FROM accounts a WHERE a.account_id = $2 AND NOT a.deleted)",
                &[&user, &id],
            )
            .await?
            .is_some())
    }
    #[cfg(test)]
    pub async fn account_rows(&self, id: &str) -> Result<Vec<(String, bool)>> {
        let client = self.pool.get().await?;
        Ok(client
            .query(
                "SELECT incarnation, deleted FROM accounts WHERE account_id = $1",
                &[&id],
            )
            .await?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect())
    }
    pub async fn acquire_lease(&self, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
        let taken = std::time::Instant::now();
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "INSERT INTO refresh_leases (account_id, holder_id, epoch, expires_at)
                 VALUES ($1, $2, 1, now() + make_interval(secs => $3::BIGINT / 1000.0))
                 ON CONFLICT (account_id) DO UPDATE SET holder_id = EXCLUDED.holder_id,
                    epoch = refresh_leases.epoch + 1, expires_at = EXCLUDED.expires_at
                 WHERE refresh_leases.expires_at <= now() OR refresh_leases.holder_id = EXCLUDED.holder_id
                 RETURNING epoch, (EXTRACT(EPOCH FROM expires_at - now()) * 1000)::BIGINT",
                &[&id, &self.holder, &ttl_ms],
            )
            .await?;
        Ok(row.map(|r| Lease {
            holder: self.holder.clone(),
            epoch: r.get(0),
            remaining_ms: r.get(1),
            taken,
        }))
    }
    pub async fn renew_lease(&self, lease: &Lease, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
        let taken = std::time::Instant::now();
        let client = self.pool.get().await?;
        let row = client
            .query_opt(
                "UPDATE refresh_leases SET expires_at = now() + make_interval(secs => $4::BIGINT / 1000.0)
                 WHERE account_id = $1 AND holder_id = $2 AND epoch = $3 AND expires_at > now()
                 RETURNING (EXTRACT(EPOCH FROM expires_at - now()) * 1000)::BIGINT",
                &[&id, &lease.holder, &lease.epoch, &ttl_ms],
            )
            .await?;
        Ok(row.map(|r| Lease {
            remaining_ms: r.get(0),
            taken,
            ..lease.clone()
        }))
    }
    pub async fn release_lease(&self, lease: &Lease, id: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "UPDATE refresh_leases SET expires_at = now()
                 WHERE account_id = $1 AND holder_id = $2 AND epoch = $3",
                &[&id, &lease.holder, &lease.epoch],
            )
            .await?;
        Ok(())
    }
    pub async fn cancel_admission(
        &self,
        user: &str,
        admission_id: &str,
        alias: &str,
    ) -> Result<CancelOutcome> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        // The same lock as admit(): a commit and a cancel never interleave.
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&alias_lock(user, alias)],
        )
        .await?;
        if tx
            .query_opt(
                "SELECT 1 FROM admissions WHERE user_id = $1 AND admission_id = $2",
                &[&user, &admission_id],
            )
            .await?
            .is_some()
        {
            return Ok(CancelOutcome::Admitted);
        }
        // Cancel a kept grant (erasing it), or leave a tombstone that put_pending never
        // replaces, so a delayed import finds a cancelled row.
        tx.execute(
            "INSERT INTO pending_admissions (user_id, admission_id, alias, state, sealed)
             VALUES ($1, $2, $3, 'cancelled', ''::BYTEA)
             ON CONFLICT (user_id, admission_id) DO UPDATE SET state = 'cancelled', sealed = ''::BYTEA
             WHERE pending_admissions.state <> 'committed'",
            &[&user, &admission_id, &alias],
        )
        .await?;
        tx.commit().await?;
        Ok(CancelOutcome::Cancelled)
    }
    pub async fn pending(&self, user: &str, admission_id: &str) -> Result<Option<PendingRow>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT alias, state, sealed FROM pending_admissions
                 WHERE user_id = $1 AND admission_id = $2",
                &[&user, &admission_id],
            )
            .await?
            .map(|r| PendingRow {
                user: user.into(),
                alias: r.get(0),
                state: match r.get::<_, String>(1).as_str() {
                    "live" => PendingState::Live,
                    "committed" => PendingState::Committed,
                    _ => PendingState::Cancelled,
                },
                sealed: r.get(2),
            }))
    }
    pub async fn put_pending(
        &self,
        admission_id: &str,
        row: &PendingRow,
        login_id: Option<&str>,
    ) -> Result<()> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        // Ordered against a delete of the alias, which cancels flows under the same lock.
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&alias_lock(&row.user, &row.alias)],
        )
        .await?;
        tx.execute(
            "INSERT INTO pending_admissions (user_id, admission_id, alias, state, sealed)
             SELECT $1, $2, $3, $4, $5
             WHERE $6::TEXT IS NULL OR EXISTS (
                SELECT 1 FROM login_flows
                WHERE id = $6 AND user_id = $1 AND NOT cancelled AND NOT consumed)
             ON CONFLICT DO NOTHING",
            &[
                &row.user,
                &admission_id,
                &row.alias,
                &state_name(row.state),
                &row.sealed,
                &login_id,
            ],
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn flow(&self, user: &str, id: &str) -> Result<Option<FlowRow>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT * FROM login_flows WHERE id = $1 AND user_id = $2",
                &[&id, &user],
            )
            .await?
            .as_ref()
            .map(flow))
    }
    pub async fn put_flow(&self, id: &str, row: &FlowRow, target: FlowTarget<'_>) -> Result<bool> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        // The same lock as delete(): the flow is written before the delete, which then
        // cancels it, or after, when the target check below fails.
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&alias_lock(&row.user, &row.alias)],
        )
        .await?;
        let holds = match target {
            FlowTarget::New => tx
                .query_opt(
                    "SELECT 1 FROM accounts
                     WHERE user_id = $1 AND lower(alias) = lower($2) AND NOT deleted",
                    &[&row.user, &row.alias],
                )
                .await?
                .is_none(),
            FlowTarget::Renew {
                account,
                incarnation,
            } => tx
                .query_opt(
                    "SELECT 1 FROM accounts
                     WHERE account_id = $1 AND user_id = $2 AND incarnation = $3
                       AND lower(alias) = lower($4) AND NOT deleted",
                    &[&account, &row.user, &incarnation, &row.alias],
                )
                .await?
                .is_some(),
        };
        if !holds {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO login_flows (id, user_id, alias, sealed, exchanging, retained, cancelled, consumed)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[&id, &row.user, &row.alias, &row.sealed, &row.exchanging, &row.retained, &row.cancelled, &row.consumed],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    pub async fn start_exchange(&self, user: &str, id: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE login_flows SET exchanging = true
                 WHERE id = $1 AND user_id = $2 AND NOT exchanging AND NOT cancelled AND NOT consumed",
                &[&id, &user],
            )
            .await?
            == 1)
    }
    pub async fn retain(&self, user: &str, id: &str, sealed: &[u8]) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE login_flows SET retained = $3
                 WHERE id = $1 AND user_id = $2 AND NOT cancelled AND NOT consumed",
                &[&id, &user, &sealed],
            )
            .await?
            == 1)
    }
    pub async fn usage(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT sealed FROM usage_cache WHERE account_id = $1",
                &[&id],
            )
            .await?
            .map(|r| r.get::<_, Vec<u8>>(0))
            // A delete erases the cached usage in place.
            .filter(|sealed| !sealed.is_empty()))
    }
    pub async fn user_usage(&self, user: &str) -> Result<Vec<(String, Vec<u8>)>> {
        let client = self.pool.get().await?;
        Ok(client
            .query(
                // A delete erases the cached usage in place, so empty rows are skipped.
                "SELECT u.account_id, u.sealed FROM usage_cache u
                 JOIN accounts a ON a.account_id = u.account_id
                 WHERE a.user_id = $1 AND NOT a.deleted AND length(u.sealed) > 0",
                &[&user],
            )
            .await?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect())
    }
    pub async fn put_usage(&self, id: &str, sealed: &[u8]) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO usage_cache (account_id, sealed)
                 SELECT $1, $2 WHERE starts_with($1, '__')
                    OR EXISTS (SELECT 1 FROM accounts WHERE account_id = $1 AND NOT deleted)
                 ON CONFLICT (account_id) DO UPDATE SET sealed = EXCLUDED.sealed",
                &[&id, &sealed],
            )
            .await?;
        Ok(())
    }
    pub async fn append_audit(&self, sealed: &[u8]) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("INSERT INTO audit_events (sealed) VALUES ($1)", &[&sealed])
            .await?;
        Ok(())
    }
    pub async fn audit(&self) -> Result<Vec<Vec<u8>>> {
        let client = self.pool.get().await?;
        Ok(client
            .query("SELECT sealed FROM audit_events ORDER BY id", &[])
            .await?
            .iter()
            .map(|r| r.get(0))
            .collect())
    }
    pub async fn users(&self) -> Result<Vec<User>> {
        let client = self.pool.get().await?;
        Ok(client
            .query("SELECT id, email, enabled FROM users ORDER BY email", &[])
            .await?
            .iter()
            .map(|r| User {
                id: r.get(0),
                email: r.get(1),
                enabled: r.get(2),
            })
            .collect())
    }
    pub async fn user(&self, id: &str) -> Result<Option<User>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt("SELECT id, email, enabled FROM users WHERE id = $1", &[&id])
            .await?
            .map(|r| User {
                id: r.get(0),
                email: r.get(1),
                enabled: r.get(2),
            }))
    }
    pub async fn record_user(&self, id: &str, email: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "INSERT INTO users (id, email, enabled) VALUES ($1, $2, true)
                 ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email WHERE users.enabled
                 RETURNING enabled",
                &[&id, &email],
            )
            .await?
            .is_some())
    }
    pub async fn set_user_enabled(&self, email: &str, enabled: bool) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE users SET enabled = $2 WHERE lower(email) = lower($1)",
                &[&email, &enabled],
            )
            .await?
            > 0)
    }
    pub async fn machines(&self, user: &str) -> Result<Vec<(String, bool)>> {
        let client = self.pool.get().await?;
        Ok(client
            .query(
                "SELECT id, revoked FROM machines WHERE user_id = $1 ORDER BY id",
                &[&user],
            )
            .await?
            .iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect())
    }
    pub async fn machine_by_token(&self, token_hash: &str) -> Result<Option<Machine>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT id, user_id, token_hash, revoked FROM machines WHERE token_hash = $1",
                &[&token_hash],
            )
            .await?
            .map(|r| Machine {
                id: r.get(0),
                user: r.get(1),
                token_hash: r.get(2),
                revoked: r.get(3),
            }))
    }
    pub async fn add_machine(&self, m: &Machine) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO machines (id, user_id, token_hash, revoked) VALUES ($1, $2, $3, $4)",
                &[&m.id, &m.user, &m.token_hash, &m.revoked],
            )
            .await?;
        Ok(())
    }
    pub async fn revoke_machine(&self, id: &str, user: Option<&str>) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE machines SET revoked = true WHERE id = $1 AND ($2::TEXT IS NULL OR user_id = $2)",
                &[&id, &user],
            )
            .await?
            == 1)
    }
    pub async fn put_enrollment(&self, kind: &str, key: &str, row: &EnrollmentRow) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO enrollment (kind, key, lookup, sealed, expires_at) VALUES ($1, $2, $3, $4, $5)",
                &[&kind, &key, &row.lookup, &row.sealed, &row.expires_at],
            )
            .await?;
        Ok(())
    }
    pub async fn find_enrollment(
        &self,
        kind: &str,
        lookup: &str,
        now: i64,
    ) -> Result<Option<(String, EnrollmentRow)>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT key, lookup, sealed, expires_at FROM enrollment
                 WHERE kind = $1 AND lookup = $2 AND consumed_at IS NULL AND expires_at > $3",
                &[&kind, &lookup, &now],
            )
            .await?
            .map(|r| {
                (
                    r.get(0),
                    EnrollmentRow {
                        lookup: r.get(1),
                        sealed: r.get(2),
                        expires_at: r.get(3),
                        consumed: false,
                    },
                )
            }))
    }
    pub async fn enrollment(
        &self,
        kind: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<EnrollmentRow>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT lookup, sealed, expires_at, consumed_at IS NOT NULL FROM enrollment
                 WHERE kind = $1 AND key = $2 AND expires_at > $3",
                &[&kind, &key, &now],
            )
            .await?
            .map(|r| EnrollmentRow {
                lookup: r.get(0),
                sealed: r.get(1),
                expires_at: r.get(2),
                consumed: r.get(3),
            }))
    }
    pub async fn swap_enrollment(
        &self,
        kind: &str,
        key: &str,
        expected: &[u8],
        sealed: &[u8],
    ) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE enrollment SET sealed = $4
                 WHERE kind = $1 AND key = $2 AND consumed_at IS NULL AND sealed = $3",
                &[&kind, &key, &expected, &sealed],
            )
            .await?
            == 1)
    }
    pub async fn consume_enrollment(
        &self,
        kind: &str,
        key: &str,
        now: i64,
    ) -> Result<Option<EnrollmentRow>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "UPDATE enrollment SET consumed_at = $3
                 WHERE kind = $1 AND key = $2 AND consumed_at IS NULL AND expires_at > $3
                 RETURNING lookup, sealed, expires_at",
                &[&kind, &key, &now],
            )
            .await?
            .map(|r| EnrollmentRow {
                lookup: r.get(0),
                sealed: r.get(1),
                expires_at: r.get(2),
                consumed: true,
            }))
    }
}
