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
    account_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    account_uuid TEXT NOT NULL,
    organization_uuid TEXT NOT NULL,
    revision BIGINT NOT NULL,
    sealed BYTEA NOT NULL,
    UNIQUE (account_uuid, organization_uuid)
);
CREATE UNIQUE INDEX IF NOT EXISTS accounts_user_alias ON accounts (user_id, lower(alias));
CREATE TABLE IF NOT EXISTS refresh_leases (
    account_id TEXT PRIMARY KEY,
    holder_id TEXT NOT NULL,
    epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS tombstones (
    account_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    deleted_at BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS pending_admissions (
    key TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    started_at BIGINT NOT NULL,
    sealed BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS login_flows (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    alias TEXT NOT NULL,
    sealed BYTEA NOT NULL,
    exchanging BOOLEAN NOT NULL DEFAULT false,
    retained BYTEA
);
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

fn alias_key(user: &str, alias: &str) -> String {
    format!("{user}\0{}", alias.to_ascii_lowercase())
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
    }
}

impl PostgresStore {
    /// Connect with a small pool. A URL without `sslmode=require` connects without TLS,
    /// which only a loopback test database may use.
    pub async fn connect(url: &str) -> Result<Self> {
        let mut config: tokio_postgres::Config =
            url.parse().context("invalid database URL")?;
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
            .query_opt("SELECT version, min_reader FROM schema_info WHERE id = 1", &[])
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
    pub async fn account(&self, id: &str) -> Result<Option<StoredAccount>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt("SELECT * FROM accounts WHERE account_id = $1", &[&id])
            .await?
            .as_ref()
            .map(account))
    }
    pub async fn accounts(&self, user: &str) -> Result<Vec<StoredAccount>> {
        let client = self.pool.get().await?;
        Ok(client
            .query(
                "SELECT * FROM accounts WHERE user_id = $1 ORDER BY alias",
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
                    WHERE account_id = $1 AND holder_id = $8 AND epoch = $9
                      AND (NOT $10 OR expires_at > now())
                    FOR UPDATE
                 )
                 UPDATE accounts SET user_id = $2, alias = $3, account_uuid = $4,
                    organization_uuid = $5, revision = $6, sealed = $7
                 WHERE account_id = $1 AND revision = $11 AND EXISTS (SELECT 1 FROM lease)",
                &[
                    &a.id,
                    &a.user,
                    &a.alias,
                    &a.account_uuid,
                    &a.organization_uuid,
                    &a.revision,
                    &a.sealed,
                    &lease.holder,
                    &lease.epoch,
                    &live,
                    &expected,
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
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&alias_key(&a.user, &a.alias)],
        )
        .await?;
        let deleted: Option<i64> = tx
            .query_opt(
                "SELECT deleted_at FROM tombstones WHERE account_id = $1",
                &[&a.id],
            )
            .await?
            .map(|r| r.get(0));
        if deleted.is_some_and(|d| d >= admission.started_at) {
            return Ok(AdmitOutcome::DeletedSince);
        }
        if let Some(login) = &admission.login_id
            && tx
                .execute("DELETE FROM login_flows WHERE id = $1", &[login])
                .await?
                == 0
        {
            return Ok(AdmitOutcome::FlowGone);
        }
        let current: Option<i64> = tx
            .query_opt(
                "SELECT revision FROM accounts WHERE account_id = $1 FOR UPDATE",
                &[&a.id],
            )
            .await?
            .map(|r| r.get(0));
        let conflict = tx
            .query_opt(
                "SELECT 1 FROM accounts WHERE account_id <> $1 AND (
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
        if current != admission.expected_revision || conflict {
            return Ok(AdmitOutcome::Conflict);
        }
        let written = tx
            .execute(
                "INSERT INTO accounts (account_id, user_id, alias, account_uuid, organization_uuid, revision, sealed)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)
                 ON CONFLICT (account_id) DO UPDATE SET user_id = $2, alias = $3, account_uuid = $4,
                    organization_uuid = $5, revision = $6, sealed = $7",
                &[
                    &a.id,
                    &a.user,
                    &a.alias,
                    &a.account_uuid,
                    &a.organization_uuid,
                    &a.revision,
                    &a.sealed,
                ],
            )
            .await;
        match written {
            Ok(_) => {}
            // A concurrent admission of the same identity on another alias.
            Err(e) if e.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
                return Ok(AdmitOutcome::Conflict);
            }
            Err(e) => return Err(e.into()),
        }
        tx.execute(
            "DELETE FROM pending_admissions WHERE key = $1",
            &[&admission.pending_key],
        )
        .await?;
        tx.commit().await?;
        Ok(AdmitOutcome::Committed)
    }
    pub async fn delete(&self, id: &str, user: &str, deleted_at: i64) -> Result<bool> {
        let mut client = self.pool.get().await?;
        let tx = client.transaction().await?;
        let Some(alias): Option<String> = tx
            .query_opt(
                "SELECT alias FROM accounts WHERE account_id = $1 AND user_id = $2",
                &[&id, &user],
            )
            .await?
            .map(|r| r.get(0))
        else {
            return Ok(false);
        };
        tx.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&alias_key(user, &alias)],
        )
        .await?;
        tx.execute("DELETE FROM accounts WHERE account_id = $1", &[&id])
            .await?;
        tx.execute("DELETE FROM refresh_leases WHERE account_id = $1", &[&id])
            .await?;
        tx.execute("DELETE FROM usage_cache WHERE account_id = $1", &[&id])
            .await?;
        tx.execute(
            "INSERT INTO tombstones (account_id, user_id, alias, deleted_at) VALUES ($1, $2, $3, $4)
             ON CONFLICT (account_id) DO UPDATE SET alias = $3, deleted_at = $4",
            &[&id, &user, &alias, &deleted_at],
        )
        .await?;
        tx.execute(
            "DELETE FROM pending_admissions WHERE user_id = $1 AND lower(alias) = lower($2)",
            &[&user, &alias],
        )
        .await?;
        tx.execute(
            "DELETE FROM login_flows WHERE user_id = $1 AND lower(alias) = lower($2)",
            &[&user, &alias],
        )
        .await?;
        tx.commit().await?;
        Ok(true)
    }
    pub async fn deleted(&self, id: &str, user: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT 1 FROM tombstones WHERE account_id = $1 AND user_id = $2",
                &[&id, &user],
            )
            .await?
            .is_some())
    }
    pub async fn acquire_lease(&self, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
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
        }))
    }
    pub async fn renew_lease(&self, lease: &Lease, id: &str, ttl_ms: i64) -> Result<Option<Lease>> {
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
    pub async fn pending(&self, key: &str) -> Result<Option<PendingRow>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT user_id, alias, started_at, sealed FROM pending_admissions WHERE key = $1",
                &[&key],
            )
            .await?
            .map(|r| PendingRow {
                user: r.get(0),
                alias: r.get(1),
                started_at: r.get(2),
                sealed: r.get(3),
            }))
    }
    pub async fn put_pending(&self, key: &str, row: &PendingRow) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO pending_admissions (key, user_id, alias, started_at, sealed)
                 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (key) DO NOTHING",
                &[&key, &row.user, &row.alias, &row.started_at, &row.sealed],
            )
            .await?;
        Ok(())
    }
    pub async fn delete_pending(&self, key: &str) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute("DELETE FROM pending_admissions WHERE key = $1", &[&key])
            .await?;
        Ok(())
    }
    pub async fn flow(&self, id: &str) -> Result<Option<FlowRow>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt(
                "SELECT user_id, alias, sealed, exchanging, retained FROM login_flows WHERE id = $1",
                &[&id],
            )
            .await?
            .map(|r| FlowRow {
                user: r.get(0),
                alias: r.get(1),
                sealed: r.get(2),
                exchanging: r.get(3),
                retained: r.get(4),
            }))
    }
    pub async fn put_flow(&self, id: &str, row: &FlowRow) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO login_flows (id, user_id, alias, sealed, exchanging, retained)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[&id, &row.user, &row.alias, &row.sealed, &row.exchanging, &row.retained],
            )
            .await?;
        Ok(())
    }
    pub async fn start_exchange(&self, id: &str) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE login_flows SET exchanging = true WHERE id = $1 AND NOT exchanging",
                &[&id],
            )
            .await?
            == 1)
    }
    pub async fn retain(&self, id: &str, sealed: &[u8]) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE login_flows SET retained = $2 WHERE id = $1",
                &[&id, &sealed],
            )
            .await?
            == 1)
    }
    pub async fn usage(&self, id: &str) -> Result<Option<Vec<u8>>> {
        let client = self.pool.get().await?;
        Ok(client
            .query_opt("SELECT sealed FROM usage_cache WHERE account_id = $1", &[&id])
            .await?
            .map(|r| r.get(0)))
    }
    pub async fn put_usage(&self, id: &str, sealed: &[u8]) -> Result<()> {
        let client = self.pool.get().await?;
        client
            .execute(
                "INSERT INTO usage_cache (account_id, sealed)
                 SELECT $1, $2 WHERE starts_with($1, '__') OR EXISTS (SELECT 1 FROM accounts WHERE account_id = $1)
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
    pub async fn machines(&self) -> Result<Vec<Machine>> {
        let client = self.pool.get().await?;
        Ok(client
            .query("SELECT id, user_id, token_hash, revoked FROM machines ORDER BY id", &[])
            .await?
            .iter()
            .map(|r| Machine {
                id: r.get(0),
                user: r.get(1),
                token_hash: r.get(2),
                revoked: r.get(3),
            })
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
                "DELETE FROM enrollment WHERE expires_at < $1",
                &[&(row.expires_at - 3_600_000)],
            )
            .await?;
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
    pub async fn enrollment(&self, kind: &str, key: &str, now: i64) -> Result<Option<EnrollmentRow>> {
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
    pub async fn update_enrollment(&self, kind: &str, key: &str, sealed: &[u8]) -> Result<bool> {
        let client = self.pool.get().await?;
        Ok(client
            .execute(
                "UPDATE enrollment SET sealed = $3 WHERE kind = $1 AND key = $2 AND consumed_at IS NULL",
                &[&kind, &key, &sealed],
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
