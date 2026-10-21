//! Environment-only credentials for unattended jobs. The ordinary machine
//! protocol supplies identity; no human registration or credential file is used.
use super::{Client, Connection, http, origin};
use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Whether this invocation selects environment-only service authentication.
pub fn configured() -> bool {
    std::env::var_os("CLAUDECTL_SERVICE_TOKEN").is_some()
        || std::env::var_os("CLAUDECTL_SERVER_URL").is_some()
}

pub(super) fn client() -> Result<Option<Client>> {
    let Some(token) = std::env::var_os("CLAUDECTL_SERVICE_TOKEN") else {
        if std::env::var_os("CLAUDECTL_SERVER_URL").is_some() {
            bail!("CLAUDECTL_SERVICE_TOKEN is required with CLAUDECTL_SERVER_URL");
        }
        return Ok(None);
    };
    let token = token
        .into_string()
        .map_err(|_| anyhow::anyhow!("CLAUDECTL_SERVICE_TOKEN must be UTF-8"))?;
    if token.trim().is_empty() {
        bail!("CLAUDECTL_SERVICE_TOKEN is empty");
    }
    let server = std::env::var("CLAUDECTL_SERVER_URL")
        .context("CLAUDECTL_SERVER_URL is required with CLAUDECTL_SERVICE_TOKEN")?;
    let server = origin(&server)?
        .to_string()
        .trim_end_matches('/')
        .to_owned();
    let mut client = Client {
        connection: Connection {
            server,
            user_id: String::new(),
            token_file: None,
        },
        token: token.trim().to_owned(),
        http: http()?,
    };
    let identity: Value = client.get("/v1/me")?;
    client.connection.user_id = identity["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .context("invalid service company-user identity")?
        .to_owned();
    Ok(Some(client))
}

/// Resolve service jobs before executing an external Claude build. Human machine
/// launches retain their existing qualification-first ordering.
pub(super) fn account(client: &Client, alias: &str) -> Result<Option<super::Account>> {
    if client.connection.token_file.is_some() {
        return Ok(None);
    }
    let account = client.account(alias)?;
    let candidate = super::candidate(&super::ServerRow {
        alias: account.alias.clone(),
        available: account.available,
        usage: Ok(client.usage(&account.account_id, false)?),
    });
    if crate::accounts::capacity_reason(&candidate).is_some() {
        bail!("service job requires fresh included capacity");
    }
    Ok(Some(account))
}

/// Return the shared credential only after commit. Delivery belongs to the admin
/// caller; this module never logs or persists its plaintext.
#[cfg(feature = "server")]
pub async fn issue(
    store: &crate::server::store::Store,
    user: &str,
    allowed_users: &[String],
) -> Result<String> {
    use crate::server::{app, store::Machine, vault};
    let company_user = store
        .user(user)
        .await?
        .filter(|u| u.enabled)
        .context("enabled company user not found; list server users first")?;
    if !app::allowed_user(allowed_users, &company_user.email) {
        bail!("company user is not allowed by --allow-user; use the server's allow-user list");
    }
    let token = vault::secret();
    if !store
        .replace_machine(&Machine {
            id: "shared-service-account".into(),
            user: user.into(),
            token_hash: vault::digest(token.as_bytes()),
            revoked: false,
            last_seen_at: None,
        })
        .await?
    {
        bail!("enabled company user not found; list server users first");
    }
    Ok(token)
}
