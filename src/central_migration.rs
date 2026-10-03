//! A durable local fence precedes any transfer of refresh ownership.
use super::*;
use crate::{api::CredentialsFile, auth_store::AuthStore};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
struct Journal {
    schema: u32,
    alias: String,
    server: String,
    user_id: String,
    migration_id: String,
    identity: Identity,
    grant_digests: Vec<String>,
    receipt: Option<Receipt>,
}
fn directory(root: &Path, alias: &str) -> PathBuf {
    let hash = format!(
        "{:x}",
        Sha256::digest(alias.to_ascii_lowercase().as_bytes())
    );
    root.join("server").join("migrations").join(hash)
}
/// This fence lives outside the profile, so removing/recreating a profile cannot undo it.
pub fn ensure_local(root: &Path, alias: &str) -> Result<()> {
    if directory(root, profile::validate_alias(alias)?)
        .join("journal.json")
        .try_exists()?
    {
        bail!("profile is fenced for server migration; resume with claudectl server migrate");
    }
    Ok(())
}
fn digests(creds: &CredentialsFile) -> Vec<String> {
    [
        Some(creds.claude_ai_oauth.access_token.as_str()),
        creds.claude_ai_oauth.refresh_token.as_deref(),
    ]
    .into_iter()
    .flatten()
    .filter(|t| !t.is_empty())
    .map(|token| format!("{:x}", Sha256::digest(token.as_bytes())))
    .collect()
}
/// Refuse restoring a migrated grant under another alias, including after profile removal.
pub fn ensure_local_grant(
    root: &Path,
    meta: &profile::AccountMeta,
    creds: &CredentialsFile,
) -> Result<()> {
    let migrations = root.join("server/migrations");
    if !migrations.try_exists()? {
        return Ok(());
    }
    let candidate = identity(meta).ok();
    let hashes = digests(creds);
    for entry in std::fs::read_dir(migrations)? {
        let file = entry?.path().join("journal.json");
        if !file.try_exists()? {
            continue;
        }
        let journal: Journal = serde_json::from_slice(&private_read(&file)?)
            .context("invalid migration fence; local credentials unchanged")?;
        if candidate.as_ref() == Some(&journal.identity)
            || hashes.iter().any(|h| journal.grant_digests.contains(h))
        {
            bail!("account or grant is fenced for server migration; local restoration refused");
        }
    }
    Ok(())
}
fn shared(a: &CredentialsFile, b: &CredentialsFile) -> bool {
    let a = &a.claude_ai_oauth;
    let b = &b.claude_ai_oauth;
    (!a.access_token.is_empty() && a.access_token == b.access_token)
        || (a.refresh_token.is_some() && a.refresh_token == b.refresh_token)
}
fn identity(meta: &profile::AccountMeta) -> Result<Identity> {
    let value = meta
        .oauth_account
        .as_ref()
        .context("migration requires saved account identity")?;
    let field = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .context("migration identity incomplete")
    };
    Ok(Identity {
        account_uuid: field("accountUuid")?,
        organization_uuid: field("organizationUuid")?,
    })
}
fn check_owners(
    paths: &Paths,
    store: &AuthStore,
    alias: &str,
    creds: &CredentialsFile,
    expected: &Identity,
) -> Result<()> {
    if profile::get_active_from(paths)?.is_some_and(|a| crate::exec::same_profile(paths, &a, alias))
    {
        bail!(
            "active profile cannot migrate; stop its sessions and select another local account first"
        );
    }
    if store
        .read_refresh_owner()?
        .as_ref()
        .is_some_and(|live| shared(creds, live))
    {
        bail!("profile shares the live refresh grant; migration refused");
    }
    if let Some(live) = store.read_oauth_account()?
        && live.get("accountUuid").and_then(Value::as_str) == Some(&expected.account_uuid)
        && live.get("organizationUuid").and_then(Value::as_str) == Some(&expected.organization_uuid)
    {
        bail!("profile matches the live account; migration refused");
    }
    for other in profile::list_profiles_from(paths)? {
        if crate::exec::same_profile(paths, &other.meta.alias, alias) {
            continue;
        }
        let fence = directory(&paths.claudectl_dir(), &other.meta.alias).join("journal.json");
        if fence.try_exists()? {
            let prior: Journal = serde_json::from_slice(&private_read(&fence)?)
                .context("invalid existing migration fence")?;
            if prior.identity == *expected
                || digests(creds)
                    .iter()
                    .any(|h| prior.grant_digests.contains(h))
                || other.credentials_path().try_exists()?
            {
                bail!("another migration or restored profile may hold this account");
            }
            continue;
        }
        // Unreadable profiles cannot establish exclusive ownership.
        let candidate = other
            .read_credentials()
            .context("cannot establish ownership of another saved profile")?;
        if shared(creds, &candidate)
            || identity(&other.meta)
                .as_ref()
                .is_ok_and(|id| id == expected)
        {
            bail!(
                "another saved profile holds this grant or account; retire duplicate holders first"
            );
        }
    }
    Ok(())
}
pub fn migrate(paths: &Paths, client: &Client, alias: &str, exclusive_owner: bool) -> Result<()> {
    let alias = profile::validate_alias(alias)?;
    if !exclusive_owner {
        bail!(
            "inventory and retire every other grant holder, then declare --exclusive-owner; includes other machines, old binaries, sessions and backups"
        );
    }
    let _server_lock = lock(paths)?;
    let store = AuthStore::real(paths.clone());
    let _auth_lock = store.lock_auth_state()?;
    let dir = directory(&paths.claudectl_dir(), alias);
    private_dir(&dir)?;
    let journal_path = dir.join("journal.json");
    let retained = dir.join("grant.json");
    let source = paths.profiles_dir().join(alias).join("credentials.json");
    let mut journal: Journal = if journal_path.try_exists()? {
        serde_json::from_slice(&private_read(&journal_path)?)
            .context("invalid migration journal")?
    } else {
        let profile = profile::get_profile_from(paths, alias)?;
        let creds = profile.read_credentials()?;
        let expected = identity(&profile.meta)?;
        check_owners(paths, &store, alias, &creds, &expected)?;
        let oauth = &creds.claude_ai_oauth;
        if oauth.expires_at.is_none_or(|e| e <= now() + 60_000)
            || oauth.refresh_token.as_ref().is_none_or(|r| r.is_empty())
        {
            bail!(
                "migration requires a usable access token and refresh grant; no refresh was attempted"
            );
        }
        let journal = Journal {
            schema: 1,
            alias: alias.into(),
            server: client.connection.server.clone(),
            user_id: client.connection.user_id.clone(),
            migration_id: crate::oauth::generate_state(),
            identity: expected,
            grant_digests: digests(&creds),
            receipt: None,
        };
        atomic(&journal_path, &journal)?;
        journal
    };
    if journal.schema != 1
        || journal.alias != alias
        || journal.server != client.connection.server
        || journal.user_id != client.connection.user_id
    {
        bail!("migration belongs to another server, user, or alias; profile remains fenced");
    }
    if journal.receipt.is_none() {
        if source.try_exists()? {
            if retained.try_exists()? {
                bail!("local grant was recreated after fencing; reconcile before continuing");
            }
            // Validate the source before moving it; no profile reader can use it after the journal exists.
            let creds: CredentialsFile =
                serde_json::from_slice(&private_read(&source)?).map_err(|_| {
                    anyhow::anyhow!("invalid source credentials; profile remains fenced")
                })?;
            check_owners(paths, &store, alias, &creds, &journal.identity)?;
            std::fs::rename(&source, &retained)?;
            File::open(source.parent().unwrap())?.sync_all()?;
            File::open(&dir)?.sync_all()?;
        }
        // Receipt lookup always precedes retry. A lost reply must never undo server ownership.
        let receipt = match client.receipt(&journal.migration_id)? {
            Some(receipt) => receipt,
            None => {
                let creds: CredentialsFile = serde_json::from_slice(&private_read(&retained)?)
                    .map_err(|_| anyhow::anyhow!("invalid retained migration grant"))?;
                let oauth = creds.claude_ai_oauth;
                client.post(
                    "/v2/anthropic/migrations",
                    &json!({"alias":alias,
                    "migration_id":journal.migration_id,"exclusive_owner":true,
                    "grant":{"access_token":oauth.access_token,"refresh_token":oauth.refresh_token,
                        "expires_at":oauth.expires_at,"scopes":oauth.scopes}}),
                )?
            }
        };
        if receipt.migration_id != journal.migration_id
            || receipt.identity != journal.identity
            || receipt.account_id.len() != 64
            || !receipt.account_id.bytes().all(|b| b.is_ascii_hexdigit())
        {
            bail!("server receipt does not match migration; profile remains fenced");
        }
        journal.receipt = Some(receipt);
        atomic(&journal_path, &journal)?;
    }
    if source.try_exists()? {
        bail!("credentials reappeared in migrated profile; reconcile the competing owner");
    }
    if retained.try_exists()? {
        std::fs::remove_file(&retained)?;
        File::open(&dir)?.sync_all()?;
    }
    println!("Migrated {alias}; refresh ownership is on the server. Use claudectl server run.");
    Ok(())
}
