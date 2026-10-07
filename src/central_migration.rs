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
    /// The grant came from the host's live login (Keychain), not a saved profile.
    #[serde(default)]
    live: bool,
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
/// Refuse keeping a newly acquired login for a fenced alias, a migrated Claude identity, or
/// a migrated grant: a refused login never leaves a local refresh-grant copy.
pub fn ensure_login_unfenced(
    root: &Path,
    alias: &str,
    creds: &CredentialsFile,
    account: &Option<Value>,
) -> Result<()> {
    ensure_local(root, alias)?;
    let meta = profile::AccountMeta {
        alias: alias.into(),
        saved_at: String::new(),
        oauth_account: account.clone(),
        label: None,
    };
    // Fail closed: with a fence present, a login whose Claude identity is unknown may be the
    // migrated account under new tokens, which the digest check cannot see.
    if identity(&meta).is_err() && fenced(root)? {
        bail!(
            "a server migration fence exists and this login's Claude identity is unknown; \
             nothing was saved. Retry when the identity can be read"
        );
    }
    ensure_local_grant(root, &meta, creds)
}
/// True when any alias holds a migration fence.
fn fenced(root: &Path) -> Result<bool> {
    let migrations = root.join("server/migrations");
    if !migrations.try_exists()? {
        return Ok(false);
    }
    for entry in std::fs::read_dir(migrations)? {
        if entry?.path().join("journal.json").try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}
fn shared(a: &CredentialsFile, b: &CredentialsFile) -> bool {
    let a = &a.claude_ai_oauth;
    let b = &b.claude_ai_oauth;
    (!a.access_token.is_empty() && a.access_token == b.access_token)
        || (a.refresh_token.is_some() && a.refresh_token == b.refresh_token)
}
fn identity(meta: &profile::AccountMeta) -> Result<Identity> {
    identity_of(
        meta.oauth_account
            .as_ref()
            .context("migration requires saved account identity")?,
    )
}
fn identity_of(value: &Value) -> Result<Identity> {
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
/// The live login must not hold the grant or the account of an inactive profile.
fn check_live(
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
    Ok(())
}
/// No other saved profile or migration may hold this grant or account.
fn check_others(
    paths: &Paths,
    alias: &str,
    creds: &CredentialsFile,
    expected: &Identity,
) -> Result<()> {
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
/// Where the grant comes from: a saved inactive profile, or the host's live login (Keychain).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source {
    Profile,
    Live,
}
/// A finished account: newly migrated, or found migrated and cleaned up again.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Done {
    Migrated,
    Already,
}
fn usable(creds: &CredentialsFile) -> Result<()> {
    let oauth = &creds.claude_ai_oauth;
    if oauth.expires_at.is_none_or(|e| e <= now() + 60_000)
        || oauth.refresh_token.as_ref().is_none_or(|r| r.is_empty())
    {
        bail!(
            "migration requires a usable access token and refresh grant; no refresh was attempted"
        );
    }
    Ok(())
}
fn same_digests(a: &[String], b: &[String]) -> bool {
    let (mut a, mut b) = (a.to_vec(), b.to_vec());
    a.sort();
    b.sort();
    a == b
}
pub fn migrate(paths: &Paths, client: &Client, alias: &str, exclusive_owner: bool) -> Result<()> {
    let alias = profile::validate_alias(alias)?;
    if !exclusive_owner {
        bail!(
            "inventory and retire every other grant holder, then declare --exclusive-owner; includes other machines, old binaries, sessions and backups"
        );
    }
    migrate_one(paths, client, alias, Source::Profile)?;
    println!("Migrated {alias}; refresh ownership is on the server. Use claudectl server run.");
    Ok(())
}
/// One account through fence -> server receipt -> local cleanup. Rerunnable at every step.
fn migrate_one(paths: &Paths, client: &Client, alias: &str, source: Source) -> Result<Done> {
    let _server_lock = lock(paths)?;
    let store = AuthStore::real(paths.clone());
    let _auth_lock = store.lock_auth_state()?;
    let dir = directory(&paths.claudectl_dir(), alias);
    private_dir(&dir)?;
    let journal_path = dir.join("journal.json");
    let retained = dir.join("grant.json");
    // The live login's own profile copy is moved here; it may be an older grant of the account.
    let aside = dir.join("profile-credentials.json");
    let profile_file = paths.profiles_dir().join(alias).join("credentials.json");
    let mut journal: Journal = if journal_path.try_exists()? {
        serde_json::from_slice(&private_read(&journal_path)?)
            .context("invalid migration journal")?
    } else {
        let (creds, expected) = match source {
            Source::Profile => {
                let profile = profile::get_profile_from(paths, alias)?;
                let creds = profile.read_credentials()?;
                let expected = identity(&profile.meta)?;
                check_live(paths, &store, alias, &creds, &expected)?;
                (creds, expected)
            }
            Source::Live => {
                let creds =
                    keychain_grant(&store)?.context("no live Claude login on this machine")?;
                // Claude Code refreshes only the Keychain on macOS: an older file copy would
                // block the post-receipt cleanup forever. Refuse before any fence.
                if let Some(file) = live_file(paths)?
                    && !same_digests(&digests(&file), &digests(&creds))
                {
                    bail!(
                        "~/.claude/.credentials.json holds an older grant than the Keychain; nothing was fenced. Run `claudectl use {alias}` (rewrites both) or delete the stale file, then rerun"
                    );
                }
                let expected = identity_of(
                    &store
                        .read_oauth_account()?
                        .context("live login has no saved identity")?,
                )?;
                if let Ok(profile) = profile::get_profile_from(paths, alias)
                    && identity(&profile.meta).is_ok_and(|id| id != expected)
                {
                    bail!("live login changed: it is no longer {alias}; nothing was fenced");
                }
                (creds, expected)
            }
        };
        check_others(paths, alias, &creds, &expected)?;
        usable(&creds)?;
        let journal = Journal {
            schema: 1,
            alias: alias.into(),
            server: client.connection.server.clone(),
            user_id: client.connection.user_id.clone(),
            migration_id: crate::oauth::generate_state(),
            identity: expected,
            grant_digests: digests(&creds),
            receipt: None,
            live: source == Source::Live,
        };
        if journal.live {
            // The Keychain stays untouched until the server verified a rotation.
            atomic(&retained, &creds)?;
        }
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
        let moved = if journal.live { &aside } else { &retained };
        if profile_file.try_exists()? {
            if moved.try_exists()? {
                bail!("local grant was recreated after fencing; reconcile before continuing");
            }
            // Validate the source before moving it; no profile reader can use it after the journal exists.
            let creds: CredentialsFile = serde_json::from_slice(&private_read(&profile_file)?)
                .map_err(|_| {
                    anyhow::anyhow!("invalid source credentials; profile remains fenced")
                })?;
            if !journal.live {
                check_live(paths, &store, alias, &creds, &journal.identity)?;
            }
            std::fs::rename(&profile_file, moved)?;
            File::open(profile_file.parent().unwrap())?.sync_all()?;
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
        cleanup(paths, &store, &journal, &dir, &profile_file)?;
        return Ok(Done::Migrated);
    }
    cleanup(paths, &store, &journal, &dir, &profile_file)?;
    Ok(Done::Already)
}
/// The live login's authoritative grant (the Keychain on macOS, the file elsewhere). Debug
/// builds let integration tests stand in a Keychain grant; release builds never read it.
fn keychain_grant(store: &AuthStore) -> Result<Option<CredentialsFile>> {
    #[cfg(debug_assertions)]
    if let Ok(path) = std::env::var("CLAUDECTL_TEST_KEYCHAIN_GRANT") {
        return Ok(Some(
            serde_json::from_slice(&std::fs::read(path)?).context("invalid test Keychain grant")?,
        ));
    }
    store.read_refresh_owner()
}
/// ~/.claude/.credentials.json: `Ok(None)` when absent, an error when unreadable.
fn live_file(paths: &Paths) -> Result<Option<CredentialsFile>> {
    let file = paths.claude_credentials_file();
    if !file.try_exists()? {
        return Ok(None);
    }
    Ok(Some(
        serde_json::from_slice(&std::fs::read(&file)?).context("invalid live credentials file")?,
    ))
}
/// Check every present live holder against the migrated grant. Ok(true) when at least one
/// holder is present (and all match).
fn verify_live_holders(
    keychain: Result<Option<CredentialsFile>>,
    file: Result<Option<CredentialsFile>>,
    migrated: &[String],
) -> Result<bool> {
    let (keychain, file) = (keychain?, file?);
    for creds in keychain.iter().chain(file.iter()) {
        if !same_digests(&digests(creds), migrated) {
            bail!("live login changed; nothing deleted. Reconcile the current login, then rerun");
        }
    }
    Ok(keychain.is_some() || file.is_some())
}
/// After a receipt (the server verified a rotation): retire every local copy. Idempotent.
fn cleanup(
    paths: &Paths,
    store: &AuthStore,
    journal: &Journal,
    dir: &Path,
    profile_file: &Path,
) -> Result<()> {
    if profile_file.try_exists()? {
        bail!("credentials reappeared in migrated profile; reconcile the competing owner");
    }
    if journal.live {
        // Compare-and-delete: every present holder must be the exact migrated grant. A
        // holder that cannot be read stops the cleanup; nothing is deleted.
        let verify = || {
            verify_live_holders(
                store
                    .read_live_grant()
                    .context("Keychain login unreadable; nothing deleted"),
                live_file(paths).context("live credentials file unreadable; nothing deleted"),
                &journal.grant_digests,
            )
        };
        if verify()? {
            // security(1) cannot delete conditionally. Narrow the window instead: no Claude
            // process may run, and the holders must still match right before the delete.
            let running = claude_processes()?;
            if !running.is_empty() {
                bail!(
                    "a Claude process started during the migration; nothing deleted. Stop it, then rerun"
                );
            }
            if verify()? {
                store.delete_live_login()?;
            }
        }
        if profile::get_active_from(paths)?
            .is_some_and(|a| crate::exec::same_profile(paths, &a, &journal.alias))
        {
            profile::clear_active_from(paths)?;
        }
        let aside = dir.join("profile-credentials.json");
        if aside.try_exists()? {
            std::fs::remove_file(aside)?;
        }
    }
    let retained = dir.join("grant.json");
    if retained.try_exists()? {
        std::fs::remove_file(&retained)?;
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// One summary row of `migrate --all`.
pub(super) struct Row {
    pub alias: String,
    pub identity: String,
    pub result: String,
    pub next: &'static str,
}
impl Row {
    fn ok(&self) -> bool {
        matches!(self.result.as_str(), "migrated" | "already")
    }
}
/// Running Claude processes as (PID, start time). claudectl itself is not one.
fn claude_processes() -> Result<Vec<(u32, String)>> {
    #[cfg(debug_assertions)]
    if let Ok(list) = std::env::var("CLAUDECTL_TEST_CLAUDE_PIDS") {
        return Ok(list
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| (s.parse().unwrap_or(0), "test".to_string()))
            .collect());
    }
    let output = std::process::Command::new("ps")
        .args(["-Ao", "pid=,lstart=,comm="])
        .output()
        .context("could not list processes; refusing to migrate")?;
    anyhow::ensure!(
        output.status.success(),
        "could not list processes; refusing to migrate"
    );
    let own = std::process::id();
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid: u32 = fields.next()?.parse().ok()?;
            let rest: Vec<&str> = fields.collect();
            // lstart is five fields: weekday, month, day, time, year.
            let (start, command) = (rest.get(..5)?.join(" "), rest.get(5..)?.join(" "));
            let name = Path::new(&command).file_name()?.to_str()?;
            (pid != own && name == "claude").then_some((pid, start))
        })
        .collect())
}
/// The host's Claude build must be qualified (K3) before any account leaves this machine.
/// The build must be qualified on this machine; a built-in hash alone is not enough here.
fn require_qualified(paths: &Paths, digest: &str) -> Result<()> {
    if super::qualify::is_qualified(paths, digest)? {
        return Ok(());
    }
    bail!("Claude build {digest} is not qualified on this machine; run claudectl server qualify")
}
fn qualified_claude(paths: &Paths) -> Result<()> {
    let binary = super::session::program(Path::new("claude"))?;
    let digest = crate::exec::sha256_file(&binary).map_err(|e| anyhow::anyhow!("{e}"))?;
    require_qualified(paths, &digest)
}
/// Refresh an expired inactive profile before any lock is taken, through the same path as
/// `claudectl status`. The live login is never refreshed here: Claude Code owns it.
fn refresh_inactive(paths: &Paths, alias: &str) -> Result<()> {
    let store = AuthStore::real(paths.clone());
    // Under the lock: decide ownership and take a snapshot. The provider call runs without it.
    let owned = |store: &AuthStore| -> Result<Option<(profile::Profile, CredentialsFile)>> {
        let active = profile::get_active_from(paths)?;
        if active
            .as_deref()
            .is_some_and(|a| crate::exec::same_profile(paths, a, alias))
        {
            return Ok(None);
        }
        let profile = profile::get_profile_from(paths, alias)?;
        let creds = profile.read_credentials()?;
        if store
            .read_refresh_owner()?
            .as_ref()
            .is_some_and(|live| shared(&creds, live))
        {
            bail!("profile shares the live refresh grant; not refreshed");
        }
        // A rotation must reach every copy of the grant: an unreadable sibling might hold it.
        for other in profile::list_profiles_from(paths)? {
            if crate::exec::same_profile(paths, &other.meta.alias, alias)
                || fenced_alias(paths, &other.meta.alias)
                || !other.credentials_path().try_exists()?
            {
                continue;
            }
            other.read_credentials().with_context(|| {
                format!(
                    "cannot read profile {}; it may hold the same grant, so {alias} was not refreshed",
                    other.meta.alias
                )
            })?;
        }
        Ok(Some((profile, creds)))
    };
    let (_, before) = {
        let _lock = store.lock_auth_state()?;
        match owned(&store)? {
            Some(found) => found,
            None => return Ok(()),
        }
    };
    if before
        .claude_ai_oauth
        .expires_at
        .is_some_and(|e| e > now() + 60_000)
    {
        return Ok(());
    }
    let grant = before
        .claude_ai_oauth
        .refresh_token
        .clone()
        .context("no refresh grant saved")?;
    let rotated =
        tokio::runtime::Runtime::new()?.block_on(crate::api::refresh_credentials_async(
            &reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()?,
            &before.claude_ai_oauth,
        ))?;
    // Again under the lock: save only over the exact grant that was refreshed.
    let _lock = store.lock_auth_state()?;
    let Some((current_profile, mut current)) = owned(&store)? else {
        bail!("{alias} became the live login during its refresh; not saved");
    };
    if current.claude_ai_oauth.refresh_token.as_deref() != Some(grant.as_str()) {
        bail!("{alias} changed during its refresh (another login or refresh); not saved");
    }
    current.claude_ai_oauth = rotated;
    let active = profile::get_active_from(paths)?;
    if let Err(error) = profile::persist_rotated_grant(
        paths,
        active.as_deref(),
        &current_profile,
        &current,
        &crate::usage_cache::UsageCache::key(&grant),
    ) {
        // The provider already rotated the grant: the successor must survive somewhere.
        let kept = root(paths)
            .join("refresh-recovery")
            .join(format!("{alias}.json"));
        atomic(&kept, &current).with_context(|| {
            format!(
                "refreshed {alias} but could neither save the profile nor keep the grant ({error})"
            )
        })?;
        bail!(
            "refreshed {alias} but could not save the profile ({error}); the new grant is kept privately at {}",
            kept.display()
        );
    }
    Ok(())
}
fn fenced_alias(paths: &Paths, alias: &str) -> bool {
    directory(&paths.claudectl_dir(), alias)
        .join("journal.json")
        .exists()
}
/// The summary row for a failed account.
fn classify(paths: &Paths, alias: &str, error: &anyhow::Error) -> (String, &'static str) {
    let fenced = fenced_alias(paths, alias);
    if server_down(error) {
        return if fenced {
            (
                "lost-reply".into(),
                "rerun: the receipt lookup finds what the server did",
            )
        } else {
            ("not-attempted".into(), "rerun when the server is reachable")
        };
    }
    if let Some(e) = error.downcast_ref::<ServerError>() {
        return match (e.status, e.reason.as_str()) {
            (_, "refresh_token_not_rotated") => (
                "unrotated".into(),
                "the provider kept the refresh token; other copies stay valid. Rerun later",
            ),
            (_, "migration_superseded") => (
                "superseded".into(),
                "claudectl server migrate --abort <alias>, then log in again",
            ),
            (410, _) | (_, "account_deleted") => {
                ("gone".into(), "claudectl server migrate --abort <alias>")
            }
            _ if fenced => (format!("failed:fenced ({})", e.reason), "rerun"),
            _ => (format!("refused:{}", e.reason), "fix the cause, then rerun"),
        };
    }
    if fenced {
        (format!("failed:fenced ({error})"), "rerun")
    } else {
        (format!("refused:{error}"), "fix the cause, then rerun")
    }
}
pub fn migrate_all(paths: &Paths, client: &Client, exclusive_owner: bool) -> Result<bool> {
    let rows = migrate_all_with(
        paths,
        client,
        exclusive_owner,
        &claude_processes,
        &qualified_claude,
    )?;
    println!("{:<24} {:<9} {:<40} next", "alias", "identity", "result");
    for row in &rows {
        println!(
            "{:<24} {:<9} {:<40} {}",
            row.alias,
            row.identity,
            row.result,
            row.next.replace("<alias>", &row.alias)
        );
    }
    Ok(rows.iter().all(Row::ok))
}
pub(super) fn migrate_all_with(
    paths: &Paths,
    client: &Client,
    exclusive_owner: bool,
    processes: &dyn Fn() -> Result<Vec<(u32, String)>>,
    qualified: &dyn Fn(&Paths) -> Result<()>,
) -> Result<Vec<Row>> {
    // The server forces a refresh after the exclusive-owner statement, so every account needs
    // it: other machines, sessions and backups must be retired first.
    if !exclusive_owner {
        bail!(
            "inventory and retire every other holder of these accounts (other machines, sessions, backups), then rerun with --exclusive-owner. Nothing was fenced"
        );
    }
    let running = processes()?;
    if !running.is_empty() {
        let list = running
            .iter()
            .map(|(pid, start)| format!("{pid} (started {start})"))
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "stop every Claude session on this machine first; running: {list}. Nothing was fenced"
        );
    }
    qualified(paths).context("the host's Claude build is not qualified; nothing was fenced")?;
    client
        .me()
        .context("account server preflight failed; nothing was fenced")?;
    let store = AuthStore::real(paths.clone());
    let live = store
        .read_oauth_account()?
        .filter(|_| store.read_refresh_owner().is_ok_and(|c| c.is_some()))
        .and_then(|v| identity_of(&v).ok());
    let mut inactive = Vec::new();
    let mut live_alias = None;
    for profile in profile::list_profiles_from(paths)? {
        let identity = identity(&profile.meta).ok();
        let prefix = identity.as_ref().map_or("-".to_string(), |i| {
            i.account_uuid.chars().take(8).collect()
        });
        let journal = directory(&paths.claudectl_dir(), &profile.meta.alias).join("journal.json");
        let live_journal = journal.try_exists()?
            && serde_json::from_slice::<Journal>(&private_read(&journal)?).is_ok_and(|j| j.live);
        if live_journal || (live.is_some() && identity == live) {
            live_alias = Some((profile.meta.alias.clone(), prefix));
        } else {
            inactive.push((profile.meta.alias.clone(), prefix));
        }
    }
    let mut rows = Vec::new();
    let mut halted = false;
    let mut work: Vec<(String, String, Source)> = inactive
        .into_iter()
        .map(|(a, p)| (a, p, Source::Profile))
        .collect();
    if let Some((alias, prefix)) = live_alias {
        work.push((alias, prefix, Source::Live));
    }
    for (alias, identity, source) in work {
        if halted {
            rows.push(Row {
                alias,
                identity,
                result: "not-attempted".into(),
                next: "rerun",
            });
            continue;
        }
        if source == Source::Profile
            && !fenced_alias(paths, &alias)
            && let Err(error) = refresh_inactive(paths, &alias)
        {
            rows.push(Row {
                alias,
                identity,
                result: format!("refused:refresh failed ({error})"),
                next: "log in again or fix the cause, then rerun",
            });
            continue;
        }
        let row = match migrate_one(paths, client, &alias, source) {
            Ok(Done::Migrated) => Row {
                alias,
                identity,
                result: "migrated".into(),
                next: "-",
            },
            Ok(Done::Already) => Row {
                alias,
                identity,
                result: "already".into(),
                next: "-",
            },
            Err(error) => {
                halted = server_down(&error);
                let (result, next) = classify(paths, &alias, &error);
                Row {
                    alias,
                    identity,
                    result,
                    next,
                }
            }
        };
        rows.push(row);
    }
    Ok(rows)
}
/// Drop a fence that never reached the server, or whose server account is gone.
pub fn abort(paths: &Paths, client: &Client, alias: &str) -> Result<()> {
    let alias = profile::validate_alias(alias)?;
    let _server_lock = lock(paths)?;
    let store = AuthStore::real(paths.clone());
    let _auth_lock = store.lock_auth_state()?;
    let dir = directory(&paths.claudectl_dir(), alias);
    let journal_path = dir.join("journal.json");
    let journal: Journal = serde_json::from_slice(
        &private_read(&journal_path).context("no migration fence for this alias")?,
    )
    .context("invalid migration journal")?;
    if journal.receipt.is_some() {
        bail!("{alias} is migrated; use claudectl server remove to delete the server account");
    }
    // Only the server that holds the fence can say it never admitted it.
    if journal.server != client.connection.server || journal.user_id != client.connection.user_id {
        bail!(
            "the fence of {alias} belongs to another server or user; reconnect to {} to abort",
            journal.server
        );
    }
    let restore = match client.receipt_state(&journal.migration_id) {
        Ok((None, state)) if state == "none" => true,
        Ok((_, state)) => bail!("the server state is {state}; abort refused, rerun the migration"),
        Err(error) => match error
            .downcast_ref::<ServerError>()
            .map(|e| e.reason.as_str())
        {
            // The server no longer holds this admission: drop the fence, keep no copy.
            Some("migration_superseded" | "account_deleted") => false,
            _ => return Err(error),
        },
    };
    let profile_file = paths.profiles_dir().join(alias).join("credentials.json");
    let retained = dir.join("grant.json");
    let aside = dir.join("profile-credentials.json");
    if restore && journal.live && retained.try_exists()? {
        // The live login first: put the fenced grant back unless a newer login replaced it.
        let present = store.read_live_grant()?.is_some() || live_file(paths)?.is_some();
        if !present {
            let creds: CredentialsFile = serde_json::from_slice(&private_read(&retained)?)
                .map_err(|_| anyhow::anyhow!("invalid retained migration grant"))?;
            store.write_credentials_after_live_commit(&creds, || {})?;
        }
    }
    let copy = if journal.live { &aside } else { &retained };
    if restore && copy.try_exists()? {
        if profile_file.try_exists()? {
            bail!("credentials reappeared in the profile; reconcile before aborting");
        }
        std::fs::rename(copy, &profile_file)?;
    }
    for path in [&retained, &aside] {
        if path.try_exists()? {
            std::fs::remove_file(path)?;
        }
    }
    std::fs::remove_file(&journal_path)?;
    File::open(&dir)?.sync_all()?;
    if restore {
        println!("Migration of {alias} aborted; the local grant is restored.");
    } else {
        println!(
            "Migration fence of {alias} removed; no local grant kept. Log in again to use it."
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::OauthCreds;

    fn creds(token: &str) -> CredentialsFile {
        CredentialsFile {
            claude_ai_oauth: OauthCreds {
                access_token: format!("{token}-access"),
                refresh_token: Some(format!("{token}-refresh")),
                expires_at: Some(chrono::Utc::now().timestamp_millis() + 3_600_000),
                scopes: vec!["user:inference".into()],
                subscription_type: None,
                rate_limit_tier: None,
                extra: Default::default(),
            },
            extra: Default::default(),
        }
    }
    /// A migration fence for alias `work` and Claude identity a/o.
    fn fence(paths: &Paths) {
        let dir = directory(&paths.claudectl_dir(), "work");
        std::fs::create_dir_all(&dir).unwrap();
        let journal = Journal {
            schema: 1,
            alias: "work".into(),
            server: "https://server.invalid".into(),
            user_id: "person".into(),
            migration_id: "m-1".into(),
            identity: Identity {
                account_uuid: "a".into(),
                organization_uuid: "o".into(),
            },
            grant_digests: digests(&creds("migrated")),
            receipt: None,
            live: false,
        };
        let file = dir.join("journal.json");
        std::fs::write(&file, serde_json::to_vec(&journal).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn a_login_for_a_fenced_identity_keeps_no_recovery_copy() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        fence(&paths);
        let account = Some(json!({"accountUuid":"a","organizationUuid":"o"}));
        // A new login of the migrated identity under another alias.
        assert!(crate::central::retain_login(&paths, "other", &creds("new"), &account).is_err());
        // A copy of the migrated grant itself, without identity.
        assert!(crate::central::retain_login(&paths, "other", &creds("migrated"), &None).is_err());
        // The fenced alias itself.
        assert!(crate::central::retain_login(&paths, "work", &creds("new"), &None).is_err());
        // An unknown identity with new tokens: it may be the migrated account, so refuse.
        assert!(crate::central::retain_login(&paths, "other", &creds("new"), &None).is_err());
        let partial = Some(json!({"accountUuid":"a"}));
        assert!(crate::central::retain_login(&paths, "other", &creds("new"), &partial).is_err());
        assert!(!paths.claudectl_dir().join("retained-logins").exists());
    }

    #[test]
    fn a_login_for_an_unfenced_identity_is_still_recoverable() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        fence(&paths);
        let other = Some(json!({"accountUuid":"b","organizationUuid":"o"}));
        let kept = crate::central::retain_login(&paths, "other", &creds("new"), &other).unwrap();
        assert!(kept.exists());
    }

    #[test]
    fn without_any_fence_an_unknown_identity_is_still_recoverable() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let kept = crate::central::retain_login(&paths, "other", &creds("new"), &None).unwrap();
        assert!(kept.exists());
    }

    #[test]
    fn a_keychain_read_error_is_never_treated_as_no_keychain() {
        let migrated = digests(&creds("live"));
        let error = || Err(anyhow::anyhow!("Keychain locked"));
        // A matching file must not license a delete while the Keychain is unreadable.
        assert!(verify_live_holders(error(), Ok(Some(creds("live"))), &migrated).is_err());
        assert!(verify_live_holders(Ok(Some(creds("live"))), error(), &migrated).is_err());
        assert!(verify_live_holders(Ok(None), Ok(Some(creds("other"))), &migrated).is_err());
        assert!(verify_live_holders(Ok(Some(creds("live"))), Ok(None), &migrated).unwrap());
        assert!(!verify_live_holders(Ok(None), Ok(None), &migrated).unwrap());
    }

    #[test]
    fn a_built_in_claude_hash_still_needs_qualification_for_migration() {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let builtin = "92f2b4fd05d0bdcf7b9a0d4e0ecef4a1e4b368b290cd8fd07cff9a50013f45a2";
        assert!(require_qualified(&paths, builtin).is_err());
    }
}
