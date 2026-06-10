use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::api::CredentialsFile;
use crate::auth_store::AuthStore;
use crate::config::{self, Paths};

#[derive(Serialize, Deserialize, Clone)]
pub struct AccountMeta {
    pub alias: String,
    pub saved_at: String,
    /// `oauthAccount` blob from ~/.claude.json (None when login couldn't fetch identity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oauth_account: Option<serde_json::Value>,
}

impl AccountMeta {
    pub fn email(&self) -> Option<&str> {
        self.oauth_account.as_ref()?.get("emailAddress")?.as_str()
    }

    pub fn account_uuid(&self) -> Option<&str> {
        self.oauth_account.as_ref()?.get("accountUuid")?.as_str()
    }
}

pub struct Profile {
    pub meta: AccountMeta,
    pub dir: PathBuf,
}

impl Profile {
    pub fn credentials_path(&self) -> PathBuf {
        self.dir.join("credentials.json")
    }

    pub fn account_path(&self) -> PathBuf {
        self.dir.join("account.json")
    }

    pub fn read_credentials(&self) -> Result<CredentialsFile> {
        let path = self.credentials_path();
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn write_credentials(&self, creds: &CredentialsFile) -> Result<()> {
        let json = serde_json::to_string(creds)?;
        let path = self.credentials_path();
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

pub fn validate_alias(alias: &str) -> Result<&str> {
    let alias = alias.trim();
    if alias.is_empty() {
        bail!("alias must not be empty");
    }
    if alias.contains('/') || alias.contains('\\') || alias == "." || alias == ".." {
        bail!("alias must not contain path separators");
    }
    Ok(alias)
}

// === Paths-accepting versions (testable) ===

pub fn list_profiles_from(paths: &Paths) -> Result<Vec<Profile>> {
    let profiles_dir = paths.profiles_dir();
    if !profiles_dir.exists() {
        return Ok(vec![]);
    }
    let mut profiles = Vec::new();
    for entry in std::fs::read_dir(&profiles_dir)
        .with_context(|| format!("failed to read {}", profiles_dir.display()))?
    {
        let path = entry?.path();
        if !path.is_dir() || !path.join("account.json").exists() {
            continue;
        }
        let meta = read_account_meta(&path)?;
        profiles.push(Profile { meta, dir: path });
    }
    profiles.sort_by(|a, b| a.meta.alias.cmp(&b.meta.alias));
    Ok(profiles)
}

pub fn get_profile_from(paths: &Paths, alias: &str) -> Result<Profile> {
    let dir = paths.profiles_dir().join(alias);
    if !dir.exists() {
        bail!("profile '{}' not found", alias);
    }
    let meta = read_account_meta(&dir)?;
    Ok(Profile { meta, dir })
}

pub fn save_profile_to(
    paths: &Paths,
    alias: &str,
    creds: &CredentialsFile,
    oauth_account: Option<serde_json::Value>,
) -> Result<Profile> {
    let alias = validate_alias(alias)?;
    let dir = paths.profiles_dir().join(alias);
    std::fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;

    let meta = AccountMeta {
        alias: alias.to_string(),
        saved_at: chrono::Utc::now().to_rfc3339(),
        oauth_account,
    };
    let profile = Profile { meta, dir };
    profile.write_credentials(creds)?;
    write_account_meta(&profile.dir, &profile.meta)?;
    Ok(profile)
}

pub fn delete_profile_from(paths: &Paths, alias: &str) -> Result<()> {
    let dir = paths.profiles_dir().join(alias);
    if !dir.exists() {
        bail!("profile '{}' not found", alias);
    }
    std::fs::remove_dir_all(&dir).with_context(|| format!("failed to remove {}", dir.display()))?;
    Ok(())
}

pub fn get_active_from(paths: &Paths) -> Result<Option<String>> {
    let active_file = paths.active_file();
    if !active_file.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&active_file)?;
    let alias = contents.trim().to_string();
    if alias.is_empty() {
        return Ok(None);
    }
    Ok(Some(alias))
}

pub fn set_active_from(paths: &Paths, alias: &str) -> Result<()> {
    std::fs::write(paths.active_file(), alias)?;
    Ok(())
}

pub fn clear_active_from(paths: &Paths) -> Result<()> {
    let active_file = paths.active_file();
    if active_file.exists() {
        std::fs::remove_file(active_file)?;
    }
    Ok(())
}

/// Switch the live Claude Code auth to `alias`. Returns the profile's email
/// for display. Pure local operation — never contacts Anthropic.
pub fn switch_to(store: &AuthStore, paths: &Paths, alias: &str) -> Result<String> {
    let profile = get_profile_from(paths, alias)?;
    let creds = profile.read_credentials()?;

    // Fold tokens Claude Code rotated back into the outgoing profile before we
    // overwrite the live auth; otherwise they're lost and the profile later
    // looks expired even though the seat is fine.
    capture_outgoing(store, paths);

    store.write_credentials(&creds)?;
    match &profile.meta.oauth_account {
        Some(account) => store.write_oauth_account(account)?,
        None => eprintln!(
            "warning: profile '{alias}' has no stored identity; ~/.claude.json oauthAccount left unchanged"
        ),
    }
    set_active_from(paths, alias)?;
    Ok(profile.meta.email().unwrap_or("unknown").to_string())
}

/// Best-effort capture of the live (possibly rotated) tokens into the active
/// profile. Skipped with a warning when the live identity no longer matches
/// the profile (the user logged in manually over it). Never blocks a switch.
fn capture_outgoing(store: &AuthStore, paths: &Paths) {
    let Ok(Some(alias)) = get_active_from(paths) else {
        return;
    };
    let Ok(profile) = get_profile_from(paths, &alias) else {
        return;
    };
    let Ok(live_creds) = store.read_credentials() else {
        return;
    };
    let live_account = store.read_oauth_account().unwrap_or(None);

    if !identity_matches(live_account.as_ref(), &profile.meta) {
        let live = live_account
            .as_ref()
            .and_then(|a| a.get("emailAddress"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        eprintln!(
            "warning: live login ({live}) does not match active profile '{alias}'; skipping token capture"
        );
        return;
    }

    if let Err(e) = profile.write_credentials(&live_creds) {
        eprintln!("warning: failed to capture tokens for profile '{alias}': {e}");
        return;
    }
    if let Some(account) = live_account {
        let meta = AccountMeta {
            oauth_account: Some(account),
            ..profile.meta.clone()
        };
        if let Err(e) = write_account_meta(&profile.dir, &meta) {
            eprintln!("warning: failed to update identity for profile '{alias}': {e}");
        }
    }
}

/// Positive identity match required: accountUuid when both sides have it,
/// otherwise emailAddress. Unknown on either side → no match (safer to skip
/// capture than to corrupt a profile with another account's tokens).
fn identity_matches(live: Option<&serde_json::Value>, meta: &AccountMeta) -> bool {
    let Some(live) = live else {
        return false;
    };
    let live_uuid = live.get("accountUuid").and_then(|v| v.as_str());
    if let (Some(live_uuid), Some(meta_uuid)) = (live_uuid, meta.account_uuid()) {
        return live_uuid == meta_uuid;
    }
    let live_email = live.get("emailAddress").and_then(|v| v.as_str());
    match (live_email, meta.email()) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn read_account_meta(dir: &std::path::Path) -> Result<AccountMeta> {
    let path = dir.join("account.json");
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("failed to parse {}", path.display()))
}

fn write_account_meta(dir: &std::path::Path, meta: &AccountMeta) -> Result<()> {
    let json = serde_json::to_string_pretty(meta)?;
    std::fs::write(dir.join("account.json"), json)?;
    Ok(())
}

// === Default-paths wrappers (used by commands) ===

pub fn list_profiles() -> Result<Vec<Profile>> {
    list_profiles_from(&config::default_paths()?)
}
pub fn get_active() -> Result<Option<String>> {
    get_active_from(&config::default_paths()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::OauthCreds;

    fn creds(token: &str) -> CredentialsFile {
        CredentialsFile {
            claude_ai_oauth: OauthCreds {
                access_token: token.to_string(),
                refresh_token: Some("rt".to_string()),
                expires_at: Some(1781087528419),
                scopes: vec![],
                subscription_type: Some("team".to_string()),
                rate_limit_tier: None,
                extra: serde_json::Map::new(),
            },
            extra: serde_json::Map::new(),
        }
    }

    fn account(email: &str, uuid: &str) -> serde_json::Value {
        serde_json::json!({"emailAddress": email, "accountUuid": uuid})
    }

    fn setup() -> (tempfile::TempDir, Paths, AuthStore) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        let store = AuthStore::file_only(paths.clone());
        (tmp, paths, store)
    }

    #[test]
    fn save_list_get_delete_round_trip() {
        let (_tmp, paths, _store) = setup();
        save_profile_to(&paths, "a@x", &creds("t1"), Some(account("a@x", "u1"))).unwrap();
        save_profile_to(&paths, "b@x", &creds("t2"), None).unwrap();

        let listed = list_profiles_from(&paths).unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|p| p.meta.alias.as_str())
                .collect::<Vec<_>>(),
            vec!["a@x", "b@x"]
        );

        let p = get_profile_from(&paths, "a@x").unwrap();
        assert_eq!(p.meta.email(), Some("a@x"));
        assert_eq!(
            p.read_credentials().unwrap().claude_ai_oauth.access_token,
            "t1"
        );

        delete_profile_from(&paths, "a@x").unwrap();
        assert!(get_profile_from(&paths, "a@x").is_err());
        assert_eq!(list_profiles_from(&paths).unwrap().len(), 1);
    }

    #[test]
    fn alias_validation() {
        assert_eq!(validate_alias("  a@x ").unwrap(), "a@x");
        assert!(validate_alias("").is_err());
        assert!(validate_alias("a/b").is_err());
        assert!(validate_alias("..").is_err());
    }

    #[test]
    fn active_tracking() {
        let (_tmp, paths, _store) = setup();
        assert_eq!(get_active_from(&paths).unwrap(), None);
        set_active_from(&paths, "a@x").unwrap();
        assert_eq!(get_active_from(&paths).unwrap(), Some("a@x".to_string()));
        clear_active_from(&paths).unwrap();
        assert_eq!(get_active_from(&paths).unwrap(), None);
    }

    #[test]
    fn switch_writes_credentials_and_oauth_account() {
        let (_tmp, paths, store) = setup();
        save_profile_to(&paths, "a@x", &creds("t1"), Some(account("a@x", "u1"))).unwrap();

        let email = switch_to(&store, &paths, "a@x").unwrap();

        assert_eq!(email, "a@x");
        assert_eq!(
            store
                .read_credentials()
                .unwrap()
                .claude_ai_oauth
                .access_token,
            "t1"
        );
        let live = store.read_oauth_account().unwrap().unwrap();
        assert_eq!(live["accountUuid"], "u1");
        assert_eq!(get_active_from(&paths).unwrap(), Some("a@x".to_string()));
    }

    #[test]
    fn switch_captures_rotated_tokens_into_outgoing_profile() {
        let (_tmp, paths, store) = setup();
        save_profile_to(&paths, "a@x", &creds("t1"), Some(account("a@x", "u1"))).unwrap();
        save_profile_to(&paths, "b@x", &creds("t2"), Some(account("b@x", "u2"))).unwrap();
        switch_to(&store, &paths, "a@x").unwrap();

        // Simulate Claude Code rotating the live tokens while a@x was active.
        store.write_credentials(&creds("t1-rotated")).unwrap();

        switch_to(&store, &paths, "b@x").unwrap();

        let a = get_profile_from(&paths, "a@x").unwrap();
        assert_eq!(
            a.read_credentials().unwrap().claude_ai_oauth.access_token,
            "t1-rotated"
        );
        assert_eq!(
            store
                .read_credentials()
                .unwrap()
                .claude_ai_oauth
                .access_token,
            "t2"
        );
    }

    #[test]
    fn switch_skips_capture_when_live_identity_differs() {
        let (_tmp, paths, store) = setup();
        save_profile_to(&paths, "a@x", &creds("t1"), Some(account("a@x", "u1"))).unwrap();
        save_profile_to(&paths, "b@x", &creds("t2"), Some(account("b@x", "u2"))).unwrap();
        switch_to(&store, &paths, "a@x").unwrap();

        // User logged in manually over a@x with a different account.
        store.write_credentials(&creds("other-token")).unwrap();
        store
            .write_oauth_account(&account("other@x", "u-other"))
            .unwrap();

        switch_to(&store, &paths, "b@x").unwrap();

        // a@x's stored tokens must be untouched.
        let a = get_profile_from(&paths, "a@x").unwrap();
        assert_eq!(
            a.read_credentials().unwrap().claude_ai_oauth.access_token,
            "t1"
        );
    }

    #[test]
    fn switch_fails_before_writing_when_target_missing() {
        let (_tmp, paths, store) = setup();
        save_profile_to(&paths, "a@x", &creds("t1"), Some(account("a@x", "u1"))).unwrap();
        switch_to(&store, &paths, "a@x").unwrap();

        assert!(switch_to(&store, &paths, "nope").is_err());
        // Live auth unchanged.
        assert_eq!(
            store
                .read_credentials()
                .unwrap()
                .claude_ai_oauth
                .access_token,
            "t1"
        );
        assert_eq!(get_active_from(&paths).unwrap(), Some("a@x".to_string()));
    }
}
