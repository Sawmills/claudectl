use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::api::CredentialsFile;
use crate::config::Paths;

pub const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";

/// Read/write seam for the live Claude Code auth.
///
/// On macOS, Claude Code keeps credentials in the login Keychain AND in
/// ~/.claude/.credentials.json; the Keychain copy is the read source of truth
/// and writes must update both. Identity (email/org/tier) lives in
/// ~/.claude.json under `oauthAccount` and must move together with the
/// credentials. Tests use `file_only` so the Keychain is never touched.
pub struct AuthStore {
    paths: Paths,
    keychain: bool,
}

impl AuthStore {
    pub fn real(paths: Paths) -> Self {
        Self {
            keychain: cfg!(target_os = "macos"),
            paths,
        }
    }

    pub fn file_only(paths: Paths) -> Self {
        Self {
            keychain: false,
            paths,
        }
    }

    pub fn read_credentials(&self) -> Result<CredentialsFile> {
        if self.keychain
            && let Some(raw) = keychain_read()
        {
            return serde_json::from_str(&raw).context("failed to parse Keychain credentials");
        }
        let path = self.paths.claude_credentials_file();
        if !path.exists() {
            bail!(
                "no live Claude Code login found (no Keychain entry and no {})",
                path.display()
            );
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))
    }

    pub fn write_credentials(&self, creds: &CredentialsFile) -> Result<()> {
        let json = serde_json::to_string(creds)?;
        if self.keychain {
            keychain_write(&json)?;
        }
        write_atomic_0600(&self.paths.claude_credentials_file(), &json)
    }

    /// The `oauthAccount` blob from ~/.claude.json, if present.
    pub fn read_oauth_account(&self) -> Result<Option<serde_json::Value>> {
        let path = self.paths.claude_json();
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        Ok(value.get("oauthAccount").cloned())
    }

    /// Replace only the `oauthAccount` key in ~/.claude.json, preserving every
    /// other key. Errors on a malformed file rather than clobbering it.
    pub fn write_oauth_account(&self, account: &serde_json::Value) -> Result<()> {
        let path = self.paths.claude_json();
        let mut root = if path.exists() {
            let contents = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            serde_json::from_str(&contents).with_context(|| {
                format!("refusing to modify malformed {}", path.display())
            })?
        } else {
            serde_json::Value::Object(serde_json::Map::new())
        };
        let serde_json::Value::Object(obj) = &mut root else {
            bail!("refusing to modify {}: not a JSON object", path.display());
        };
        obj.insert("oauthAccount".to_string(), account.clone());
        write_atomic_0600(&path, &serde_json::to_string_pretty(&root)?)
    }
}

/// Read the Keychain credential blob. Any failure (item missing, locked
/// keychain, no `security` binary) falls through to the file copy.
fn keychain_read() -> Option<String> {
    let output = Command::new("security")
        .args(["find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8(output.stdout).ok()?;
    let raw = raw.trim();
    (!raw.is_empty()).then(|| raw.to_string())
}

fn keychain_write(json: &str) -> Result<()> {
    let user = std::env::var("USER").context("USER not set; cannot address Keychain entry")?;
    let output = Command::new("security")
        .args([
            "add-generic-password",
            "-U",
            "-a",
            &user,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            json,
        ])
        .output()
        .context("failed to run security(1)")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("failed to write Keychain entry (locked keychain?): {}", stderr.trim());
    }
    Ok(())
}

fn write_atomic_0600(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let tmp = path.with_extension("claudectl-tmp");
    std::fs::write(&tmp, contents).with_context(|| format!("failed to write {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to move {} into place", tmp.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::OauthCreds;

    fn test_creds(token: &str) -> CredentialsFile {
        CredentialsFile {
            claude_ai_oauth: OauthCreds {
                access_token: token.to_string(),
                refresh_token: Some("rt".to_string()),
                expires_at: Some(1781087528419),
                scopes: vec!["user:inference".to_string()],
                subscription_type: Some("team".to_string()),
                rate_limit_tier: None,
                extra: serde_json::Map::new(),
            },
            extra: serde_json::Map::new(),
        }
    }

    fn store() -> (tempfile::TempDir, AuthStore) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        (tmp, AuthStore::file_only(paths))
    }

    #[test]
    fn write_then_read_credentials_round_trips() {
        let (_tmp, store) = store();
        store.write_credentials(&test_creds("tok-1")).unwrap();
        let read = store.read_credentials().unwrap();
        assert_eq!(read.claude_ai_oauth.access_token, "tok-1");
        assert_eq!(read.claude_ai_oauth.expires_at, Some(1781087528419));
    }

    #[test]
    #[cfg(unix)]
    fn write_credentials_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, store) = store();
        store.write_credentials(&test_creds("tok")).unwrap();
        let path = Paths::from_home(tmp.path().to_path_buf()).claude_credentials_file();
        let mode = std::fs::metadata(path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn write_oauth_account_preserves_other_keys() {
        let (tmp, store) = store();
        let claude_json = Paths::from_home(tmp.path().to_path_buf()).claude_json();
        std::fs::write(
            &claude_json,
            r#"{"oauthAccount": {"emailAddress": "old@x"}, "numStartups": 5, "projects": {"/a": {}}}"#,
        )
        .unwrap();

        store
            .write_oauth_account(&serde_json::json!({"emailAddress": "new@x"}))
            .unwrap();

        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&claude_json).unwrap()).unwrap();
        assert_eq!(value["oauthAccount"]["emailAddress"], "new@x");
        assert_eq!(value["numStartups"], 5);
        assert!(value["projects"]["/a"].is_object());
    }

    #[test]
    fn read_credentials_missing_everything_errors() {
        let (_tmp, store) = store();
        let err = store.read_credentials().unwrap_err().to_string();
        assert!(err.contains("no live Claude Code login"), "got: {err}");
    }

    #[test]
    fn write_oauth_account_rejects_malformed_claude_json() {
        let (tmp, store) = store();
        let claude_json = Paths::from_home(tmp.path().to_path_buf()).claude_json();
        std::fs::write(&claude_json, "{not json").unwrap();

        let err = store
            .write_oauth_account(&serde_json::json!({"emailAddress": "x@y"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("malformed"), "got: {err}");
        // Original content untouched.
        assert_eq!(std::fs::read_to_string(&claude_json).unwrap(), "{not json");
    }

    #[test]
    fn read_oauth_account_missing_file_is_none() {
        let (_tmp, store) = store();
        assert!(store.read_oauth_account().unwrap().is_none());
    }
}
