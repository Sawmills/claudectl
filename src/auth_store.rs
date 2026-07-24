use std::cell::RefCell;
use std::io::IsTerminal;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::api::CredentialsFile;
use crate::config::Paths;
use crate::shell;

pub const KEYCHAIN_SERVICE: &str = "Claude Code-credentials";

/// Read/write seam for the live Claude Code auth.
///
/// On macOS, Claude Code keeps credentials in a Keychain AND in
/// ~/.claude/.credentials.json; the Keychain copy is the read source of truth.
/// Writes target the Keychain containing the existing credentials item, or the
/// default Keychain when the item does not exist, and must update the file too.
/// Identity (email/org/tier) lives in
/// ~/.claude.json under `oauthAccount` and must move together with the
/// credentials. Tests use `file_only` so the Keychain is never touched.
pub struct AuthStore {
    paths: Paths,
    keychain: bool,
    keychain_target: RefCell<Option<String>>,
}

impl AuthStore {
    pub fn real(paths: Paths) -> Self {
        Self {
            keychain: cfg!(target_os = "macos"),
            keychain_target: RefCell::new(None),
            paths,
        }
    }

    pub fn file_only(paths: Paths) -> Self {
        Self {
            keychain: false,
            keychain_target: RefCell::new(None),
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
        self.write_credentials_after_live_commit(creds, || {})
    }

    pub(crate) fn write_credentials_after_live_commit<F>(
        &self,
        creds: &CredentialsFile,
        after_live_commit: F,
    ) -> Result<()>
    where
        F: FnOnce(),
    {
        let runner = ProcessSecurityCommandRunner;
        let access = SecurityKeychain { runner: &runner };
        self.write_credentials_after_live_commit_with(creds, after_live_commit, &access)
    }

    fn write_credentials_after_live_commit_with<F>(
        &self,
        creds: &CredentialsFile,
        after_live_commit: F,
        access: &dyn KeychainAccess,
    ) -> Result<()>
    where
        F: FnOnce(),
    {
        let json = serde_json::to_string(creds)?;
        if self.keychain {
            let keychain = self.keychain_target_with(access)?;
            access.write_credentials(&keychain, &json)?;
            after_live_commit();
            write_atomic_0600(&self.paths.claude_credentials_file(), &json)
        } else {
            write_atomic_0600(&self.paths.claude_credentials_file(), &json)?;
            after_live_commit();
            Ok(())
        }
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
            serde_json::from_str(&contents)
                .with_context(|| format!("refusing to modify malformed {}", path.display()))?
        } else {
            serde_json::Value::Object(serde_json::Map::new())
        };
        let serde_json::Value::Object(obj) = &mut root else {
            bail!("refusing to modify {}: not a JSON object", path.display());
        };
        obj.insert("oauthAccount".to_string(), account.clone());
        write_atomic_0600(&path, &serde_json::to_string_pretty(&root)?)
    }

    /// Make sure the macOS Keychain targeted by the credentials write is unlocked.
    ///
    /// Callers run this *before* anything expensive or irreversible (browser,
    /// OAuth exchange), so a locked Keychain is discovered before the user
    /// finishes a login. This does not prove that the existing credentials
    /// item's ACL will allow claudectl to update it; a late ACL denial remains
    /// recoverable because login saves the profile before activation. No-op for
    /// file-only stores.
    pub fn ensure_keychain_ready(&self) -> Result<()> {
        if !self.keychain {
            return Ok(());
        }
        let runner = ProcessSecurityCommandRunner;
        let access = SecurityKeychain { runner: &runner };
        self.ensure_keychain_ready_with(&access)
    }

    fn ensure_keychain_ready_with(&self, access: &dyn KeychainAccess) -> Result<()> {
        let keychain = self.keychain_target_with(access)?;
        ensure_keychain_unlocked_with(access, &keychain)
    }

    fn keychain_target_with(&self, access: &dyn KeychainAccess) -> Result<String> {
        if let Some(keychain) = self.keychain_target.borrow().clone() {
            return Ok(keychain);
        }
        let keychain = access.target_keychain()?;
        self.keychain_target.replace(Some(keychain.clone()));
        Ok(keychain)
    }

    pub(crate) fn preflight_oauth_account_write(&self) -> Result<()> {
        let path = self.paths.claude_json();
        if !path.exists() {
            return Ok(());
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let root: serde_json::Value = serde_json::from_str(&contents)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let serde_json::Value::Object(_) = root else {
            bail!("refusing to modify {}: not a JSON object", path.display());
        };
        Ok(())
    }
}

/// Injectable seam over the Keychain operations used by readiness and writes.
trait KeychainAccess {
    /// Existing credentials item's Keychain, or the default Keychain when absent.
    fn target_keychain(&self) -> Result<String>;
    /// Whether the target Keychain is unlocked.
    fn is_unlocked(&self, keychain: &str) -> Result<bool>;
    /// Whether there is a terminal `security(1)` can prompt on.
    fn is_interactive(&self) -> bool;
    /// Ask macOS to unlock the Keychain. claudectl never sees the password.
    fn unlock(&self, keychain: &str) -> Result<()>;
    /// Write credentials to the exact Keychain selected by `target_keychain`.
    fn write_credentials(&self, keychain: &str, json: &str) -> Result<()>;
}

/// Unlocked → done. Locked with a terminal → let macOS prompt, then re-check.
/// Locked without a terminal → fail now, while failing is still cheap.
fn ensure_keychain_unlocked_with(access: &dyn KeychainAccess, keychain: &str) -> Result<()> {
    if access.is_unlocked(keychain)? {
        return Ok(());
    }
    if !access.is_interactive() {
        bail!("{}", locked_noninteractively(keychain));
    }
    eprintln!("credential Keychain is locked; macOS will prompt for your password to unlock it.");
    access.unlock(keychain)?;
    if !access.is_unlocked(keychain)? {
        bail!("{}", still_locked(keychain));
    }
    Ok(())
}

fn locked_noninteractively(keychain: &str) -> String {
    let keychain = shell::quote_arg(keychain);
    format!(
        "credential Keychain is locked and there is no terminal for macOS to prompt on, \
         so writing credentials would fail. unlock it first, then retry: \
         security unlock-keychain {keychain}"
    )
}

fn still_locked(keychain: &str) -> String {
    let keychain = shell::quote_arg(keychain);
    format!(
        "credential Keychain is still locked after the unlock attempt. unlock it \
         (Keychain Access, or: security unlock-keychain {keychain}) and retry"
    )
}

struct SecurityCommandOutput {
    success: bool,
    stdout: String,
    stderr: String,
}

trait SecurityCommandRunner {
    fn output(&self, args: &[&str]) -> Result<SecurityCommandOutput>;
    fn status_inherited(&self, args: &[&str]) -> Result<bool>;
}

struct ProcessSecurityCommandRunner;

impl SecurityCommandRunner for ProcessSecurityCommandRunner {
    fn output(&self, args: &[&str]) -> Result<SecurityCommandOutput> {
        let output = Command::new("security")
            .args(args)
            .output()
            .context("failed to run security(1)")?;
        Ok(SecurityCommandOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    fn status_inherited(&self, args: &[&str]) -> Result<bool> {
        // status(), never output(): security(1) must inherit stdin/stdout/stderr
        // so it reads the password itself. No password flag, argv, env, or buffer
        // exists in claudectl.
        Ok(Command::new("security")
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .context("failed to run security(1)")?
            .success())
    }
}

struct SecurityKeychain<'a> {
    runner: &'a dyn SecurityCommandRunner,
}

impl KeychainAccess for SecurityKeychain<'_> {
    fn target_keychain(&self) -> Result<String> {
        let user = std::env::var("USER").context("USER not set; cannot address Keychain entry")?;
        let existing =
            self.runner
                .output(&["find-generic-password", "-a", &user, "-s", KEYCHAIN_SERVICE])?;
        if existing.success {
            return parse_item_keychain(&existing).context(
                "security(1) found the credentials item but reported no containing Keychain",
            );
        }
        if !keychain_item_not_found(&existing.stderr) {
            bail!(
                "could not locate the existing credentials item: {}",
                command_error(&existing)
            );
        }

        let default = self.runner.output(&["default-keychain"])?;
        if !default.success {
            bail!(
                "could not locate the default Keychain: {}",
                command_error(&default)
            );
        }
        let path = parse_keychain_path(&default.stdout);
        if path.is_empty() {
            bail!("security(1) reported no default Keychain");
        }
        Ok(path)
    }

    fn is_unlocked(&self, keychain: &str) -> Result<bool> {
        let output = self.runner.output(&["show-keychain-info", keychain])?;
        if output.success {
            return Ok(true);
        }
        if keychain_is_locked(&output.stderr) {
            return Ok(false);
        }
        bail!(
            "failed to inspect credential Keychain {}: {}",
            keychain,
            command_error(&output)
        )
    }

    fn is_interactive(&self) -> bool {
        // Conservative: isatty does not prove this process owns the foreground
        // terminal, so a background job can still stop on SIGTTIN.
        std::io::stdin().is_terminal()
    }

    fn unlock(&self, keychain: &str) -> Result<()> {
        if !self
            .runner
            .status_inherited(&["unlock-keychain", keychain])?
        {
            bail!("unlocking the credential Keychain was cancelled or failed");
        }
        Ok(())
    }

    fn write_credentials(&self, keychain: &str, json: &str) -> Result<()> {
        let user = std::env::var("USER").context("USER not set; cannot address Keychain entry")?;
        let output = self.runner.output(&[
            "add-generic-password",
            "-U",
            "-a",
            &user,
            "-s",
            KEYCHAIN_SERVICE,
            "-w",
            json,
            keychain,
        ])?;
        if !output.success {
            bail!("{}", keychain_write_error(output.stderr.trim()));
        }
        Ok(())
    }
}

fn parse_item_keychain(output: &SecurityCommandOutput) -> Option<String> {
    output
        .stdout
        .lines()
        .chain(output.stderr.lines())
        .find_map(|line| line.trim().strip_prefix("keychain:"))
        .map(parse_keychain_path)
        .filter(|path| !path.is_empty())
}

fn keychain_item_not_found(stderr: &str) -> bool {
    stderr.contains("The specified item could not be found in the keychain")
}

fn keychain_is_locked(stderr: &str) -> bool {
    stderr.contains("User interaction is not allowed")
}

fn command_error(output: &SecurityCommandOutput) -> &str {
    let stderr = output.stderr.trim();
    if stderr.is_empty() {
        output.stdout.trim()
    } else {
        stderr
    }
}

/// Keychain-location commands print paths indented and quoted.
fn parse_keychain_path(stdout: &str) -> String {
    stdout.trim().trim_matches('"').trim().to_string()
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

fn keychain_write_error(stderr: &str) -> String {
    if stderr.contains("User interaction is not allowed") {
        return format!(
            "failed to write Keychain entry: macOS denied non-interactive access. \
             the Keychain is unlocked, but the existing item's access controls may \
             still require authorization. resolve that in Keychain Access, then retry. \
             security(1): {stderr}"
        );
    }
    format!("failed to write Keychain entry: {stderr}")
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
    use std::collections::VecDeque;

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

    fn keychain_store() -> (tempfile::TempDir, AuthStore) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        (
            tmp,
            AuthStore {
                paths,
                keychain: true,
                keychain_target: RefCell::new(None),
            },
        )
    }

    const FAKE_KEYCHAIN: &str = "/Users/test/Library/Keychains/login.keychain-db";

    struct FakeKeychain {
        unlocked: std::cell::Cell<bool>,
        interactive: bool,
        /// Whether the unlock attempt actually leaves the Keychain unlocked.
        unlock_works: bool,
        probe_error: Option<&'static str>,
        target_calls: std::cell::Cell<usize>,
        unlock_calls: std::cell::Cell<usize>,
        probed_keychains: RefCell<Vec<String>>,
        written_keychains: RefCell<Vec<String>>,
    }

    impl FakeKeychain {
        fn new(unlocked: bool, interactive: bool, unlock_works: bool) -> Self {
            Self {
                unlocked: std::cell::Cell::new(unlocked),
                interactive,
                unlock_works,
                probe_error: None,
                target_calls: std::cell::Cell::new(0),
                unlock_calls: std::cell::Cell::new(0),
                probed_keychains: RefCell::new(Vec::new()),
                written_keychains: RefCell::new(Vec::new()),
            }
        }

        fn with_probe_error(message: &'static str) -> Self {
            Self {
                probe_error: Some(message),
                ..Self::new(false, true, true)
            }
        }
    }

    impl KeychainAccess for FakeKeychain {
        fn target_keychain(&self) -> Result<String> {
            self.target_calls.set(self.target_calls.get() + 1);
            Ok(FAKE_KEYCHAIN.to_string())
        }

        fn is_unlocked(&self, keychain: &str) -> Result<bool> {
            self.probed_keychains
                .borrow_mut()
                .push(keychain.to_string());
            if let Some(message) = self.probe_error {
                bail!("{message}");
            }
            Ok(self.unlocked.get())
        }

        fn is_interactive(&self) -> bool {
            self.interactive
        }

        fn unlock(&self, _keychain: &str) -> Result<()> {
            self.unlock_calls.set(self.unlock_calls.get() + 1);
            self.unlocked.set(self.unlock_works);
            Ok(())
        }

        fn write_credentials(&self, keychain: &str, _json: &str) -> Result<()> {
            self.written_keychains
                .borrow_mut()
                .push(keychain.to_string());
            Ok(())
        }
    }

    struct RecordingRunner {
        outputs: RefCell<VecDeque<SecurityCommandOutput>>,
        output_calls: RefCell<Vec<Vec<String>>>,
        status_calls: RefCell<Vec<Vec<String>>>,
        status_success: bool,
    }

    impl RecordingRunner {
        fn new(outputs: Vec<SecurityCommandOutput>, status_success: bool) -> Self {
            Self {
                outputs: RefCell::new(outputs.into()),
                output_calls: RefCell::new(Vec::new()),
                status_calls: RefCell::new(Vec::new()),
                status_success,
            }
        }
    }

    impl SecurityCommandRunner for RecordingRunner {
        fn output(&self, args: &[&str]) -> Result<SecurityCommandOutput> {
            self.output_calls
                .borrow_mut()
                .push(args.iter().map(|arg| (*arg).to_string()).collect());
            self.outputs
                .borrow_mut()
                .pop_front()
                .context("unexpected captured-output security command")
        }

        fn status_inherited(&self, args: &[&str]) -> Result<bool> {
            self.status_calls
                .borrow_mut()
                .push(args.iter().map(|arg| (*arg).to_string()).collect());
            Ok(self.status_success)
        }
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
    fn write_credentials_after_live_commit_runs_after_successful_write() {
        let (_tmp, store) = store();
        let called = std::cell::Cell::new(false);

        store
            .write_credentials_after_live_commit(&test_creds("tok"), || called.set(true))
            .unwrap();

        assert!(called.get());
    }

    #[test]
    #[cfg(unix)]
    fn write_credentials_after_live_commit_skips_callback_when_write_fails() {
        use std::os::unix::fs::PermissionsExt;

        let (tmp, store) = store();
        let claude_dir = Paths::from_home(tmp.path().to_path_buf())
            .claude_credentials_file()
            .parent()
            .unwrap()
            .to_path_buf();
        std::fs::create_dir_all(&claude_dir).unwrap();
        let original_mode = std::fs::metadata(&claude_dir).unwrap().permissions().mode();
        std::fs::set_permissions(&claude_dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let called = std::cell::Cell::new(false);

        let result =
            store.write_credentials_after_live_commit(&test_creds("tok"), || called.set(true));
        std::fs::set_permissions(
            &claude_dir,
            std::fs::Permissions::from_mode(original_mode & 0o777),
        )
        .unwrap();

        assert!(result.is_err());
        assert!(!called.get());
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
    fn keychain_write_error_explains_late_item_acl_denial() {
        let err = keychain_write_error(
            "security: SecKeychainItemModifyContent: User interaction is not allowed.",
        );

        assert!(
            err.contains("existing item's access controls"),
            "got: {err}"
        );
        assert!(err.contains("Keychain Access"), "got: {err}");
    }

    #[test]
    fn keychain_preflight_passes_without_prompting_when_unlocked() {
        let (_tmp, store) = keychain_store();
        let fake = FakeKeychain::new(true, true, true);

        store.ensure_keychain_ready_with(&fake).unwrap();

        assert_eq!(fake.unlock_calls.get(), 0);
    }

    #[test]
    fn keychain_preflight_unlocks_interactively_when_locked() {
        let (_tmp, store) = keychain_store();
        let fake = FakeKeychain::new(false, true, true);

        store.ensure_keychain_ready_with(&fake).unwrap();

        assert_eq!(fake.unlock_calls.get(), 1);
    }

    #[test]
    fn keychain_preflight_fails_without_prompting_when_not_interactive() {
        let (_tmp, store) = keychain_store();
        let fake = FakeKeychain::new(false, false, true);

        let err = store
            .ensure_keychain_ready_with(&fake)
            .unwrap_err()
            .to_string();

        assert!(
            err.contains(&format!("security unlock-keychain '{FAKE_KEYCHAIN}'")),
            "got: {err}"
        );
        assert_eq!(fake.unlock_calls.get(), 0);
    }

    #[test]
    fn keychain_preflight_fails_when_still_locked_after_unlock() {
        let (_tmp, store) = keychain_store();
        let fake = FakeKeychain::new(false, true, false);

        let err = store
            .ensure_keychain_ready_with(&fake)
            .unwrap_err()
            .to_string();

        assert!(err.contains("still locked"), "got: {err}");
        assert_eq!(fake.unlock_calls.get(), 1);
    }

    #[test]
    fn keychain_preflight_surfaces_probe_errors_without_unlocking() {
        let (_tmp, store) = keychain_store();
        let fake = FakeKeychain::with_probe_error("keychain database is corrupt");

        let err = store
            .ensure_keychain_ready_with(&fake)
            .unwrap_err()
            .to_string();

        assert!(err.contains("database is corrupt"), "got: {err}");
        assert_eq!(fake.unlock_calls.get(), 0);
    }

    #[test]
    fn keychain_target_is_resolved_once_and_reused_for_probe_and_write() {
        let (_tmp, store) = keychain_store();
        let fake = FakeKeychain::new(true, true, true);

        store.ensure_keychain_ready_with(&fake).unwrap();
        store
            .write_credentials_after_live_commit_with(&test_creds("tok"), || {}, &fake)
            .unwrap();

        assert_eq!(fake.target_calls.get(), 1);
        assert_eq!(
            fake.probed_keychains.borrow().as_slice(),
            &[FAKE_KEYCHAIN.to_string()]
        );
        assert_eq!(
            fake.written_keychains.borrow().as_slice(),
            &[FAKE_KEYCHAIN.to_string()]
        );
    }

    #[test]
    fn target_keychain_prefers_existing_credentials_item() {
        let runner = RecordingRunner::new(
            vec![SecurityCommandOutput {
                success: true,
                stdout: String::new(),
                stderr: format!("keychain: \"{FAKE_KEYCHAIN}\"\nversion: 512\n"),
            }],
            true,
        );
        let access = SecurityKeychain { runner: &runner };

        assert_eq!(access.target_keychain().unwrap(), FAKE_KEYCHAIN);
        assert_eq!(
            runner.output_calls.borrow().as_slice(),
            &[vec![
                "find-generic-password".to_string(),
                "-a".to_string(),
                std::env::var("USER").unwrap(),
                "-s".to_string(),
                KEYCHAIN_SERVICE.to_string()
            ]]
        );
    }

    #[test]
    fn target_keychain_falls_back_to_default_when_credentials_item_is_absent() {
        let runner = RecordingRunner::new(
            vec![
                SecurityCommandOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "The specified item could not be found in the keychain.".to_string(),
                },
                SecurityCommandOutput {
                    success: true,
                    stdout: format!("    \"{FAKE_KEYCHAIN}\"\n"),
                    stderr: String::new(),
                },
            ],
            true,
        );
        let access = SecurityKeychain { runner: &runner };

        assert_eq!(access.target_keychain().unwrap(), FAKE_KEYCHAIN);
        assert_eq!(
            runner.output_calls.borrow().as_slice(),
            &[
                vec![
                    "find-generic-password".to_string(),
                    "-a".to_string(),
                    std::env::var("USER").unwrap(),
                    "-s".to_string(),
                    KEYCHAIN_SERVICE.to_string()
                ],
                vec!["default-keychain".to_string()]
            ]
        );
    }

    #[test]
    fn keychain_probe_classifies_interaction_denied_as_locked() {
        let runner = RecordingRunner::new(
            vec![SecurityCommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "SecKeychainCopySettings: User interaction is not allowed.".to_string(),
            }],
            true,
        );
        let access = SecurityKeychain { runner: &runner };

        assert!(!access.is_unlocked(FAKE_KEYCHAIN).unwrap());
    }

    #[test]
    fn keychain_probe_surfaces_non_lock_security_error() {
        let runner = RecordingRunner::new(
            vec![SecurityCommandOutput {
                success: false,
                stdout: String::new(),
                stderr: "SecKeychainCopySettings: invalid database".to_string(),
            }],
            true,
        );
        let access = SecurityKeychain { runner: &runner };

        let err = access.is_unlocked(FAKE_KEYCHAIN).unwrap_err().to_string();

        assert!(err.contains("invalid database"), "got: {err}");
    }

    #[test]
    fn unlock_uses_inherited_status_without_password_argument() {
        let runner = RecordingRunner::new(Vec::new(), true);
        let access = SecurityKeychain { runner: &runner };

        access.unlock(FAKE_KEYCHAIN).unwrap();

        assert!(runner.output_calls.borrow().is_empty());
        assert_eq!(
            runner.status_calls.borrow().as_slice(),
            &[vec![
                "unlock-keychain".to_string(),
                FAKE_KEYCHAIN.to_string()
            ]]
        );
        assert!(
            runner.status_calls.borrow()[0]
                .iter()
                .all(|arg| arg != "-p")
        );
    }

    #[test]
    fn credential_write_explicitly_targets_resolved_keychain() {
        let runner = RecordingRunner::new(
            vec![SecurityCommandOutput {
                success: true,
                stdout: String::new(),
                stderr: String::new(),
            }],
            true,
        );
        let access = SecurityKeychain { runner: &runner };

        access.write_credentials(FAKE_KEYCHAIN, "{}").unwrap();

        let calls = runner.output_calls.borrow();
        let args = calls.first().unwrap();
        assert_eq!(args.last().unwrap(), FAKE_KEYCHAIN);
        assert_eq!(args[0], "add-generic-password");
        assert!(args.iter().any(|arg| arg == "-U"));
    }

    #[test]
    fn file_only_store_skips_the_keychain_preflight() {
        let (_tmp, store) = store();
        store.ensure_keychain_ready().unwrap();
    }

    #[test]
    fn parse_keychain_path_strips_quotes_and_indentation() {
        assert_eq!(
            parse_keychain_path("    \"/Users/test/Library/Keychains/login.keychain-db\"\n"),
            FAKE_KEYCHAIN
        );
    }

    #[test]
    fn read_oauth_account_missing_file_is_none() {
        let (_tmp, store) = store();
        assert!(store.read_oauth_account().unwrap().is_none());
    }
}
