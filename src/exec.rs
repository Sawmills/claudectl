//! Run one child process on one saved profile without touching the live login.
//!
//! The child receives the saved access token through an inherited pipe named by
//! `CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR`, and a fresh private
//! `CLAUDE_CONFIG_DIR`. The live Keychain entry, `~/.claude.json`,
//! `~/.claude/.credentials.json` and the active marker are never written.
//!
//! Refresh ownership: this module never refreshes a token. It refuses the
//! active profile and any saved grant that the live login shares, and it
//! refuses a token that expires before `min_valid` runs out.

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::api;
use crate::auth_store::AuthStore;
use crate::config::Paths;
use crate::profile;

pub const TOKEN_FD_ENV: &str = "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR";
pub const CONFIG_DIR_ENV: &str = "CLAUDE_CONFIG_DIR";

/// Credential sources the child must not inherit that `is_scrubbed_env`'s
/// name rules do not cover.
const SCRUBBED_ENV: &[&str] = &[
    "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    "CLAUDE_CODE_OAUTH_SCOPES",
    "CLAUDE_CODE_HOST_CREDS_FILE",
    "CCR_OAUTH_TOKEN_FILE",
];

/// Name endings that mark a credential, a credential descriptor, an endpoint
/// or extra headers.
const SCRUBBED_SUFFIXES: &[&str] = &[
    "_API_KEY",
    "_TOKEN",
    "_FILE_DESCRIPTOR",
    "_BASE_URL",
    "_HOST",
    "_HEADERS",
    "_HELPER",
];

/// True for an environment name the child must not inherit (or get from a
/// settings file), so the saved profile is the only login it can use and the
/// token goes only to Anthropic. It covers every `ANTHROPIC_*` and
/// `CLAUDE_CODE_*` name that selects a provider (`CLAUDE_CODE_USE_*`) or ends
/// in a credential, descriptor, endpoint or header suffix, for example
/// `ANTHROPIC_API_KEY`, `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR` and
/// `ANTHROPIC_BASE_URL`. Rules, not a list, so a name added in a later
/// Claude Code release with the same shape is covered too.
pub fn is_scrubbed_env(name: &str) -> bool {
    if SCRUBBED_ENV.contains(&name) {
        return true;
    }
    if !(name.starts_with("ANTHROPIC_") || name.starts_with("CLAUDE_CODE_")) {
        return false;
    }
    name.starts_with("CLAUDE_CODE_USE_")
        || SCRUBBED_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

/// Top-level settings keys that run a command to get a credential.
const SETTINGS_CREDENTIAL_KEYS: &[&str] = &[
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
];

/// The directory that holds Claude Code's managed (policy) settings.
pub fn managed_settings_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/ClaudeCode")
    } else {
        PathBuf::from("/etc/claude-code")
    }
}

/// Refuse when a settings file Claude Code would load in `cwd` could change
/// the login or the endpoint: an `env` entry `is_scrubbed_env` covers, or a
/// credential helper. The private config dir has no user settings, but
/// project, local and managed settings still apply. It checks
/// `.claude/settings.json` and `.claude/settings.local.json` in `cwd` and
/// every parent, and `managed-settings.json` plus `managed-settings.d/*.json`
/// in `managed`. A parent that is `home` is skipped: its `.claude` holds user
/// settings, which the private config dir replaces. When `cwd` is `home`
/// itself, Claude Code reads that directory as the project, so it is checked.
/// A file that exists but cannot be read or parsed is refused. Values are
/// never read into the error.
/// The host user settings (`~/.claude/settings.json` and `settings.local.json`), for a child
/// that keeps the host config (`server run`). Same rules as [`check_settings`].
pub fn check_user_settings(home: &Path) -> Result<(), ExecError> {
    check_files(vec![
        home.join(".claude/settings.json"),
        home.join(".claude/settings.local.json"),
    ])
}

fn check_files(files: Vec<std::path::PathBuf>) -> Result<(), ExecError> {
    for file in files {
        let bytes = match std::fs::read(&file) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => continue,
            Err(e) => {
                return Err(ExecError::Refused(format!(
                    "cannot read {} ({})",
                    file.display(),
                    e.kind()
                )));
            }
        };
        let settings: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| {
            ExecError::Refused(format!(
                "cannot parse {}; exec cannot prove it leaves the login alone",
                file.display()
            ))
        })?;
        let overrides = settings
            .get("env")
            .and_then(|env| env.as_object())
            .into_iter()
            .flat_map(|env| env.keys())
            // exec sets these two for the child itself; a settings value
            // would replace them after the spawn.
            .filter(|name| {
                is_scrubbed_env(name) || *name == CONFIG_DIR_ENV || *name == TOKEN_FD_ENV
            })
            .map(String::as_str)
            .chain(
                SETTINGS_CREDENTIAL_KEYS
                    .iter()
                    .copied()
                    .filter(|key| settings.get(key).is_some()),
            )
            .collect::<Vec<_>>();
        if !overrides.is_empty() {
            return Err(ExecError::Refused(format!(
                "{} sets {}, which can change the login or the endpoint; run from another directory",
                file.display(),
                overrides.join(", ")
            )));
        }
    }
    Ok(())
}

pub fn check_settings(cwd: &Path, home: &Path, managed: &Path) -> Result<(), ExecError> {
    let home = home.canonicalize().unwrap_or_else(|_| home.to_path_buf());
    let mut files = Vec::new();
    for dir in cwd.ancestors() {
        if dir != cwd && dir == home {
            continue;
        }
        files.push(dir.join(".claude/settings.json"));
        files.push(dir.join(".claude/settings.local.json"));
    }
    files.push(managed.join("managed-settings.json"));
    match std::fs::read_dir(managed.join("managed-settings.d")) {
        Ok(entries) => {
            let mut extra = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| {
                    ExecError::Refused(format!("cannot list managed settings ({})", e.kind()))
                })?;
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "json") {
                    extra.push(path);
                }
            }
            extra.sort();
            files.extend(extra);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(ExecError::Refused(format!(
                "cannot list managed settings ({})",
                e.kind()
            )));
        }
    }
    check_files(files)
}

/// `check_settings` for this process's working directory, which the child
/// inherits.
/// The settings check for this process, reported as `ExecError::Settings`:
/// the refusal concerns the directory and settings, not the account.
fn check_current_settings(paths: &Paths) -> Result<(), ExecError> {
    let cwd = std::env::current_dir().map_err(|e| {
        ExecError::Settings(format!("cannot read the working directory ({})", e.kind()))
    })?;
    check_settings(&cwd, &paths.home, &managed_settings_dir()).map_err(|error| match error {
        ExecError::Refused(message) => ExecError::Settings(message),
        other => other,
    })
}

pub struct ExecRequest {
    pub alias: String,
    pub expect_account: Option<String>,
    pub expect_sha256: Option<String>,
    pub min_valid: Duration,
    pub receipt: Option<PathBuf>,
    pub program: OsString,
    pub args: Vec<OsString>,
    /// A directory to use as `CLAUDE_CONFIG_DIR` and keep after the run, so
    /// session transcripts survive (the `claude` launcher's lane). None gives
    /// a fresh private directory that is removed when the run ends.
    pub state_dir: Option<PathBuf>,
}

/// Account lookup for the identity check. Production uses the OAuth profile
/// endpoint; tests supply a fake through the library API only.
pub trait IdentitySource {
    fn account_uuid(&self, access_token: &str) -> anyhow::Result<Option<String>>;
}

pub struct LiveIdentity;

impl IdentitySource for LiveIdentity {
    fn account_uuid(&self, access_token: &str) -> anyhow::Result<Option<String>> {
        Ok(api::fetch_oauth_account(access_token)?.and_then(|account| {
            account
                .get("accountUuid")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        }))
    }
}

#[derive(Debug)]
pub enum ExecError {
    /// The settings or the working directory make any account unsafe to run
    /// here (same exit code as Refused).
    Settings(String),
    /// Policy refusal: active alias, shared grant, short lifetime, bad profile.
    Refused(String),
    /// Identity missing or mismatched.
    Identity(String),
    /// Executable or claudectl pin failed.
    Pin(String),
    /// A receipt record could not be written.
    Receipt(String),
    /// The child could not be started.
    Spawn(String),
    /// The child ran, but its private config directory could not be removed.
    Cleanup(String),
}

impl ExecError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ExecError::Identity(_) => 3,
            ExecError::Pin(_) => 4,
            ExecError::Refused(_) | ExecError::Settings(_) => 5,
            ExecError::Receipt(_) => 6,
            ExecError::Spawn(_) => 7,
            ExecError::Cleanup(_) => 8,
        }
    }
}

impl std::error::Error for ExecError {}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecError::Refused(m) | ExecError::Settings(m) => write!(f, "refused: {m}"),
            ExecError::Identity(m) => write!(f, "identity check failed: {m}"),
            ExecError::Pin(m) => write!(f, "executable pin failed: {m}"),
            ExecError::Receipt(m) => write!(f, "receipt write failed: {m}"),
            ExecError::Spawn(m) => write!(f, "could not start child: {m}"),
            ExecError::Cleanup(m) => write!(f, "cleanup failed: {m}"),
        }
    }
}

/// A validated run. Holds the token only in memory; `Debug` is not derived so
/// the token cannot reach a log through formatting.
pub struct Prepared {
    alias: String,
    account_uuid: String,
    email: Option<String>,
    token: String,
    token_expires_at_ms: i64,
    live_token: Option<String>,
    program: PathBuf,
    program_sha256: String,
    claudectl: SelfIdentity,
}

#[derive(Clone)]
pub struct SelfIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

impl SelfIdentity {
    /// The running claudectl's path, SHA-256 and version. The hash must
    /// describe the image that is executing, not a file that replaced it on
    /// disk after start, so it fails closed when that cannot be shown.
    pub fn current() -> Result<Self, ExecError> {
        let path = std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .map_err(|e| ExecError::Pin(format!("cannot resolve claudectl path: {e}")))?;
        let bytes = running_image_bytes(&path)?;
        Ok(Self {
            path,
            sha256: format!("{:x}", Sha256::digest(&bytes)),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }
}

/// Linux: /proc/self/exe opens the executing image even after the path was
/// replaced.
#[cfg(target_os = "linux")]
fn running_image_bytes(_path: &Path) -> Result<Vec<u8>, ExecError> {
    std::fs::read("/proc/self/exe")
        .map_err(|e| ExecError::Pin(format!("cannot read the running claudectl image: {e}")))
}

/// macOS: the path may now name a different file, so compare the file's
/// build UUID with the UUID of the image loaded in memory.
#[cfg(target_os = "macos")]
fn running_image_bytes(path: &Path) -> Result<Vec<u8>, ExecError> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    // Open the path once, then prove that this exact file (device and inode)
    // is the one the kernel mapped for the running image, and read the bytes
    // from that same handle.
    let mut file = std::fs::File::open(path)
        .map_err(|e| ExecError::Pin(format!("cannot open {}: {e}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| ExecError::Pin(format!("cannot stat {}: {e}", path.display())))?;
    let (dev, ino) = mapped_image_identity()
        .ok_or_else(|| ExecError::Pin("cannot read the running claudectl image identity".into()))?;
    if u64::from(dev) != meta.dev() || ino != meta.ino() {
        return Err(ExecError::Pin(format!(
            "{} is not the running claudectl (it was replaced after start)",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| ExecError::Pin(format!("cannot read {}: {e}", path.display())))?;
    let loaded = loaded_image_uuid()
        .ok_or_else(|| ExecError::Pin("cannot read the running claudectl build UUID".into()))?;
    match macho_uuid(&bytes) {
        Some(file) if file == loaded => Ok(bytes),
        Some(_) => Err(ExecError::Pin(format!(
            "{} is not the running claudectl (it was replaced after start)",
            path.display()
        ))),
        None => Err(ExecError::Pin(format!(
            "cannot read a build UUID from {}",
            path.display()
        ))),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn running_image_bytes(_path: &Path) -> Result<Vec<u8>, ExecError> {
    Err(ExecError::Pin(
        "cannot bind the claudectl hash to the running image on this platform".into(),
    ))
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// dyld's header of loaded image `image_index`; 0 is the main executable.
    fn _dyld_get_image_header(image_index: u32) -> *const std::ffi::c_void;
}

/// `struct proc_regioninfo` from <sys/proc_info.h>.
#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcRegionInfo {
    protection: u32,
    max_protection: u32,
    inheritance: u32,
    flags: u32,
    offset: u64,
    behavior: u32,
    user_wired_count: u32,
    user_tag: u32,
    pages_resident: u32,
    pages_shared_now_private: u32,
    pages_swapped_out: u32,
    pages_dirtied: u32,
    ref_count: u32,
    shadow_depth: u32,
    share_mode: u32,
    private_pages_resident: u32,
    shared_pages_resident: u32,
    obj_id: u32,
    depth: u32,
    address: u64,
    size: u64,
}

/// `struct proc_regionwithpathinfo` from <sys/proc_info.h>.
#[cfg(target_os = "macos")]
#[repr(C)]
struct ProcRegionWithPathInfo {
    region: ProcRegionInfo,
    vnode: libc::vnode_info_path,
}

/// Device and inode of the file the kernel mapped for this code: the
/// running image, whatever its path names now.
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub fn mapped_image_identity() -> Option<(u32, u64)> {
    const PROC_PIDREGIONPATHINFO: libc::c_int = 8;
    let address = mapped_image_identity as *const () as usize as u64;
    // SAFETY: proc_pidinfo writes at most `size` bytes into `info`.
    unsafe {
        let mut info: ProcRegionWithPathInfo = std::mem::zeroed();
        let size = std::mem::size_of::<ProcRegionWithPathInfo>() as libc::c_int;
        let written = libc::proc_pidinfo(
            libc::getpid(),
            PROC_PIDREGIONPATHINFO,
            address,
            (&mut info as *mut ProcRegionWithPathInfo).cast(),
            size,
        );
        if written != size {
            return None;
        }
        let stat = &info.vnode.vip_vi.vi_stat;
        Some((stat.vst_dev, stat.vst_ino))
    }
}

/// The LC_UUID of the main executable image loaded in this process.
#[cfg(target_os = "macos")]
fn loaded_image_uuid() -> Option<[u8; 16]> {
    // SAFETY: image 0 is the main executable; dyld keeps its header mapped for
    // the life of the process. Only its header and load commands are read.
    unsafe {
        let header = _dyld_get_image_header(0).cast::<u8>();
        if header.is_null() {
            return None;
        }
        let fixed = std::slice::from_raw_parts(header, 32);
        let sizeofcmds = u32::from_le_bytes(fixed[20..24].try_into().ok()?) as usize;
        let image = std::slice::from_raw_parts(header, 32 + sizeofcmds);
        macho_uuid(image)
    }
}

/// The LC_UUID of a thin 64-bit little-endian Mach-O image, if present.
#[doc(hidden)]
pub fn macho_uuid(image: &[u8]) -> Option<[u8; 16]> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const LC_UUID: u32 = 0x1b;
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(image.get(at..at + 4)?.try_into().ok()?))
    };
    if word(0)? != MH_MAGIC_64 {
        return None;
    }
    let ncmds = word(16)? as usize;
    let mut at = 32;
    for _ in 0..ncmds {
        let (cmd, size) = (word(at)?, word(at + 4)? as usize);
        if cmd == LC_UUID {
            return image.get(at + 8..at + 24)?.try_into().ok();
        }
        if size < 8 {
            return None;
        }
        at += size;
    }
    None
}

/// Validate everything before any child exists. `run` repeats the ownership
/// and lifetime checks under the auth lock right before the spawn.
pub fn prepare(
    paths: &Paths,
    store: &AuthStore,
    req: &ExecRequest,
    identity: &dyn IdentitySource,
    claudectl: SelfIdentity,
) -> Result<Prepared, ExecError> {
    let alias = profile::validate_alias(&req.alias)
        .map_err(|e| ExecError::Refused(format!("{e:#}")))?
        .to_string();
    let saved = profile::get_profile_from(paths, &alias)
        .map_err(|e| ExecError::Refused(format!("{e:#}")))?;

    check_current_settings(paths)?;
    let (creds, live_token) = {
        let _lock = lock_with_retry(store)?;
        check_ownership(paths, store, &alias, None, req.min_valid)?
    };
    let oauth = &creds.claude_ai_oauth;
    let expires_at_ms = oauth.expires_at.unwrap_or_default();

    let saved_uuid = saved
        .meta
        .account_uuid()
        .map(str::to_string)
        .ok_or_else(|| {
            ExecError::Identity(format!(
                "'{alias}' has no saved accountUuid; run `claudectl login {alias}` again"
            ))
        })?;
    if let Some(expected) = &req.expect_account
        && expected != &saved_uuid
    {
        return Err(ExecError::Identity(format!(
            "'{alias}' is account {saved_uuid}, expected {expected}"
        )));
    }
    let token_uuid = identity
        .account_uuid(&oauth.access_token)
        .map_err(|e| ExecError::Identity(format!("account lookup failed: {e:#}")))?
        .ok_or_else(|| ExecError::Identity("account lookup returned no account".into()))?;
    if token_uuid != saved_uuid {
        return Err(ExecError::Identity(format!(
            "'{alias}' token belongs to account {token_uuid}, profile says {saved_uuid}"
        )));
    }
    // ~/.claude.json and the active marker can lag the live credentials (a
    // switch that failed half way). Ask the identity service which account
    // owns the live token itself; refuse when it is this account or unknown.
    if let Some(live_token) = &live_token {
        let live_uuid = identity
            .account_uuid(live_token)
            .ok()
            .flatten()
            .ok_or_else(|| {
                ExecError::Refused(
                    "live refresh ownership unknown: cannot identify the live login's account (if Claude Code is idle, use it once so it refreshes its token, then retry)".into(),
                )
            })?;
        if live_uuid == saved_uuid {
            return Err(ExecError::Refused(format!(
                "'{alias}' is the same account as the live login; claudectl cannot prove it holds an independent grant"
            )));
        }
    }

    let program = resolve_program(&req.program)?;
    let program_sha256 = sha256_file(&program)?;
    if let Some(expected) = &req.expect_sha256
        && !expected.eq_ignore_ascii_case(&program_sha256)
    {
        return Err(ExecError::Pin(format!(
            "{} has sha256 {program_sha256}, expected {expected}",
            program.display()
        )));
    }

    Ok(Prepared {
        alias,
        account_uuid: saved_uuid,
        email: saved.meta.email().map(str::to_string),
        token: oauth.access_token.clone(),
        token_expires_at_ms: expires_at_ms,
        live_token,
        program,
        program_sha256,
        claudectl,
    })
}

/// Decide refresh ownership and lifetime. The caller holds the auth lock.
/// With `expected = (token, account_uuid)`, the saved token and the saved
/// account identity must still be the ones `prepare` verified.
fn check_ownership(
    paths: &Paths,
    store: &AuthStore,
    alias: &str,
    expected: Option<(&str, &str)>,
    min_valid: Duration,
) -> Result<(crate::api::CredentialsFile, Option<String>), ExecError> {
    let active = profile::get_active_from(paths)
        .map_err(|e| ExecError::Refused(format!("cannot read active profile: {e:#}")))?;
    if active
        .as_deref()
        .is_some_and(|active| same_profile(paths, active, alias))
    {
        return Err(ExecError::Refused(format!(
            "'{alias}' is the active profile; Claude Code owns its login, run plain claude instead"
        )));
    }
    let saved = profile::get_profile_from(paths, alias)
        .map_err(|e| ExecError::Refused(format!("{e:#}")))?;
    let creds = saved
        .read_credentials()
        // Never include the parser's message: for a malformed file it can
        // quote credential values.
        .map_err(|e| {
            ExecError::Refused(format!(
                "saved credentials unreadable ({})",
                credential_error_category(&e)
            ))
        })?;
    let live = store.read_refresh_owner().map_err(|e| {
        ExecError::Refused(format!(
            "live refresh ownership unknown ({})",
            credential_error_category(&e)
        ))
    })?;
    let oauth = &creds.claude_ai_oauth;
    if oauth.access_token.trim().is_empty() {
        return Err(ExecError::Refused(format!(
            "'{alias}' has no access token; log in again"
        )));
    }
    if let Some((token, account)) = expected {
        if oauth.access_token != token {
            return Err(ExecError::Refused(format!(
                "'{alias}' credentials changed during preparation; run again"
            )));
        }
        if saved.meta.account_uuid() != Some(account) {
            return Err(ExecError::Identity(format!(
                "'{alias}' saved account identity changed during preparation; run again"
            )));
        }
    }
    // Witnesses of the live grant: the live login itself, and the active
    // profile's saved copy. After Claude Code rotates the live tokens, a
    // second saved copy of the same grant still matches the active
    // profile's saved copy.
    let live_present = live.is_some();
    // The live access token, so callers can bind its owner and detect a
    // change between preparation and spawn. Never logged.
    let live_token = live
        .as_ref()
        .map(|live| live.claude_ai_oauth.access_token.clone());
    let mut witnesses = Vec::new();
    if let Some(live) = live {
        witnesses.push(live.claude_ai_oauth);
    }
    if let Some(active) = active.as_deref() {
        // Fail closed: an unreadable active profile could be the only link
        // between this saved alias and the live grant.
        let active_creds = profile::get_profile_from(paths, active)
            .and_then(|active_profile| active_profile.read_credentials())
            .map_err(|e| {
                ExecError::Refused(format!(
                    "live refresh ownership unknown: active profile credentials unreadable ({})",
                    credential_error_category(&e)
                ))
            })?;
        witnesses.push(active_creds.claude_ai_oauth);
    }
    // Grant lineage is not recorded: after a rotation and `claudectl save`,
    // an older saved copy of the live grant matches no witness token. Two
    // saved logins of the same account cannot be shown to hold independent
    // grants, so refuse any profile of the live login's account.
    let mut live_accounts: Vec<String> = Vec::new();
    if let Some(active) = active.as_deref()
        && let Ok(active_profile) = profile::get_profile_from(paths, active)
        && let Some(uuid) = active_profile.meta.account_uuid()
    {
        live_accounts.push(uuid.to_string());
    }
    let live_identity = store.read_oauth_account().map_err(|e| {
        ExecError::Refused(format!(
            "live refresh ownership unknown: live identity unreadable ({})",
            credential_error_category(&e)
        ))
    })?;
    match live_identity
        .as_ref()
        .and_then(|account| account.get("accountUuid"))
        .and_then(|uuid| uuid.as_str())
    {
        Some(uuid) => live_accounts.push(uuid.to_string()),
        // A live login whose account is unknown could be this profile's
        // account; fail closed instead of skipping the check.
        None if live_present => {
            return Err(ExecError::Refused(
                "live refresh ownership unknown: the live login has no readable accountUuid in ~/.claude.json".into(),
            ));
        }
        None => {}
    }
    if let Some(uuid) = saved.meta.account_uuid()
        && live_accounts.iter().any(|live| live == uuid)
    {
        return Err(ExecError::Refused(format!(
            "'{alias}' is the same account as the live login; claudectl cannot prove it holds an independent grant"
        )));
    }
    for witness in &witnesses {
        let same_refresh =
            oauth.refresh_token.is_some() && oauth.refresh_token == witness.refresh_token;
        let same_access = oauth.access_token == witness.access_token;
        if same_refresh || same_access {
            return Err(ExecError::Refused(format!(
                "'{alias}' shares its grant with the live login; Claude Code owns that refresh"
            )));
        }
    }
    let expires_at_ms = oauth
        .expires_at
        .ok_or_else(|| ExecError::Refused(format!("'{alias}' has no token expiry")))?;
    let remaining_ms = expires_at_ms - chrono::Utc::now().timestamp_millis();
    let needed_ms = i64::try_from(min_valid.as_millis()).unwrap_or(i64::MAX);
    if remaining_ms <= 0 {
        return Err(ExecError::Refused(format!(
            "'{alias}' token has expired; run `claudectl status {alias}` to refresh it"
        )));
    }
    if remaining_ms < needed_ms {
        return Err(ExecError::Refused(format!(
            "'{alias}' token is valid for {} min, {} min required. claudectl refreshes a saved token only after it expires: retry after that and run `claudectl status {alias}`. `claudectl login {alias}` also gives a fresh token, but it makes '{alias}' the active profile, so switch back with `claudectl use <previous>` before running exec",
            remaining_ms / 60_000,
            needed_ms / 60_000
        )));
    }
    Ok((creds, live_token))
}

/// Start the child and wait for it. Returns the exit code to propagate.
/// A receipt failure before the spawn starts no child; after the spawn it
/// stops the child and fails.
pub fn run(
    paths: &Paths,
    store: &AuthStore,
    prepared: Prepared,
    req: &ExecRequest,
) -> Result<i32, ExecError> {
    let receipt = Receipt::open(req.receipt.as_deref())?;
    run_with_receipt(paths, store, prepared, req, receipt)
}

/// Like `run`, but writes receipt records to `sink`. For tests that need a
/// receipt sink which fails.
#[doc(hidden)]
pub fn run_with_writer(
    paths: &Paths,
    store: &AuthStore,
    prepared: Prepared,
    req: &ExecRequest,
    sink: Box<dyn Write>,
) -> Result<i32, ExecError> {
    run_with_receipt(paths, store, prepared, req, Receipt::from_writer(sink))
}

/// Signal handling is process-wide, so one process runs one `exec` at a time.
static RUN_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) struct RunSlot;

impl RunSlot {
    pub(crate) fn take() -> Result<Self, ExecError> {
        use std::sync::atomic::Ordering;
        RUN_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| RunSlot)
            .map_err(|_| {
                ExecError::Refused(
                    "another exec run is active in this process; run one at a time".into(),
                )
            })
    }
}

impl Drop for RunSlot {
    fn drop(&mut self) {
        RUN_ACTIVE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

/// The descriptor number the child reads the token from.
pub const CHILD_TOKEN_FD: i32 = 3;

fn run_with_receipt(
    paths: &Paths,
    store: &AuthStore,
    prepared: Prepared,
    req: &ExecRequest,
    mut receipt: Receipt,
) -> Result<i32, ExecError> {
    let _slot = RunSlot::take()?;
    // Handle cancellation for the whole life of the private directory, so a
    // signal cannot skip its removal.
    signals::install();
    let config_dir = match &req.state_dir {
        Some(dir) => kept_config_dir(dir),
        None => fresh_config_dir(paths, &prepared.alias).map(ConfigDir::Temp),
    };
    let config_dir = match config_dir {
        Ok(dir) => dir,
        Err(error) => {
            signals::reset();
            return Err(error);
        }
    };
    let dir_path = config_dir.path().to_path_buf();
    let mut base = receipt_base(&prepared, &dir_path, req);
    let outcome = run_in_dir(
        paths,
        store,
        &prepared,
        req,
        &mut receipt,
        &dir_path,
        &mut base,
    );
    // Remove the private directory on every path, and never hide a removal
    // failure behind another error.
    let closed = config_dir.close();
    signals::reset();
    match closed {
        Ok(()) => outcome,
        Err(error) => {
            let earlier = match &outcome {
                Ok(code) => format!("child exited with {code}"),
                Err(e) => e.to_string(),
            };
            let message = format!("{earlier}; removing {} failed: {error}", dir_path.display());
            let _ = receipt.write(&with(
                &base,
                "cleanup_failed",
                serde_json::json!({ "error": error.to_string(), "earlier": earlier }),
            ));
            Err(ExecError::Cleanup(message))
        }
    }
}

fn run_in_dir(
    paths: &Paths,
    store: &AuthStore,
    prepared: &Prepared,
    req: &ExecRequest,
    receipt: &mut Receipt,
    config_dir: &Path,
    base: &mut serde_json::Value,
) -> Result<i32, ExecError> {
    // Execute a private copy, so the bytes that run are the bytes that were
    // hashed, even if the original path is replaced during the run.
    seed_claude_json(paths, config_dir)?;
    let snapshot = snapshot_executable(&prepared.program, config_dir)?;
    let snapshot_sha256 = sha256_file(&snapshot)?;
    if snapshot_sha256 != prepared.program_sha256 {
        return Err(ExecError::Pin(format!(
            "{} changed after it was verified",
            prepared.program.display()
        )));
    }
    // The parent keeps FD_CLOEXEC on the pipe, so no other child can inherit
    // it; only this child's pre-exec step maps it to CHILD_TOKEN_FD.
    let (reader, mut writer) =
        std::io::pipe().map_err(|e| ExecError::Spawn(format!("cannot create token pipe: {e}")))?;
    writer
        .write_all(prepared.token.as_bytes())
        .map_err(|e| ExecError::Spawn(format!("cannot write token pipe: {e}")))?;
    drop(writer);

    base["executed_snapshot"] = serde_json::json!(snapshot);
    receipt.write(&with(base, "prepared", serde_json::json!({})))?;

    let mut command = Command::new(&snapshot);
    command.args(&req.args);
    set_arg0(&mut command, &prepared.program);
    for (name, _) in std::env::vars_os() {
        if name.to_str().is_some_and(is_scrubbed_env) {
            command.env_remove(&name);
        }
    }
    command.env(CONFIG_DIR_ENV, config_dir);
    command.env(TOKEN_FD_ENV, CHILD_TOKEN_FD.to_string());
    map_token_fd(&mut command, &reader);

    // The child gets its own process group, so cancellation and teardown
    // reach its descendants and every signal reaches it exactly once. When
    // claudectl owns the terminal foreground at the spawn, the child's group
    // takes it, as a shell job does: terminal keys (Ctrl-C, Ctrl-Z) and
    // window size changes then go to the child directly, and claudectl gets
    // the foreground back when the child exits.
    set_process_group(&mut command);
    let terminal = foreground::is_terminal();
    if terminal {
        take_foreground(&mut command);
    }

    let (spawned, suspended_before_exec) = {
        // Hold the lock from the final ownership check through the spawn, so
        // no `use` can make this grant live in between.
        let lock = lock_with_retry(store);
        let checked = lock.and_then(|_lock| {
            let (_, live_now) = check_ownership(
                paths,
                store,
                &prepared.alias,
                Some((&prepared.token, &prepared.account_uuid)),
                req.min_valid,
            )?;
            // The live owner was identified for this exact live token.
            if live_now != prepared.live_token {
                return Err(ExecError::Refused(
                    "the live login changed during preparation; run again".into(),
                ));
            }
            check_current_settings(paths)?;
            signals::block();
            if let Some(signal) = signals::pending() {
                signals::unblock();
                return Err(ExecError::Spawn(format!(
                    "cancelled by signal {signal} before the child started"
                )));
            }
            // The child takes the terminal before its exec; a stop in that
            // window must still suspend the job.
            let watchdog = terminal.then(SpawnWatchdog::start);
            let spawned = command.spawn();
            let suspended = watchdog.is_some_and(SpawnWatchdog::finish);
            if spawned.is_err() {
                signals::unblock();
                if terminal && foreground::owned_by_gone_group() {
                    // The child took the foreground before its exec failed.
                    foreground::reclaim();
                }
            }
            Ok((spawned, suspended))
        });
        match checked {
            Ok(result) => result,
            Err(error) => {
                receipt.write(&with(
                    base,
                    "refused",
                    serde_json::json!({ "error": error.to_string() }),
                ))?;
                return Err(error);
            }
        }
    };
    drop(reader);
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            receipt
                .write(&with(
                    base,
                    "spawn_failed",
                    serde_json::json!({ "error": error.to_string() }),
                ))
                .map_err(|receipt_error| {
                    ExecError::Receipt(format!("{receipt_error} (after spawn failure: {error})"))
                })?;
            return Err(ExecError::Spawn(error.to_string()));
        }
    };
    let pid = child.id();
    // Interactive only if the child really took the foreground: claudectl
    // may have been stopped and resumed with `bg` before the spawn. A child
    // the watchdog suspended took it, even if `bg` resumed it since.
    let interactive =
        terminal && (suspended_before_exec || i32::try_from(pid).is_ok_and(foreground::owned_by));
    // Held signals are released here and forwarded once, with their own
    // numbers, now that the child is registered.
    signals::watch(pid);
    let started = receipt.write(&with(base, "started", serde_json::json!({ "pid": pid })));
    if started.is_err() {
        terminate(pid, SIGKILL);
    }
    // Wait for the exit without reaping. While the child is an unreaped
    // zombie its PID stays reserved, so every signal to its process group,
    // through the final SIGKILL, can only reach this run's processes.
    let waited = wait_exit_no_reap(pid, interactive);
    // Take the terminal back only from this run's child. After Ctrl-Z and
    // `bg` the shell owns it, and a background claudectl must not take it.
    if interactive && i32::try_from(pid).is_ok_and(foreground::owned_by) {
        foreground::reclaim();
    }
    let descendants = if waited.is_ok() {
        teardown_group(pid)
    } else {
        Descendants::Unknown
    };
    // Stop forwarding while the leader is still unreaped, so no late signal
    // can reach a reused PID.
    signals::unwatch();
    let status = child.wait();
    waited.map_err(|e| ExecError::Spawn(format!("cannot wait for child {pid}: {e}")))?;
    let status = status.map_err(|e| ExecError::Spawn(format!("cannot reap child {pid}: {e}")))?;
    let code = exit_code_of(&status);
    let exited = receipt.write(&with(
        base,
        "exited",
        serde_json::json!({
            "pid": pid,
            "exit_code": status.code(),
            "signal": signal_of(&status),
            "descendants": descendants.as_str(),
        }),
    ));
    let teardown_failure = match descendants {
        Descendants::Survived => Some("its descendants survived SIGKILL"),
        Descendants::Unverified | Descendants::Unknown => {
            Some("descendant termination could not be verified")
        }
        _ => None,
    };
    if let Some(failure) = teardown_failure {
        // A receipt error must not hide this: report both.
        let receipt_errors: Vec<String> = [&started, &exited]
            .into_iter()
            .filter_map(|result| result.as_ref().err().map(ToString::to_string))
            .collect();
        let mut message = format!("child {pid} exited with {code}, but {failure}");
        if !receipt_errors.is_empty() {
            message.push_str(&format!("; also {}", receipt_errors.join("; ")));
        }
        return Err(ExecError::Cleanup(message));
    }
    started?;
    exited?;
    Ok(code)
}

pub(crate) enum Descendants {
    None,
    Terminated,
    Killed,
    Survived,
    Unverified,
    Unknown,
}

impl Descendants {
    fn as_str(&self) -> &'static str {
        match self {
            Descendants::None => "none",
            Descendants::Terminated => "terminated",
            Descendants::Killed => "killed",
            Descendants::Survived => "survived",
            Descendants::Unverified => "signalled_unverified",
            Descendants::Unknown => "unknown",
        }
    }
}

/// Bounded TERM-to-KILL teardown of the child's process group. The caller
/// keeps the leader unreaped for the whole call.
pub(crate) fn teardown_group(leader: u32) -> Descendants {
    let members = match descendants_in_group(leader) {
        Ok(members) => members,
        Err(_) => {
            // Membership is unknown, but the leader is still reserved, so
            // signalling its group is safe. Tear down blind and say so.
            ask_to_exit(leader);
            std::thread::sleep(Duration::from_secs(2));
            terminate(leader, SIGKILL);
            return Descendants::Unverified;
        }
    };
    if members.is_empty() {
        return Descendants::None;
    }
    ask_to_exit(leader);
    match wait_descendants_gone(leader, Duration::from_secs(2)) {
        Remaining::Gone => return Descendants::Terminated,
        Remaining::ListingFailed => {
            terminate(leader, SIGKILL);
            return Descendants::Unverified;
        }
        Remaining::Present => {}
    }
    terminate(leader, SIGKILL);
    match wait_descendants_gone(leader, Duration::from_secs(2)) {
        Remaining::Gone => Descendants::Killed,
        Remaining::Present => Descendants::Survived,
        Remaining::ListingFailed => Descendants::Unverified,
    }
}

enum Remaining {
    Gone,
    Present,
    ListingFailed,
}

fn wait_descendants_gone(leader: u32, limit: Duration) -> Remaining {
    let started = std::time::Instant::now();
    loop {
        match descendants_in_group(leader) {
            Ok(members) if members.is_empty() => return Remaining::Gone,
            Ok(_) => {}
            Err(_) => return Remaining::ListingFailed,
        }
        if started.elapsed() >= limit {
            return Remaining::Present;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Live processes in the group led by `leader`, excluding the leader itself
/// (an unreaped zombie at this point).
#[cfg(target_os = "macos")]
fn descendants_in_group(leader: u32) -> std::io::Result<Vec<i32>> {
    // From <sys/proc_info.h>.
    const PROC_PGRP_ONLY: u32 = 2;
    let mut pids = vec![0i32; 4096];
    let size = i32::try_from(pids.len() * std::mem::size_of::<i32>()).unwrap_or(i32::MAX);
    // SAFETY: the buffer is valid for `size` bytes.
    let bytes =
        unsafe { libc::proc_listpids(PROC_PGRP_ONLY, leader, pids.as_mut_ptr().cast(), size) };
    // proc_listpids reports some failures as 0 instead of -1. The unreaped
    // leader is always in its own group, so a real listing is never empty.
    let count = usize::try_from(bytes.max(0)).unwrap_or(0) / std::mem::size_of::<i32>();
    let leader = i32::try_from(leader).unwrap_or(0);
    group_members_from_listing(&pids[..count.min(pids.len())], leader)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn descendants_in_group(leader: u32) -> std::io::Result<Vec<i32>> {
    let leader = i32::try_from(leader).unwrap_or(0);
    let mut listed = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        // The command name in `stat` is raw bytes, not always UTF-8.
        let stat = match std::fs::read(entry.path().join("stat")) {
            Ok(stat) => stat,
            // The process exited between the directory read and this read.
            Err(error) if process_gone(&error) => continue,
            Err(error) => return Err(error),
        };
        let Some(close) = stat.iter().rposition(|&b| b == b')') else {
            return Err(std::io::Error::other(format!("malformed /proc/{pid}/stat")));
        };
        // Fields after the ")" of the command name: state ppid pgrp ...
        let rest = String::from_utf8_lossy(&stat[close + 1..]);
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.len() <= 2 {
            return Err(std::io::Error::other(format!("malformed /proc/{pid}/stat")));
        }
        let in_group = fields[2].parse::<i32>().ok() == Some(leader);
        // Count the unreaped leader, but not other zombies: they no longer run.
        if in_group && (pid == leader || fields[0] != "Z") {
            listed.push(pid);
        }
    }
    group_members_from_listing(&listed, leader)
}

/// A secret-safe description of a credential read failure: the I/O error
/// kind, or "malformed" for any parse error. Parser messages are never used,
/// because they can quote the credential text.
fn credential_error_category(error: &anyhow::Error) -> String {
    match error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        Some(io) => format!("read error: {:?}", io.kind()),
        None => "malformed or unavailable".into(),
    }
}

/// Whether two aliases name the same profile directory. Compares the
/// directories themselves, so `Work` and `work` on a case-insensitive
/// filesystem, or a symlinked alias, count as the same profile.
pub fn same_profile(paths: &Paths, a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    let dir = |alias: &str| std::fs::metadata(paths.profiles_dir().join(alias));
    match (dir(a), dir(b)) {
        (Ok(first), Ok(second)) => same_file(&first, &second),
        _ => false,
    }
}

#[cfg(unix)]
fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &std::fs::Metadata, _b: &std::fs::Metadata) -> bool {
    false
}

/// Whether a `/proc/<pid>` read failed only because the process exited
/// during the scan. Linux reports that as ENOENT, or as ESRCH once the file
/// is open; Rust maps only ENOENT to `NotFound`.
#[doc(hidden)]
pub fn process_gone(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
        || (cfg!(unix) && error.raw_os_error() == Some(libc::ESRCH))
}

/// The live members of `leader`'s group other than the leader. A listing
/// without the leader cannot be complete, because the caller keeps the leader
/// unreaped, so it is an error.
#[doc(hidden)]
pub fn group_members_from_listing(listed: &[i32], leader: i32) -> std::io::Result<Vec<i32>> {
    if !listed.contains(&leader) {
        return Err(std::io::Error::other(
            "process listing does not include the unreaped group leader",
        ));
    }
    Ok(listed
        .iter()
        .copied()
        .filter(|&pid| pid > 0 && pid != leader)
        .collect())
}

#[cfg(not(unix))]
fn descendants_in_group(_leader: u32) -> std::io::Result<Vec<i32>> {
    Ok(Vec::new())
}

/// Whether the child `pid` already exited, without reaping it. A zombie still accepts
/// signals, so this tells an exit apart from a delivered signal.
#[cfg(unix)]
pub(crate) fn has_exited(pid: u32) -> bool {
    // SAFETY: waitid writes only into `info`; WNOWAIT leaves the child reapable.
    unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        libc::waitid(
            libc::P_PID,
            pid as libc::id_t,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        ) == 0
            && info.si_pid() != 0
    }
}

/// Wait until the child exits, without reaping it. For an interactive child,
/// a stop (Ctrl-Z) also suspends claudectl, as its shell job.
#[cfg(unix)]
pub(crate) fn wait_exit_no_reap(pid: u32, interactive: bool) -> std::io::Result<()> {
    let flags = if interactive {
        libc::WEXITED | libc::WSTOPPED | libc::WNOWAIT
    } else {
        libc::WEXITED | libc::WNOWAIT
    };
    loop {
        // SAFETY: waitid writes only into `info`; WNOWAIT leaves the child
        // reapable by Child::wait.
        let (result, code) = unsafe {
            let mut info: libc::siginfo_t = std::mem::zeroed();
            let result = libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags);
            (result, info.si_code)
        };
        if result == 0 {
            match code {
                libc::CLD_STOPPED if interactive => suspend_with(pid),
                // macOS reports a stop even without WSTOPPED. A stopped
                // child has not exited: wait until someone continues it.
                libc::CLD_STOPPED => std::thread::sleep(Duration::from_millis(100)),
                _ => return Ok(()),
            }
            continue;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

/// The child stopped. Take the foreground back, stop claudectl's shell job
/// as the terminal would, and when claudectl is continued, continue the
/// child, in the foreground again if claudectl was resumed there (`fg`).
#[cfg(unix)]
fn suspend_with(leader: u32) {
    let Ok(leader) = i32::try_from(leader) else {
        return;
    };
    if foreground::owned_by(leader) {
        foreground::reclaim();
    }
    stop_job();
    if foreground::owned() {
        let _ = foreground::give(leader);
    }
    // SAFETY: kill only sends a signal to the child's group.
    unsafe { libc::kill(-leader, libc::SIGCONT) };
}

/// Watches for a stop of the forked child while `Command::spawn` blocks. The
/// child takes the terminal in `pre_exec`, so a Ctrl-Z before its exec stops
/// it while claudectl waits inside spawn; the shell would never see the job
/// stop. The watchdog then suspends claudectl's job as `wait_exit_no_reap`
/// does after the spawn, and `fg` continues the child, which runs its exec.
#[cfg(unix)]
struct SpawnWatchdog {
    done: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Returns whether it suspended the job for the child.
    thread: Option<std::thread::JoinHandle<bool>>,
}

#[cfg(unix)]
impl SpawnWatchdog {
    /// How often the watchdog looks for a stopped child.
    const POLL: Duration = Duration::from_millis(2);

    fn start() -> Self {
        use std::sync::atomic::Ordering;
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = {
            let done = done.clone();
            std::thread::spawn(move || {
                let mut suspended = false;
                while !done.load(Ordering::SeqCst) {
                    if let Some(pid) = stopped_foreground_child() {
                        suspend_with(pid);
                        suspended = true;
                    }
                    std::thread::sleep(Self::POLL);
                }
                suspended
            })
        };
        Self {
            done,
            thread: Some(thread),
        }
    }

    /// Stop watching once spawn has returned. Returns whether the watchdog
    /// suspended the job for the child.
    fn finish(mut self) -> bool {
        self.stop()
    }

    fn stop(&mut self) -> bool {
        self.done.store(true, std::sync::atomic::Ordering::SeqCst);
        self.thread
            .take()
            .is_some_and(|thread| thread.join().unwrap_or(false))
    }
}

#[cfg(unix)]
impl Drop for SpawnWatchdog {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A stopped child of claudectl that leads its own group and owns the
/// terminal: only a child that took the foreground before its exec can.
/// WNOWAIT leaves its state for `Child::wait`.
#[cfg(unix)]
fn stopped_foreground_child() -> Option<u32> {
    // SAFETY: waitid writes only into `info`; WNOHANG returns at once and
    // WNOWAIT reaps nothing.
    let (result, code, pid) = unsafe {
        let mut info: libc::siginfo_t = std::mem::zeroed();
        let result = libc::waitid(
            libc::P_ALL,
            0,
            &mut info,
            libc::WSTOPPED | libc::WNOWAIT | libc::WNOHANG,
        );
        (result, info.si_code, info.si_pid())
    };
    if result != 0 || code != libc::CLD_STOPPED || pid <= 0 {
        return None;
    }
    // SAFETY: getpgid only reads process state.
    let leads_group = unsafe { libc::getpgid(pid) } == pid;
    (leads_group && foreground::owned_by(pid)).then_some(pid as u32)
}

#[cfg(not(unix))]
struct SpawnWatchdog;

#[cfg(not(unix))]
impl SpawnWatchdog {
    fn start() -> Self {
        Self
    }

    fn finish(self) -> bool {
        false
    }
}

/// Set by the SIGCONT handler while `stop_job` waits.
#[cfg(unix)]
static CONTINUED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn note_continued(_signal: libc::c_int) {
    CONTINUED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// Stop claudectl's shell job (a pipeline shares claudectl's group) as the
/// terminal would, and return once claudectl is continued. The SIGTSTP can go
/// to another thread of claudectl and leave this one running for a moment, so
/// this thread waits for the SIGCONT. The kernel discards SIGTSTP for an
/// orphaned group; then no SIGCONT comes, and the wait ends after a bound.
#[cfg(unix)]
fn stop_job() {
    use std::sync::atomic::Ordering;
    CONTINUED.store(false, Ordering::SeqCst);
    // SAFETY: installs a handler that only stores an atomic, saves the
    // previous action, and restores it below; kill only sends a signal.
    let previous = unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = note_continued as *const () as libc::sighandler_t;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        let mut previous: libc::sigaction = std::mem::zeroed();
        libc::sigaction(libc::SIGCONT, &action, &mut previous);
        libc::kill(0, libc::SIGTSTP);
        previous
    };
    let started = std::time::Instant::now();
    while !CONTINUED.load(Ordering::SeqCst) && started.elapsed() < Duration::from_millis(250) {
        std::thread::sleep(Duration::from_millis(1));
    }
    // SAFETY: restores the SIGCONT action saved above.
    unsafe { libc::sigaction(libc::SIGCONT, &previous, std::ptr::null_mut()) };
}

#[cfg(not(unix))]
pub(crate) fn wait_exit_no_reap(_pid: u32, _interactive: bool) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
const SIGTERM: i32 = libc::SIGTERM;
#[cfg(unix)]
const SIGKILL: i32 = libc::SIGKILL;
#[cfg(unix)]
const SIGCONT: i32 = libc::SIGCONT;
#[cfg(not(unix))]
const SIGTERM: i32 = 15;
#[cfg(not(unix))]
const SIGKILL: i32 = 9;
#[cfg(not(unix))]
const SIGCONT: i32 = 18;

/// Signal the child's whole process group. Returns whether any process
/// received the signal.
#[cfg(unix)]
fn terminate(leader: u32, signal: i32) -> bool {
    let Ok(leader) = i32::try_from(leader) else {
        return false;
    };
    // SAFETY: kill only sends a signal.
    unsafe { libc::kill(-leader, signal) == 0 }
}

#[cfg(not(unix))]
fn terminate(_leader: u32, _signal: i32) -> bool {
    false
}

/// SIGTERM to the child's group, then SIGCONT, because a stopped process
/// acts on SIGTERM only after it is continued.
fn ask_to_exit(leader: u32) {
    terminate(leader, SIGTERM);
    terminate(leader, SIGCONT);
}

#[cfg(unix)]
pub(crate) fn set_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
pub(crate) fn set_process_group(_command: &mut Command) {}

/// Make the child's new group the terminal foreground before it runs, if
/// claudectl's group owns the foreground at that moment. Rust runs this
/// after the child's setpgid, and spawn returns only after the exec, so the
/// child owns the foreground from its first instruction. A Ctrl-Z between
/// this handoff and the exec stops the forked child while claudectl waits
/// inside spawn; `SpawnWatchdog` suspends claudectl's job then.
#[cfg(unix)]
pub(crate) fn take_foreground(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: getpgrp only reads process state.
    let claudectl_group = unsafe { libc::getpgrp() };
    let pause = test_hooks::pre_exec_pause();
    // SAFETY: runs in the forked child; tcgetpgrp, getpid,
    // foreground::give and nanosleep are async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::tcgetpgrp(libc::STDIN_FILENO) == claudectl_group {
                foreground::give(libc::getpid())?;
            }
            if let Some(mut left) = pause {
                // A stop and continue can end the sleep early: sleep the rest.
                loop {
                    let wanted = left;
                    if libc::nanosleep(&wanted, &mut left) == 0 {
                        break;
                    }
                }
            }
            Ok(())
        });
    }
}

/// Hooks for the integration tests, which run exec in their own process.
#[doc(hidden)]
pub mod test_hooks {
    use std::sync::atomic::{AtomicU64, Ordering};

    static PRE_EXEC_PAUSE_MS: AtomicU64 = AtomicU64::new(0);

    /// Make the child sleep after it takes the terminal and before its exec,
    /// so a test can stop it in that window.
    pub fn set_pre_exec_pause(pause: std::time::Duration) {
        PRE_EXEC_PAUSE_MS.store(pause.as_millis() as u64, Ordering::SeqCst);
    }

    #[cfg(unix)]
    pub(super) fn pre_exec_pause() -> Option<libc::timespec> {
        let ms = PRE_EXEC_PAUSE_MS.load(Ordering::SeqCst);
        (ms > 0).then(|| libc::timespec {
            tv_sec: (ms / 1000) as libc::time_t,
            tv_nsec: ((ms % 1000) * 1_000_000) as libc::c_long,
        })
    }
}

#[cfg(not(unix))]
fn take_foreground(_command: &mut Command) {}

/// The terminal foreground on stdin, handed between claudectl and an
/// interactive child as a shell hands it to a job.
#[cfg(unix)]
mod foreground {
    /// Whether stdin is a terminal with a foreground group.
    pub fn is_terminal() -> bool {
        // SAFETY: tcgetpgrp only reads terminal state.
        unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) != -1 }
    }

    /// Whether claudectl's group owns the foreground. A stdin that is not a
    /// terminal (tcgetpgrp fails) is not interactive.
    pub fn owned() -> bool {
        // SAFETY: getpgrp only reads process state.
        owned_by(unsafe { libc::getpgrp() })
    }

    /// Whether the group `group` owns the foreground.
    pub fn owned_by(group: libc::pid_t) -> bool {
        // SAFETY: tcgetpgrp only reads terminal state.
        let foreground = unsafe { libc::tcgetpgrp(libc::STDIN_FILENO) };
        foreground != -1 && foreground == group
    }

    /// Whether the foreground belongs to a group with no live process, as
    /// after a child that took it failed its exec.
    pub fn owned_by_gone_group() -> bool {
        // SAFETY: tcgetpgrp and getpgrp only read state; kill with signal 0
        // only checks that the group exists.
        unsafe {
            let foreground = libc::tcgetpgrp(libc::STDIN_FILENO);
            foreground > 0
                && foreground != libc::getpgrp()
                && libc::kill(-foreground, 0) == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        }
    }

    /// Make `group` the foreground. SIGTTOU is blocked for the call, so a
    /// caller outside the foreground group is not stopped, and the previous
    /// signal mask is restored. Async-signal-safe.
    pub fn give(group: libc::pid_t) -> std::io::Result<()> {
        // SAFETY: changes only this thread's signal mask, and restores it.
        unsafe {
            let mut ttou: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut ttou);
            libc::sigaddset(&mut ttou, libc::SIGTTOU);
            let mut saved: libc::sigset_t = std::mem::zeroed();
            let blocked = libc::pthread_sigmask(libc::SIG_BLOCK, &ttou, &mut saved);
            if blocked != 0 {
                return Err(std::io::Error::from_raw_os_error(blocked));
            }
            let result = libc::tcsetpgrp(libc::STDIN_FILENO, group);
            let error = std::io::Error::last_os_error();
            libc::pthread_sigmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut());
            if result == -1 { Err(error) } else { Ok(()) }
        }
    }

    /// Take the foreground back for claudectl. After a hangup the terminal is
    /// gone; that changes nothing for the run's result or its cleanup.
    pub fn reclaim() {
        // SAFETY: getpgrp only reads process state.
        let Err(error) = give(unsafe { libc::getpgrp() }) else {
            return;
        };
        let hung_up = matches!(
            error.raw_os_error(),
            Some(libc::EIO | libc::ENOTTY | libc::ENXIO)
        );
        if !hung_up {
            eprintln!("claudectl exec: cannot take the terminal back: {error}");
        }
    }
}

#[cfg(not(unix))]
mod foreground {
    pub fn is_terminal() -> bool {
        false
    }
    pub fn owned() -> bool {
        false
    }
    pub fn owned_by(_group: i32) -> bool {
        false
    }
    pub fn owned_by_gone_group() -> bool {
        false
    }
    pub fn reclaim() {}
}

fn snapshot_executable(program: &Path, config_dir: &Path) -> Result<PathBuf, ExecError> {
    let dir = config_dir.join("bin");
    std::fs::create_dir(&dir)
        .map_err(|e| ExecError::Pin(format!("cannot create snapshot dir: {e}")))?;
    let name = program
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("program"));
    let snapshot = dir.join(name);
    std::fs::copy(program, &snapshot)
        .map_err(|e| ExecError::Pin(format!("cannot snapshot {}: {e}", program.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o500))
            .map_err(|e| ExecError::Pin(format!("cannot restrict snapshot: {e}")))?;
    }
    Ok(snapshot)
}

#[cfg(unix)]
fn set_arg0(command: &mut Command, program: &Path) {
    use std::os::unix::process::CommandExt;
    command.arg0(program);
}

#[cfg(not(unix))]
fn set_arg0(_command: &mut Command, _program: &Path) {}

#[cfg(unix)]
fn map_token_fd(command: &mut Command, reader: &std::io::PipeReader) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let source = reader.as_raw_fd();
    let held = signals::forwarded_set();
    // SAFETY: runs in the forked child before exec; dup2, fcntl and
    // sigprocmask are async-signal-safe and touch only this child's state.
    unsafe {
        command.pre_exec(move || {
            // The parent holds the forwarded signals during the spawn; the
            // child must not inherit that mask.
            if libc::sigprocmask(libc::SIG_UNBLOCK, &held, std::ptr::null_mut()) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if source == CHILD_TOKEN_FD {
                if libc::fcntl(source, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            } else if libc::dup2(source, CHILD_TOKEN_FD) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn map_token_fd(_command: &mut Command, _reader: &std::io::PipeReader) {}

/// Forward SIGTERM, SIGINT and SIGHUP to the child, so cancelling claudectl
/// cancels the run and cleanup still happens.
#[cfg(unix)]
#[doc(hidden)]
pub mod signals {
    use std::sync::atomic::{AtomicI32, Ordering};

    static CHILD: AtomicI32 = AtomicI32::new(0);
    /// 1 when SIGCHLD was ignored before install(), so reset() restores it.
    static SAVED_SIGCHLD: AtomicI32 = AtomicI32::new(0);
    /// Signals received while no child was registered, one bit per signal.
    static PENDING: AtomicI32 = AtomicI32::new(0);
    /// Forwarded signals that were ignored before install(), one bit per
    /// signal. They stay ignored for the run (as under nohup), and the child
    /// inherits that, so reset() restores them.
    static SAVED_IGNORED: AtomicI32 = AtomicI32::new(0);
    const SIGNALS: [libc::c_int; 3] = [libc::SIGTERM, libc::SIGINT, libc::SIGHUP];
    /// Handlers currently between reading CHILD and finishing their kill.
    static IN_FLIGHT: AtomicI32 = AtomicI32::new(0);

    fn bit(signal: libc::c_int) -> i32 {
        SIGNALS
            .iter()
            .position(|&s| s == signal)
            .map_or(0, |index| 1 << index)
    }

    /// Send `signal` to the child's group. A stopped process acts on a
    /// handled signal only after it is continued, so SIGCONT follows.
    /// Async-signal-safe.
    fn send(pid: i32, signal: libc::c_int) {
        // SAFETY: kill is async-signal-safe. The child leads its own process
        // group, so this reaches its descendants too.
        unsafe {
            libc::kill(-pid, signal);
            libc::kill(-pid, libc::SIGCONT);
        }
    }

    /// Forward every signal whose bit is set in `bits`.
    fn forward_bits(pid: i32, bits: i32) {
        for signal in SIGNALS {
            if bits & bit(signal) != 0 {
                send(pid, signal);
            }
        }
    }

    pub extern "C" fn forward(signal: libc::c_int) {
        IN_FLIGHT.fetch_add(1, Ordering::SeqCst);
        let pid = CHILD.load(Ordering::SeqCst);
        if pid > 0 {
            send(pid, signal);
        } else {
            let mine = bit(signal);
            PENDING.fetch_or(mine, Ordering::SeqCst);
            // `watch` may have registered the child after the load above. If
            // so, exactly one of this handler and `watch` clears this bit and
            // forwards the signal.
            let pid = CHILD.load(Ordering::SeqCst);
            if pid > 0 && PENDING.fetch_and(!mine, Ordering::SeqCst) & mine != 0 {
                forward_bits(pid, mine);
            }
        }
        IN_FLIGHT.fetch_sub(1, Ordering::SeqCst);
    }

    /// Install the handlers for the whole run, before any private state exists.
    pub fn install() {
        CHILD.store(0, Ordering::SeqCst);
        PENDING.store(0, Ordering::SeqCst);
        // An inherited "ignore SIGCHLD" makes the kernel reap the child on
        // exit, which breaks waiting without reaping and the PID
        // reservation. Use the default disposition for the run.
        // SAFETY: sigaction with a zeroed default action; the previous
        // action is saved for reset().
        unsafe {
            let mut default: libc::sigaction = std::mem::zeroed();
            default.sa_sigaction = libc::SIG_DFL;
            libc::sigemptyset(&mut default.sa_mask);
            let mut previous: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, &default, &mut previous);
            SAVED_SIGCHLD.store(
                if previous.sa_sigaction == libc::SIG_IGN {
                    1
                } else {
                    0
                },
                Ordering::SeqCst,
            );
        }
        let mut ignored = 0;
        for signal in SIGNALS {
            // SAFETY: reads the current action only.
            let current = unsafe {
                let mut current: libc::sigaction = std::mem::zeroed();
                libc::sigaction(signal, std::ptr::null(), &mut current);
                current.sa_sigaction
            };
            if current == libc::SIG_IGN {
                ignored |= bit(signal);
                continue;
            }
            // SAFETY: installs a handler that only uses async-signal-safe
            // calls. SA_RESTART keeps interrupted system calls in other
            // threads from failing with EINTR.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = forward as *const () as libc::sighandler_t;
                action.sa_flags = libc::SA_RESTART;
                libc::sigemptyset(&mut action.sa_mask);
                libc::sigaction(signal, &action, std::ptr::null_mut());
            }
        }
        SAVED_IGNORED.store(ignored, Ordering::SeqCst);
    }

    /// The set of signals claudectl forwards.
    pub fn forwarded_set() -> libc::sigset_t {
        // SAFETY: builds a signal set in local memory.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for signal in SIGNALS {
                libc::sigaddset(&mut set, signal);
            }
            set
        }
    }

    fn mask(how: libc::c_int) {
        let set = forwarded_set();
        // SAFETY: changes only this thread's signal mask.
        unsafe { libc::pthread_sigmask(how, &set, std::ptr::null_mut()) };
    }

    /// Hold the forwarded signals on this thread from the last cancellation
    /// check through the spawn. The spawned child starts with an empty signal
    /// mask: the pre-exec step unblocks these signals.
    pub fn block() {
        mask(libc::SIG_BLOCK);
    }

    pub fn unblock() {
        mask(libc::SIG_UNBLOCK);
    }

    /// A signal received before a child was registered, if any.
    pub fn pending() -> Option<libc::c_int> {
        let bits = PENDING.load(Ordering::SeqCst);
        SIGNALS.into_iter().find(|&signal| bits & bit(signal) != 0)
    }

    /// Register the child, then release held signals. Each held signal is
    /// delivered to the handler once and forwarded with its own number. A
    /// signal another thread recorded before the registration is taken here.
    pub fn watch(pid: u32) {
        let pid = i32::try_from(pid).unwrap_or(0);
        CHILD.store(pid, Ordering::SeqCst);
        unblock();
        let recorded = PENDING.swap(0, Ordering::SeqCst);
        if pid > 0 {
            forward_bits(pid, recorded);
        }
    }

    /// Stop forwarding, and wait until no handler can still signal the
    /// child's group. Call while the child is still unreaped.
    pub fn unwatch() {
        CHILD.store(0, Ordering::SeqCst);
        while IN_FLIGHT.load(Ordering::SeqCst) > 0 {
            std::hint::spin_loop();
        }
    }

    pub fn reset() {
        CHILD.store(0, Ordering::SeqCst);
        let ignored = SAVED_IGNORED.swap(0, Ordering::SeqCst);
        for signal in SIGNALS {
            let action = if ignored & bit(signal) != 0 {
                libc::SIG_IGN
            } else {
                libc::SIG_DFL
            };
            // SAFETY: restores the disposition claudectl started with.
            unsafe { libc::signal(signal, action) };
        }
        if SAVED_SIGCHLD.swap(0, Ordering::SeqCst) == 1 {
            // SAFETY: restores the inherited "ignore" disposition.
            unsafe { libc::signal(libc::SIGCHLD, libc::SIG_IGN) };
        }
    }
}

#[cfg(not(unix))]
#[doc(hidden)]
pub mod signals {
    pub fn install() {}
    pub fn block() {}
    pub fn unblock() {}
    pub fn pending() -> Option<i32> {
        None
    }
    pub fn watch(_pid: u32) {}
    pub fn unwatch() {}
    pub fn reset() {}
}

fn receipt_base(prepared: &Prepared, config_dir: &Path, req: &ExecRequest) -> serde_json::Value {
    serde_json::json!({
        "alias": prepared.alias,
        "account_uuid": prepared.account_uuid,
        "email": prepared.email,
        "executable": prepared.program,
        "executable_sha256": prepared.program_sha256,
        "claudectl": {
            "path": prepared.claudectl.path,
            "sha256": prepared.claudectl.sha256,
            "version": prepared.claudectl.version,
        },
        "token_expires_at": chrono::DateTime::from_timestamp_millis(prepared.token_expires_at_ms)
            .map(|t| t.to_rfc3339()),
        "min_valid_secs": req.min_valid.as_secs(),
        "config_dir": config_dir,
    })
}

fn with(base: &serde_json::Value, event: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut record = base.clone();
    let map = record.as_object_mut().expect("receipt base is an object");
    map.insert("event".into(), event.into());
    map.insert("at".into(), chrono::Utc::now().to_rfc3339().into());
    if let Some(extra) = extra.as_object() {
        for (key, value) in extra {
            map.insert(key.clone(), value.clone());
        }
    }
    record
}

struct Receipt {
    sink: Box<dyn Write>,
    sync: Option<std::fs::File>,
}

impl Receipt {
    fn open(path: Option<&Path>) -> Result<Self, ExecError> {
        let Some(path) = path else {
            return Ok(Self::from_writer(Box::new(std::io::stderr())));
        };
        let mut options = std::fs::File::options();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| ExecError::Receipt(format!("{}: {e}", path.display())))?;
        let sync = file
            .try_clone()
            .map_err(|e| ExecError::Receipt(format!("{}: {e}", path.display())))?;
        Ok(Self {
            sink: Box::new(file),
            sync: Some(sync),
        })
    }

    fn from_writer(sink: Box<dyn Write>) -> Self {
        Self { sink, sync: None }
    }

    fn write(&mut self, record: &serde_json::Value) -> Result<(), ExecError> {
        let line = format!("{record}\n");
        self.sink
            .write_all(line.as_bytes())
            .and_then(|()| self.sink.flush())
            .and_then(|()| self.sync.as_ref().map_or(Ok(()), |file| file.sync_data()))
            .map_err(|e| ExecError::Receipt(e.to_string()))
    }
}

/// A new private directory per run, removed when the run ends.
#[doc(hidden)]
/// The child's `CLAUDE_CONFIG_DIR`: a private temporary directory, or a kept
/// state directory that outlives the run.
enum ConfigDir {
    Temp(tempfile::TempDir),
    Kept(PathBuf),
}

impl ConfigDir {
    fn path(&self) -> &Path {
        match self {
            ConfigDir::Temp(dir) => dir.path(),
            ConfigDir::Kept(dir) => dir,
        }
    }

    /// Remove a temporary directory; a kept one stays.
    fn close(self) -> std::io::Result<()> {
        match self {
            ConfigDir::Temp(dir) => dir.close(),
            ConfigDir::Kept(_) => Ok(()),
        }
    }
}

/// A kept state directory, cleared of the executable snapshot; the seeded
/// `.claude.json` is rebuilt by `seed_claude_json`.
fn kept_config_dir(dir: &Path) -> Result<ConfigDir, ExecError> {
    let metadata = std::fs::symlink_metadata(dir)
        .map_err(|e| ExecError::Spawn(format!("cannot use {}: {e}", dir.display())))?;
    if !metadata.is_dir() {
        return Err(ExecError::Spawn(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    let bin = dir.join("bin");
    if bin.exists() {
        std::fs::remove_dir_all(&bin)
            .map_err(|e| ExecError::Spawn(format!("cannot clear {}: {e}", bin.display())))?;
    }
    Ok(ConfigDir::Kept(dir.to_path_buf()))
}

pub fn fresh_config_dir(paths: &Paths, alias: &str) -> Result<tempfile::TempDir, ExecError> {
    let root = paths.claudectl_dir().join("run").join(alias);
    std::fs::create_dir_all(&root)
        .map_err(|e| ExecError::Spawn(format!("cannot create {}: {e}", root.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [paths.claudectl_dir().join("run"), root.clone()] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| ExecError::Spawn(format!("cannot restrict {}: {e}", dir.display())))?;
        }
    }
    let dir = tempfile::Builder::new()
        .prefix("config-")
        .tempdir_in(&root)
        .map_err(|e| ExecError::Spawn(format!("cannot create config dir: {e}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(|e| ExecError::Spawn(format!("cannot restrict config dir: {e}")))?;
    }
    Ok(dir)
}

/// Keys of `~/.claude.json` that Claude Code checks before its theme and
/// login screens.
const ONBOARDING_KEYS: &[&str] = &["hasCompletedOnboarding", "lastOnboardingVersion"];

/// Per-project approvals for external CLAUDE.md imports, copied for the
/// current directory only and only when true.
const IMPORT_KEYS: &[&str] = &[
    "hasClaudeMdExternalIncludesApproved",
    "hasClaudeMdExternalIncludesWarningShown",
];

/// Start the child at its prompt: copy the user's onboarding state, the
/// folder trust that covers the current directory, and its import approvals
/// into the private
/// config dir. Accounts, tokens, approved keys, allowed tools and MCP servers
/// are never copied. Without a readable `~/.claude.json` nothing is seeded,
/// and Claude shows its first-run screens as before.
fn seed_claude_json(paths: &Paths, config_dir: &Path) -> Result<(), ExecError> {
    // A kept lane directory still holds the last run's file. Carry only the
    // start-up decisions made in the lane; everything else in it, account
    // state included, is dropped before the new seed is written.
    let old = config_dir.join(".claude.json");
    let carried = carried_decisions(&old);
    if old.exists() {
        std::fs::remove_file(&old)
            .map_err(|e| ExecError::Spawn(format!("cannot clear {}: {e}", old.display())))?;
    }
    let mut seed = serde_json::Map::new();
    let mut seeded_projects = serde_json::Map::new();
    if let Some(user) = read_claude_json(paths) {
        for key in ONBOARDING_KEYS {
            if let Some(value) = user.get(*key) {
                seed.insert((*key).to_string(), value.clone());
            }
        }
        let projects = user.get("projects");
        let project = |dir: &str| projects.and_then(|p| p.get(dir));
        let cwd = std::env::current_dir().ok();
        if let Some(cwd) = cwd.as_deref() {
            // Claude trusts a directory under any trusted ancestor, and it
            // writes `false` entries on its own for every directory it opens
            // (Claude Code 2.1.292, checked live). Copy the closest `true`,
            // under that directory's own key: the trust the user's Claude grants.
            let trusted = cwd.ancestors().filter_map(Path::to_str).find(|dir| {
                project(dir)
                    .and_then(|entry| entry.get("hasTrustDialogAccepted"))
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
            });
            if let Some(dir) = trusted {
                seeded_projects.insert(
                    dir.to_string(),
                    serde_json::json!({ "hasTrustDialogAccepted": true }),
                );
            }
            if let Some((dir, entry)) = cwd.to_str().and_then(|dir| Some((dir, project(dir)?))) {
                for key in IMPORT_KEYS {
                    if entry.get(*key).and_then(|v| v.as_bool()) == Some(true) {
                        let slot = seeded_projects
                            .entry(dir.to_string())
                            .or_insert_with(|| serde_json::json!({}));
                        slot[*key] = serde_json::Value::Bool(true);
                    }
                }
            }
        }
    }
    for (dir, decisions) in carried {
        let slot = seeded_projects
            .entry(dir)
            .or_insert_with(|| serde_json::json!({}));
        for (key, value) in decisions {
            slot[key] = value;
        }
    }
    if !seeded_projects.is_empty() {
        seed.insert(
            "projects".into(),
            serde_json::Value::Object(seeded_projects),
        );
    }
    if seed.is_empty() {
        return Ok(());
    }
    let path = config_dir.join(".claude.json");
    let mut options = std::fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| ExecError::Spawn(format!("cannot create {}: {e}", path.display())))?;
    file.write_all(serde_json::Value::Object(seed).to_string().as_bytes())
        .map_err(|e| ExecError::Spawn(format!("cannot write {}: {e}", path.display())))
}

/// Per-project start-up decisions a lane may carry from one run to the next:
/// folder trust and the external-import approvals.
fn is_decision_key(key: &str) -> bool {
    key == "hasTrustDialogAccepted" || IMPORT_KEYS.contains(&key)
}

/// The decision keys set to true in a previous seed file, by project.
fn carried_decisions(path: &Path) -> Vec<(String, serde_json::Map<String, serde_json::Value>)> {
    let Some(serde_json::Value::Object(old)) = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
    else {
        return Vec::new();
    };
    let Some(serde_json::Value::Object(projects)) = old.get("projects") else {
        return Vec::new();
    };
    projects
        .iter()
        .filter_map(|(dir, entry)| {
            let decisions: serde_json::Map<String, serde_json::Value> = entry
                .as_object()?
                .iter()
                .filter(|(key, value)| is_decision_key(key) && value.as_bool() == Some(true))
                .map(|(key, _)| (key.clone(), serde_json::Value::Bool(true)))
                .collect();
            (!decisions.is_empty()).then(|| (dir.clone(), decisions))
        })
        .collect()
}

/// `~/.claude.json` as an object, or None when it is missing. Claude rewrites
/// the file while it runs, so a parse error gets one retry, then a warning;
/// a malformed file is refused earlier, by the live identity check.
fn read_claude_json(paths: &Paths) -> Option<serde_json::Map<String, serde_json::Value>> {
    let path = paths.claude_json();
    for attempt in 0..2 {
        let text = std::fs::read_to_string(&path).ok()?;
        match serde_json::from_str(&text) {
            Ok(serde_json::Value::Object(user)) => return Some(user),
            _ if attempt == 0 => std::thread::sleep(Duration::from_millis(50)),
            _ => {}
        }
    }
    eprintln!(
        "claudectl exec: cannot parse {}; the child shows its first-run screens",
        path.display()
    );
    None
}

fn resolve_program(program: &OsString) -> Result<PathBuf, ExecError> {
    let as_path = Path::new(program);
    let candidate = if as_path.components().count() > 1 {
        Some(as_path.to_path_buf())
    } else {
        std::env::var_os("PATH").and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(as_path))
                .find(|p| is_executable(p))
        })
    };
    let candidate = candidate
        .ok_or_else(|| ExecError::Pin(format!("{} not found on PATH", as_path.display())))?;
    candidate
        .canonicalize()
        .map_err(|e| ExecError::Pin(format!("cannot resolve {}: {e}", candidate.display())))
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

pub fn sha256_file(path: &Path) -> Result<String, ExecError> {
    let bytes = std::fs::read(path)
        .map_err(|e| ExecError::Pin(format!("cannot read {}: {e}", path.display())))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}

pub(crate) fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    status
        .code()
        .unwrap_or_else(|| 128 + signal_of(status).unwrap_or(1))
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.signal()
}

#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<i32> {
    None
}

/// Retry briefly when another claudectl command holds the auth lock, so two
/// concurrent runs on different aliases do not fail each other.
fn lock_with_retry(store: &AuthStore) -> Result<std::fs::File, ExecError> {
    let mut last = None;
    for _ in 0..50 {
        match store.lock_auth_state() {
            Ok(lock) => return Ok(lock),
            Err(error) => last = Some(error),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(ExecError::Refused(format!(
        "auth state is busy: {:#}",
        last.expect("at least one attempt")
    )))
}

/// Parse `30m`, `900s`, `1h` or a bare number of seconds.
pub fn parse_duration(input: &str) -> Result<Duration, String> {
    let input = input.trim();
    let (number, unit) = match input.char_indices().find(|(_, c)| !c.is_ascii_digit()) {
        Some((i, _)) => input.split_at(i),
        None => (input, "s"),
    };
    let value: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration '{input}'"))?;
    let seconds = match unit {
        "s" => value,
        "m" => value
            .checked_mul(60)
            .ok_or_else(|| format!("duration '{input}' is too large"))?,
        "h" => value
            .checked_mul(3600)
            .ok_or_else(|| format!("duration '{input}' is too large"))?,
        _ => {
            return Err(format!(
                "invalid duration unit in '{input}' (use s, m or h)"
            ));
        }
    };
    Ok(Duration::from_secs(seconds))
}

#[cfg(all(test, unix))]
mod exit_tests {
    #[test]
    fn an_exited_child_is_told_apart_from_a_running_one_without_reaping_it() {
        let mut done = std::process::Command::new("true").spawn().unwrap();
        super::wait_exit_no_reap(done.id(), false).unwrap();
        // Exited but not reaped: kill would still succeed, has_exited says so.
        assert!(super::has_exited(done.id()));
        assert!(
            super::has_exited(done.id()),
            "the check must not reap the child"
        );
        done.wait().unwrap();
        let mut running = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        assert!(!super::has_exited(running.id()));
        running.kill().unwrap();
        running.wait().unwrap();
    }
}
