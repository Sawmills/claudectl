//! `exec` tests start child processes. They live in their own test binary, so a
//! fork here never copies another unit test's open auth-lock descriptor.

use std::path::Path;

use std::time::Duration;

use claudectl::api::{CredentialsFile, OauthCreds};
use claudectl::auth_store::AuthStore;
use claudectl::config::Paths;
use claudectl::exec::*;

const HOUR_MS: i64 = 3_600_000;

/// Signal handlers are process-wide, and on macOS a pipe is not close-on-exec
/// until just after it is created, so a fork in another test thread can leak
/// it. Tests that start processes run one at a time.
static RUN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn run_guard() -> std::sync::MutexGuard<'static, ()> {
    RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Settings that could route the saved token to another host or add headers.
const ENDPOINT_OVERRIDES: &[&str] = &[
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_API_HOST",
    "ANTHROPIC_ASSETS_HOST",
    "ANTHROPIC_CUSTOM_HEADERS",
    "ANTHROPIC_AWS_BASE_URL",
    "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_BEDROCK_MANTLE_BASE_URL",
    "ANTHROPIC_FOUNDRY_BASE_URL",
    "ANTHROPIC_GOOGLE_CLOUD_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL",
];

/// Settings that make Claude Code use another provider's credentials.
const PROVIDER_SELECTORS: &[&str] = &[
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_ANTHROPIC_AWS",
    "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD",
    "CLAUDE_CODE_USE_GATEWAY",
    "CLAUDE_CODE_USE_MANTLE",
];

struct FakeIdentity(Result<Option<String>, String>);

/// Access tokens the tests use for the live login. Like the real identity
/// service, the fake reports their owner as the live login's account (the
/// one `write_live` writes to ~/.claude.json), not the profile under test.
const LIVE_TOKENS: &[&str] = &["a-live", "a-rotated", "a-other"];

impl IdentitySource for FakeIdentity {
    fn account_uuid(&self, access_token: &str) -> anyhow::Result<Option<String>> {
        if LIVE_TOKENS.contains(&access_token) {
            return Ok(Some("uuid-live-login".into()));
        }
        self.0.clone().map_err(anyhow::Error::msg)
    }
}

/// Maps each access token to its owning account; unknown tokens have none.
struct MapIdentity(Vec<(&'static str, &'static str)>);

impl IdentitySource for MapIdentity {
    fn account_uuid(&self, access_token: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .0
            .iter()
            .find(|(token, _)| *token == access_token)
            .map(|(_, uuid)| (*uuid).to_string()))
    }
}

fn ok_identity(uuid: &str) -> FakeIdentity {
    FakeIdentity(Ok(Some(uuid.to_string())))
}

fn creds(access: &str, refresh: &str, expires_in_ms: i64) -> CredentialsFile {
    CredentialsFile {
        claude_ai_oauth: OauthCreds {
            access_token: access.into(),
            refresh_token: Some(refresh.into()),
            expires_at: Some(chrono::Utc::now().timestamp_millis() + expires_in_ms),
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: Default::default(),
        },
        extra: Default::default(),
    }
}

fn save(paths: &Paths, alias: &str, uuid: &str, c: &CredentialsFile) {
    claudectl::profile::save_profile_to(
        paths,
        alias,
        c,
        Some(serde_json::json!({ "accountUuid": uuid, "emailAddress": format!("{alias}@example.com") })),
    )
    .unwrap();
}

/// Write live credentials. A real live login also has an identity in
/// ~/.claude.json; write one for a separate account unless a test set its own.
fn write_live(paths: &Paths, c: &CredentialsFile) {
    let file = paths.claude_credentials_file();
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, serde_json::to_string(c).unwrap()).unwrap();
    if !paths.claude_json().exists() {
        std::fs::write(
            paths.claude_json(),
            r#"{"oauthAccount":{"accountUuid":"uuid-live-login"}}"#,
        )
        .unwrap();
    }
}

fn self_identity() -> SelfIdentity {
    SelfIdentity {
        path: "/claudectl-under-test".into(),
        sha256: "0".repeat(64),
        version: "test".into(),
    }
}

/// A child that records what it received into `out`, then exits with `code`.
fn fake_child(dir: &Path, out: &Path, code: i32) -> std::path::PathBuf {
    let script = dir.join("fake-claude");
    let body = format!(
        r#"#!/bin/sh
out='{out}'
eval "cat <&$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR" > "$out/token"
printf '%s' "$CLAUDE_CONFIG_DIR" > "$out/config_dir"
if [ -d "$CLAUDE_CONFIG_DIR" ]; then echo yes > "$out/config_exists"; fi
env | cut -d= -f1 | grep -E '^(CLAUDE_CODE_OAUTH_TOKEN|CLAUDE_CODE_OAUTH_REFRESH_TOKEN|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN|CLAUDE_CODE_USE_(BEDROCK|VERTEX|FOUNDRY|ANTHROPIC_AWS|ANTHROPIC_GOOGLE_CLOUD|GATEWAY|MANTLE)|ANTHROPIC_(BASE_URL|API_HOST|ASSETS_HOST|CUSTOM_HEADERS)|ANTHROPIC_(AWS|BEDROCK|BEDROCK_MANTLE|FOUNDRY|GOOGLE_CLOUD|VERTEX)_BASE_URL)$' > "$out/leaked_env" || true
if [ -n "${{FAKE_SELF_HUP:-}}" ]; then kill -HUP $$; echo survived > "$out/self_hup"; fi
printf '%s ' "$@" > "$out/args"
env | cut -d= -f1 > "$out/env_names"
printf '%s' "$CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR" > "$out/fd_name"
: > "$out/extra_fds"
# A leaked token descriptor is a pipe; the shell's own script fd is a file.
n=4; while [ $n -le 63 ]; do
  if [ -p "/dev/fd/$n" ]; then echo "$n" >> "$out/extra_fds"; fi
  n=$((n+1))
done
# Describe a leak for the failure message: this process and its parent.
if [ -s "$out/extra_fds" ]; then
  {{ lsof -p $$; ps -o pid,command -p $PPID; lsof -p $PPID; }} > "$out/fd_detail" 2>&1
fi
sleep "${{FAKE_SLEEP:-0}}"
exit {code}
"#,
        out = out.display()
    );
    std::fs::write(&script, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script
}

/// Pipes the child reported in `extra_fds`, less the ones this test process
/// itself inherited without close-on-exec (a CI runner can pass one on).
/// Every child of this process inherits those, so they are not a leak from
/// claudectl; the token pipe is close-on-exec here.
fn leaked_fds(out: &Path) -> Vec<String> {
    std::fs::read_to_string(out.join("extra_fds"))
        .unwrap()
        .lines()
        .filter(|line| {
            let Ok(fd) = line.parse::<i32>() else {
                return true;
            };
            // SAFETY: F_GETFD only reads this process's descriptor flags.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            flags == -1 || flags & libc::FD_CLOEXEC != 0
        })
        .map(str::to_owned)
        .collect()
}

fn request(alias: &str, program: &Path) -> ExecRequest {
    ExecRequest {
        alias: alias.into(),
        expect_account: None,
        expect_sha256: None,
        min_valid: Duration::from_secs(1800),
        receipt: None,
        program: program.as_os_str().to_owned(),
        args: vec!["-p".into(), "hello".into()],
    }
}

fn setup() -> (tempfile::TempDir, Paths, AuthStore) {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().to_path_buf());
    paths.ensure_dirs().unwrap();
    let store = AuthStore::file_only(paths.clone());
    (home, paths, store)
}

fn refused(result: Result<Prepared, ExecError>) -> ExecError {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error,
    }
}

#[test]
fn refuses_the_active_alias_without_contacting_identity() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    claudectl::profile::set_active_from(&paths, "work").unwrap();
    let child = fake_child(home.path(), home.path(), 0);
    let identity = FakeIdentity(Err("must not be called".into()));
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &identity,
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(error.to_string().contains("active profile"));
}

#[test]
fn refuses_a_grant_shared_with_the_live_login() {
    let (home, paths, store) = setup();
    let shared = creds("a-other", "r-shared", 2 * HOUR_MS);
    save(
        &paths,
        "copy",
        "uuid-live",
        &creds("a-copy", "r-shared", 2 * HOUR_MS),
    );
    write_live(&paths, &shared);
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("copy", &child),
        &ok_identity("uuid-live"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(error.to_string().contains("shares its grant"));
}

#[test]
fn refuses_when_live_refresh_ownership_is_unknown() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    let mut live = creds("a-live", "", 2 * HOUR_MS);
    live.claude_ai_oauth.refresh_token = None;
    write_live(&paths, &live);
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    assert!(error.to_string().contains("ownership unknown"), "{error}");
}

#[test]
fn refuses_a_token_that_expires_before_min_valid() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 10 * 60_000),
    );
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(error.to_string().contains("30 min required"));
    assert!(
        error.to_string().contains("claudectl status work"),
        "{error}"
    );
    assert!(
        error.to_string().contains("claudectl use <previous>"),
        "login activates the profile, so the message says how to switch back: {error}"
    );
}

#[test]
fn identity_failures_fail_closed() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    let child = fake_child(home.path(), home.path(), 0);
    for identity in [
        FakeIdentity(Ok(Some("uuid-someone-else".into()))),
        FakeIdentity(Ok(None)),
        FakeIdentity(Err("HTTP 500".into())),
    ] {
        let error = refused(prepare(
            &paths,
            &store,
            &request("work", &child),
            &identity,
            self_identity(),
        ));
        assert!(matches!(error, ExecError::Identity(_)), "{error}");
        assert_eq!(error.exit_code(), 3);
    }
    let mut req = request("work", &child);
    req.expect_account = Some("uuid-pinned".into());
    let error = refused(prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Identity(_)), "{error}");
}

#[test]
fn a_profile_without_saved_identity_fails_closed() {
    let (home, paths, store) = setup();
    claudectl::profile::save_profile_to(&paths, "anon", &creds("a", "r", 2 * HOUR_MS), None)
        .unwrap();
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("anon", &child),
        &ok_identity("x"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Identity(_)), "{error}");
}

#[test]
fn executable_pin_mismatch_fails_closed() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    let child = fake_child(home.path(), home.path(), 0);
    let mut req = request("work", &child);
    req.expect_sha256 = Some("f".repeat(64));
    let error = refused(prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Pin(_)), "{error}");
    assert_eq!(error.exit_code(), 4);
}

fn snapshot(paths: &Paths) -> Vec<Option<Vec<u8>>> {
    [
        paths.claude_credentials_file(),
        paths.claude_json(),
        paths.active_file(),
    ]
    .iter()
    .map(|p| std::fs::read(p).ok())
    .collect()
}

#[test]
fn runs_the_child_on_the_saved_profile_and_leaves_global_state_alone() {
    let _guard = run_guard();
    let (home, paths, store) = setup();
    let token = "a-work-secret";
    save(
        &paths,
        "work",
        "uuid-work",
        &creds(token, "r-work", 2 * HOUR_MS),
    );
    save(
        &paths,
        "live",
        "uuid-live",
        &creds("a-live", "r-live", 2 * HOUR_MS),
    );
    write_live(&paths, &creds("a-live", "r-live", 2 * HOUR_MS));
    std::fs::write(
        paths.claude_json(),
        r#"{"oauthAccount":{"accountUuid":"uuid-live"}}"#,
    )
    .unwrap();
    claudectl::profile::set_active_from(&paths, "live").unwrap();
    let before = snapshot(&paths);

    let out = home.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let child = fake_child(home.path(), &out, 7);
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let code = run(&paths, &store, prepared, &req).unwrap();

    assert_eq!(code, 7, "child exit code passes through");
    let received = std::fs::read(out.join("token")).unwrap();
    assert!(
        received == token.as_bytes(),
        "child did not receive the saved token"
    );
    // Names only: a failure must never print a credential value.
    let leaked = std::fs::read_to_string(out.join("leaked_env")).unwrap();
    assert!(
        leaked.is_empty(),
        "child inherited {:?}",
        leaked.lines().collect::<Vec<_>>()
    );
    assert_eq!(
        std::fs::read_to_string(out.join("args")).unwrap(),
        "-p hello "
    );
    assert!(out.join("config_exists").exists());
    assert_eq!(std::fs::read_to_string(out.join("fd_name")).unwrap(), "3");
    assert_eq!(
        leaked_fds(&out),
        Vec::<String>::new(),
        "the child must inherit no descriptor besides the token fd\n{}",
        std::fs::read_to_string(out.join("fd_detail")).unwrap_or_default()
    );
    let config_dir =
        std::path::PathBuf::from(std::fs::read_to_string(out.join("config_dir")).unwrap());
    assert!(config_dir.starts_with(paths.claudectl_dir().join("run").join("work")));
    assert!(
        !config_dir.exists(),
        "per-run config dir is removed after the run"
    );
    assert!(before == snapshot(&paths), "global login state changed");

    let receipt = std::fs::read_to_string(home.path().join("receipt.jsonl")).unwrap();
    assert!(!receipt.contains(token), "receipt must not hold the token");
    let events: Vec<serde_json::Value> = receipt
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    let kinds: Vec<&str> = events
        .iter()
        .map(|e| e["event"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["prepared", "started", "exited"]);
    let executed = events[0]["executed_snapshot"].as_str().unwrap();
    assert!(
        std::path::Path::new(executed).starts_with(&config_dir),
        "the child runs from the private snapshot"
    );
    assert!(events[0].get("pid").is_none(), "no pid before the spawn");
    assert!(events[1]["pid"].as_u64().is_some());
    assert_eq!(events[2]["exit_code"], 7);
    assert_eq!(events[0]["account_uuid"], "uuid-work");
    assert_eq!(
        events[0]["executable_sha256"].as_str().unwrap(),
        sha256_file(&child.canonicalize().unwrap()).unwrap()
    );
}

#[test]
fn private_config_dir_is_mode_0700() {
    let (_home, paths, _store) = setup();
    let dir = fresh_config_dir(&paths, "work").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }
    let other = fresh_config_dir(&paths, "work").unwrap();
    assert_ne!(dir.path(), other.path(), "each run gets its own dir");
}

#[test]
fn receipt_failure_before_spawn_starts_no_child() {
    let _guard = run_guard();
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    let out = home.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let child = fake_child(home.path(), &out, 0);
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("missing-dir").join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    assert!(matches!(error, ExecError::Receipt(_)), "{error}");
    assert!(
        !out.join("token").exists(),
        "no child may start without a receipt"
    );
}

/// Runs one alias in this process when the parent test asks for it through
/// the environment; otherwise it does nothing.
#[test]
fn helper_run_one_alias() {
    let (Ok(home), Ok(alias), Ok(out)) = (
        std::env::var("CLAUDECTL_TEST_HOME"),
        std::env::var("CLAUDECTL_TEST_ALIAS"),
        std::env::var("CLAUDECTL_TEST_OUT"),
    ) else {
        return;
    };
    let paths = Paths::from_home(home.into());
    let store = AuthStore::file_only(paths.clone());
    let out = std::path::PathBuf::from(out);
    std::fs::write(out.join("helper_pid"), std::process::id().to_string()).unwrap();
    #[cfg(unix)]
    {
        // Record the inherited SIGCHLD disposition, so a test can prove its setup.
        // SAFETY: reads the current action only.
        let ignored = unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut current);
            current.sa_sigaction == libc::SIG_IGN
        };
        std::fs::write(
            out.join("sigchld_at_start"),
            if ignored { "ignored" } else { "default" },
        )
        .unwrap();
    }
    let child = out.join("fake-claude");
    let mut req = request(&alias, &child);
    req.receipt = Some(out.join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity(&format!("uuid-{alias}")),
        self_identity(),
    )
    .unwrap();
    run(&paths, &store, prepared, &req).unwrap();
    #[cfg(unix)]
    {
        // Record the SIGHUP disposition the run leaves behind.
        // SAFETY: reads the current action only.
        let ignored = unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGHUP, std::ptr::null(), &mut current);
            current.sa_sigaction == libc::SIG_IGN
        };
        std::fs::write(
            out.join("sighup_after"),
            if ignored { "ignored" } else { "default" },
        )
        .unwrap();
        // Record whether this process owns the terminal foreground again.
        // SAFETY: tcgetpgrp and getpgrp only read process state.
        let owned = unsafe {
            let foreground = libc::tcgetpgrp(libc::STDIN_FILENO);
            foreground != -1 && foreground == libc::getpgrp()
        };
        std::fs::write(
            out.join("foreground_after"),
            if owned { "owned" } else { "not_owned" },
        )
        .unwrap();
    }
}

/// Start `helper_run_one_alias` for `alias` with extra environment, and wait.
fn run_helper(
    home: &Path,
    alias: &str,
    out: &Path,
    env: &[(&str, &str)],
    ignore_sighup: bool,
) -> std::process::ExitStatus {
    run_helper_in(home, alias, out, env, ignore_sighup, None)
}

/// `run_helper` with the helper started in `cwd` when given.
fn run_helper_in(
    home: &Path,
    alias: &str,
    out: &Path,
    env: &[(&str, &str)],
    ignore_sighup: bool,
    cwd: Option<&Path>,
) -> std::process::ExitStatus {
    let mut helper = std::process::Command::new(std::env::current_exe().unwrap());
    if let Some(cwd) = cwd {
        helper.current_dir(cwd);
    }
    helper
        .args(["--exact", "helper_run_one_alias", "--test-threads=1"])
        .env("CLAUDECTL_TEST_HOME", home)
        .env("CLAUDECTL_TEST_ALIAS", alias)
        .env("CLAUDECTL_TEST_OUT", out)
        .envs(env.iter().copied())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if ignore_sighup {
        // SAFETY: runs in the forked helper before exec; signal() is
        // async-signal-safe. This is what nohup does.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut helper, || {
                libc::signal(libc::SIGHUP, libc::SIG_IGN);
                Ok(())
            });
        }
    }
    helper.status().unwrap()
}

#[test]
fn child_env_drops_credentials_provider_selectors_and_endpoint_overrides() {
    let _guard = run_guard();
    let (home, paths, _store) = setup();
    save(
        &paths,
        "one",
        "uuid-one",
        &creds("a-one", "r-one", 2 * HOUR_MS),
    );
    let out = home.path().join("out-env");
    std::fs::create_dir(&out).unwrap();
    fake_child(&out, &out, 0);
    let mut env: Vec<(&str, &str)> = vec![
        ("ANTHROPIC_API_KEY", "parent-key"),
        ("ANTHROPIC_AUTH_TOKEN", "parent-token"),
    ];
    env.extend(PROVIDER_SELECTORS.iter().map(|name| (*name, "1")));
    env.extend(
        ENDPOINT_OVERRIDES
            .iter()
            .map(|name| (*name, "https://example.invalid")),
    );
    // Found in the Claude Code 2.1.286 binary; not in the fixed lists above.
    env.extend([
        ("CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR", "5"),
        ("CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR", "6"),
        ("CLAUDE_CODE_WEBSOCKET_AUTH_FILE_DESCRIPTOR", "7"),
        ("ANTHROPIC_AWS_API_KEY", "parent-aws"),
        ("ANTHROPIC_FOUNDRY_API_KEY", "parent-foundry"),
        ("ANTHROPIC_FOUNDRY_AUTH_TOKEN", "parent-foundry-token"),
        ("CLAUDE_CODE_API_BASE_URL", "https://example.invalid"),
        ("CLAUDE_CODE_PROXY_HOST", "example.invalid"),
        ("CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER", "1"),
        ("CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST", "1"),
    ]);
    let status = run_helper(home.path(), "one", &out, &env, false);
    assert!(status.success());
    // Names only: a failure must never print a credential value.
    let leaked = std::fs::read_to_string(out.join("leaked_env")).unwrap();
    assert!(
        leaked.is_empty(),
        "child inherited {:?}",
        leaked.lines().collect::<Vec<_>>()
    );
    let names = std::fs::read_to_string(out.join("env_names")).unwrap();
    let leaked: Vec<&str> = names
        .lines()
        .filter(|name| is_scrubbed_env(name) && *name != TOKEN_FD_ENV)
        .collect();
    assert!(leaked.is_empty(), "child inherited {leaked:?}");
    for (name, _) in &env {
        assert!(!names.lines().any(|n| n == *name), "child inherited {name}");
    }
    assert!(
        std::fs::read(out.join("token")).unwrap() == b"a-one",
        "test setup: the child ran with the saved token"
    );
}

#[test]
fn scrubbed_env_names_cover_credentials_providers_and_endpoints() {
    for name in ENDPOINT_OVERRIDES.iter().chain(PROVIDER_SELECTORS) {
        assert!(is_scrubbed_env(name), "{name}");
    }
    for name in [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
        "CLAUDE_CODE_OAUTH_TOKEN_FILE_DESCRIPTOR",
        "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
        "CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR",
        "ANTHROPIC_AWS_API_KEY",
        "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
        "CLAUDE_CODE_API_BASE_URL",
        "CLAUDE_CODE_GATEWAY_HINT_HEADERS",
        "CLAUDE_CODE_ENABLE_PROXY_AUTH_HELPER",
        "CLAUDE_CODE_OAUTH_SCOPES",
        "CCR_OAUTH_TOKEN_FILE",
    ] {
        assert!(is_scrubbed_env(name), "{name}");
    }
    for name in [
        "PATH",
        "HOME",
        "CLAUDE_CONFIG_DIR",
        "ANTHROPIC_MODEL",
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
        "CLAUDE_CODE_ENTRYPOINT",
        "MY_API_KEY",
    ] {
        assert!(!is_scrubbed_env(name), "{name}");
    }
}

fn write_settings(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(name), body).unwrap();
}

#[test]
fn settings_that_change_the_login_or_endpoint_are_refused() {
    let refused = |cwd: &Path, managed: &Path| match check_settings(
        cwd,
        Path::new("/nonexistent-home"),
        managed,
    ) {
        Err(error @ ExecError::Refused(_)) => error.to_string(),
        other => panic!("expected a refusal, got {other:?}"),
    };
    let root = tempfile::tempdir().unwrap();
    let managed = root.path().join("managed");
    let project = root.path().join("repo/sub");
    std::fs::create_dir_all(&project).unwrap();
    // No settings, or settings that change nothing about the login, pass.
    check_settings(&project, Path::new("/nonexistent-home"), &managed).unwrap();
    write_settings(
        &project.join(".claude"),
        "settings.json",
        r#"{"env":{"ANTHROPIC_MODEL":"m"},"model":"x"}"#,
    );
    check_settings(&project, Path::new("/nonexistent-home"), &managed).unwrap();

    write_settings(
        &project.join(".claude"),
        "settings.json",
        r#"{"env":{"ANTHROPIC_API_KEY":"secret-value"}}"#,
    );
    let message = refused(&project, &managed);
    assert!(message.contains("ANTHROPIC_API_KEY"), "{message}");
    assert!(!message.contains("secret-value"), "{message}");
    std::fs::remove_file(project.join(".claude/settings.json")).unwrap();

    write_settings(
        &project.join(".claude"),
        "settings.local.json",
        r#"{"apiKeyHelper":"/bin/echo"}"#,
    );
    assert!(refused(&project, &managed).contains("apiKeyHelper"));
    std::fs::remove_file(project.join(".claude/settings.local.json")).unwrap();

    // A parent directory's settings count too.
    write_settings(
        &root.path().join("repo/.claude"),
        "settings.json",
        r#"{"env":{"CLAUDE_CODE_USE_BEDROCK":"1"}}"#,
    );
    assert!(refused(&project, &managed).contains("CLAUDE_CODE_USE_BEDROCK"));

    // A settings value applies inside the child, after exec sets its own.
    write_settings(
        &root.path().join("repo/.claude"),
        "settings.json",
        r#"{"env":{"CLAUDE_CONFIG_DIR":"/elsewhere"}}"#,
    );
    assert!(refused(&project, &managed).contains("CLAUDE_CONFIG_DIR"));
    std::fs::remove_file(root.path().join("repo/.claude/settings.json")).unwrap();

    write_settings(
        &managed,
        "managed-settings.json",
        r#"{"env":{"ANTHROPIC_BASE_URL":"https://example.invalid"}}"#,
    );
    assert!(refused(&project, &managed).contains("ANTHROPIC_BASE_URL"));
    std::fs::remove_file(managed.join("managed-settings.json")).unwrap();

    write_settings(
        &managed.join("managed-settings.d"),
        "10-auth.json",
        r#"{"awsAuthRefresh":"aws sso login"}"#,
    );
    assert!(refused(&project, &managed).contains("awsAuthRefresh"));
    std::fs::remove_file(managed.join("managed-settings.d/10-auth.json")).unwrap();

    // A file that cannot be parsed fails closed and quotes nothing.
    write_settings(
        &project.join(".claude"),
        "settings.json",
        r#"{"env":{"ANTHROPIC_API_KEY":"secret-value""#,
    );
    let message = refused(&project, &managed);
    assert!(message.contains("cannot parse"), "{message}");
    assert!(!message.contains("secret-value"), "{message}");
}

#[test]
fn user_settings_in_home_are_skipped_below_home_but_checked_at_home() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let home = root.join("home");
    let managed = root.join("managed");
    let project = home.join("code/repo");
    std::fs::create_dir_all(&project).unwrap();
    write_settings(
        &home.join(".claude"),
        "settings.json",
        r#"{"apiKeyHelper":"/bin/echo"}"#,
    );
    // Below home, ~/.claude/settings.json is user scope, which the private
    // config dir replaces.
    check_settings(&project, &home, &managed).unwrap();
    // At home, Claude Code reads it as the project's settings.
    assert!(matches!(
        check_settings(&home, &home, &managed),
        Err(ExecError::Refused(_))
    ));
    // A parent above home still counts.
    write_settings(
        &root.join(".claude"),
        "settings.json",
        r#"{"apiKeyHelper":"/bin/echo"}"#,
    );
    assert!(matches!(
        check_settings(&project, &home, &managed),
        Err(ExecError::Refused(_))
    ));
}

#[test]
fn exec_refuses_to_start_in_a_project_whose_settings_set_a_credential() {
    let _guard = run_guard();
    let (home, paths, _store) = setup();
    save(
        &paths,
        "one",
        "uuid-one",
        &creds("a-one", "r-one", 2 * HOUR_MS),
    );
    let out = home.path().join("out-settings");
    std::fs::create_dir(&out).unwrap();
    fake_child(&out, &out, 0);
    let project = home.path().join("project");
    write_settings(
        &project.join(".claude"),
        "settings.json",
        r#"{"env":{"ANTHROPIC_API_KEY":"project-key"}}"#,
    );
    let status = run_helper_in(home.path(), "one", &out, &[], false, Some(&project));
    assert!(!status.success(), "the run must be refused");
    assert!(!out.join("token").exists(), "no child may start");
}

#[test]
fn inherited_ignored_sighup_stays_ignored_for_child_and_after_run() {
    let _guard = run_guard();
    let (home, paths, _store) = setup();
    save(
        &paths,
        "one",
        "uuid-one",
        &creds("a-one", "r-one", 2 * HOUR_MS),
    );
    let out = home.path().join("out-hup");
    std::fs::create_dir(&out).unwrap();
    fake_child(&out, &out, 0);
    let status = run_helper(home.path(), "one", &out, &[("FAKE_SELF_HUP", "1")], true);
    assert!(status.success());
    assert!(
        out.join("self_hup").exists(),
        "the child must inherit SIGHUP as ignored, as under nohup"
    );
    assert_eq!(
        std::fs::read_to_string(out.join("sighup_after")).unwrap(),
        "ignored",
        "the run must restore the inherited ignored SIGHUP"
    );
}

#[test]
fn concurrent_runs_in_two_processes_stay_isolated() {
    let _guard = run_guard();
    let (home, paths, _store) = setup();
    for alias in ["one", "two"] {
        save(
            &paths,
            alias,
            &format!("uuid-{alias}"),
            &creds(&format!("a-{alias}"), &format!("r-{alias}"), 2 * HOUR_MS),
        );
    }
    let mut children = Vec::new();
    for alias in ["one", "two"] {
        let out = home.path().join(format!("out-{alias}"));
        std::fs::create_dir(&out).unwrap();
        let child = fake_child(&out, &out, 0);
        let script = std::fs::read_to_string(&child).unwrap();
        std::fs::write(&child, script.replace("${FAKE_SLEEP:-0}", "0.5")).unwrap();
        children.push((
            alias,
            out.clone(),
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "helper_run_one_alias", "--test-threads=1"])
                .env("CLAUDECTL_TEST_HOME", home.path())
                .env("CLAUDECTL_TEST_ALIAS", alias)
                .env("CLAUDECTL_TEST_OUT", &out)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        ));
    }
    let mut dirs = Vec::new();
    for (alias, out, mut process) in children {
        assert!(process.wait().unwrap().success(), "{alias} run failed");
        let token = std::fs::read(out.join("token")).unwrap();
        assert!(
            token == format!("a-{alias}").into_bytes(),
            "{alias} received another alias's token"
        );
        assert_eq!(
            leaked_fds(&out),
            Vec::<String>::new(),
            "{alias} inherited another descriptor\n{}",
            std::fs::read_to_string(out.join("fd_detail")).unwrap_or_default()
        );
        dirs.push(std::fs::read_to_string(out.join("config_dir")).unwrap());
    }
    assert_ne!(dirs[0], dirs[1], "runs share a config dir");
}

#[cfg(unix)]
#[test]
fn an_overlapping_run_in_the_same_process_is_refused() {
    let _guard = run_guard();
    let (home, paths, store) = setup();
    for alias in ["one", "two"] {
        save(
            &paths,
            alias,
            &format!("uuid-{alias}"),
            &creds(&format!("a-{alias}"), &format!("r-{alias}"), 2 * HOUR_MS),
        );
    }
    let out = home.path().join("out-one");
    std::fs::create_dir(&out).unwrap();
    let first_child = fake_child(&out, &out, 0);
    let script = std::fs::read_to_string(&first_child).unwrap();
    std::fs::write(&first_child, script.replace("${FAKE_SLEEP:-0}", "30")).unwrap();
    let first_req = request("one", &first_child);
    let first = prepare(
        &paths,
        &store,
        &first_req,
        &ok_identity("uuid-one"),
        self_identity(),
    )
    .unwrap();
    let runner = {
        let paths = paths.clone();
        std::thread::spawn(move || {
            let store = AuthStore::file_only(paths.clone());
            run(&paths, &store, first, &first_req)
        })
    };
    let started = std::time::Instant::now();
    while std::fs::read_to_string(out.join("args")).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "first run did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let second_out = home.path().join("out-two");
    std::fs::create_dir(&second_out).unwrap();
    let second_child = fake_child(&second_out, &second_out, 0);
    let second_req = request("two", &second_child);
    let second = prepare(
        &paths,
        &store,
        &second_req,
        &ok_identity("uuid-two"),
        self_identity(),
    )
    .unwrap();
    let error = run(&paths, &store, second, &second_req).unwrap_err();
    assert!(
        error.to_string().contains("another exec run is active"),
        "{error}"
    );
    assert!(
        !second_out.join("token").exists(),
        "the overlapping run started no child"
    );
    {
        use std::os::unix::thread::JoinHandleExt;
        // SAFETY: the first runner is alive with its handler installed.
        unsafe { libc::pthread_kill(runner.as_pthread_t() as libc::pthread_t, libc::SIGTERM) };
    }
    let code = runner.join().unwrap().unwrap();
    assert_eq!(
        code,
        128 + libc::SIGTERM,
        "the first run still owns its signals"
    );
}

#[test]
fn a_group_listing_without_the_leader_is_an_error() {
    assert!(
        group_members_from_listing(&[], 42).is_err(),
        "an empty listing is a failed lookup"
    );
    assert!(group_members_from_listing(&[7, 9], 42).is_err());
    assert_eq!(
        group_members_from_listing(&[42], 42).unwrap(),
        Vec::<i32>::new()
    );
    assert_eq!(group_members_from_listing(&[42, 7], 42).unwrap(), vec![7]);
}

#[test]
fn parses_durations() {
    assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
    assert_eq!(parse_duration("900s").unwrap(), Duration::from_secs(900));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
    assert!(parse_duration("5d").is_err());
    assert!(parse_duration("abc").is_err());
    assert!(parse_duration("4611686018427387904m").is_err());
    assert!(parse_duration("5124095576030432h").is_err());
}

/// Accepts `ok_writes` records, then fails every write.
struct FailingSink {
    ok_writes: usize,
    written: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl std::io::Write for FailingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Keep every attempted record, failed ones too, so the test can see
        // whether a spawn was attempted.
        self.written.lock().unwrap().extend_from_slice(buf);
        if buf.ends_with(b"\n") {
            if self.ok_writes == 0 {
                return Err(std::io::Error::other("disk full"));
            }
            self.ok_writes -= 1;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn receipt_write_failure_fails_closed_before_and_after_spawn() {
    let _guard = run_guard();
    for (ok_writes, child_may_start) in [(0, false), (1, true)] {
        let (home, paths, store) = setup();
        save(
            &paths,
            "work",
            "uuid-work",
            &creds("a-work", "r-work", 2 * HOUR_MS),
        );
        let out = home.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let child = fake_child(home.path(), &out, 0);
        let req = request("work", &child);
        let prepared = prepare(
            &paths,
            &store,
            &req,
            &ok_identity("uuid-work"),
            self_identity(),
        )
        .unwrap();
        let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let receipt: Box<dyn std::io::Write> = Box::new(FailingSink {
            ok_writes,
            written: written.clone(),
        });
        let error = run_with_writer(&paths, &store, prepared, &req, receipt).unwrap_err();
        assert!(matches!(error, ExecError::Receipt(_)), "{error}");
        let attempted = String::from_utf8(written.lock().unwrap().clone()).unwrap();
        let spawned = attempted.contains("\"started\"");
        assert_eq!(
            spawned, child_may_start,
            "a failed prepared record must stop the spawn"
        );
        if child_may_start {
            // A failed started record kills the child, and the run still
            // attempts a truthful terminal record for the PID it started.
            let exited = attempted
                .lines()
                .find(|line| line.contains("\"exited\""))
                .expect("a terminal record is attempted for a started child");
            let exited: serde_json::Value = serde_json::from_str(exited).unwrap();
            assert_eq!(exited["signal"], 9, "the child is killed");
            assert!(exited["pid"].as_u64().is_some());
        }
    }
}

fn work_setup() -> (
    tempfile::TempDir,
    Paths,
    AuthStore,
    std::path::PathBuf,
    std::path::PathBuf,
) {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    let out = home.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let child = fake_child(home.path(), &out, 0);
    (home, paths, store, out, child)
}

#[test]
fn an_executable_replaced_after_verification_is_refused() {
    let _guard = run_guard();
    let (_home, paths, store, out, child) = work_setup();
    let req = request("work", &child);
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let script = std::fs::read_to_string(&child).unwrap();
    std::fs::write(&child, format!("{script}\n# replaced\n")).unwrap();
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    assert!(matches!(error, ExecError::Pin(_)), "{error}");
    assert!(
        !out.join("token").exists(),
        "no child may run replaced bytes"
    );
}

#[test]
fn ownership_is_rechecked_right_before_the_spawn() {
    let _guard = run_guard();
    let (home, paths, store, out, child) = work_setup();
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    claudectl::profile::set_active_from(&paths, "work").unwrap();
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(
        !out.join("token").exists(),
        "no child for a profile that became active"
    );
    let receipt = std::fs::read_to_string(home.path().join("receipt.jsonl")).unwrap();
    assert!(receipt.contains("\"refused\""), "the refusal is recorded");
    assert!(!receipt.contains("\"started\""));
}

#[cfg(unix)]
#[test]
fn a_terminate_signal_stops_the_child_and_cleans_up() {
    let _guard = run_guard();
    let (_home, paths, store, out, child) = work_setup();
    let script = std::fs::read_to_string(&child).unwrap();
    std::fs::write(&child, script.replace("${FAKE_SLEEP:-0}", "30")).unwrap();
    let req = request("work", &child);
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let runner = {
        let paths = paths.clone();
        std::thread::spawn(move || {
            let store = AuthStore::file_only(paths.clone());
            run(&paths, &store, prepared, &req)
        })
    };
    let started = std::time::Instant::now();
    while !out.join("extra_fds").exists() || std::fs::read_to_string(out.join("args")).is_err() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "child did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(100));
    // Deliver SIGTERM to the runner thread only, so other test threads are
    // not interrupted. The CLI is single-threaded; there SIGTERM hits run().
    {
        use std::os::unix::thread::JoinHandleExt;
        // SAFETY: the runner thread is alive and has the handler installed.
        unsafe { libc::pthread_kill(runner.as_pthread_t() as libc::pthread_t, libc::SIGTERM) };
    }
    let code = runner.join().unwrap().unwrap();
    assert_eq!(code, 128 + libc::SIGTERM, "the child was terminated");
    assert!(started.elapsed() < Duration::from_secs(20));
    let config_dir = std::fs::read_to_string(out.join("config_dir")).unwrap();
    assert!(!std::path::Path::new(&config_dir).exists(), "cleanup ran");
}

/// A child script with a custom body, written to `dir/name`.
fn script_child(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let script = dir.join(name);
    std::fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    script
}

#[test]
fn a_saved_identity_change_after_prepare_is_refused() {
    let _guard = run_guard();
    let (home, paths, store, out, child) = work_setup();
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let account = paths.profiles_dir().join("work").join("account.json");
    let meta = std::fs::read_to_string(&account).unwrap();
    std::fs::write(&account, meta.replace("uuid-work", "uuid-intruder")).unwrap();
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    assert!(matches!(error, ExecError::Identity(_)), "{error}");
    assert!(
        !out.join("token").exists(),
        "no child after an identity change"
    );
}

#[cfg(unix)]
#[test]
fn a_cancel_while_waiting_for_the_final_lock_starts_no_child() {
    let _guard = run_guard();
    let (home, paths, store, out, child) = work_setup();
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    // Retry like claudectl does: a fork in another test thread can hold a
    // copy of the lock descriptor for a moment.
    let held = {
        let started = std::time::Instant::now();
        loop {
            match store.lock_auth_state() {
                Ok(lock) => break lock,
                Err(error) if started.elapsed() > Duration::from_secs(5) => panic!("{error}"),
                Err(_) => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    };
    let runner = {
        let paths = paths.clone();
        std::thread::spawn(move || {
            let store = AuthStore::file_only(paths.clone());
            run(&paths, &store, prepared, &req)
        })
    };
    let receipt = home.path().join("receipt.jsonl");
    let started = std::time::Instant::now();
    while !std::fs::read_to_string(&receipt)
        .unwrap_or_default()
        .contains("\"prepared\"")
    {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "run never prepared"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    std::thread::sleep(Duration::from_millis(200));
    {
        use std::os::unix::thread::JoinHandleExt;
        // SAFETY: the runner thread is alive and waits for the auth lock.
        unsafe { libc::pthread_kill(runner.as_pthread_t() as libc::pthread_t, libc::SIGTERM) };
    }
    std::thread::sleep(Duration::from_millis(200));
    drop(held);
    let error = runner.join().unwrap().unwrap_err();
    assert!(
        error.to_string().contains(&format!(
            "cancelled by signal {} before the child started",
            libc::SIGTERM
        )),
        "the refusal names the signal it received: {error}"
    );
    assert!(
        !out.join("token").exists(),
        "no child may start after a cancel"
    );
    let text = std::fs::read_to_string(&receipt).unwrap();
    assert!(text.contains("\"refused\"") && !text.contains("\"started\""));
}

fn process_alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn wait_dead(pid: i32) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(5) {
        if !process_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[cfg(unix)]
#[test]
fn descendants_are_stopped_when_the_child_exits() {
    let _guard = run_guard();
    let (home, paths, store, out, _child) = work_setup();
    let child = script_child(
        home.path(),
        "spawner",
        &format!("sleep 30 &\necho $! > '{}/bg_pid'\nexit 0", out.display()),
    );
    let req = request("work", &child);
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let code = run(&paths, &store, prepared, &req).unwrap();
    assert_eq!(code, 0);
    let bg: i32 = std::fs::read_to_string(out.join("bg_pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(wait_dead(bg), "a background descendant survived the run");
}

#[cfg(unix)]
#[test]
fn a_terminate_signal_also_stops_descendants() {
    let _guard = run_guard();
    let (home, paths, store, out, _child) = work_setup();
    let child = script_child(
        home.path(),
        "spawner",
        &format!(
            "sleep 30 &\necho $! > '{o}/bg_pid'\n: > '{o}/ready'\nsleep 30",
            o = out.display()
        ),
    );
    let req = request("work", &child);
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let runner = {
        let paths = paths.clone();
        std::thread::spawn(move || {
            let store = AuthStore::file_only(paths.clone());
            run(&paths, &store, prepared, &req)
        })
    };
    let started = std::time::Instant::now();
    while !out.join("ready").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "child did not start"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    {
        use std::os::unix::thread::JoinHandleExt;
        // SAFETY: the runner thread is alive and has the handler installed.
        unsafe { libc::pthread_kill(runner.as_pthread_t() as libc::pthread_t, libc::SIGTERM) };
    }
    let code = runner.join().unwrap().unwrap();
    assert_eq!(code, 128 + libc::SIGTERM);
    let bg: i32 = std::fs::read_to_string(out.join("bg_pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(wait_dead(bg), "a background descendant survived the cancel");
}

#[cfg(unix)]
#[test]
fn a_config_dir_that_cannot_be_removed_is_an_error() {
    let _guard = run_guard();
    let (home, paths, store, out, _child) = work_setup();
    let child = script_child(
        home.path(),
        "locker",
        &format!(
            "mkdir \"$CLAUDE_CONFIG_DIR/locked\" && : > \"$CLAUDE_CONFIG_DIR/locked/f\" && chmod 000 \"$CLAUDE_CONFIG_DIR/locked\"\nprintf '%s' \"$CLAUDE_CONFIG_DIR\" > '{}/config_dir'\nexit 0",
            out.display()
        ),
    );
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    let config_dir =
        std::path::PathBuf::from(std::fs::read_to_string(out.join("config_dir")).unwrap());
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            config_dir.join("locked"),
            std::fs::Permissions::from_mode(0o700),
        );
    }
    assert!(matches!(error, ExecError::Cleanup(_)), "{error}");
    assert_eq!(error.exit_code(), 8);
    assert!(error.to_string().contains("exited with 0"), "{error}");
    let text = std::fs::read_to_string(home.path().join("receipt.jsonl")).unwrap();
    assert!(text.contains("\"exited\"") && text.contains("\"cleanup_failed\""));
}

#[cfg(unix)]
#[test]
fn a_descendant_that_ignores_sigterm_is_killed_before_the_run_returns() {
    let _guard = run_guard();
    let (home, paths, store, out, _child) = work_setup();
    let child = script_child(
        home.path(),
        "stubborn",
        &format!(
            "trap '' TERM\nsleep 30 &\necho $! > '{}/bg_pid'\nexit 0",
            out.display()
        ),
    );
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let code = run(&paths, &store, prepared, &req).unwrap();
    assert_eq!(code, 0);
    let bg: i32 = std::fs::read_to_string(out.join("bg_pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        wait_dead(bg),
        "a SIGTERM-ignoring descendant outlived the run"
    );
    let text = std::fs::read_to_string(home.path().join("receipt.jsonl")).unwrap();
    let exited: serde_json::Value =
        serde_json::from_str(text.lines().find(|l| l.contains("\"exited\"")).unwrap()).unwrap();
    assert_eq!(exited["descendants"], "killed");
}

#[cfg(unix)]
#[test]
fn an_interrupt_sent_to_claudectl_reaches_the_child_once() {
    let _guard = run_guard();
    let (home, paths, store, out, _child) = work_setup();
    let child = script_child(
        home.path(),
        "interruptible",
        &format!(
            "trap 'echo int >> {o}/ints' INT\n: > '{o}/ready'\ni=0\nwhile [ $i -lt 20 ]; do sleep 0.1; i=$((i+1)); done\nexit 0",
            o = out.display()
        ),
    );
    let req = request("work", &child);
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let runner = {
        let paths = paths.clone();
        std::thread::spawn(move || {
            let store = AuthStore::file_only(paths.clone());
            run(&paths, &store, prepared, &req)
        })
    };
    let started = std::time::Instant::now();
    while !out.join("ready").exists() {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "child did not start"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    {
        use std::os::unix::thread::JoinHandleExt;
        // SAFETY: the runner thread is alive and has the handler installed.
        unsafe { libc::pthread_kill(runner.as_pthread_t() as libc::pthread_t, libc::SIGINT) };
    }
    let code = runner.join().unwrap().unwrap();
    assert_eq!(code, 0, "the child handled the interrupt and finished");
    let ints = std::fs::read_to_string(out.join("ints")).unwrap_or_default();
    assert_eq!(
        ints.lines().count(),
        1,
        "the child saw the interrupt exactly once"
    );
}

#[cfg(unix)]
#[test]
fn a_receipt_failure_does_not_hide_a_cleanup_failure() {
    let _guard = run_guard();
    let (home, paths, store, out, _child) = work_setup();
    let child = script_child(
        home.path(),
        "locker",
        &format!(
            "mkdir \"$CLAUDE_CONFIG_DIR/locked\" && : > \"$CLAUDE_CONFIG_DIR/locked/f\" && chmod 000 \"$CLAUDE_CONFIG_DIR/locked\"\nprintf '%s' \"$CLAUDE_CONFIG_DIR\" > '{}/config_dir'\nexit 0",
            out.display()
        ),
    );
    let req = request("work", &child);
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let written = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    // prepared and started succeed; exited fails.
    let sink: Box<dyn std::io::Write> = Box::new(FailingSink {
        ok_writes: 2,
        written: written.clone(),
    });
    let error = run_with_writer(&paths, &store, prepared, &req, sink).unwrap_err();
    let config_dir =
        std::path::PathBuf::from(std::fs::read_to_string(out.join("config_dir")).unwrap());
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(
            config_dir.join("locked"),
            std::fs::Permissions::from_mode(0o700),
        );
    }
    assert!(matches!(error, ExecError::Cleanup(_)), "{error}");
    let message = error.to_string();
    assert!(
        message.contains("receipt write failed"),
        "the receipt failure is kept: {message}"
    );
    assert!(
        message.contains("removing"),
        "the cleanup failure is kept: {message}"
    );
}

#[cfg(unix)]
#[test]
fn two_distinct_signals_recorded_before_registration_are_both_forwarded() {
    // The signal handoff is process-wide state; run alone.
    let _guard = run_guard();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("signals");
    let ready = dir.path().join("ready");
    // One process with its own handlers: no helper programs share the
    // group, so each forwarded signal reaches exactly this handler.
    let script = format!(
        r#"my %seen; $SIG{{INT}} = sub {{ $seen{{INT}} = 1 }}; $SIG{{TERM}} = sub {{ $seen{{TERM}} = 1 }}; open(my $r, ">", "{ready}") or die; close $r; for (1 .. 200) {{ last if keys %seen == 2; select(undef, undef, undef, 0.025) }} open(my $l, ">", "{log}") or die; print $l join(" ", sort keys %seen); close $l; exit(keys %seen == 2 ? 0 : 1)"#,
        log = log.display(),
        ready = ready.display()
    );
    let mut command = std::process::Command::new("perl");
    command.arg("-e").arg(script);
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().unwrap();
    while !ready.exists() {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    // Both arrive before the child is registered.
    claudectl::exec::signals::forward(libc::SIGINT);
    claudectl::exec::signals::forward(libc::SIGTERM);
    claudectl::exec::signals::watch(child.id());
    let status = child.wait().unwrap();
    claudectl::exec::signals::unwatch();
    assert!(status.success());
    let seen = std::fs::read_to_string(&log).unwrap();
    assert!(seen.contains("INT"), "SIGINT was dropped: {seen}");
    assert!(seen.contains("TERM"), "SIGTERM was dropped: {seen}");
}

#[cfg(unix)]
#[test]
fn a_process_that_exits_during_the_scan_is_not_a_listing_failure() {
    assert!(process_gone(&std::io::Error::from_raw_os_error(
        libc::ENOENT
    )));
    assert!(process_gone(&std::io::Error::from_raw_os_error(
        libc::ESRCH
    )));
    assert!(!process_gone(&std::io::Error::from_raw_os_error(
        libc::EACCES
    )));
    assert!(!process_gone(&std::io::Error::from_raw_os_error(libc::EIO)));
}

#[cfg(unix)]
#[test]
fn an_active_marker_naming_the_same_directory_is_refused() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    // Another spelling of the same profile directory, as on a
    // case-insensitive filesystem.
    std::os::unix::fs::symlink(
        paths.profiles_dir().join("work"),
        paths.profiles_dir().join("Work-alias"),
    )
    .unwrap();
    claudectl::profile::set_active_from(&paths, "Work-alias").unwrap();
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(error.to_string().contains("active profile"), "{error}");
    assert!(same_profile(&paths, "work", "Work-alias"));
    assert!(!same_profile(&paths, "work", "missing"));
}

/// A credentials.json whose credential object is double-encoded as a JSON
/// string, so a parser error would quote the token text.
fn write_double_encoded_credentials(paths: &Paths, alias: &str, token: &str) {
    let inner = format!(r#"{{"accessToken":"{token}","refreshToken":"{token}-r"}}"#);
    let outer = serde_json::json!({ "claudeAiOauth": inner });
    std::fs::write(
        paths.profiles_dir().join(alias).join("credentials.json"),
        outer.to_string(),
    )
    .unwrap();
}

#[test]
fn malformed_saved_credentials_never_appear_in_errors() {
    let (home, paths, store) = setup();
    let token = "secret-token-value-123";
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    write_double_encoded_credentials(&paths, "work", token);
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    let text = error.to_string();
    assert!(
        text.contains("saved credentials unreadable"),
        "unexpected error kind"
    );
    assert!(
        !text.contains(token),
        "a credential value reached the error text"
    );
}

#[test]
fn malformed_live_credentials_never_appear_in_errors() {
    let (home, paths, store) = setup();
    let token = "live-secret-token-456";
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("a-work", "r-work", 2 * HOUR_MS),
    );
    let file = paths.claude_credentials_file();
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    let inner = format!(r#"{{"accessToken":"{token}","refreshToken":"{token}-r"}}"#);
    std::fs::write(
        &file,
        serde_json::json!({ "claudeAiOauth": inner }).to_string(),
    )
    .unwrap();
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &ok_identity("uuid-work"),
        self_identity(),
    ));
    let text = error.to_string();
    assert!(
        text.contains("live refresh ownership unknown"),
        "unexpected error kind"
    );
    assert!(
        !text.contains(token),
        "a live credential value reached the error text"
    );
}

#[test]
fn a_credential_file_broken_after_prepare_stays_out_of_the_receipt() {
    let _guard = run_guard();
    let (home, paths, store, out, child) = work_setup();
    let token = "late-secret-token-789";
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    write_double_encoded_credentials(&paths, "work", token);
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    assert!(
        !error.to_string().contains(token),
        "a credential value reached the error text"
    );
    let receipt = std::fs::read_to_string(home.path().join("receipt.jsonl")).unwrap();
    assert!(receipt.contains("\"refused\""), "the refusal is recorded");
    assert!(
        !receipt.contains(token),
        "a credential value reached the receipt"
    );
    assert!(!out.join("token").exists(), "no child started");
}

#[test]
fn a_saved_copy_of_the_live_grant_is_refused_after_live_rotation() {
    let (home, paths, store) = setup();
    let original = creds("a-shared", "r-shared", 2 * HOUR_MS);
    save(&paths, "live", "uuid-live", &original);
    // Labelled as another account, so only the token witness can catch it.
    save(&paths, "copy", "uuid-other", &original);
    claudectl::profile::set_active_from(&paths, "live").unwrap();
    // Claude Code rotated the live login; both saved copies hold the old grant.
    write_live(&paths, &creds("a-rotated", "r-rotated", 2 * HOUR_MS));
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("copy", &child),
        &ok_identity("uuid-other"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(error.to_string().contains("shares its grant"), "{error}");
}

#[cfg(unix)]
#[test]
/// Linux auto-reaps children when SIGCHLD is inherited as ignored, which
/// breaks waiting without reaping; this test fails there without the fix.
/// macOS does not auto-reap for an ignore set before exec, so on macOS the
/// test only proves the run still works.
fn an_inherited_ignored_sigchld_does_not_break_the_run() {
    let _guard = run_guard();
    let (home, paths, _store) = setup();
    save(
        &paths,
        "one",
        "uuid-one",
        &creds("a-one", "r-one", 2 * HOUR_MS),
    );
    let out = home.path().join("out-one");
    std::fs::create_dir(&out).unwrap();
    fake_child(&out, &out, 0);
    let mut helper = std::process::Command::new(std::env::current_exe().unwrap());
    helper
        .args(["--exact", "helper_run_one_alias", "--test-threads=1"])
        .env("CLAUDECTL_TEST_HOME", home.path())
        .env("CLAUDECTL_TEST_ALIAS", "one")
        .env("CLAUDECTL_TEST_OUT", &out)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: runs in the forked helper before exec; signal() is
    // async-signal-safe. A supervisor that ignores SIGCHLD passes this on.
    unsafe {
        std::os::unix::process::CommandExt::pre_exec(&mut helper, || {
            libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            Ok(())
        });
    }
    let mut running = helper.spawn().unwrap();
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = running.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(60) {
            let _ = running.kill();
            let _ = running.wait();
            panic!("the run hung when SIGCHLD was inherited as ignored");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        std::fs::read_to_string(out.join("sigchld_at_start")).unwrap(),
        "ignored",
        "test setup: the helper must start with SIGCHLD ignored"
    );
    assert!(
        status.success(),
        "the run failed when SIGCHLD was inherited as ignored"
    );
    let receipt = std::fs::read_to_string(out.join("receipt.jsonl")).unwrap();
    assert!(
        receipt.contains("\"exited\""),
        "the exited record is written"
    );
}

#[test]
fn an_unreadable_active_profile_fails_closed() {
    let (home, paths, store) = setup();
    let token = "active-secret-token-321";
    let original = creds("a-shared", "r-shared", 2 * HOUR_MS);
    save(&paths, "live", "uuid-live", &original);
    save(&paths, "copy", "uuid-live", &original);
    claudectl::profile::set_active_from(&paths, "live").unwrap();
    // Claude Code rotated the live login, so the active profile's saved copy
    // is the only link to the live grant, and it cannot be parsed.
    write_live(&paths, &creds("a-rotated", "r-rotated", 2 * HOUR_MS));
    write_double_encoded_credentials(&paths, "live", token);
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("copy", &child),
        &ok_identity("uuid-live"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    let text = error.to_string();
    assert!(text.contains("ownership unknown"), "unexpected error kind");
    assert!(
        !text.contains(token),
        "a credential value reached the error text"
    );
}

#[test]
fn the_self_identity_hash_describes_the_running_image() {
    let identity = SelfIdentity::current().expect("the running image is identified");
    let exe = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert_eq!(identity.path, exe);
    assert_eq!(identity.sha256, sha256_file(&exe).unwrap());
}

#[cfg(target_os = "macos")]
#[test]
fn a_different_build_has_a_different_build_uuid() {
    let this = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let other = std::fs::read(env!("CARGO_BIN_EXE_claudectl")).unwrap();
    let this_uuid = macho_uuid(&this).expect("the test binary has a build UUID");
    let other_uuid = macho_uuid(&other).expect("claudectl has a build UUID");
    assert_ne!(
        this_uuid, other_uuid,
        "a replaced file is told apart from the running image"
    );
    assert_eq!(macho_uuid(b"not a mach-o image"), None);
}

#[test]
fn a_profile_of_the_live_account_is_refused_after_save() {
    let (home, paths, store) = setup();
    let original = creds("a-shared", "r-shared", 2 * HOUR_MS);
    save(&paths, "live", "uuid-live", &original);
    save(&paths, "copy", "uuid-live", &original);
    claudectl::profile::set_active_from(&paths, "live").unwrap();
    // Claude Code rotated the grant and `claudectl save live` stored the new
    // tokens, so no token links "copy" to the live grant any more.
    let rotated = creds("a-rotated", "r-rotated", 2 * HOUR_MS);
    write_live(&paths, &rotated);
    save(&paths, "live", "uuid-live", &rotated);
    let child = fake_child(home.path(), home.path(), 0);
    let error = refused(prepare(
        &paths,
        &store,
        &request("copy", &child),
        &ok_identity("uuid-live"),
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(
        error.to_string().contains("same account as the live login"),
        "{error}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn the_mapped_image_identity_is_this_executable() {
    use std::os::unix::fs::MetadataExt;
    let (dev, ino) = mapped_image_identity().expect("the running image is identified");
    let meta = std::fs::metadata(std::env::current_exe().unwrap()).unwrap();
    assert_eq!((u64::from(dev), ino), (meta.dev(), meta.ino()));
}

#[test]
fn a_live_login_without_a_readable_account_id_fails_closed() {
    for claude_json in [
        None,
        Some(r#"{"other":1}"#),
        Some(r#"{"oauthAccount":{}}"#),
        Some(r#"{"oauthAccount":{"accountUuid":null}}"#),
        Some(r#"{"oauthAccount":{"accountUuid":42}}"#),
    ] {
        let (home, paths, store) = setup();
        save(
            &paths,
            "copy",
            "uuid-copy",
            &creds("a-copy", "r-copy", 2 * HOUR_MS),
        );
        let file = paths.claude_credentials_file();
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(
            &file,
            serde_json::to_string(&creds("a-live", "r-live", 2 * HOUR_MS)).unwrap(),
        )
        .unwrap();
        if let Some(text) = claude_json {
            std::fs::write(paths.claude_json(), text).unwrap();
        }
        let child = fake_child(home.path(), home.path(), 0);
        let error = refused(prepare(
            &paths,
            &store,
            &request("copy", &child),
            &ok_identity("uuid-copy"),
            self_identity(),
        ));
        assert!(
            matches!(error, ExecError::Refused(_)),
            "{claude_json:?}: {error}"
        );
        assert!(
            error.to_string().contains("ownership unknown"),
            "{claude_json:?}: {error}"
        );
    }
}

#[test]
fn a_half_finished_switch_cannot_hide_the_live_account() {
    let (home, paths, store) = setup();
    // A switch from A to B wrote B's live credentials, then failed before
    // ~/.claude.json and the active marker moved: both still name A.
    save(&paths, "a", "uuid-a", &creds("tok-a", "ref-a", 2 * HOUR_MS));
    save(
        &paths,
        "b-old",
        "uuid-b",
        &creds("tok-b-old", "ref-b-old", 2 * HOUR_MS),
    );
    claudectl::profile::set_active_from(&paths, "a").unwrap();
    std::fs::write(
        paths.claude_json(),
        r#"{"oauthAccount":{"accountUuid":"uuid-a"}}"#,
    )
    .unwrap();
    write_live(&paths, &creds("tok-b-live", "ref-b-live", 2 * HOUR_MS));
    let child = fake_child(home.path(), home.path(), 0);
    let identity = MapIdentity(vec![
        ("tok-a", "uuid-a"),
        ("tok-b-old", "uuid-b"),
        ("tok-b-live", "uuid-b"),
    ]);
    let error = refused(prepare(
        &paths,
        &store,
        &request("b-old", &child),
        &identity,
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(
        error.to_string().contains("same account as the live login"),
        "{error}"
    );
}

#[test]
fn an_unidentifiable_live_token_fails_closed() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "work",
        "uuid-work",
        &creds("tok-work", "ref-work", 2 * HOUR_MS),
    );
    write_live(&paths, &creds("tok-live-unknown", "ref-live", 2 * HOUR_MS));
    let child = fake_child(home.path(), home.path(), 0);
    let identity = MapIdentity(vec![("tok-work", "uuid-work")]);
    let error = refused(prepare(
        &paths,
        &store,
        &request("work", &child),
        &identity,
        self_identity(),
    ));
    assert!(matches!(error, ExecError::Refused(_)), "{error}");
    assert!(
        error.to_string().contains("cannot identify the live login"),
        "{error}"
    );
}

#[test]
fn a_live_login_change_after_prepare_is_refused() {
    let _guard = run_guard();
    let (home, paths, store, out, child) = work_setup();
    write_live(&paths, &creds("a-live", "r-live", 2 * HOUR_MS));
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    write_live(&paths, &creds("a-rotated", "r-rotated", 2 * HOUR_MS));
    let error = run(&paths, &store, prepared, &req).unwrap_err();
    assert!(error.to_string().contains("live login changed"), "{error}");
    assert!(
        !out.join("token").exists(),
        "no child after a live login change"
    );
}

/// A child that uses the terminal. It records its PID, its process group and
/// the terminal's foreground group, then runs `body`.
#[cfg(unix)]
fn tty_child(out: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    let script = out.join("fake-claude");
    let text = format!(
        r#"#!/bin/sh
out='{out}'
echo $$ > "$out/pid"
ps -o pgid= -p $$ | tr -d ' ' > "$out/pgid"
ps -o tpgid= -p $$ | tr -d ' ' > "$out/tpgid"
{body}
"#,
        out = out.display()
    );
    std::fs::write(&script, text).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `helper_run_one_alias` as a job of a job-control shell that leads a new
/// session on a pty, as in a terminal pane. When the job stops on SIGTSTP the
/// shell records that and resumes it with `fg`, or with `bg` when `resume`
/// is "bg".
#[cfg(unix)]
struct PtyJob {
    shell: std::process::Child,
    master: std::fs::File,
    output: std::sync::mpsc::Receiver<Vec<u8>>,
    out: std::path::PathBuf,
    tty: String,
    done: bool,
}

/// A shell whose `set -m` sees a job stop. macOS /bin/sh (bash 3.2) does not
/// see one; dash does, and it is /bin/sh on Ubuntu.
#[cfg(unix)]
const STOP_SHELL: &str = "/bin/dash";

#[cfg(unix)]
const JOB_SHELL: &str = r#"set -m
"$@"
s=$?
echo "$s" >> "$CLAUDECTL_TEST_OUT/job_status"
if [ "$s" = "$TSTP_STATUS" ] && [ "$JOB_RESUME" = bg ]; then
  bg
  : > "$CLAUDECTL_TEST_OUT/in_background"
  wait
  s=$?
  echo "$s" >> "$CLAUDECTL_TEST_OUT/job_status"
  # Who owns the terminal once the background job is done. Without job
  # control, so the probe does not become a foreground job itself.
  set +m
  ps -o tpgid= -p $$ | tr -d ' ' > "$CLAUDECTL_TEST_OUT/shell_tpgid"
  ps -o pgid= -p $$ | tr -d ' ' > "$CLAUDECTL_TEST_OUT/shell_pgid"
elif [ "$s" = "$TSTP_STATUS" ]; then
  fg
  s=$?
  echo "$s" >> "$CLAUDECTL_TEST_OUT/job_status"
fi
exit "$s"
"#;

#[cfg(unix)]
impl PtyJob {
    fn start(home: &Path, alias: &str, out: &Path) -> Self {
        Self::start_resuming(home, alias, out, "fg")
    }

    fn start_resuming(home: &Path, alias: &str, out: &Path, resume: &str) -> Self {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::process::CommandExt;
        // SAFETY: plain pty calls; ptsname's static buffer is read at once,
        // and the run guard keeps other tests from calling it meanwhile.
        let (master, name) = unsafe {
            let fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(fd >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
            assert_eq!(libc::grantpt(fd), 0);
            assert_eq!(libc::unlockpt(fd), 0);
            let name = std::ffi::CStr::from_ptr(libc::ptsname(fd))
                .to_str()
                .unwrap()
                .to_owned();
            (std::fs::File::from_raw_fd(fd), name)
        };
        let slave = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&name)
            .unwrap();
        let name = name.trim_start_matches("/dev/").to_owned();
        // Only the Ctrl-Z test needs the shell to see a job stop, and it
        // runs only with STOP_SHELL; the other tests accept any /bin/sh.
        let job_shell = if Path::new(STOP_SHELL).exists() {
            STOP_SHELL
        } else {
            "/bin/sh"
        };
        let mut shell = std::process::Command::new(job_shell);
        shell
            .args(["-c", JOB_SHELL, "sh"])
            .arg(std::env::current_exe().unwrap())
            .args(["--exact", "helper_run_one_alias", "--test-threads=1"])
            .env("CLAUDECTL_TEST_HOME", home)
            .env("CLAUDECTL_TEST_ALIAS", alias)
            .env("CLAUDECTL_TEST_OUT", out)
            .env("TSTP_STATUS", (128 + libc::SIGTSTP).to_string())
            .env("JOB_RESUME", resume)
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave);
        // SAFETY: runs in the forked shell before exec; setsid and ioctl are
        // async-signal-safe. The pty becomes the new session's terminal.
        unsafe {
            shell.pre_exec(|| {
                if libc::setsid() == -1
                    || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as _, 0) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = shell.spawn().unwrap();
        // Close the parent's slave copies, which the command holds, so the
        // reader sees the end of the session.
        drop(shell);
        let mut reader = master.try_clone().unwrap();
        let (sender, output) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 || sender.send(buffer[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        Self {
            shell: child,
            master,
            output,
            out: out.to_path_buf(),
            tty: name,
            done: false,
        }
    }

    fn type_text(&mut self, text: &[u8]) {
        use std::io::Write;
        self.master.write_all(text).unwrap();
    }

    /// The shell's exit status, or None after `limit`.
    fn wait(&mut self, limit: Duration) -> Option<std::process::ExitStatus> {
        let started = std::time::Instant::now();
        while started.elapsed() < limit {
            if let Some(status) = self.shell.try_wait().unwrap() {
                self.done = true;
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// The terminal output so far and the session's processes, for a
    /// failure message.
    fn transcript(&self) -> String {
        let bytes: Vec<u8> = self.output.try_iter().flatten().collect();
        let processes = std::process::Command::new("ps")
            .args(["-o", "pid,pgid,tpgid,stat,command", "-t", &self.tty])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        format!("{}\n{processes}", String::from_utf8_lossy(&bytes))
    }
}

#[cfg(unix)]
impl Drop for PtyJob {
    /// A run that did not finish leaves no process behind: kill the child's
    /// group, the job's group and the shell.
    fn drop(&mut self) {
        if self.done {
            return;
        }
        for file in ["pid", "helper_pid"] {
            if let Some(pid) = std::fs::read_to_string(self.out.join(file))
                .ok()
                .and_then(|text| text.trim().parse::<i32>().ok())
            {
                // SAFETY: kill only sends a signal.
                unsafe { libc::kill(-pid, libc::SIGKILL) };
            }
        }
        let _ = self.shell.kill();
        let _ = self.shell.wait();
    }
}

/// Wait until `path` exists.
#[cfg(unix)]
fn wait_for(path: &Path, limit: Duration) -> bool {
    let started = std::time::Instant::now();
    while started.elapsed() < limit {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[cfg(unix)]
fn tty_child_setup(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let (home, paths, _store) = setup();
    save(
        &paths,
        "one",
        "uuid-one",
        &creds("a-one", "r-one", 2 * HOUR_MS),
    );
    let out = home.path().join("out-tty");
    std::fs::create_dir(&out).unwrap();
    tty_child(&out, body);
    (home, out)
}

#[cfg(unix)]
fn read_out(out: &Path, name: &str) -> String {
    std::fs::read_to_string(out.join(name)).unwrap_or_default()
}

#[cfg(unix)]
const LIMIT: Duration = Duration::from_secs(15);

#[cfg(unix)]
#[test]
fn an_interactive_child_owns_the_terminal_and_reads_it() {
    let _guard = run_guard();
    let (home, out) = tty_child_setup(
        r#"echo ready > "$out/ready"
IFS= read -r line
printf '%s' "$line" > "$out/line""#,
    );
    let mut job = PtyJob::start(home.path(), "one", &out);
    assert!(wait_for(&out.join("ready"), LIMIT), "{}", job.transcript());
    job.type_text(b"hello\n");
    let status = job.wait(LIMIT);
    assert!(
        status.is_some_and(|s| s.success()),
        "the child did not finish: {:?}\n{}",
        status,
        job.transcript()
    );
    assert_eq!(read_out(&out, "pgid"), read_out(&out, "tpgid"));
    assert_eq!(read_out(&out, "line"), "hello");
}

#[cfg(unix)]
#[test]
fn ctrl_c_reaches_an_interactive_child_once_from_the_terminal() {
    let _guard = run_guard();
    let (home, out) = tty_child_setup(
        r#"trap 'echo int >> "$out/int"; exit 0' INT
echo ready > "$out/ready"
while :; do sleep 1; done"#,
    );
    let mut job = PtyJob::start(home.path(), "one", &out);
    assert!(wait_for(&out.join("ready"), LIMIT), "{}", job.transcript());
    job.type_text(b"\x03");
    let status = job.wait(LIMIT);
    assert!(
        status.is_some_and(|s| s.success()),
        "the child did not finish: {:?}\n{}",
        status,
        job.transcript()
    );
    // The terminal sends SIGINT to the child's group; claudectl is outside
    // the foreground group and forwards no second copy.
    assert_eq!(read_out(&out, "pgid"), read_out(&out, "tpgid"));
    assert_eq!(read_out(&out, "int"), "int\n");
}

#[cfg(unix)]
#[test]
fn ctrl_z_suspends_the_job_and_fg_resumes_the_child() {
    if !Path::new(STOP_SHELL).exists() {
        eprintln!(
            "skipped: {STOP_SHELL} is missing, and no other shell is known to see a job stop"
        );
        return;
    }
    let _guard = run_guard();
    let (home, out) = tty_child_setup(
        r#"echo ready > "$out/ready"
IFS= read -r line
printf '%s' "$line" > "$out/line""#,
    );
    let mut job = PtyJob::start(home.path(), "one", &out);
    assert!(wait_for(&out.join("ready"), LIMIT), "{}", job.transcript());
    // Let the child reach its read before the suspend key.
    std::thread::sleep(Duration::from_millis(300));
    job.type_text(b"\x1a");
    assert!(
        wait_for(&out.join("job_status"), LIMIT),
        "the job did not stop: {}",
        job.transcript()
    );
    job.type_text(b"after\n");
    let status = job.wait(LIMIT);
    assert!(
        status.is_some_and(|s| s.success()),
        "the job did not finish after fg: {:?}\n{}",
        status,
        job.transcript()
    );
    let stopped = (128 + libc::SIGTSTP).to_string();
    assert_eq!(
        read_out(&out, "job_status").lines().collect::<Vec<_>>(),
        [stopped.as_str(), "0"]
    );
    assert_eq!(read_out(&out, "line"), "after");
}

#[cfg(unix)]
#[test]
fn claudectl_owns_the_terminal_again_after_an_interactive_child() {
    let _guard = run_guard();
    let (home, out) = tty_child_setup(r#"echo ready > "$out/ready""#);
    let mut job = PtyJob::start(home.path(), "one", &out);
    let status = job.wait(LIMIT);
    assert!(
        status.is_some_and(|s| s.success()),
        "{:?}\n{}",
        status,
        job.transcript()
    );
    assert_eq!(read_out(&out, "foreground_after"), "owned");
}

/// A child that handles `signal` and stopped itself; claudectl receives
/// `signal` and must still end the run.
#[cfg(unix)]
fn forwarded_signal_ends_a_stopped_child(signal: libc::c_int) {
    let _guard = run_guard();
    // Handlers like the Claude TUI's: macOS ends a stopped process on a
    // default-action signal, but a handled one waits for SIGCONT.
    let (home, out) = tty_child_setup(
        r#"trap 'exit 130' INT
trap 'exit 143' TERM
echo ready > "$out/ready"
kill -STOP $$"#,
    );
    let mut helper = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "helper_run_one_alias", "--test-threads=1"])
        .env("CLAUDECTL_TEST_HOME", home.path())
        .env("CLAUDECTL_TEST_ALIAS", "one")
        .env("CLAUDECTL_TEST_OUT", &out)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    assert!(wait_for(&out.join("ready"), LIMIT));
    let pid: i32 = read_out(&out, "pid").trim().parse().unwrap();
    let started = std::time::Instant::now();
    let mut stopped = false;
    while started.elapsed() < LIMIT && !stopped {
        let state = std::process::Command::new("ps")
            .args(["-o", "stat=", "-p", &pid.to_string()])
            .output()
            .unwrap();
        stopped = String::from_utf8_lossy(&state.stdout)
            .trim_start()
            .starts_with('T');
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(stopped, "test setup: the child stopped itself");
    // SAFETY: kill only sends a signal to the helper.
    unsafe { libc::kill(helper.id() as i32, signal) };
    let started = std::time::Instant::now();
    let mut status = None;
    while started.elapsed() < LIMIT && status.is_none() {
        status = helper.try_wait().unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    if status.is_none() {
        // SAFETY: kill only sends signals; no process is left behind.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
            libc::kill(helper.id() as i32, libc::SIGKILL);
        }
    }
    let _ = helper.wait();
    assert!(
        status.is_some(),
        "claudectl did not end the stopped child on signal {signal}"
    );
}

#[cfg(unix)]
#[test]
fn a_forwarded_sigterm_ends_a_stopped_child() {
    forwarded_signal_ends_a_stopped_child(libc::SIGTERM);
}

#[cfg(unix)]
#[test]
fn a_forwarded_sigint_ends_a_stopped_child() {
    forwarded_signal_ends_a_stopped_child(libc::SIGINT);
}

#[cfg(unix)]
#[test]
fn a_child_that_exits_in_the_background_leaves_the_terminal_to_the_shell() {
    if !Path::new(STOP_SHELL).exists() {
        eprintln!(
            "skipped: {STOP_SHELL} is missing, and no other shell is known to see a job stop"
        );
        return;
    }
    let _guard = run_guard();
    let (home, out) = tty_child_setup(
        r#"echo ready > "$out/ready"
while [ ! -e "$out/go" ]; do sleep 0.1; done"#,
    );
    let mut job = PtyJob::start_resuming(home.path(), "one", &out, "bg");
    assert!(wait_for(&out.join("ready"), LIMIT), "{}", job.transcript());
    job.type_text(b"\x1a");
    assert!(
        wait_for(&out.join("in_background"), LIMIT),
        "the job did not stop: {}",
        job.transcript()
    );
    std::fs::write(out.join("go"), "").unwrap();
    let status = job.wait(LIMIT);
    assert!(
        status.is_some_and(|s| s.success()),
        "the background job did not finish: {:?}\n{}",
        status,
        job.transcript()
    );
    // claudectl ran in the background when its child exited; the shell
    // keeps the terminal.
    assert_eq!(read_out(&out, "shell_tpgid"), read_out(&out, "shell_pgid"));
    assert_eq!(
        read_out(&out, "foreground_after"),
        "not_owned",
        "job_status={:?} child pgid={:?} helper={:?}\n{}",
        read_out(&out, "job_status"),
        read_out(&out, "pgid"),
        read_out(&out, "helper_pid"),
        job.transcript()
    );
}
