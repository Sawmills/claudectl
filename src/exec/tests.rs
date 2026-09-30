use std::path::Path;

use super::*;
use crate::api::{CredentialsFile, OauthCreds};

const HOUR_MS: i64 = 3_600_000;

struct FakeIdentity(Result<Option<String>, String>);

impl IdentitySource for FakeIdentity {
    fn account_uuid(&self, _access_token: &str) -> anyhow::Result<Option<String>> {
        self.0.clone().map_err(anyhow::Error::msg)
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
    crate::profile::save_profile_to(
        paths,
        alias,
        c,
        Some(serde_json::json!({ "accountUuid": uuid, "emailAddress": format!("{alias}@example.com") })),
    )
    .unwrap();
}

fn write_live(paths: &Paths, c: &CredentialsFile) {
    let file = paths.claude_credentials_file();
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    std::fs::write(file, serde_json::to_string(c).unwrap()).unwrap();
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
env | grep -E '^(CLAUDE_CODE_OAUTH_TOKEN|CLAUDE_CODE_OAUTH_REFRESH_TOKEN|ANTHROPIC_API_KEY|ANTHROPIC_AUTH_TOKEN)=' > "$out/leaked_env" || true
printf '%s ' "$@" > "$out/args"
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
    crate::profile::set_active_from(&paths, "work").unwrap();
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
    crate::profile::save_profile_to(&paths, "anon", &creds("a", "r", 2 * HOUR_MS), None).unwrap();
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
    crate::profile::set_active_from(&paths, "live").unwrap();
    let before = snapshot(&paths);

    let out = home.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let child = fake_child(home.path(), &out, 7);
    let mut req = request("work", &child);
    req.receipt = Some(home.path().join("receipt.jsonl"));
    // SAFETY: test-only; the scrub must hide credentials the parent holds.
    unsafe { std::env::set_var("ANTHROPIC_API_KEY", "parent-key") };

    let prepared = prepare(
        &paths,
        &store,
        &req,
        &ok_identity("uuid-work"),
        self_identity(),
    )
    .unwrap();
    let code = run(&paths, prepared, &req).unwrap();

    assert_eq!(code, 7, "child exit code passes through");
    let received = std::fs::read(out.join("token")).unwrap();
    assert!(
        received == token.as_bytes(),
        "child did not receive the saved token"
    );
    assert_eq!(std::fs::read_to_string(out.join("leaked_env")).unwrap(), "");
    assert_eq!(
        std::fs::read_to_string(out.join("args")).unwrap(),
        "-p hello "
    );
    assert!(out.join("config_exists").exists());
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
    let error = run(&paths, prepared, &req).unwrap_err();
    assert!(matches!(error, ExecError::Receipt(_)), "{error}");
    assert!(
        !out.join("token").exists(),
        "no child may start without a receipt"
    );
}

#[test]
fn concurrent_runs_on_two_aliases_stay_isolated() {
    let (home, paths, store) = setup();
    save(
        &paths,
        "one",
        "uuid-one",
        &creds("a-one", "r-one", 2 * HOUR_MS),
    );
    save(
        &paths,
        "two",
        "uuid-two",
        &creds("a-two", "r-two", 2 * HOUR_MS),
    );
    drop(store);
    let mut handles = Vec::new();
    for alias in ["one", "two"] {
        let paths = paths.clone();
        let out = home.path().join(format!("out-{alias}"));
        std::fs::create_dir(&out).unwrap();
        let child = fake_child(&out, &out, 0);
        handles.push(std::thread::spawn(move || {
            let store = AuthStore::file_only(paths.clone());
            let mut req = request(alias, &child);
            req.receipt = Some(out.join("receipt.jsonl"));
            let prepared = prepare(
                &paths,
                &store,
                &req,
                &ok_identity(&format!("uuid-{alias}")),
                self_identity(),
            )
            .unwrap();
            run(&paths, prepared, &req).unwrap();
            let token = std::fs::read(out.join("token")).unwrap();
            let dir = std::fs::read_to_string(out.join("config_dir")).unwrap();
            (alias, token == format!("a-{alias}").into_bytes(), dir)
        }));
    }
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    for (alias, token_matches, _) in &results {
        assert!(token_matches, "{alias} received another alias's token");
    }
    assert_ne!(results[0].2, results[1].2, "runs share a config dir");
}

#[test]
fn parses_durations() {
    assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
    assert_eq!(parse_duration("900s").unwrap(), Duration::from_secs(900));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_duration("45").unwrap(), Duration::from_secs(45));
    assert!(parse_duration("5d").is_err());
    assert!(parse_duration("abc").is_err());
}
