#![cfg(all(feature = "server", target_os = "linux"))]
//! `claudectl server migrate --all` against a scripted account server. Linux only: the live
//! login is a file there, so no Keychain is touched. Synthetic tokens only.
use assert_cmd::Command;
use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use claudectl::{
    api::{CredentialsFile, OauthCreds},
    config::Paths,
    profile,
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

/// What the fake server does with an alias's import.
#[derive(Clone, Copy, PartialEq)]
enum Script {
    Ok,
    /// First import refused (409), later ones succeed.
    Flaky,
    Superseded,
    Unrotated,
    Gone,
    /// The import commits but the reply is lost (503).
    Lost,
    /// 503 and nothing committed.
    Down,
    /// 503 after admitting without a verified rotation.
    Pending,
}

#[derive(Default)]
struct Fake {
    scripts: HashMap<String, Script>,
    identities: HashMap<String, String>,
    receipts: HashMap<String, Value>,
    pending: HashSet<String>,
    imports: HashMap<String, usize>,
    imported_refresh: HashMap<String, String>,
    me_down: bool,
    /// The claudectl auth lock, probed while a refresh is in flight.
    lock_path: Option<PathBuf>,
    lock_held_during_refresh: Option<bool>,
    /// A profile file rewritten while the refresh is in flight.
    rewrite: Option<(PathBuf, String)>,
    refreshes: usize,
    /// Receipt lookups answer 200 with a body that is not JSON.
    garbage_receipts: bool,
    cancelled: HashSet<String>,
}
type Shared = Arc<Mutex<Fake>>;

fn error(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({"error": reason}))).into_response()
}

async fn me(State(fake): State<Shared>) -> Response {
    if fake.lock().unwrap().me_down {
        return error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    }
    Json(json!({"id":"person","machine":"m"})).into_response()
}
async fn receipt(State(fake): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Response {
    let fake = fake.lock().unwrap();
    if fake.garbage_receipts {
        return (StatusCode::OK, "not json").into_response();
    }
    let id = &q["migration_id"];
    match fake.receipts.get(id) {
        Some(r) => Json(json!({"receipt": r, "state": "complete"})).into_response(),
        None if fake.pending.contains(id) => {
            Json(json!({"receipt": null, "state": "pending"})).into_response()
        }
        None => Json(json!({"receipt": null, "state": "none"})).into_response(),
    }
}
async fn import(State(fake): State<Shared>, Json(body): Json<Value>) -> Response {
    let mut fake = fake.lock().unwrap();
    let alias = body["alias"].as_str().unwrap().to_string();
    let id = body["migration_id"].as_str().unwrap().to_string();
    let count = {
        let c = fake.imports.entry(id.clone()).or_default();
        *c += 1;
        *c
    };
    fake.imported_refresh.insert(
        alias.clone(),
        body["grant"]["refresh_token"].as_str().unwrap().into(),
    );
    let receipt = json!({
        "account_id": "a".repeat(64),
        "identity": {"account_uuid": fake.identities[&alias], "organization_uuid": "org"},
        "migration_id": id,
    });
    match fake.scripts.get(&alias).copied().unwrap_or(Script::Ok) {
        Script::Flaky if count == 1 => {
            error(StatusCode::CONFLICT, "admission_refused_reconcile_receipt")
        }
        Script::Superseded => error(StatusCode::CONFLICT, "migration_superseded"),
        Script::Unrotated => error(StatusCode::CONFLICT, "refresh_token_not_rotated"),
        Script::Gone => error(StatusCode::GONE, "account_deleted"),
        Script::Down => error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
        Script::Pending => {
            fake.pending.insert(id);
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        Script::Lost => {
            fake.receipts.insert(id, receipt);
            error(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
        _ => {
            fake.receipts.insert(id, receipt.clone());
            Json(receipt).into_response()
        }
    }
}
async fn cancel(State(fake): State<Shared>, Json(body): Json<Value>) -> Response {
    let mut fake = fake.lock().unwrap();
    let id = body["migration_id"].as_str().unwrap().to_string();
    if fake.receipts.contains_key(&id) || fake.pending.contains(&id) {
        return error(StatusCode::CONFLICT, "migration_admitted");
    }
    fake.cancelled.insert(id);
    Json(json!({"state":"cancelled"})).into_response()
}
async fn token(State(fake): State<Shared>) -> Json<Value> {
    let mut fake = fake.lock().unwrap();
    fake.refreshes += 1;
    if let Some(path) = fake.lock_path.clone() {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .unwrap();
        fake.lock_held_during_refresh = Some(file.try_lock().is_err());
    }
    if let Some((path, contents)) = fake.rewrite.take() {
        std::fs::write(path, contents).unwrap();
    }
    Json(
        json!({"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}),
    )
}

struct Env {
    home: tempfile::TempDir,
    paths: Paths,
    origin: String,
    bin: PathBuf,
    fake: Shared,
    _server: std::thread::JoinHandle<()>,
}

fn creds(token: &str, expires_in_ms: i64) -> CredentialsFile {
    CredentialsFile {
        claude_ai_oauth: OauthCreds {
            access_token: format!("{token}-access"),
            refresh_token: Some(format!("{token}-refresh")),
            expires_at: Some(chrono::Utc::now().timestamp_millis() + expires_in_ms),
            scopes: vec!["user:inference".into(), "user:profile".into()],
            subscription_type: None,
            rate_limit_tier: None,
            extra: Default::default(),
        },
        extra: Default::default(),
    }
}
fn private_write(path: &Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

impl Env {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(home.path().into());
        let fake: Shared = Arc::default();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/v1/me", get(me))
            .route("/v2/anthropic/migrations", get(receipt).post(import))
            .route("/v2/anthropic/migrations/cancel", post(cancel))
            .route("/token", post(token))
            .with_state(fake.clone());
        let server = std::thread::spawn(move || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                    axum::serve(listener, app).await.unwrap();
                });
        });
        // Connection to the fake server.
        let dir = paths.claudectl_dir().join("server");
        private_write(
            &dir.join("connection.json"),
            &json!({"server":origin,"user_id":"person","token_file":dir.join("machine.json")})
                .to_string(),
        );
        private_write(
            &dir.join("machine.json"),
            &json!("synthetic-machine-token").to_string(),
        );
        // A qualified synthetic Claude build on PATH.
        let bin = home.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let claude = bin.join("claude");
        std::fs::write(&claude, "#!/bin/sh\nexit 0\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let env = Self {
            home,
            paths,
            origin,
            bin,
            fake,
            _server: server,
        };
        env.qualify();
        env
    }
    fn qualify(&self) {
        let digest = claudectl::exec::sha256_file(&self.bin.join("claude")).unwrap();
        private_write(
            &self
                .paths
                .claudectl_dir()
                .join("server/qualified-host-config-builds.json"),
            &json!([{"sha256":digest,"platform":std::env::consts::OS,"qualified_at":"2026-10-07T00:00:00Z","check":"supervised_host_config"}])
                .to_string(),
        );
    }
    fn unqualify(&self) {
        std::fs::remove_file(
            self.paths
                .claudectl_dir()
                .join("server/qualified-host-config-builds.json"),
        )
        .unwrap();
    }
    fn profile(&self, alias: &str, uuid: &str, script: Script, expires_in_ms: i64) {
        profile::save_profile_to(
            &self.paths,
            alias,
            &creds(alias, expires_in_ms),
            Some(json!({"accountUuid":uuid,"organizationUuid":"org"})),
        )
        .unwrap();
        let mut fake = self.fake.lock().unwrap();
        fake.scripts.insert(alias.into(), script);
        fake.identities.insert(alias.into(), uuid.into());
    }
    /// The host's live login for `alias` (Linux: the credentials file and ~/.claude.json).
    fn live(&self, alias: &str, uuid: &str, token: &str) {
        self.profile(alias, uuid, Script::Ok, 3_600_000);
        private_write(
            &self.paths.claude_credentials_file(),
            &serde_json::to_string(&creds(token, 3_600_000)).unwrap(),
        );
        std::fs::write(
            self.paths.claude_json(),
            json!({"oauthAccount":{"accountUuid":uuid,"organizationUuid":"org"}}).to_string(),
        )
        .unwrap();
        profile::set_active_from(&self.paths, alias).unwrap();
    }
    fn script(&self, alias: &str, script: Script) {
        self.fake
            .lock()
            .unwrap()
            .scripts
            .insert(alias.into(), script);
    }
    fn run(&self, args: &[&str], pids: &str) -> (bool, String) {
        self.run_with(args, pids, &[])
    }
    fn run_with(&self, args: &[&str], pids: &str, env: &[(&str, &Path)]) -> (bool, String) {
        let path = format!("{}:{}", self.bin.display(), std::env::var("PATH").unwrap());
        let output = Command::cargo_bin("claudectl")
            .unwrap()
            .envs(env.iter().map(|(k, v)| (*k, *v)))
            .env("HOME", self.home.path())
            .env("PATH", path)
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .env("CLAUDECTL_TEST_CLAUDE_PIDS", pids)
            .env("CLAUDECTL_TEST_TOKEN_URL", format!("{}/token", self.origin))
            .args(["server", "migrate"])
            .args(args)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.success(), text)
    }
    fn all(&self) -> (bool, String) {
        self.run(&["--all", "--exclusive-owner"], "")
    }
    fn row(text: &str, alias: &str) -> String {
        text.lines()
            .find(|l| l.split_whitespace().next() == Some(alias))
            .unwrap_or_else(|| panic!("no row for {alias} in:\n{text}"))
            .to_string()
    }
    fn has_credentials(&self, alias: &str) -> bool {
        self.paths
            .profiles_dir()
            .join(alias)
            .join("credentials.json")
            .exists()
    }
    fn fenced(&self, alias: &str) -> bool {
        use sha2::{Digest, Sha256};
        let hash = format!(
            "{:x}",
            Sha256::digest(alias.to_ascii_lowercase().as_bytes())
        );
        self.paths
            .claudectl_dir()
            .join("server/migrations")
            .join(hash)
            .join("journal.json")
            .exists()
    }
    fn imports(&self) -> usize {
        self.fake.lock().unwrap().imports.values().sum()
    }
}

#[test]
fn all_saved_accounts_migrate_and_a_rerun_reports_already() {
    let env = Env::new();
    for (alias, uuid) in [
        ("a1", "u-a1-0000"),
        ("b2", "u-b2-0000"),
        ("c3", "u-c3-0000"),
    ] {
        env.profile(alias, uuid, Script::Ok, 3_600_000);
    }
    let (ok, text) = env.all();
    assert!(ok, "{text}");
    for alias in ["a1", "b2", "c3"] {
        assert!(Env::row(&text, alias).contains("migrated"), "{text}");
        assert!(!env.has_credentials(alias));
        assert!(env.fenced(alias));
    }
    let (ok, text) = env.all();
    assert!(ok, "{text}");
    for alias in ["a1", "b2", "c3"] {
        assert!(Env::row(&text, alias).contains("already"), "{text}");
    }
    assert_eq!(env.imports(), 3, "a rerun must not import again");
}

#[test]
fn one_account_failing_mid_run_stays_fenced_and_a_rerun_completes_it() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    env.profile("b2", "u-b2-0000", Script::Flaky, 3_600_000);
    env.profile("c3", "u-c3-0000", Script::Ok, 3_600_000);
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("migrated"), "{text}");
    assert!(Env::row(&text, "b2").contains("failed:fenced"), "{text}");
    assert!(Env::row(&text, "c3").contains("migrated"), "{text}");
    assert!(env.fenced("b2"));
    let (ok, text) = env.all();
    assert!(ok, "{text}");
    assert!(Env::row(&text, "b2").contains("migrated"), "{text}");
}

#[test]
fn a_lost_reply_halts_the_run_and_a_rerun_finds_the_receipt_without_a_second_import() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Lost, 3_600_000);
    env.profile("b2", "u-b2-0000", Script::Ok, 3_600_000);
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("lost-reply"), "{text}");
    assert!(Env::row(&text, "b2").contains("not-attempted"), "{text}");
    assert!(!env.fenced("b2"), "no fence after the server went down");
    let (ok, text) = env.all();
    assert!(ok, "{text}");
    assert!(Env::row(&text, "a1").contains("migrated"), "{text}");
    assert!(Env::row(&text, "b2").contains("migrated"), "{text}");
    assert_eq!(
        env.imports(),
        2,
        "the lost import was found by receipt lookup"
    );
}

#[test]
fn an_unreachable_server_fences_nothing() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    env.fake.lock().unwrap().me_down = true;
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(text.contains("nothing was fenced"), "{text}");
    assert!(!env.fenced("a1"));
    assert!(env.has_credentials("a1"));
    // A 5xx mid-run stops the loop: the next account is not fenced.
    env.fake.lock().unwrap().me_down = false;
    env.script("a1", Script::Down);
    env.profile("b2", "u-b2-0000", Script::Ok, 3_600_000);
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "b2").contains("not-attempted"), "{text}");
    assert!(!env.fenced("b2"));
}

#[test]
fn superseded_unrotated_and_gone_accounts_get_their_own_rows() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Superseded, 3_600_000);
    env.profile("b2", "u-b2-0000", Script::Unrotated, 3_600_000);
    env.profile("c3", "u-c3-0000", Script::Gone, 3_600_000);
    env.profile("d4", "u-d4-0000", Script::Ok, 3_600_000);
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("superseded"), "{text}");
    assert!(Env::row(&text, "a1").contains("--abort a1"), "{text}");
    assert!(Env::row(&text, "b2").contains("unrotated"), "{text}");
    assert!(Env::row(&text, "c3").contains("gone"), "{text}");
    assert!(Env::row(&text, "d4").contains("migrated"), "{text}");
}

#[test]
fn abort_restores_only_when_the_server_never_admitted() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Down, 3_600_000);
    let (_, text) = env.all();
    assert!(env.fenced("a1"), "{text}");
    assert!(!env.has_credentials("a1"));
    let (ok, text) = env.run(&["--abort", "a1"], "");
    assert!(ok, "{text}");
    assert!(!env.fenced("a1"));
    assert!(env.has_credentials("a1"), "the grant is restored");
    assert_eq!(
        env.fake.lock().unwrap().cancelled.len(),
        1,
        "the server confirmed a cancel before the restore"
    );

    env.profile("b2", "u-b2-0000", Script::Pending, 3_600_000);
    env.script("a1", Script::Ok);
    let (_, text) = env.all();
    assert!(env.fenced("b2"), "{text}");
    let (ok, text) = env.run(&["--abort", "b2"], "");
    assert!(!ok, "{text}");
    assert!(text.contains("pending"), "{text}");
    assert!(env.fenced("b2"));
    assert!(!env.has_credentials("b2"));
}

#[test]
fn the_live_login_migrates_last_and_is_never_deleted_automatically() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    env.live("me", "u-me-0000", "live");
    // Without --exclusive-owner nothing migrates, the live login included.
    let (ok, text) = env.run(&["--all"], "");
    assert!(!ok, "{text}");
    assert!(text.contains("--exclusive-owner"), "{text}");
    assert!(!env.fenced("a1") && !env.fenced("me"));
    assert!(env.paths.claude_credentials_file().exists());

    // The import commits but the reply is lost; then Claude rotates the live login.
    env.script("me", Script::Lost);
    let (ok, text) = env.run(&["--all", "--exclusive-owner"], "");
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "me").contains("lost-reply"), "{text}");
    assert_eq!(
        env.fake.lock().unwrap().imported_refresh["me"],
        "live-refresh",
        "the live Keychain grant was migrated, not the profile copy"
    );
    private_write(
        &env.paths.claude_credentials_file(),
        &serde_json::to_string(&creds("changed", 3_600_000)).unwrap(),
    );
    // The receipt is found: migrated. The changed live login is reported, never touched.
    let (ok, text) = env.run(&["--all", "--exclusive-owner"], "");
    assert!(ok, "{text}");
    let row = Env::row(&text, "me");
    assert!(row.contains("migrated"), "{text}");
    assert!(row.contains("live login changed"), "{text}");
    let kept: CredentialsFile =
        serde_json::from_slice(&std::fs::read(env.paths.claude_credentials_file()).unwrap())
            .unwrap();
    assert_eq!(
        kept.claude_ai_oauth.access_token, "changed-access",
        "nothing deleted"
    );

    // Back to the migrated grant: the migration completes, and the live login is never
    // deleted automatically (HQ decision): the user is told to log it out.
    private_write(
        &env.paths.claude_credentials_file(),
        &serde_json::to_string(&creds("live", 3_600_000)).unwrap(),
    );
    let (ok, text) = env.run(&["--all", "--exclusive-owner"], "");
    assert!(ok, "{text}");
    assert!(Env::row(&text, "me").contains("already"), "{text}");
    assert!(
        Env::row(&text, "me").contains("log out the live login"),
        "{text}"
    );
    assert!(text.contains("claude auth logout"), "{text}");
    assert!(
        env.paths.claude_credentials_file().exists(),
        "nothing deleted"
    );
    assert_eq!(
        profile::get_active_from(&env.paths).unwrap().as_deref(),
        Some("me")
    );
    assert!(!env.has_credentials("me"));
}

#[test]
fn a_running_claude_refuses_the_whole_run_even_with_exclusive_owner() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    let (ok, text) = env.run(&["--all", "--exclusive-owner"], "4242");
    assert!(!ok, "{text}");
    assert!(text.contains("4242"), "{text}");
    assert!(!env.fenced("a1"));
    assert_eq!(env.imports(), 0);
}

#[test]
fn an_unqualified_claude_build_fences_nothing() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    env.unqualify();
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(text.contains("not qualified"), "{text}");
    assert!(!env.fenced("a1"));
}

#[test]
fn an_expired_inactive_profile_is_refreshed_before_its_fence() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, -1_000);
    let (ok, text) = env.all();
    assert!(ok, "{text}");
    assert_eq!(
        env.fake.lock().unwrap().imported_refresh["a1"],
        "rotated-refresh",
        "the rotated grant was migrated"
    );
    assert!(
        !env.paths
            .claudectl_dir()
            .join("server/refresh-recovery/a1.json")
            .exists(),
        "a saved refresh keeps no recovery copy"
    );
}

#[test]
fn abort_of_a_live_migration_restores_the_profile_and_never_the_live_login() {
    let env = Env::new();
    env.live("me", "u-me-0000", "live");
    env.script("me", Script::Down);
    let (_, text) = env.run(&["--all", "--exclusive-owner"], "");
    assert!(env.fenced("me"), "{text}");
    // The live login is lost meanwhile (for example a logout); abort does not recreate it.
    std::fs::remove_file(env.paths.claude_credentials_file()).unwrap();
    let (ok, text) = env.run(&["--abort", "me"], "");
    assert!(ok, "{text}");
    assert!(text.contains("claudectl use me"), "{text}");
    assert!(
        !env.paths.claude_credentials_file().exists(),
        "abort wrote the live login"
    );
    let restored = profile::get_profile_from(&env.paths, "me")
        .unwrap()
        .read_credentials()
        .unwrap();
    // The profile gets the fenced live grant, the newest copy of the account.
    assert_eq!(
        restored.claude_ai_oauth.refresh_token.as_deref(),
        Some("live-refresh")
    );
    assert!(!env.fenced("me"));
}

#[test]
fn abort_leaves_a_login_made_after_the_fence_untouched() {
    let env = Env::new();
    env.live("me", "u-me-0000", "live");
    env.script("me", Script::Down);
    let (_, text) = env.run(&["--all", "--exclusive-owner"], "");
    assert!(env.fenced("me"), "{text}");
    // Another login lands while the fence holds.
    let newer = serde_json::to_string(&creds("newer", 3_600_000)).unwrap();
    private_write(&env.paths.claude_credentials_file(), &newer);
    let (ok, text) = env.run(&["--abort", "me"], "");
    assert!(ok, "{text}");
    assert_eq!(
        std::fs::read_to_string(env.paths.claude_credentials_file()).unwrap(),
        newer
    );
    assert!(env.has_credentials("me"));
    assert!(!env.fenced("me"));
}

#[test]
fn a_profile_refresh_holds_no_lock_during_the_network_call() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, -1_000);
    env.fake.lock().unwrap().lock_path = Some(env.paths.claudectl_dir().join("auth-state.lock"));
    let (ok, text) = env.all();
    assert!(ok, "{text}");
    assert_eq!(
        env.fake.lock().unwrap().lock_held_during_refresh,
        Some(false),
        "auth-state.lock was held during the provider call"
    );
}

#[test]
fn a_profile_changed_during_its_refresh_is_not_overwritten() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, -1_000);
    let file = env.paths.profiles_dir().join("a1").join("credentials.json");
    let other = serde_json::to_string(&creds("relogin", 3_600_000)).unwrap();
    env.fake.lock().unwrap().rewrite = Some((file.clone(), other));
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("refused"), "{text}");
    let kept: CredentialsFile = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(kept.claude_ai_oauth.access_token, "relogin-access");
    assert!(!env.fenced("a1"));
    // The provider rotated the old grant: its successor must stay recoverable.
    let recovery = env
        .paths
        .claudectl_dir()
        .join("server/refresh-recovery/a1.json");
    let saved: CredentialsFile =
        serde_json::from_slice(&std::fs::read(&recovery).unwrap()).unwrap();
    assert_eq!(
        saved.claude_ai_oauth.refresh_token.as_deref(),
        Some("rotated-refresh")
    );
}

#[test]
fn migrate_all_without_the_exclusive_owner_statement_fences_nothing() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    let (ok, text) = env.run(&["--all"], "");
    assert!(!ok, "{text}");
    assert!(text.contains("--exclusive-owner"), "{text}");
    assert!(!env.fenced("a1"));
    assert!(env.has_credentials("a1"));
    assert_eq!(env.imports(), 0);
}

#[test]
fn a_stale_live_credentials_file_refuses_only_the_live_account_and_fences_nothing() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    env.live("me", "u-me-0000", "stale");
    // macOS: Claude Code refreshed only the Keychain; the file still holds the older grant.
    let keychain = env.home.path().join("keychain-grant.json");
    private_write(
        &keychain,
        &serde_json::to_string(&creds("newer", 3_600_000)).unwrap(),
    );
    let (ok, text) = env.run_with(
        &["--all", "--exclusive-owner"],
        "",
        &[("CLAUDECTL_TEST_KEYCHAIN_GRANT", keychain.as_path())],
    );
    assert!(!ok, "{text}");
    let row = Env::row(&text, "me");
    assert!(row.contains("nothing was fenced"), "{text}");
    assert!(row.contains("claudectl use me"), "{text}");
    assert!(!env.fenced("me"));
    assert!(env.paths.claude_credentials_file().exists());
    assert!(Env::row(&text, "a1").contains("migrated"), "{text}");
}

#[test]
fn abort_refuses_a_fence_of_another_server_or_user() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Down, 3_600_000);
    let (_, text) = env.all();
    assert!(env.fenced("a1"), "{text}");
    // The machine is now connected as another company user; that server knows no admission.
    let dir = env.paths.claudectl_dir().join("server");
    private_write(
        &dir.join("connection.json"),
        &json!({"server":env.origin,"user_id":"someone-else","token_file":dir.join("machine.json")})
            .to_string(),
    );
    let (ok, text) = env.run(&["--abort", "a1"], "");
    assert!(!ok, "{text}");
    assert!(text.contains("another server or user"), "{text}");
    assert!(env.fenced("a1"));
    assert!(!env.has_credentials("a1"));
}

#[test]
fn an_unreadable_sibling_with_the_same_grant_blocks_the_refresh() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, -1_000);
    env.profile("b2", "u-b2-0000", Script::Ok, 3_600_000);
    // b2 cannot be read, so nobody can tell whether it shares a1's grant.
    let b2 = env.paths.profiles_dir().join("b2").join("credentials.json");
    std::fs::write(&b2, "not json").unwrap();
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("refused"), "{text}");
    assert_eq!(
        env.fake.lock().unwrap().refreshes,
        0,
        "the grant was rotated"
    );
    assert!(!env.fenced("a1"));
}

#[test]
fn an_active_profile_with_the_same_grant_blocks_the_refresh() {
    let env = Env::new();
    // b2 is the selected profile; the live login has since moved to a newer grant.
    env.live("b2", "u-b2-0000", "b2-live-newer");
    env.profile("a1", "u-a1-0000", Script::Ok, -1_000);
    // a1's saved copy holds b2's saved grant: rotating it would strand b2.
    private_write(
        &env.paths.profiles_dir().join("a1").join("credentials.json"),
        &serde_json::to_string(&creds("b2", -1_000)).unwrap(),
    );
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("refused"), "{text}");
    assert_eq!(
        env.fake.lock().unwrap().refreshes,
        0,
        "the grant was rotated"
    );
    assert!(!env.fenced("a1"));
}

#[test]
fn a_malformed_receipt_reply_halts_the_run() {
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, 3_600_000);
    env.profile("b2", "u-b2-0000", Script::Ok, 3_600_000);
    env.fake.lock().unwrap().garbage_receipts = true;
    let (ok, text) = env.all();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "b2").contains("not-attempted"), "{text}");
    assert!(!env.fenced("b2"));
}

#[test]
fn a_refreshed_grant_that_cannot_be_saved_is_kept_in_a_private_recovery_file() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new();
    env.profile("a1", "u-a1-0000", Script::Ok, -1_000);
    let dir = env.paths.profiles_dir().join("a1");
    let file = dir.join("credentials.json");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (ok, text) = env.all();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(!ok, "{text}");
    assert!(Env::row(&text, "a1").contains("refused"), "{text}");
    assert_eq!(env.fake.lock().unwrap().refreshes, 1);
    let kept = env
        .paths
        .claudectl_dir()
        .join("server/refresh-recovery/a1.json");
    let saved: CredentialsFile = serde_json::from_slice(&std::fs::read(&kept).unwrap()).unwrap();
    assert_eq!(
        saved.claude_ai_oauth.refresh_token.as_deref(),
        Some("rotated-refresh")
    );
    assert_eq!(
        std::fs::metadata(&kept).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(!env.fenced("a1"));
}
