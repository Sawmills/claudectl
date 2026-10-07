use claudectl::{
    central::{Access, Account, Identity, session::Session},
    config::Paths,
};
use serde_json::Value;

fn grant(token: &str, generation: u64) -> Access {
    Access {
        provider: "anthropic".into(),
        account_id: "a".repeat(64),
        user_id: "person".into(),
        identity: Identity {
            account_uuid: "claude-account".into(),
            organization_uuid: "claude-org".into(),
        },
        access_token: token.into(),
        expires_at: chrono::Utc::now().timestamp_millis() + 3600000,
        scopes: vec!["user:inference".into(), "user:profile".into()],
        revision: format!("revision-{generation}"),
        generation,
    }
}
#[test]
fn published_tokens_stay_on_one_account_and_child_receives_no_refresh_authority() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(root.path().into());
    let a = grant("synthetic-a", 1);
    let account = Account {
        provider: "anthropic".into(),
        account_id: a.account_id.clone(),
        alias: "work".into(),
        identity: a.identity.clone(),
        available: true,
    };
    let mut session = Session::new(&paths, &account, a.clone()).unwrap();
    let mut wrong = grant("synthetic-foreign", 2);
    wrong.identity.account_uuid = "another-account".into();
    assert!(session.publish(wrong).is_err());
    session.publish(grant("synthetic-b", 2)).unwrap();
    assert!(session.publish(a).is_err());
    let mut command=session.command(std::path::Path::new("/bin/sh"),&["-c".into(),"cat \"$CLAUDE_CONFIG_DIR/settings.json\"; test -z \"${CLAUDE_CODE_OAUTH_REFRESH_TOKEN:-}\"".into()]).unwrap();
    let output = command.output().unwrap();
    assert!(output.status.success());
    let settings: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(settings["env"]["CLAUDE_CODE_OAUTH_TOKEN"], "synthetic-b");
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("refresh")
    );
    let private = session.directory().to_path_buf();
    drop(session);
    assert!(!private.exists());
}

#[test]
fn conversation_storage_cannot_be_reused_for_a_different_verified_identity() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(root.path().into());
    let access = grant("first", 1);
    let mut account = Account {
        provider: "anthropic".into(),
        account_id: access.account_id.clone(),
        alias: "work".into(),
        identity: access.identity.clone(),
        available: true,
    };
    drop(Session::new(&paths, &account, access).unwrap());
    let mut other = grant("different-account", 1);
    other.identity.account_uuid = "foreign-account".into();
    account.identity = other.identity.clone();
    assert!(Session::new(&paths, &account, other).is_err());
}

#[test]
fn session_crash_helper() {
    let Some(home) = std::env::var_os("CLAUDECTL_TEST_SESSION_CRASH") else {
        return;
    };
    let paths = Paths::from_home(home.into());
    let mut access = grant("synthetic-crash", 1);
    access.expires_at = chrono::Utc::now().timestamp_millis() + 500;
    let account = Account {
        provider: "anthropic".into(),
        account_id: access.account_id.clone(),
        alias: "work".into(),
        identity: access.identity.clone(),
        available: true,
    };
    let _session = Session::new(&paths, &account, access).unwrap();
    std::process::exit(0); // An abrupt exit skips the session destructor.
}

#[test]
fn next_launch_retires_expired_abandoned_sessions_but_keeps_live_ones() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().into());
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "session_crash_helper"])
        .env("CLAUDECTL_TEST_SESSION_CRASH", home.path())
        .output()
        .unwrap();
    assert!(child.status.success());
    let abandoned = std::fs::read_dir(paths.claudectl_dir().join("server/sessions"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut access = grant("synthetic-live", 1);
    access.expires_at = chrono::Utc::now().timestamp_millis() + 500;
    let account = Account {
        provider: "anthropic".into(),
        account_id: access.account_id.clone(),
        alias: "work".into(),
        identity: access.identity.clone(),
        available: true,
    };
    let live = Session::new(&paths, &account, access).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(650));
    let _next = Session::new(&paths, &account, grant("synthetic-next", 2)).unwrap();
    assert!(!abandoned.exists());
    assert!(live.directory().exists());
}
