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
fn account_for(access: &Access) -> Account {
    Account {
        provider: "anthropic".into(),
        account_id: access.account_id.clone(),
        alias: "work".into(),
        identity: access.identity.clone(),
        available: true,
    }
}

#[cfg(unix)]
fn hold_command(session: &Session, args: &[&str]) -> std::process::Output {
    let home = session
        .directory()
        .parent()
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .and_then(std::path::Path::parent)
        .expect("session home");
    session
        .command(
            &assert_cmd::cargo::cargo_bin("claudectl"),
            &args
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
        )
        .unwrap()
        .env("HOME", home)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn hold_start_refuses_an_older_running_wrapper_that_cannot_enforce_it() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().to_path_buf());
    let access = grant("synthetic", 1);
    let session = Session::new(&paths, &account_for(&access), access).unwrap();
    let path = session.directory().join("session.json");
    let mut status: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    status
        .as_object_mut()
        .unwrap()
        .remove("restart_gate_version");
    std::fs::write(path, serde_json::to_vec(&status).unwrap()).unwrap();
    let output = hold_command(&session, &["hold", "start", "--reason", "FLT-553 prod"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not support holds"));
    assert!(!home.path().join(".claudectl/server/holds").exists());
}

#[cfg(unix)]
#[test]
fn ending_another_runs_hold_does_not_clear_a_production_hold() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().to_path_buf());
    let access = grant("synthetic", 1);
    let first = Session::new(&paths, &account_for(&access), access.clone()).unwrap();
    let second = Session::new(&paths, &account_for(&access), access).unwrap();
    assert!(
        hold_command(&first, &["hold", "start", "--reason", "FLT-553 prod"])
            .status
            .success()
    );
    assert!(hold_command(&second, &["hold", "end"]).status.success());
    let path = home.path().join(".claudectl/server/holds").join(format!(
        "{}.json",
        first.directory().file_name().unwrap().to_str().unwrap()
    ));
    assert!(path.exists());
    assert!(
        !hold_command(&first, &["hold", "start", "--reason", "another step"])
            .status
            .success()
    );
    assert!(hold_command(&first, &["hold", "end"]).status.success());
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn an_abandoned_hold_survives_run_cleanup_until_explicit_end() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().to_path_buf());
    let access = grant("synthetic", 1);
    let session = Session::new(&paths, &account_for(&access), access).unwrap();
    let run = session
        .directory()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        hold_command(&session, &["hold", "start", "--reason", "FLT-553 prod"])
            .status
            .success()
    );
    drop(session);
    let hold = home
        .path()
        .join(".claudectl/server/holds")
        .join(format!("{run}.json"));
    assert!(hold.exists());
    let output = assert_cmd::Command::cargo_bin("claudectl")
        .unwrap()
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["status", "--cached", "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["sessions"][0]["run"], run);
    assert_eq!(status["sessions"][0]["reason"], "stale_hold");
    assert_eq!(status["sessions"][0]["stage"], "blocked");
    let output = assert_cmd::Command::cargo_bin("claudectl")
        .unwrap()
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", "/usr/bin:/bin")
        .args(["hold", "end", "--run", &run])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!hold.exists());
}

#[cfg(unix)]
#[test]
fn a_stale_hold_overrides_cached_deferred_status_without_losing_its_counter() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().to_path_buf());
    let access = grant("synthetic", 1);
    let session = Session::new(&paths, &account_for(&access), access).unwrap();
    assert!(
        hold_command(&session, &["hold", "start", "--reason", "FLT-553 prod"])
            .status
            .success()
    );
    let run = session.directory().file_name().unwrap().to_str().unwrap();
    let hold = home
        .path()
        .join(".claudectl/server/holds")
        .join(format!("{run}.json"));
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&hold).unwrap()).unwrap();
    saved["owner_started"] = "previous process incarnation".into();
    std::fs::write(&hold, serde_json::to_vec(&saved).unwrap()).unwrap();
    std::fs::write(
        session.directory().join("restart-status.json"),
        serde_json::to_vec(
            &serde_json::json!({"run":run,"session_id":"sess-1","alias":"work",
            "deferred":true,"reason":"explicit_hold","stage":"deferred",
            "restart_deferred_total":7}),
        )
        .unwrap(),
    )
    .unwrap();
    let output = hold_command(&session, &["status", "--cached", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    let row = &status["sessions"][0];
    assert_eq!(row["reason"], "stale_hold");
    assert_eq!(row["stage"], "blocked");
    assert_eq!(row["restart_deferred_total"], 7);
    assert_eq!(row["session_id"], "sess-1");
    assert_eq!(row["run"], run);
    assert!(hold.exists());
}

#[cfg(unix)]
#[test]
fn damaged_restart_diagnostics_report_attention_without_hiding_account_status() {
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().to_path_buf());
    let access = grant("synthetic", 1);
    let session = Session::new(&paths, &account_for(&access), access).unwrap();
    std::fs::write(session.directory().join("restart-status.json"), "damaged").unwrap();
    let output = hold_command(&session, &["status", "--cached", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["sessions"][0]["reason"], "evidence_unknown");
    assert_eq!(status["sessions"][0]["stage"], "blocked");
    assert_eq!(status["sessions"][0]["attention_required"], true);
}

/// Run the launch seam in its own process so PATH tests do not mutate global test state.
#[test]
fn session_path_helper() {
    let Some(home) = std::env::var_os("CLAUDECTL_TEST_SESSION_PATH_HOME") else {
        return;
    };
    let paths = Paths::from_home(home.into());
    let access = grant("synthetic-path", 1);
    let session = Session::new(&paths, &account_for(&access), access).unwrap();
    let output = session
        .command(
            std::path::Path::new("/bin/sh"),
            &["-c".into(), "printf '%s' \"$PATH\"".into()],
        )
        .unwrap()
        .output()
        .unwrap();
    assert!(output.status.success());
    std::fs::write(
        std::env::var_os("CLAUDECTL_TEST_SESSION_PATH_OUT").unwrap(),
        output.stdout,
    )
    .unwrap();
}

#[test]
fn server_sessions_put_existing_lane_bin_first_without_reordering_other_paths() {
    for case in ["present", "absent", "first", "later"] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("user home");
        let lane_bin = home.join(".local/lib/lane-bin");
        if case != "absent" {
            std::fs::create_dir_all(&lane_bin).unwrap();
        }
        let lane = lane_bin.display().to_string();
        let (inherited, expected) = match case {
            "absent" => (
                "/usr/local/bin:/usr/bin:/bin".to_owned(),
                "/usr/local/bin:/usr/bin:/bin".to_owned(),
            ),
            "first" => (
                format!("{lane}:/usr/local/bin:/usr/bin:/bin"),
                format!("{lane}:/usr/local/bin:/usr/bin:/bin"),
            ),
            "later" => (
                format!("/usr/local/bin::{lane}:/usr/bin:{lane}:/bin:/usr/bin"),
                format!("{lane}:/usr/local/bin::/usr/bin:/bin:/usr/bin"),
            ),
            _ => (
                "/usr/local/bin:/usr/bin:/bin".to_owned(),
                format!("{lane}:/usr/local/bin:/usr/bin:/bin"),
            ),
        };
        let out = root.path().join("child-path");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "session_path_helper"])
            .env("CLAUDECTL_TEST_SESSION_PATH_HOME", &home)
            .env("CLAUDECTL_TEST_SESSION_PATH_OUT", &out)
            .env("HOME", &home)
            .env("PATH", inherited)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{case}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(std::fs::read_to_string(out).unwrap(), expected, "{case}");
    }
}

/// SAW-12555: the child keeps the host Claude config (no CLAUDE_CONFIG_DIR), so --resume,
/// skills, hooks and trust work; only the server access token is swapped in, and no refresh
/// authority reaches it.
#[test]
fn the_child_keeps_the_host_config_and_gets_only_the_server_access_token() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(root.path().into());
    let access = grant("synthetic-a", 1);
    let session = Session::new(&paths, &account_for(&access), access).unwrap();
    let mut command = session
        .command(
            std::path::Path::new("/bin/sh"),
            &[
                "-c".into(),
                "printf '%s|%s|%s' \"${CLAUDE_CONFIG_DIR-unset}\" \"$CLAUDE_CODE_OAUTH_TOKEN\" \"${CLAUDE_CODE_OAUTH_REFRESH_TOKEN-unset}\"".into(),
            ],
        )
        .unwrap();
    let output = command.output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "unset|synthetic-a|unset"
    );
    let private = session.directory().to_path_buf();
    assert!(!private.join("settings.json").exists());
    assert!(!private.join("projects").exists());
    drop(session);
    assert!(!private.exists());
}

/// The guard reads when a server tab's token ends, to relaunch it with --resume first.
#[test]
fn a_session_records_its_alias_account_and_token_expiry() {
    let root = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(root.path().into());
    let access = grant("synthetic-a", 1);
    let session = Session::new(&paths, &account_for(&access), access.clone()).unwrap();
    let status: Value =
        serde_json::from_slice(&std::fs::read(session.directory().join("session.json")).unwrap())
            .unwrap();
    assert_eq!(status["alias"], "work");
    assert_eq!(status["account_id"], access.account_id.as_str());
    assert_eq!(status["expires_at"], access.expires_at);
    assert!(
        !String::from_utf8(std::fs::read(session.directory().join("session.json")).unwrap())
            .unwrap()
            .contains("synthetic-a")
    );
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
