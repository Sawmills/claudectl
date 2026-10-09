use assert_cmd::Command;

#[test]
fn status_reports_missing_token_separately_from_expiry() {
    let home = tempfile::tempdir().unwrap();
    let profile = home.path().join(".claudectl/profiles/missing");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(
        profile.join("account.json"),
        r#"{"alias":"missing","saved_at":"2026-09-04T00:00:00Z"}"#,
    )
    .unwrap();
    std::fs::write(
        profile.join("credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":""}}"#,
    )
    .unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["status", "--details"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("Usage checked at"));
    assert!(stdout.contains("Token expiry"));
    assert!(stdout.contains("Usage fetch"));
    assert!(stdout.contains("unknown"));
    assert!(stdout.contains("missing access token; log in again"));

    std::fs::write(
        profile.join("credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"","expiresAt":1}}"#,
    )
    .unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["status", "--details"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("expired"));
    assert!(stdout.contains("missing access token; log in again"));
}

#[test]
fn version_flag_prints_package_version() {
    let expected = format!("claudectl {}\n", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let output = Command::cargo_bin("claudectl")
            .unwrap()
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
    }
}

#[test]
fn version_and_help_do_not_need_writable_home() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("not-a-dir");
    std::fs::write(&home, "").unwrap();
    for flag in ["--version", "--help"] {
        Command::cargo_bin("claudectl")
            .unwrap()
            .env("HOME", &home)
            .arg(flag)
            .assert()
            .success();
    }
}

#[test]
fn help_shows_all_subcommands() {
    let mut cmd = Command::cargo_bin("claudectl").unwrap();
    let output = cmd.arg("--help").output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for subcommand in [
        "status",
        "login",
        "save",
        "use",
        "switch",
        "list",
        "remove",
        "whoami",
        "label",
        "rate",
        "completions",
    ] {
        assert!(stdout.contains(subcommand), "missing {subcommand}");
    }
}

#[test]
fn unknown_subcommand_fails() {
    let mut cmd = Command::cargo_bin("claudectl").unwrap();
    cmd.arg("nonexistent").assert().failure();
}

#[test]
fn completions_emit_profile_completer_for_each_shell() {
    for shell in ["zsh", "bash", "fish"] {
        let mut cmd = Command::cargo_bin("claudectl").unwrap();
        let output = cmd.args(["completions", shell]).output().unwrap();
        assert!(output.status.success(), "{shell} completions failed");
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains(".claudectl/profiles"),
            "{shell} completions missing profile completer"
        );
    }
}

#[test]
fn zsh_completions_wire_alias_args_to_profile_completer() {
    let mut cmd = Command::cargo_bin("claudectl").unwrap();
    let output = cmd.args(["completions", "zsh"]).output().unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("_claudectl_profiles'").count(), 4);
    assert!(stdout.contains("':alias -- Profile alias to label:_claudectl_profiles'"));
}

#[test]
fn fish_completions_offer_aliases_for_the_label_alias_only() {
    let output = |shell: &str| {
        let output = Command::cargo_bin("claudectl")
            .unwrap()
            .args(["completions", shell])
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    };
    assert!(
        output("fish").contains(
            "__fish_seen_subcommand_from label; and test (count (commandline -opc)) -eq 2"
        )
    );
}

#[test]
fn cached_status_needs_no_network_or_saved_profiles() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["status", "--cached"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("No accounts yet")
    );
}

fn saved_profile(home: &std::path::Path, alias: &str) {
    let paths = claudectl::config::Paths::from_home(home.to_path_buf());
    let creds =
        serde_json::from_str(r#"{"claudeAiOauth":{"accessToken":"test-only-cli"}}"#).unwrap();
    claudectl::profile::save_profile_to(&paths, alias, &creds, None).unwrap();
}

#[test]
fn cached_status_filters_before_loading_other_profiles() {
    let home = tempfile::tempdir().unwrap();
    saved_profile(home.path(), "chosen");
    saved_profile(home.path(), "other");
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["status", "chosen", "--cached"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(output.status.success());
    assert!(stdout.contains("chosen"));
    assert!(!stdout.contains("other"));
}

#[test]
fn concurrent_cli_fails_without_starting_another_check() {
    let home = tempfile::tempdir().unwrap();
    saved_profile(home.path(), "chosen");
    let _lock = claudectl::usage_cache::UsageCache::open(&home.path().join(".claudectl")).unwrap();

    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .arg("status")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(
        String::from_utf8(output.stderr)
            .unwrap()
            .contains("usage check already in progress")
    );
}

#[test]
fn cached_and_refresh_flags_conflict() {
    let home = tempfile::tempdir().unwrap();

    Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["status", "--cached", "--refresh"])
        .assert()
        .failure();
}

#[test]
fn status_default_explains_login_without_token_columns() {
    let home = tempfile::tempdir().unwrap();
    saved_profile(home.path(), "missing");
    std::fs::write(
        home.path()
            .join(".claudectl/profiles/missing/credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":""}}"#,
    )
    .unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["status", "--cached"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    // The compact view (SAW-12677): the state, and the fix as the Next line.
    assert!(text.contains("login needed"), "{text}");
    assert!(text.contains("Next: claudectl login 'missing'"), "{text}");
    assert!(!text.contains("Token expiry"), "{text}");
    assert!(!text.contains("Usage fetch"), "{text}");
}

#[test]
fn exec_refuses_the_active_profile_before_any_network_or_child() {
    let home = tempfile::tempdir().unwrap();
    let profile = home.path().join(".claudectl/profiles/work");
    std::fs::create_dir_all(&profile).unwrap();
    std::fs::write(
        profile.join("account.json"),
        r#"{"alias":"work","saved_at":"2026-09-30T00:00:00Z","oauth_account":{"accountUuid":"uuid-work"}}"#,
    )
    .unwrap();
    std::fs::write(
        profile.join("credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"placeholder","refreshToken":"placeholder-r","expiresAt":99999999999999}}"#,
    )
    .unwrap();
    std::fs::write(home.path().join(".claudectl/active"), "work").unwrap();
    let marker = home.path().join("child-ran");
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["exec", "--profile", "work", "--", "/usr/bin/touch"])
        .arg(&marker)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("is the active profile"), "{stderr}");
    assert!(!marker.exists(), "no child may run for the active profile");
}

#[test]
fn exec_requires_a_command_after_the_separator() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["exec", "--profile", "work"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn label_shows_in_list_and_clears() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".claudectl/profiles/work");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("account.json"),
        r#"{"alias":"work","saved_at":"2026-01-01T00:00:00Z","oauth_account":{"emailAddress":"w@x.io"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"t"}}"#,
    )
    .unwrap();
    let run = |args: &[&str]| {
        let output = Command::cargo_bin("claudectl")
            .unwrap()
            .args(args)
            .env("HOME", home.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    };
    assert!(run(&["label", "work", "Team seat"]).contains("labelled 'work' as 'Team seat'"));
    assert!(run(&["list"]).contains("work [Team seat] (w@x.io)"));
    assert!(run(&["label", "work"]).contains("cleared the label of 'work'"));
    assert!(run(&["list"]).contains("  work (w@x.io)"));
}

#[test]
fn bash_completions_offer_aliases_only_for_the_alias_argument() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claudectl/profiles/work")).unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .args(["completions", "bash"])
        .output()
        .unwrap();
    let script = home.path().join("claudectl.bash");
    std::fs::write(&script, output.stdout).unwrap();
    let complete = |words: &str, cword: usize| {
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "source '{}'; COMP_WORDS=({words}); COMP_CWORD={cword}; \
                 _claudectl_with_profiles claudectl \"${{COMP_WORDS[COMP_CWORD]}}\"; \
                 printf '%s\\n' \"${{COMPREPLY[@]}}\"",
                script.display()
            ))
            .env("HOME", home.path())
            .output()
            .unwrap();
        String::from_utf8(output.stdout).unwrap()
    };
    assert!(
        complete("claudectl label ''", 2)
            .lines()
            .any(|w| w == "work")
    );
    assert!(complete("claudectl use ''", 2).lines().any(|w| w == "work"));
    assert!(
        !complete("claudectl label work ''", 3)
            .lines()
            .any(|w| w == "work")
    );
}

#[test]
fn rate_without_lanes_reports_no_activity() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .args(["rate", "--json"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["version"], 1);
    assert_eq!(report["window_minutes"], 10);
    assert_eq!(report["accounts"], serde_json::json!([]));
    assert_eq!(report["skipped"], 0);
}
