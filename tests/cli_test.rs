use assert_cmd::Command;

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
    assert_eq!(stdout.matches("_claudectl_profiles'").count(), 2);
}
