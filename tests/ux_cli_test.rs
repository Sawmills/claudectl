//! The phase 1 command surface (SAW-12677): no-args status, top-level run/add/renew/rm,
//! hidden internal commands that still work. No server and no real Claude.
use assert_cmd::Command;

struct Home(tempfile::TempDir);
impl Home {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::cargo_bin("claudectl")
            .unwrap()
            .args(args)
            .env("HOME", self.0.path())
            .env_remove("CLAUDE_CONFIG_DIR")
            .write_stdin("")
            .output()
            .unwrap()
    }
}
fn out(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}
/// The command names a help page lists, one per line after "Commands:".
fn listed(help: &str) -> Vec<String> {
    help.lines()
        .skip_while(|l| !l.starts_with("Commands:"))
        .skip(1)
        .take_while(|l| l.starts_with("  "))
        .filter_map(|l| l.split_whitespace().next().map(String::from))
        .collect()
}

#[test]
fn the_top_level_help_leads_with_the_daily_commands() {
    let home = Home::new();
    let help = out(&home.run(&["--help"]));
    let commands = listed(&help);
    for wanted in ["run", "status", "add", "renew", "rm"] {
        assert!(
            commands.contains(&wanted.to_string()),
            "{wanted} missing: {commands:?}"
        );
    }
    assert!(
        !commands.contains(&"statusline".to_string()),
        "{commands:?}"
    );
    // `run` comes first: it is the daily job.
    assert_eq!(
        commands.first().map(String::as_str),
        Some("run"),
        "{commands:?}"
    );
}

#[test]
fn internal_server_commands_are_hidden_but_still_work() {
    let home = Home::new();
    let commands = listed(&out(&home.run(&["server", "--help"])));
    for hidden in [
        "qualify",
        "refresh-access",
        "complete-login",
        "statusline",
        "hook",
    ] {
        assert!(
            !commands.contains(&hidden.to_string()),
            "{hidden} listed: {commands:?}"
        );
    }
    assert!(commands.contains(&"run".to_string()));
    // Old command lines keep working for scripts.
    for args in [
        &["server", "qualify", "--help"][..],
        &["server", "refresh-access", "--help"],
        &["server", "complete-login", "--help"],
        &["server", "statusline", "--help"],
        &["statusline", "--help"],
        &["server", "run", "--help"],
        &["server", "login", "--help"],
        &["server", "renew", "--help"],
        &["server", "remove", "--help"],
    ] {
        let o = home.run(args);
        assert!(o.status.success(), "{args:?}: {}", out(&o));
    }
}

#[test]
fn no_arguments_shows_the_status_not_the_help() {
    let home = Home::new();
    let o = home.run(&[]);
    assert!(o.status.success(), "{}", out(&o));
    let text = out(&o);
    assert!(!text.contains("Usage:"), "{text}");
    assert!(text.contains("Next:"), "{text}");
}

#[test]
fn every_argument_of_the_daily_commands_has_help_and_run_has_an_example() {
    let home = Home::new();
    for (command, args) in [
        ("run", &["[ACCOUNT]", "--claude"][..]),
        ("add", &["<NAME>", "--no-browser"]),
        ("renew", &["<ACCOUNT>", "--no-browser"]),
        ("rm", &["<ACCOUNT>", "--yes"]),
    ] {
        let help = out(&home.run(&[command, "--help"]));
        for arg in args {
            let line = help
                .lines()
                .find(|l| l.trim_start().starts_with(arg))
                .unwrap_or_else(|| panic!("{command}: {arg} missing\n{help}"));
            assert!(
                line.trim_start().len() > arg.len() + 4,
                "{command}: {arg} has no help: {line:?}"
            );
        }
    }
    let run = out(&home.run(&["run", "--help"]));
    assert!(
        run.contains("Examples:") && run.contains("claudectl run amir2"),
        "{run}"
    );
}

#[test]
fn every_visible_server_command_argument_has_help() {
    let home = Home::new();
    let commands = listed(&out(&home.run(&["server", "--help"])));
    for command in commands.iter().filter(|c| c.as_str() != "help") {
        let help = out(&home.run(&["server", command, "--help"]));
        let args: Vec<&str> = help
            .lines()
            .skip_while(|l| !(l.starts_with("Arguments:") || l.starts_with("Options:")))
            .filter(|l| l.starts_with("  ") && !l.contains("--help"))
            .collect();
        for line in args {
            let trimmed = line.trim_start();
            // "<NAME>  description" or "--flag <V>  description": text after a 2-space gap.
            let described = trimmed
                .split("  ")
                .skip(1)
                .any(|part| !part.trim().is_empty());
            assert!(
                described,
                "server {command}: no help for {trimmed:?}\n{help}"
            );
        }
    }
}

#[test]
fn rm_on_a_machine_without_a_server_refuses_before_it_asks() {
    // With a server, the refusal names the resolved account (tests/ux_names_test.rs).
    let home = Home::new();
    let o = home.run(&["rm", "work"]);
    assert!(!o.status.success());
    assert!(
        out(&o).contains("Try: claudectl server connect"),
        "{}",
        out(&o)
    );
}

#[test]
fn run_on_a_machine_without_a_server_says_how_to_connect() {
    let home = Home::new();
    let o = home.run(&["run"]);
    assert!(!o.status.success());
    assert!(
        out(&o).contains("Try: claudectl server connect"),
        "{}",
        out(&o)
    );
}
