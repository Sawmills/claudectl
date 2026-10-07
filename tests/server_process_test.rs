#![cfg(feature = "server")]
//! The server binary as an operator runs it. No Claude or Codex binary is on PATH.
use assert_cmd::Command;
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn server() -> Command {
    let mut command = Command::cargo_bin("claudectl-server").unwrap();
    command.env("PATH", "");
    command
}

#[test]
fn the_server_starts_alone_reports_ready_and_owns_its_state() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    server()
        .args(["setup", "--state"])
        .arg(&state)
        .arg("--key-file")
        .arg(&key)
        .assert()
        .success();
    let address = format!("127.0.0.1:{}", free_port());
    let serve = |address: &str| {
        let mut command =
            std::process::Command::new(assert_cmd::cargo::cargo_bin("claudectl-server"));
        command
            .env("PATH", "")
            .args(["serve", "--state"])
            .arg(&state)
            .arg("--key-file")
            .arg(&key)
            .args([
                "--listen",
                address,
                "--public-url",
                &format!("http://{address}/"),
            ])
            .args(["--allow-user", "amir@sawmills.ai"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        command.spawn().unwrap()
    };
    let mut first = serve(&address);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = server()
            .args(["health-check", "--address", &address])
            .output()
            .unwrap();
        if ready.status.success() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{}",
            String::from_utf8_lossy(&ready.stderr)
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let second = serve(&format!("127.0.0.1:{}", free_port()))
        .wait_with_output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("another process owns this state"));
    first.kill().unwrap();
    first.wait().unwrap();
}

#[test]
fn a_network_listener_requires_https_and_company_sso() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    server()
        .args(["setup", "--state"])
        .arg(&state)
        .arg("--key-file")
        .arg(&key)
        .assert()
        .success();
    let output = server()
        .args(["serve", "--state"])
        .arg(&state)
        .arg("--key-file")
        .arg(&key)
        .args([
            "--listen",
            "0.0.0.0:0",
            "--public-url",
            "https://claudectl.example.com/",
        ])
        .args(["--allow-user", "amir@sawmills.ai"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("company SSO"));
}

#[test]
fn setup_if_absent_keeps_existing_state_for_a_restarted_pod() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    let setup = |extra: &[&str]| {
        server()
            .args(["setup", "--state"])
            .arg(&state)
            .arg("--key-file")
            .arg(&key)
            .args(extra)
            .output()
            .unwrap()
    };
    assert!(setup(&[]).status.success());
    let (machine, _) = claudectl::server::app::register(&state, "amir@sawmills.ai", "mac").unwrap();
    assert!(!setup(&[]).status.success());
    assert!(setup(&["--if-absent"]).status.success());
    let machines = claudectl::server::vault::machines(&state).unwrap();
    assert_eq!(machines.len(), 1);
    assert_eq!(machines[0].id, machine);
}

#[test]
fn an_operator_revoke_writes_an_audit_line() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let key = root.path().join("key");
    server()
        .args(["setup", "--state"])
        .arg(&state)
        .arg("--key-file")
        .arg(&key)
        .assert()
        .success();
    let (machine, _) = claudectl::server::app::register(&state, "amir@sawmills.ai", "mac").unwrap();
    server()
        .args(["revoke", "--state"])
        .arg(&state)
        .arg("--key-file")
        .arg(&key)
        .args(["--machine", &machine])
        .assert()
        .success();
    let events = claudectl::server::audit::read(&state, &key).unwrap();
    let last = events.last().unwrap();
    assert_eq!(last["operation"], "revoke");
    assert_eq!(last["machine"], "operator");
    assert_eq!(last["target"], machine.as_str());
    assert!(claudectl::server::vault::machines(&state).unwrap()[0].revoked);
}
