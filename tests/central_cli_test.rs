use assert_cmd::Command;

#[test]
fn cached_server_status_works_offline_without_machine_credentials() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::cargo_bin("claudectl")
        .unwrap()
        .env("HOME", home.path())
        .args(["server", "status", "work", "--cached"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let usage: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(usage["stale"], true);
    assert!(usage["data"].is_null());
}

#[cfg(target_os = "linux")] // CLI uses authoritative Keychain on macOS; no real Keychain in tests.
#[test]
fn lost_import_response_keeps_profile_fenced_and_resumes_from_receipt() {
    use claudectl::{
        api::{CredentialsFile, OauthCreds},
        config::Paths,
        profile,
    };
    use serde_json::json;
    use std::{
        io::{BufRead, Read, Write},
        net::TcpListener,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };
    let home = tempfile::tempdir().unwrap();
    let paths = Paths::from_home(home.path().into());
    let creds = CredentialsFile {
        claude_ai_oauth: OauthCreds {
            access_token: "synthetic-access".into(),
            refresh_token: Some("synthetic-refresh".into()),
            expires_at: Some(chrono::Utc::now().timestamp_millis() + 3600000),
            scopes: vec!["user:inference".into(), "user:profile".into()],
            subscription_type: None,
            rate_limit_tier: None,
            extra: Default::default(),
        },
        extra: Default::default(),
    };
    let saved = profile::save_profile_to(
        &paths,
        "work",
        &creds,
        Some(json!({"accountUuid":"account-a","organizationUuid":"org-a"})),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let dir = paths.claudectl_dir().join("server");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("connection.json"),
        json!({"server":origin,"user_id":"person","token_file":dir.join("machine.json")})
            .to_string(),
    )
    .unwrap();
    std::fs::write(
        dir.join("machine.json"),
        json!("synthetic-machine-token").to_string(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["connection.json", "machine.json"] {
            std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
    }
    let imported = Arc::new(AtomicBool::new(false));
    let witness = imported.clone();
    let server = std::thread::spawn(move || {
        let mut receipt = serde_json::Value::Null;
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut input = std::io::BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            input.read_line(&mut first).unwrap();
            let mut length = 0;
            loop {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some((name, value)) = line.split_once(':')
                    && name.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; length];
            input.read_exact(&mut body).unwrap();
            let (status, body) = if first.starts_with("POST ") {
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["grant"]["refresh_token"], "synthetic-refresh");
                assert_eq!(request["exclusive_owner"], true);
                receipt = json!({"account_id":"a".repeat(64),"identity":{"account_uuid":"account-a","organization_uuid":"org-a"},"migration_id":request["migration_id"]});
                witness.store(true, Ordering::SeqCst);
                ("503 Service Unavailable", "{}".to_owned())
            } else {
                ("200 OK", json!({"receipt":receipt}).to_string())
            };
            write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    let run = || {
        Command::cargo_bin("claudectl")
            .unwrap()
            .env("HOME", home.path())
            .env("CLAUDECTL_ALLOW_INSECURE_LOOPBACK", "1")
            .args(["server", "migrate", "work", "--exclusive-owner"])
            .output()
            .unwrap()
    };
    let first = run();
    assert!(!first.status.success());
    assert!(
        imported.load(Ordering::SeqCst),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(!saved.credentials_path().exists());
    assert!(saved.read_credentials().is_err());
    assert!(saved.write_credentials(&creds).is_err());
    assert!(
        profile::save_profile_to(
            &paths,
            "another-alias",
            &creds,
            saved.meta.oauth_account.clone()
        )
        .is_err()
    );
    profile::delete_profile_from(&paths, "work").unwrap();
    assert!(profile::save_profile_to(&paths, "work", &creds, None).is_err());
    let resumed = run();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(profile::save_profile_to(&paths, "work", &creds, None).is_err());
    server.join().unwrap();
    // No client refresh copy survives the receipt, including the migration journal.
    fn no_refresh(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                no_refresh(&path)
            } else {
                assert!(
                    !std::fs::read(&path)
                        .unwrap()
                        .windows(b"synthetic-refresh".len())
                        .any(|w| w == b"synthetic-refresh")
                );
            }
        }
    }
    no_refresh(&paths.claudectl_dir());
}
