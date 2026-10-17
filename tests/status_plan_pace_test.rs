//! Status output from synthetic cached observations; no provider or Keychain calls.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

fn write_json(path: &Path, value: Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, value.to_string()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn server(home: &Path, alias: &str, data: Value) {
    server_at(home, alias, data, chrono::Utc::now().timestamp_millis());
}

fn server_at(home: &Path, alias: &str, data: Value, observed_at: i64) {
    let root = home.join(".claudectl/server");
    write_json(
        &root.join("connection.json"),
        json!({
            "server":"https://synthetic.invalid", "user_id":"person", "token_file":root.join("machine.json")
        }),
    );
    let now = chrono::Utc::now().timestamp_millis();
    let digest = format!("{:x}", Sha256::digest(alias.as_bytes()));
    write_json(
        &root.join("status").join(format!("{digest}.json")),
        json!({
            "server":"https://synthetic.invalid", "user_id":"person",
            "account":{"provider":"anthropic", "account_id":"a".repeat(64), "alias":alias,
                "identity":{"account_uuid":"a", "organization_uuid":"o"}, "available":true},
        "usage":{"data":data, "observed_at":observed_at, "next_retry_at":now+300_000, "stale":false, "error":null}
        }),
    );
}

fn status(home: &Path, json: bool) -> String {
    let mut cmd = assert_cmd::Command::cargo_bin("claudectl").unwrap();
    cmd.env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin");
    cmd.args(["status", "--cached"]);
    if json {
        cmd.arg("--json");
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn server_plan_reaches_status_table_and_json() {
    let home = tempfile::tempdir().unwrap();
    server(
        home.path(),
        "work",
        json!({"subscription_type":"max",
        "five_hour":{"utilization":5}, "extra_usage":{"is_enabled":false}}),
    );
    let table = status(home.path(), false);
    let row = table
        .lines()
        .find(|l| l.split_whitespace().any(|w| w == "work"))
        .unwrap();
    assert!(row.contains("Max"), "{table}");
    let report: Value = serde_json::from_str(&status(home.path(), true)).unwrap();
    assert_eq!(report["server"]["accounts"][0]["plan"], "max");
}

#[cfg(target_os = "linux")] // Local credentials use the real Keychain on Darwin.
#[test]
fn local_plan_is_the_subscription_type_instead_of_storage_location() {
    let home = tempfile::tempdir().unwrap();
    let profile = home.path().join(".claudectl/profiles/local-work");
    write_json(
        &profile.join("account.json"),
        json!({"alias":"local-work", "saved_at":"2026-10-17T00:00:00Z"}),
    );
    write_json(
        &profile.join("credentials.json"),
        json!({"claudeAiOauth":{
            "accessToken":"synthetic", "expiresAt":chrono::Utc::now().timestamp_millis()+3_600_000,
            "subscriptionType":"team"
        }}),
    );
    let table = status(home.path(), false);
    let row = table
        .lines()
        .find(|l| l.split_whitespace().any(|w| w == "local-work"))
        .unwrap();
    assert!(row.split_whitespace().any(|w| w == "Team"), "{table}");
    let report: Value = serde_json::from_str(&status(home.path(), true)).unwrap();
    assert_eq!(report["accounts"][0]["plan"], "team");
}

#[test]
fn weekly_pace_shows_signed_points_ahead_and_behind() {
    let home = tempfile::tempdir().unwrap();
    let reset = chrono::Utc::now() + chrono::Duration::days(3) + chrono::Duration::hours(12);
    for (alias, used) in [("fast", 75), ("slow", 25)] {
        server(
            home.path(),
            alias,
            json!({"subscription_type":"pro",
            "seven_day":{"utilization":used, "resets_at":reset.to_rfc3339()}}),
        );
    }
    let table = status(home.path(), false);
    assert!(table.lines().next().unwrap().contains("Pace"), "{table}");
    assert!(
        table.contains("+25 ahead") && table.contains("-25 behind"),
        "{table}"
    );
    let report: Value = serde_json::from_str(&status(home.path(), true)).unwrap();
    let accounts = report["server"]["accounts"].as_array().unwrap();
    assert!((accounts[0]["pace_points"].as_f64().unwrap() - 25.0).abs() < 0.01);
    assert!((accounts[1]["pace_points"].as_f64().unwrap() + 25.0).abs() < 0.01);
}

#[test]
fn pace_stays_unknown_for_stale_missing_or_invalid_weekly_observations() {
    let now = chrono::Utc::now();
    let half_week = now + chrono::Duration::hours(84);
    for (data, age_ms) in [
        (json!({}), 0),
        (json!({"seven_day":{"utilization":25}}), 0),
        (json!({"seven_day":{"resets_at":half_week.to_rfc3339()}}), 0),
        (
            json!({"seven_day":{"utilization":101,"resets_at":half_week.to_rfc3339()}}),
            0,
        ),
        (
            json!({"seven_day":{"utilization":-1,"resets_at":half_week.to_rfc3339()}}),
            0,
        ),
        (
            json!({"seven_day":{"utilization":25,"resets_at":(now-chrono::Duration::seconds(1)).to_rfc3339()}}),
            0,
        ),
        (
            json!({"seven_day":{"utilization":25,"resets_at":(now+chrono::Duration::days(8)).to_rfc3339()}}),
            0,
        ),
        (
            json!({"seven_day":{"utilization":25,"resets_at":"invalid"}}),
            0,
        ),
        (
            json!({"seven_day":{"utilization":25,"resets_at":half_week.to_rfc3339()}}),
            3_600_000,
        ),
    ] {
        let home = tempfile::tempdir().unwrap();
        server_at(home.path(), "work", data, now.timestamp_millis() - age_ms);
        let table = status(home.path(), false);
        assert!(!table.lines().next().unwrap().contains("Pace"), "{table}");
        let report: Value = serde_json::from_str(&status(home.path(), true)).unwrap();
        assert!(
            report["server"]["accounts"][0]["pace_points"].is_null(),
            "{report}"
        );
    }
}

#[test]
fn pace_keeps_unknown_cells_when_another_account_has_weekly_data() {
    let home = tempfile::tempdir().unwrap();
    server(home.path(), "missing", json!({"subscription_type":"team"}));
    server(
        home.path(),
        "known",
        json!({"seven_day":{"utilization":50,
        "resets_at":(chrono::Utc::now()+chrono::Duration::hours(84)).to_rfc3339()}}),
    );
    let table = status(home.path(), false);
    assert!(table.lines().next().unwrap().contains("Pace"), "{table}");
    assert!(table.contains("0 on pace"), "{table}");
    let report: Value = serde_json::from_str(&status(home.path(), true)).unwrap();
    assert!(report["server"]["accounts"][1]["pace_points"].is_null());
}
