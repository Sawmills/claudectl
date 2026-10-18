#![cfg(unix)]

#[test]
fn server_image_manifest_validates_the_registry_digest_before_publishing() {
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/server_image_manifest_test.py"
        ))
        .arg("-v")
        .output()
        .expect("run server image manifest protocol tests");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
