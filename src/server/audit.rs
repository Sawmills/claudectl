//! Audit trail: one line per migrate, issue, refresh, and revoke.
//! A line names the operation, machine, account digest, and result, never a token.
//! Each line goes to stderr and, sealed with the vault key, to a daily file.
use super::{fs, vault};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::Value;
use std::{io::Write, path::Path};

#[derive(Serialize)]
pub struct Event<'a> {
    pub operation: &'static str,
    pub machine: &'a str,
    pub account: &'a str,
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated: Option<bool>,
    /// The revoked machine, for a machine revoke.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<&'a str>,
}

/// An audit write failure fails the operation it records.
pub fn record(state: &Path, key: &Path, event: &Event) -> Result<()> {
    let mut line = serde_json::to_value(event)?;
    line["at"] = chrono::Utc::now().to_rfc3339().into();
    eprintln!("{}", serde_json::json!({"audit": line}));
    let directory = state.join("audit");
    fs::ensure_private_dir(&directory)?;
    let sealed = STANDARD.encode(vault::encrypt(key, &serde_json::to_vec(&line)?)?);
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let path = directory.join(format!("{}.log", chrono::Utc::now().format("%Y-%m-%d")));
    let mut file = options.open(path).context("audit log unavailable")?;
    file.write_all(format!("{sealed}\n").as_bytes())?;
    file.sync_data()?;
    Ok(())
}

/// Decrypt every audit line, oldest file first.
pub fn read(state: &Path, key: &Path) -> Result<Vec<Value>> {
    let mut files: Vec<_> = std::fs::read_dir(state.join("audit"))?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    files.sort();
    let mut events = Vec::new();
    for file in files {
        for line in String::from_utf8(vault::private_read(&file)?)?.lines() {
            let bytes = STANDARD.decode(line).context("audit line is not base64")?;
            events.push(serde_json::from_slice(&vault::decrypt(key, &bytes)?)?);
        }
    }
    Ok(events)
}
