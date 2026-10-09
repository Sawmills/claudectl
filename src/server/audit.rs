//! Audit trail: one line per migrate, issue, refresh, and revoke.
//! A line names the operation, machine, account digest, and result, never a token.
//! Each line goes to stderr and, sealed with the vault key, to the store.
use super::{store::Store, vault};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

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
    /// Why a refresh ran: forced, expired, migration or margin.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// Who acted in the browser dashboard (`dashboard:<email>`); machine requests have none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<&'a str>,
}

/// An audit write failure fails the operation it records.
pub async fn record(store: &Store, key: &Path, event: &Event<'_>) -> Result<()> {
    let mut line = serde_json::to_value(event)?;
    line["at"] = chrono::Utc::now().to_rfc3339().into();
    eprintln!("{}", serde_json::json!({"audit": line}));
    store
        .append_audit(&vault::encrypt(key, &serde_json::to_vec(&line)?)?)
        .await
}

/// Decrypt every audit line, oldest first.
pub async fn read(store: &Store, key: &Path) -> Result<Vec<Value>> {
    let mut events = Vec::new();
    for sealed in store.audit().await? {
        events.push(serde_json::from_slice(&vault::decrypt(key, &sealed)?)?);
    }
    Ok(events)
}
