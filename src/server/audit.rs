//! Audit trail: one line per migrate, issue, refresh, revoke, finished login or renewal,
//! dashboard action, and Google sign-in the provider answered.
//! A line names the operation, machine, account digest, and result, never a token.
//! Each line goes to stderr and, sealed with the vault key, to the store.
use super::{store::Store, vault};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

/// The audit row could not be stored. Callers report it as `audit_unavailable` and never
/// answer success without the row.
#[derive(Debug)]
pub struct AuditUnavailable;
impl std::fmt::Display for AuditUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("audit log unavailable")
    }
}
impl std::error::Error for AuditUnavailable {}

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
    /// Why a refresh ran (`forced`, `expired`, `migration`, `margin`), or why a sign-in was
    /// refused (`sso_denied`, `company_identity_required`, `user_not_allowed`,
    /// `user_unavailable`, `persistence_failed`), or `retry` for a login or renewal line
    /// written by a retry that returned the kept receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    /// Who acted in the browser dashboard (`dashboard:<email>`); machine requests have none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<&'a str>,
}

/// An audit write failure fails the operation it records.
pub async fn record(store: &Store, key: &Path, event: &Event<'_>) -> Result<()> {
    let line = line(event)?;
    eprintln!("{}", serde_json::json!({"audit": line}));
    store
        .append_audit(&vault::encrypt(key, &serde_json::to_vec(&line)?)?)
        .await
        .context(AuditUnavailable)
}

/// Append an audit row once for a pending reset request. The store owns the scoped atomic
/// dedupe marker, so this path never scans or decrypts another user's audit rows.
pub async fn record_idempotent(
    store: &Store,
    key: &Path,
    event: &Event<'_>,
    user: &str,
    organization: &str,
    request_id: &str,
) -> Result<()> {
    let mut stored = line(event)?;
    stored["request_id"] = request_id.into();
    let mut displayed = stored.clone();
    displayed
        .as_object_mut()
        .expect("audit event is an object")
        .remove("request_id");
    let inserted = store
        .append_audit_idempotent(
            &vault::encrypt(key, &serde_json::to_vec(&stored)?)?,
            user,
            organization,
            event.account,
            request_id,
        )
        .await
        .context(AuditUnavailable)?;
    if inserted {
        eprintln!("{}", serde_json::json!({"audit": displayed}));
    }
    Ok(())
}

fn line(event: &Event<'_>) -> Result<Value> {
    let mut line = serde_json::to_value(event)?;
    line["at"] = chrono::Utc::now().to_rfc3339().into();
    Ok(line)
}

/// Decrypt every audit line, oldest first.
pub async fn read(store: &Store, key: &Path) -> Result<Vec<Value>> {
    let mut events = Vec::new();
    for sealed in store.audit().await? {
        events.push(serde_json::from_slice(&vault::decrypt(key, &sealed)?)?);
    }
    Ok(events)
}
