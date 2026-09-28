//! Shared request policy for the usage endpoint. No credential values are stored.
use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::{self, UsageHttpError, UsageResponse};

pub const CACHE_SECONDS: i64 = 300;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum FetchMode {
    #[default]
    Normal,
    Refresh,
    Cached,
}

#[derive(Clone, Default)]
pub struct Snapshot {
    pub usage: Option<UsageResponse>,
    pub fetched_at: Option<i64>,
    pub next_fetch_at: Option<i64>,
    pub source: &'static str,
    pub error: Option<String>,
    pub fresh: bool,
    pub valid_until: Option<i64>,
}

impl Snapshot {
    pub fn is_fresh_at(&self, now: i64) -> bool {
        self.fresh
            && self.fetched_at.is_some_and(|at| now >= at)
            && self.valid_until.is_some_and(|until| now < until)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Entry {
    usage: Option<UsageResponse>,
    fetched_at: Option<i64>,
    next_attempt: i64,
    failures: u32,
    error: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    entries: BTreeMap<String, Entry>,
    rate_until: i64,
    rate_failures: u32,
    next_request_ms: i64,
}

/// The OS releases this lock even if the process is killed. A contender fails
/// promptly instead of starting a second batch or waiting behind a network call.
pub struct UsageCache {
    _lock: File,
    dir: PathBuf,
    state: State,
    endpoint: String,
    request_spacing: Duration,
    checked: HashSet<String>,
}

impl UsageCache {
    pub fn open(root: &Path) -> Result<Self> {
        let dir = root.join("usage");
        std::fs::create_dir_all(&dir).context("cannot create usage cache directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let mut options = File::options();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options
            .open(dir.join("request.lock"))
            .context("cannot open usage request lock")?;
        lock.try_lock().context(
            "usage check already in progress or lock unavailable; retry after it finishes",
        )?;
        let state = match std::fs::read(dir.join("cache-v1.json")) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).context("invalid usage cache; no requests sent")?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e).context("cannot read usage cache; no requests sent"),
        };
        Ok(Self {
            _lock: lock,
            dir,
            state,
            endpoint: api::USAGE_URL.into(),
            request_spacing: Duration::from_secs(1),
            checked: HashSet::new(),
        })
    }

    fn save(&self) -> Result<()> {
        let mut file =
            tempfile::NamedTempFile::new_in(&self.dir).context("cannot create usage cache file")?;
        file.write_all(&serde_json::to_vec(&self.state)?)?;
        file.as_file().sync_all()?;
        file.persist(self.dir.join("cache-v1.json"))
            .context("cannot save usage cache; request result not persisted")?;
        Ok(())
    }

    /// Use a token digest to isolate identities, including aliases that are reused
    /// or live credentials changed outside claudectl. Never store the token itself.
    pub fn key(access_token: &str) -> String {
        format!("{:x}", Sha256::digest(access_token.as_bytes()))
    }

    fn snapshot(&self, key: &str, now: i64) -> Snapshot {
        let entry = self.state.entries.get(key);
        let fetched_at = entry.and_then(|e| e.fetched_at);
        let usage = entry.and_then(|e| e.usage.clone());
        let valid_until = fetched_at.map(|at| {
            let reset = usage
                .as_ref()
                .into_iter()
                .flat_map(|u| {
                    [
                        &u.five_hour,
                        &u.seven_day,
                        &u.seven_day_opus,
                        &u.seven_day_sonnet,
                    ]
                })
                .filter_map(|w| w.as_ref().and_then(|w| w.reset_timestamp()))
                .filter(|reset| *reset > at)
                .min()
                .unwrap_or(i64::MAX);
            at.saturating_add(CACHE_SECONDS).min(reset)
        });
        let fresh =
            fetched_at.is_some_and(|at| now >= at) && valid_until.is_some_and(|until| now < until);
        let next_attempt = entry
            .map_or(0, |e| e.next_attempt)
            .max(self.state.rate_until);
        let successful = fresh && entry.is_some_and(|e| e.error.is_none());
        let error = if self.state.rate_until > now && !successful {
            Some("shared HTTP 429 delay; no request sent".into())
        } else {
            entry.and_then(|e| e.error.clone())
        };
        Snapshot {
            usage,
            fetched_at,
            next_fetch_at: Some(next_attempt.max(if fresh {
                valid_until.unwrap_or(now)
            } else {
                0
            })),
            source: if self.state.rate_until > now && !successful {
                "cooldown"
            } else {
                "cached"
            },
            error,
            fresh,
            valid_until,
        }
    }

    pub fn should_request(&self, token: &str, mode: FetchMode, now: i64) -> bool {
        let key = Self::key(token);
        let snapshot = self.snapshot(&key, now);
        mode != FetchMode::Cached
            && !self.checked.contains(&key)
            && self.state.rate_until <= now
            && !self
                .state
                .entries
                .get(&key)
                .is_some_and(|e| e.next_attempt > now)
            && (mode == FetchMode::Refresh || !snapshot.fresh || snapshot.error.is_some())
    }

    pub async fn get(
        &mut self,
        client: &reqwest::Client,
        token: &str,
        mode: FetchMode,
        now: i64,
    ) -> Result<Snapshot> {
        let started = std::time::Instant::now();
        let key = Self::key(token);
        let snapshot = self.snapshot(&key, now);
        let blocked = self.state.rate_until > now
            || self
                .state
                .entries
                .get(&key)
                .is_some_and(|e| e.next_attempt > now);
        if mode == FetchMode::Cached
            || self.checked.contains(&key)
            || blocked
            || (mode == FetchMode::Normal && snapshot.fresh && snapshot.error.is_none())
        {
            return Ok(snapshot);
        }
        let wait_ms = self
            .state
            .next_request_ms
            .saturating_sub(chrono::Utc::now().timestamp_millis());
        if wait_ms > 0 {
            tokio::time::sleep(Duration::from_millis(
                (wait_ms as u64).min(self.request_spacing.as_millis() as u64),
            ))
            .await;
        }
        self.checked.insert(key.clone());
        let result = api::fetch_usage_at(client, token, &self.endpoint).await;
        self.state.next_request_ms = chrono::Utc::now()
            .timestamp_millis()
            .saturating_add(self.request_spacing.as_millis() as i64);
        let now = now.saturating_add(started.elapsed().as_secs() as i64);
        match result {
            Ok(usage) => {
                self.state.entries.insert(
                    key.clone(),
                    Entry {
                        usage: Some(usage),
                        fetched_at: Some(now),
                        ..Entry::default()
                    },
                );
                self.state.rate_failures = 0;
                self.state.rate_until = 0;
            }
            Err(error) => self.record_failure(&key, &error, now, "usage"),
        }
        self.prune(now);
        self.save()?;
        let mut snapshot = self.snapshot(&key, now);
        if snapshot.error.is_none() {
            snapshot.source = "live";
        } else {
            snapshot.source = "failed";
            snapshot.error = self.state.entries.get(&key).and_then(|e| e.error.clone());
        }
        Ok(snapshot)
    }
    pub fn refresh_succeeded(&mut self, grant: &str) -> Result<()> {
        if self
            .state
            .entries
            .remove(&format!("refresh:{}", Self::key(grant)))
            .is_some()
        {
            self.save()?;
        }
        Ok(())
    }

    pub fn refresh_failed_for_grant(
        &mut self,
        token: &str,
        grant: &str,
        error: &anyhow::Error,
        now: i64,
    ) -> Result<Snapshot> {
        let key = format!("refresh:{}", Self::key(grant));
        if self.checked.insert(key.clone()) {
            self.record_failure(&key, error, now, "token refresh");
        }
        let mut snapshot = self.refresh_failed(token, error, now)?;
        if let Some(entry) = self.state.entries.get(&key) {
            snapshot.next_fetch_at =
                Some(snapshot.next_fetch_at.unwrap_or(0).max(entry.next_attempt));
        }
        Ok(snapshot)
    }

    pub fn refresh_cooldown(&self, token: &str, grant: &str, now: i64) -> Option<Snapshot> {
        let key = format!("refresh:{}", Self::key(grant));
        let entry = self.state.entries.get(&key)?;
        if entry.next_attempt <= now {
            return None;
        }
        let mut snapshot = self.snapshot(&Self::key(token), now);
        snapshot.error = entry.error.clone();
        snapshot.next_fetch_at = Some(snapshot.next_fetch_at.unwrap_or(0).max(entry.next_attempt));
        snapshot.source = "cooldown";
        Some(snapshot)
    }

    pub fn refresh_failed(
        &mut self,
        token: &str,
        error: &anyhow::Error,
        now: i64,
    ) -> Result<Snapshot> {
        let key = Self::key(token);
        if self.checked.insert(key.clone()) {
            self.record_failure(&key, error, now, "token refresh");
            self.prune(now);
            self.save()?;
        }
        let mut snapshot = self.snapshot(&key, now);
        snapshot.source = "failed";
        snapshot.error = self.state.entries.get(&key).and_then(|e| e.error.clone());
        Ok(snapshot)
    }

    fn prune(&mut self, now: i64) {
        let cutoff = now.saturating_sub(86400);
        self.state.entries.retain(|_, entry| {
            entry.next_attempt >= cutoff || entry.fetched_at.is_some_and(|at| at >= cutoff)
        });
    }

    fn record_failure(&mut self, key: &str, error: &anyhow::Error, now: i64, stage: &str) {
        let entry = self.state.entries.entry(key.into()).or_default();
        entry.failures = entry.failures.saturating_add(1);
        entry.error = Some(format!("{stage} failed (network or invalid response)"));
        let mut retry_after = 0;
        let mut server_error = false;
        if let Some(http) = error.downcast_ref::<UsageHttpError>() {
            server_error = true;
            retry_after = http
                .retry_after
                .map(|n| n.min(i64::MAX as u64) as i64)
                .unwrap_or(0);
            entry.error = Some(match http.status {
                401 => format!("{stage}: authentication rejected (HTTP 401)"),
                403 => format!("{stage}: access denied (HTTP 403)"),
                code => format!("{stage} fetch failed (HTTP {code})"),
            });
            if http.status == 429 && stage == "usage" {
                self.state.rate_failures = self.state.rate_failures.saturating_add(1);
                let delay = http
                    .retry_after
                    .map(|n| n.min(i64::MAX as u64) as i64)
                    .unwrap_or(0)
                    .max(backoff(self.state.rate_failures));
                self.state.rate_until = now.saturating_add(delay);
            }
        }
        let retry_at = if server_error {
            now.saturating_add(backoff(entry.failures).max(retry_after))
        } else {
            now
        };
        entry.next_attempt = self.state.rate_until.max(retry_at);
    }
}

fn backoff(failures: u32) -> i64 {
    (300_i64 * 2_i64.pow(failures.saturating_sub(1).min(4))).min(3600)
}

#[cfg(test)]
mod tests;
