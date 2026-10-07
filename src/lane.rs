//! A lane: one long-lived Claude session that can move between saved
//! accounts. Its state lives in `~/.claudectl/lanes/<lane>/`:
//!
//! - `lock`: held while a launcher runs the lane, so two cannot share it.
//! - `accounts.jsonl`: which account ran when, for `rate`.
//! - `config/`: the child's `CLAUDE_CONFIG_DIR`. Only `projects/` (session
//!   transcripts) is kept between runs; everything else is removed, and exec
//!   rebuilds `.claude.json` at every launch keeping only the lane's start-up
//!   decisions, so no account state moves to the next account.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::config::Paths;

/// Session transcripts, kept between runs.
const KEPT: &str = "projects";
/// The last seed. exec carries only its start-up decisions into the next seed
/// and rebuilds the rest, so it is left for exec to replace.
const SEED: &str = ".claude.json";

pub struct Lane {
    root: PathBuf,
    /// Holds the lane lock for the lane's lifetime.
    _lock: std::fs::File,
}

/// A rate-limit API error that Claude Code wrote into a lane transcript.
#[derive(Debug, Clone, PartialEq)]
pub struct RateLimitHit {
    pub uuid: String,
    pub session_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Lane {
    /// Open the lane and take its lock. A lane in use by another launcher is
    /// refused.
    pub fn open(paths: &Paths, name: &str) -> Result<Self> {
        let name = crate::profile::validate_alias(name).context("invalid lane name")?;
        let lanes = paths.claudectl_dir().join("lanes");
        let root = lanes.join(name);
        let config = root.join("config");
        std::fs::create_dir_all(&config)
            .with_context(|| format!("failed to create {}", config.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&lanes, &root, &config] {
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| format!("failed to restrict {}", dir.display()))?;
            }
        }
        let lock_path = root.join("lock");
        let lock = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open {}", lock_path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock only locks the open file.
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                bail!("lane '{name}' is in use by another claudectl claude");
            }
        }
        Ok(Self { root, _lock: lock })
    }

    /// The child's `CLAUDE_CONFIG_DIR`.
    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }

    /// Remove everything in the config directory except `projects/` and the
    /// last `.claude.json`, which exec rebuilds keeping only the start-up
    /// decisions, so a launch on any account starts from no account state.
    pub fn clear_account_state(&self) -> Result<()> {
        let config = self.config_dir();
        for entry in std::fs::read_dir(&config)
            .with_context(|| format!("failed to read {}", config.display()))?
        {
            let entry = entry?;
            if entry.file_name() == KEPT || entry.file_name() == SEED {
                continue;
            }
            let path = entry.path();
            let removed = if entry.file_type()?.is_dir() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            removed.with_context(|| format!("failed to remove {}", path.display()))?;
        }
        Ok(())
    }

    /// Refuse a launch when credentials for the lane exist outside the
    /// inherited token pipe: a `.credentials.json` in the config directory,
    /// or (on macOS) the Keychain item Claude Code would use for it.
    pub fn assert_no_credentials(&self) -> Result<()> {
        let file = self.config_dir().join(".credentials.json");
        if file.exists() {
            bail!(
                "{} holds credentials; remove it before launching the lane",
                file.display()
            );
        }
        #[cfg(target_os = "macos")]
        {
            const NOT_FOUND: i32 = 44;
            let service = keychain_service(&self.config_dir());
            let status = std::process::Command::new("security")
                .args(["find-generic-password", "-s", &service])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .context("failed to run security")?;
            // 44 is security's "item not found". Any other result, including a
            // locked Keychain or denied access, cannot prove there is none.
            match status.code() {
                Some(NOT_FOUND) => {}
                Some(0) => bail!(
                    "the Keychain holds a '{service}' item for this lane; delete it before launching"
                ),
                _ => bail!(
                    "cannot check the Keychain for a '{service}' item ({status}); unlock it and retry"
                ),
            }
        }
        Ok(())
    }

    /// Append one line to the lane's account log.
    pub fn log(&self, event: &str, alias: &str, session_id: Option<&str>) -> Result<()> {
        let path = self.root.join("accounts.jsonl");
        let mut file = std::fs::File::options()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        let line = serde_json::json!({
            "at": chrono::Utc::now().to_rfc3339(),
            "event": event,
            "alias": alias,
            "session_id": session_id,
        });
        writeln!(file, "{line}").with_context(|| format!("failed to write {}", path.display()))
    }

    /// How many `event` lines the lane log holds from the last `within`.
    pub fn recent_events(&self, event: &str, within: chrono::Duration) -> Result<usize> {
        let path = self.root.join("accounts.jsonl");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).with_context(|| format!("failed to read {}", path.display())),
        };
        let since = chrono::Utc::now() - within;
        Ok(text
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|record| record["event"] == event)
            .filter_map(|record| chrono::DateTime::parse_from_rfc3339(record["at"].as_str()?).ok())
            .filter(|at| *at >= since)
            .count())
    }

    /// The newest rate-limit API error for `cwd` at or after `since`, from
    /// the main thread of a session (not a subagent).
    pub fn find_rate_limit(
        &self,
        cwd: &Path,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Option<RateLimitHit> {
        find_rate_limit_in(&self.config_dir(), cwd, since)
    }
}

/// `Lane::find_rate_limit` for a config directory, usable from a watcher
/// thread that does not own the lane.
pub fn find_rate_limit_in(
    config_dir: &Path,
    cwd: &Path,
    since: chrono::DateTime<chrono::Utc>,
) -> Option<RateLimitHit> {
    let cwd = cwd.to_str()?;
    let projects = config_dir.join(KEPT);
    let mut newest: Option<RateLimitHit> = None;
    for project in std::fs::read_dir(projects).ok()?.flatten() {
        let Ok(files) = std::fs::read_dir(project.path()) else {
            continue;
        };
        for file in files.flatten() {
            let path = file.path();
            if path.extension().is_none_or(|ext| ext != "jsonl") {
                continue;
            }
            let modified = file.metadata().and_then(|m| m.modified()).ok();
            if modified.is_some_and(|m| chrono::DateTime::<chrono::Utc>::from(m) < since) {
                continue;
            }
            for hit in rate_limits_in(&path, cwd, since) {
                if newest.as_ref().is_none_or(|n| hit.timestamp > n.timestamp) {
                    newest = Some(hit);
                }
            }
        }
    }
    newest
}

fn rate_limits_in(
    path: &Path,
    cwd: &str,
    since: chrono::DateTime<chrono::Utc>,
) -> Vec<RateLimitHit> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    std::io::BufReader::new(file)
        .lines()
        .map_while(Result::ok)
        .filter(|line| line.contains("\"rate_limit\""))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
        .filter(|record| {
            record["type"] == "assistant"
                && record["error"] == "rate_limit"
                && record["isApiErrorMessage"] == true
                && record["isSidechain"] != true
                && record["cwd"] == cwd
        })
        .filter_map(|record| {
            let timestamp = chrono::DateTime::parse_from_rfc3339(record["timestamp"].as_str()?)
                .ok()?
                .with_timezone(&chrono::Utc);
            (timestamp >= since).then(|| RateLimitHit {
                uuid: record["uuid"].as_str().unwrap_or_default().to_string(),
                session_id: record["sessionId"].as_str().unwrap_or_default().to_string(),
                timestamp,
            })
        })
        .filter(|hit| !hit.session_id.is_empty())
        .collect()
}

/// The Keychain service Claude Code uses for a custom `CLAUDE_CONFIG_DIR`
/// (checked in Claude Code 2.1.292): the default name plus the first 8 hex
/// digits of the SHA-256 of the directory path.
pub fn keychain_service(config_dir: &Path) -> String {
    let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{}", crate::auth_store::KEYCHAIN_SERVICE, &hex[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        (tmp, paths)
    }

    #[test]
    fn a_lane_is_locked_while_open() {
        let (_tmp, paths) = paths();
        let lane = Lane::open(&paths, "lane-a").unwrap();
        assert!(Lane::open(&paths, "lane-a").is_err());
        assert!(Lane::open(&paths, "lane-b").is_ok());
        drop(lane);
        assert!(Lane::open(&paths, "lane-a").is_ok());
        assert!(Lane::open(&paths, "../x").is_err());
    }

    #[test]
    fn clearing_keeps_only_projects() {
        let (_tmp, paths) = paths();
        let lane = Lane::open(&paths, "lane").unwrap();
        let config = lane.config_dir();
        std::fs::create_dir_all(config.join("projects/p")).unwrap();
        std::fs::write(config.join("projects/p/s.jsonl"), "{}").unwrap();
        std::fs::write(config.join(".claude.json"), "{}").unwrap();
        std::fs::create_dir_all(config.join("statsig")).unwrap();
        lane.clear_account_state().unwrap();
        let left: Vec<_> = std::fs::read_dir(&config)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let mut left = left;
        left.sort();
        assert_eq!(left, [".claude.json", "projects"]);
        assert!(config.join("projects/p/s.jsonl").exists());
    }

    #[test]
    fn a_credentials_file_in_the_lane_is_refused() {
        let (_tmp, paths) = paths();
        let lane = Lane::open(&paths, "lane").unwrap();
        std::fs::write(lane.config_dir().join(".credentials.json"), "{}").unwrap();
        assert!(lane.assert_no_credentials().is_err());
    }

    #[test]
    fn keychain_service_matches_claude_code_naming() {
        let expected = {
            let digest = Sha256::digest(b"/tmp/x");
            format!(
                "Claude Code-credentials-{:02x}{:02x}{:02x}{:02x}",
                digest[0], digest[1], digest[2], digest[3]
            )
        };
        assert_eq!(keychain_service(Path::new("/tmp/x")), expected);
    }

    fn record(extra: serde_json::Value) -> String {
        let mut base = serde_json::json!({
            "type": "assistant",
            "error": "rate_limit",
            "isApiErrorMessage": true,
            "isSidechain": false,
            "cwd": "/work",
            "sessionId": "s1",
            "uuid": "u1",
            "timestamp": "2026-10-07T10:00:00Z",
        });
        for (key, value) in extra.as_object().unwrap() {
            base[key] = value.clone();
        }
        base.to_string()
    }

    #[test]
    fn finds_the_newest_main_thread_rate_limit_for_the_cwd() {
        let (_tmp, paths) = paths();
        let lane = Lane::open(&paths, "lane").unwrap();
        let dir = lane.config_dir().join("projects/-work");
        std::fs::create_dir_all(&dir).unwrap();
        let now = chrono::Utc::now();
        let at = |minutes: i64| (now + chrono::Duration::minutes(minutes)).to_rfc3339();
        let lines = [
            record(serde_json::json!({"uuid": "old", "timestamp": at(-120)})),
            record(serde_json::json!({"uuid": "sub", "isSidechain": true, "timestamp": at(-1)})),
            record(serde_json::json!({"uuid": "other", "cwd": "/elsewhere", "timestamp": at(-1)})),
            record(
                serde_json::json!({"uuid": "auth", "error": "authentication_failed", "timestamp": at(-1)}),
            ),
            record(serde_json::json!({"uuid": "hit", "sessionId": "s2", "timestamp": at(-5)})),
        ];
        std::fs::write(dir.join("s.jsonl"), lines.join("\n")).unwrap();
        let since = now - chrono::Duration::minutes(60);
        let hit = lane.find_rate_limit(Path::new("/work"), since).unwrap();
        assert_eq!((hit.uuid.as_str(), hit.session_id.as_str()), ("hit", "s2"));
        assert_eq!(
            lane.find_rate_limit(Path::new("/work"), now),
            None,
            "nothing after now"
        );
    }

    #[test]
    fn recent_events_count_only_the_window() {
        let (_tmp, paths) = paths();
        let lane = Lane::open(&paths, "lane").unwrap();
        assert_eq!(
            lane.recent_events("recovery", chrono::Duration::hours(1))
                .unwrap(),
            0
        );
        lane.log("recovery", "a", Some("s")).unwrap();
        lane.log("start", "a", None).unwrap();
        let log = paths.claudectl_dir().join("lanes/lane/accounts.jsonl");
        let old = serde_json::json!({
            "at": (chrono::Utc::now() - chrono::Duration::hours(2)).to_rfc3339(),
            "event": "recovery", "alias": "a", "session_id": "s",
        });
        let mut text = std::fs::read_to_string(&log).unwrap();
        text.push_str(&format!("{old}\n"));
        std::fs::write(&log, text).unwrap();
        assert_eq!(
            lane.recent_events("recovery", chrono::Duration::hours(1))
                .unwrap(),
            1
        );
    }

    #[test]
    fn the_account_log_appends_json_lines() {
        let (_tmp, paths) = paths();
        let lane = Lane::open(&paths, "lane").unwrap();
        lane.log("start", "work", None).unwrap();
        lane.log("end", "work", Some("s1")).unwrap();
        let text = std::fs::read_to_string(paths.claudectl_dir().join("lanes/lane/accounts.jsonl"))
            .unwrap();
        let events: Vec<serde_json::Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(events[0]["event"], "start");
        assert_eq!(events[1]["session_id"], "s1");
    }
}
