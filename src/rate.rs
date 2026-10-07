//! Per-account response and rate-limit counts from lane transcripts. Only
//! lanes record which account ran when (`accounts.jsonl`), so only lane
//! sessions are counted; a turn outside every logged span is unattributed.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::config::Paths;

#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct AccountRate {
    /// `None` for turns outside every logged span.
    pub alias: Option<String>,
    pub lanes: BTreeSet<String>,
    /// Assistant responses, one per API message.
    pub ok: u64,
    /// Rate-limit API errors.
    pub rate_limited: u64,
}

impl AccountRate {
    pub fn rate_limited_percent(&self) -> f64 {
        let total = self.ok + self.rate_limited;
        if total == 0 {
            0.0
        } else {
            self.rate_limited as f64 * 100.0 / total as f64
        }
    }
}

/// One account's time on a lane: from `start` to the next `end` or
/// `refused`, or to `now` while it still runs.
#[derive(Debug, Clone, PartialEq)]
struct Span {
    alias: String,
    from: DateTime<Utc>,
    to: DateTime<Utc>,
}

/// Counts for every account seen in a lane since `since`, sorted by alias,
/// unattributed turns first.
pub fn collect(
    paths: &Paths,
    since: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<Vec<AccountRate>> {
    let lanes = paths.claudectl_dir().join("lanes");
    let entries = match std::fs::read_dir(&lanes) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", lanes.display())),
    };
    let mut accounts: BTreeMap<Option<String>, AccountRate> = BTreeMap::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let lane = entry.file_name().to_string_lossy().into_owned();
        let log = entry.path().join("accounts.jsonl");
        let spans = match std::fs::read_to_string(&log) {
            Ok(text) => {
                spans(&text, now).with_context(|| format!("bad record in {}", log.display()))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("failed to read {}", log.display())),
        };
        for turn in turns(&entry.path().join("config/projects"), since)? {
            let alias = spans
                .iter()
                .find(|s| s.from <= turn.at && turn.at <= s.to)
                .map(|s| s.alias.clone());
            let account = accounts
                .entry(alias.clone())
                .or_insert_with(|| AccountRate {
                    alias,
                    ..AccountRate::default()
                });
            account.lanes.insert(lane.clone());
            if turn.rate_limited {
                account.rate_limited += 1;
            } else {
                account.ok += 1;
            }
        }
    }
    Ok(accounts.into_values().collect())
}

/// The account spans in a lane log. The log is the only record of which
/// account ran, so a bad record fails rather than shift the attribution;
/// only a last line still being written (no newline yet) is skipped.
fn spans(log: &str, now: DateTime<Utc>) -> Result<Vec<Span>> {
    let mut spans = Vec::new();
    let mut open: Option<(String, DateTime<Utc>)> = None;
    for (index, line) in log.split_inclusive('\n').enumerate() {
        let Some(line) = line.strip_suffix('\n') else {
            break;
        };
        if line.trim().is_empty() {
            continue;
        }
        let record: serde_json::Value =
            serde_json::from_str(line).with_context(|| format!("line {}", index + 1))?;
        let (Some(event), Some(alias), Some(at)) = (
            record["event"].as_str(),
            record["alias"].as_str(),
            record["at"]
                .as_str()
                .and_then(|at| DateTime::parse_from_rfc3339(at).ok()),
        ) else {
            anyhow::bail!("line {}: no event, alias, or time", index + 1);
        };
        let at = at.with_timezone(&Utc);
        match event {
            "start" => {
                // A launcher that died leaves a span open: the next start ends it.
                if let Some((alias, from)) = open.take() {
                    spans.push(Span {
                        alias,
                        from,
                        to: at,
                    });
                }
                open = Some((alias.to_string(), at));
            }
            "end" | "refused" => {
                if let Some((alias, from)) = open.take() {
                    spans.push(Span {
                        alias,
                        from,
                        to: at,
                    });
                }
            }
            _ => {}
        }
    }
    if let Some((alias, from)) = open {
        spans.push(Span {
            alias,
            from,
            to: now,
        });
    }
    Ok(spans)
}

#[derive(Debug, PartialEq)]
struct Turn {
    at: DateTime<Utc>,
    rate_limited: bool,
}

/// Assistant responses and rate-limit errors in the lane transcripts since
/// `since`. Claude Code writes one record per content block, so responses
/// count once per API message id.
fn turns(projects: &Path, since: DateTime<Utc>) -> Result<Vec<Turn>> {
    let mut turns = Vec::new();
    let mut seen = HashSet::new();
    let Some(dirs) = read_dir(projects)? else {
        return Ok(turns);
    };
    for dir in dirs {
        if !dir.file_type()?.is_dir() {
            continue;
        }
        let Some(files) = read_dir(&dir.path())? else {
            continue;
        };
        for file in files {
            let path = file.path();
            if path.extension().is_none_or(|ext| ext != "jsonl") {
                continue;
            }
            // A file not written since `since` holds nothing newer.
            let modified = file
                .metadata()
                .and_then(|m| m.modified())
                .with_context(|| format!("failed to read {}", path.display()))?;
            if DateTime::<Utc>::from(modified) < since {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            turns.extend(turns_in(&text, since, &mut seen));
        }
    }
    Ok(turns)
}

/// The entries of `dir`, or `None` when it does not exist. Any other error
/// fails: a report with unread transcripts would look like no activity.
fn read_dir(dir: &Path) -> Result<Option<Vec<std::fs::DirEntry>>> {
    let failed = || format!("failed to read {}", dir.display());
    match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .collect::<std::io::Result<Vec<_>>>()
            .map(Some)
            .with_context(failed),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(failed),
    }
}

fn turns_in(text: &str, since: DateTime<Utc>, seen: &mut HashSet<String>) -> Vec<Turn> {
    text.lines()
        .filter(|line| line.contains("\"assistant\""))
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|record| record["type"] == "assistant")
        .filter_map(|record| {
            let at = DateTime::parse_from_rfc3339(record["timestamp"].as_str()?)
                .ok()?
                .with_timezone(&Utc);
            if at < since {
                return None;
            }
            if record["isApiErrorMessage"] == true {
                return (record["error"] == "rate_limit").then_some(Turn {
                    at,
                    rate_limited: true,
                });
            }
            let id = record["message"]["id"]
                .as_str()
                .or(record["uuid"].as_str())?
                .to_string();
            seen.insert(id).then_some(Turn {
                at,
                rate_limited: false,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(text: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(text)
            .unwrap()
            .with_timezone(&Utc)
    }

    fn event(event: &str, alias: &str, when: &str) -> String {
        serde_json::json!({"at": when, "event": event, "alias": alias, "session_id": null})
            .to_string()
    }

    fn assistant(when: &str, message_id: &str) -> String {
        serde_json::json!({
            "type": "assistant", "timestamp": when, "uuid": format!("u-{message_id}-{when}"),
            "message": {"id": message_id},
        })
        .to_string()
    }

    fn limited(when: &str) -> String {
        serde_json::json!({
            "type": "assistant", "timestamp": when, "uuid": format!("l-{when}"),
            "error": "rate_limit", "isApiErrorMessage": true, "apiErrorStatus": 429,
        })
        .to_string()
    }

    #[test]
    fn spans_close_on_end_refused_or_the_next_start() {
        let log = [
            event("start", "a", "2026-10-07T10:00:00Z"),
            event("end", "a", "2026-10-07T10:10:00Z"),
            event("recovery", "a", "2026-10-07T10:10:01Z"),
            event("start", "b", "2026-10-07T10:11:00Z"),
            event("refused", "b", "2026-10-07T10:11:05Z"),
            event("start", "c", "2026-10-07T10:12:00Z"),
            event("start", "d", "2026-10-07T10:20:00Z"),
        ]
        .join("\n")
            + "\n";
        let now = at("2026-10-07T11:00:00Z");
        let names: Vec<_> = spans(&log, now)
            .unwrap()
            .into_iter()
            .map(|s| (s.alias, s.to))
            .collect();
        assert_eq!(
            names,
            [
                ("a".into(), at("2026-10-07T10:10:00Z")),
                ("b".into(), at("2026-10-07T10:11:05Z")),
                ("c".into(), at("2026-10-07T10:20:00Z")),
                ("d".into(), now),
            ]
        );
    }

    #[test]
    fn a_bad_log_record_fails_but_a_partial_last_line_does_not() {
        let now = at("2026-10-07T11:00:00Z");
        let start = event("start", "a", "2026-10-07T10:00:00Z");
        let partial = format!("{start}\n{{\"at\":\"2026-10");
        assert_eq!(spans(&partial, now).unwrap().len(), 1);
        let torn = format!("{start}\n{{\"at\":\"2026-10\n{start}\n");
        assert!(spans(&torn, now).is_err());
        let missing = format!("{start}\n{{\"event\":\"end\"}}\n");
        assert!(spans(&missing, now).is_err());
    }

    #[test]
    fn turns_count_messages_once_and_only_rate_limit_errors() {
        let auth = serde_json::json!({
            "type": "assistant", "timestamp": "2026-10-07T10:05:00Z",
            "error": "authentication_failed", "isApiErrorMessage": true,
        })
        .to_string();
        let user =
            serde_json::json!({"type": "user", "timestamp": "2026-10-07T10:05:00Z"}).to_string();
        let text = [
            assistant("2026-10-07T09:00:00Z", "old"),
            assistant("2026-10-07T10:01:00Z", "m1"),
            assistant("2026-10-07T10:01:01Z", "m1"),
            assistant("2026-10-07T10:02:00Z", "m2"),
            limited("2026-10-07T10:03:00Z"),
            auth,
            user,
        ]
        .join("\n");
        let mut seen = HashSet::new();
        let turns = turns_in(&text, at("2026-10-07T10:00:00Z"), &mut seen);
        let limited: Vec<_> = turns.iter().map(|t| t.rate_limited).collect();
        assert_eq!(limited, [false, false, true]);
    }

    #[test]
    fn collect_attributes_turns_to_the_account_that_ran() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        let lane = paths.claudectl_dir().join("lanes/work");
        let projects = lane.join("config/projects/-repo");
        std::fs::create_dir_all(&projects).unwrap();
        std::fs::write(
            lane.join("accounts.jsonl"),
            [
                event("start", "a", "2026-10-07T10:00:00Z"),
                event("end", "a", "2026-10-07T10:10:00Z"),
                event("start", "b", "2026-10-07T10:11:00Z"),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        std::fs::write(
            projects.join("s.jsonl"),
            [
                assistant("2026-10-07T10:01:00Z", "m1"),
                limited("2026-10-07T10:09:00Z"),
                assistant("2026-10-07T10:10:30Z", "gap"),
                assistant("2026-10-07T10:12:00Z", "m2"),
                assistant("2026-10-07T10:13:00Z", "m3"),
            ]
            .join("\n")
                + "\n",
        )
        .unwrap();
        let rates = collect(
            &paths,
            // Before the file's modified time, which is the test's run time.
            at("2026-01-01T00:00:00Z"),
            at("2026-10-07T10:30:00Z"),
        )
        .unwrap();
        let counts: Vec<_> = rates
            .iter()
            .map(|r| (r.alias.as_deref(), r.ok, r.rate_limited))
            .collect();
        assert_eq!(counts, [(None, 1, 0), (Some("a"), 1, 1), (Some("b"), 2, 0)]);
        assert_eq!(rates[1].rate_limited_percent(), 50.0);
        assert!(rates[2].lanes.contains("work"));
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_transcript_directory_fails() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        let projects = paths.claudectl_dir().join("lanes/work/config/projects");
        std::fs::create_dir_all(projects.join("-repo")).unwrap();
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o000)).unwrap();
        let now = Utc::now();
        let result = collect(&paths, now, now);
        std::fs::set_permissions(&projects, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn no_lanes_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        let now = Utc::now();
        assert!(collect(&paths, now, now).unwrap().is_empty());
    }
}
