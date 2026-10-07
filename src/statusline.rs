//! A one-line usage summary of the active account for prompts, such as
//! Claude Code's `statusLine` command. `status` writes a small sample for the
//! active account; `statusline` only reads it, and prints nothing when the
//! sample is missing, old, for another account, or slow to read.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::api::{UsageResponse, UsageWindow};
use crate::config::Paths;
use crate::usage_cache::CACHE_SECONDS;

const VERSION: u32 = 1;
/// A sample older than the usage cache lifetime is not shown.
const MAX_AGE_SECONDS: i64 = CACHE_SECONDS;
/// The prompt must never wait on claudectl.
pub const READ_BUDGET: Duration = Duration::from_millis(150);
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_NAME_CHARS: usize = 20;

/// The sample `status` writes. It holds usage numbers only, never credentials.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Sample {
    pub version: u32,
    pub sampled_at: i64,
    pub alias: String,
    /// The account behind the alias when sampled; an alias saved again for
    /// another login must not show this account's usage.
    pub account_uuid: String,
    pub five_hour: Option<Window>,
    pub seven_day: Option<Window>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Window {
    pub used_percent: f64,
    pub resets_at: i64,
}

impl Window {
    fn from_usage(window: Option<&UsageWindow>) -> Option<Self> {
        let window = window?;
        Some(Self {
            used_percent: window.utilization?,
            resets_at: window.reset_timestamp()?,
        })
    }
}

fn sample_path(paths: &Paths) -> std::path::PathBuf {
    paths.claudectl_dir().join("statusline.json")
}

/// The active account as `status` saw it.
pub struct Active<'a> {
    pub alias: &'a str,
    pub account_uuid: Option<&'a str>,
    /// Fresh usage only; None when the check failed or is old.
    pub usage: Option<&'a UsageResponse>,
}

/// Record the active account's usage, or remove the sample when there is no
/// fresh usage or no known account for it, so the statusline never shows
/// another account's data.
pub fn record(paths: &Paths, active: Option<Active<'_>>, now: i64) -> Result<()> {
    let path = sample_path(paths);
    let sample = active.and_then(|active| {
        let usage = active.usage?;
        Some(Sample {
            version: VERSION,
            sampled_at: now,
            alias: active.alias.to_string(),
            account_uuid: active.account_uuid?.to_string(),
            five_hour: Window::from_usage(usage.five_hour.as_ref()),
            seven_day: Window::from_usage(usage.seven_day.as_ref()),
        })
    });
    let Some(sample) = sample else {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("failed to remove {}", path.display()))
            }
            _ => Ok(()),
        };
    };
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&sample)?)
        .with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("failed to replace {}", path.display()))
}

/// The line to print, or None when anything is in doubt.
pub fn render(paths: &Paths, now: i64) -> Option<String> {
    let sample = read_sample(&sample_path(paths))?;
    let active = std::fs::read_to_string(paths.active_file()).ok()?;
    if sample.version != VERSION || sample.alias != active.trim() {
        return None;
    }
    let alias = crate::profile::validate_alias(&sample.alias).ok()?;
    let profile = crate::profile::get_profile_from(paths, alias).ok()?;
    if profile.meta.account_uuid() != Some(sample.account_uuid.as_str())
        || live_account_uuid(paths).as_deref() != Some(sample.account_uuid.as_str())
    {
        return None;
    }
    let age = now.checked_sub(sample.sampled_at)?;
    if !(0..=MAX_AGE_SECONDS).contains(&age) {
        return None;
    }
    let week = sample.seven_day.as_ref()?;
    if week.resets_at <= now {
        return None;
    }
    // The current label, so a label change shows at once.
    let name = display_name(profile.meta.label.as_deref(), &sample.alias)?;
    let mut line = format!(
        "{name} {}% wk · {}",
        remaining(week.used_percent),
        duration(week.resets_at - now)
    );
    if let Some(five) = sample.five_hour.as_ref().filter(|w| w.resets_at > now) {
        line.push_str(&format!(" · {}% 5h", remaining(five.used_percent)));
    }
    Some(line)
}

/// Largest `~/.claude.json` the prompt path reads.
const MAX_CLAUDE_JSON_BYTES: u64 = 16 * 1024 * 1024;

/// The live login's account from `~/.claude.json`, a local file: no network
/// and no Keychain.
fn live_account_uuid(paths: &Paths) -> Option<String> {
    let bytes = read_capped(&paths.claude_json(), MAX_CLAUDE_JSON_BYTES)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    json.get("oauthAccount")?
        .get("accountUuid")?
        .as_str()
        .map(str::to_string)
}

fn read_sample(path: &Path) -> Option<Sample> {
    // claudectl writes the sample itself, so a link there is not trusted.
    if !std::fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    serde_json::from_slice(&read_capped(path, MAX_FILE_BYTES)?).ok()
}

/// A regular file's bytes, read through one handle and only when it holds at
/// most `cap` bytes, so a file that grows or is replaced after the check is
/// still bounded. The path check first keeps a FIFO from blocking the open.
fn read_capped(path: &Path, cap: u64) -> Option<Vec<u8>> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= cap).then_some(bytes)
}

/// The label, or the alias's local part; only `[A-Za-z0-9 ._-]`, so no
/// terminal escape can reach the prompt.
fn display_name(label: Option<&str>, alias: &str) -> Option<String> {
    let raw = label.unwrap_or_else(|| alias.split('@').next().unwrap_or(alias));
    let name: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-'))
        .take(MAX_NAME_CHARS)
        .collect();
    let name = name.trim().to_string();
    (!name.is_empty()).then_some(name)
}

fn remaining(used_percent: f64) -> i64 {
    (100.0 - used_percent).clamp(0.0, 100.0).round() as i64
}

fn duration(seconds: i64) -> String {
    let (days, hours, minutes) = (
        seconds / 86_400,
        seconds % 86_400 / 3_600,
        seconds % 3_600 / 60,
    );
    if days > 0 {
        format!("{days}d{hours}h")
    } else if hours > 0 {
        format!("{hours}h{minutes}m")
    } else {
        format!("{}m", minutes.max(1))
    }
}

/// `render` on a helper thread, abandoned after `READ_BUDGET`.
pub fn render_within_budget(paths: Paths, now: i64) -> Option<String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(render(&paths, now));
    });
    receiver.recv_timeout(READ_BUDGET).ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn setup(active: &str) -> (tempfile::TempDir, Paths) {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_home(tmp.path().to_path_buf());
        paths.ensure_dirs().unwrap();
        std::fs::write(paths.active_file(), active).unwrap();
        save_profile(&paths, active, "u1");
        set_live_login(&paths, "u1");
        (tmp, paths)
    }

    fn set_live_login(paths: &Paths, uuid: &str) {
        std::fs::write(
            paths.claude_json(),
            serde_json::json!({ "oauthAccount": { "accountUuid": uuid } }).to_string(),
        )
        .unwrap();
    }

    fn save_profile(paths: &Paths, alias: &str, uuid: &str) {
        let creds: crate::api::CredentialsFile =
            serde_json::from_str(r#"{"claudeAiOauth":{"accessToken":"t"}}"#).unwrap();
        crate::profile::save_profile_to(
            paths,
            alias,
            &creds,
            Some(serde_json::json!({ "accountUuid": uuid })),
        )
        .unwrap();
    }

    fn active<'a>(
        paths: &Paths,
        alias: &'a str,
        label: Option<&str>,
        usage: Option<&'a UsageResponse>,
    ) -> Option<Active<'a>> {
        let store = crate::auth_store::AuthStore::file_only(paths.clone());
        crate::profile::set_label_from(paths, &store, alias, label).unwrap();
        Some(Active {
            alias,
            account_uuid: Some("u1"),
            usage,
        })
    }

    fn usage(five: f64, week: f64) -> UsageResponse {
        let at = |offset: i64| {
            chrono::DateTime::from_timestamp(NOW + offset, 0)
                .unwrap()
                .to_rfc3339()
        };
        serde_json::from_value(serde_json::json!({
            "five_hour": {"utilization": five, "resets_at": at(2 * 3_600 + 5 * 60)},
            "seven_day": {"utilization": week, "resets_at": at(6 * 86_400 + 22 * 3_600)},
        }))
        .unwrap()
    }

    #[test]
    fn renders_label_weekly_and_five_hour_room() {
        let (_tmp, paths) = setup("amir5@sawmills.ai");
        let u = usage(10.0, 38.0);
        record(
            &paths,
            active(&paths, "amir5@sawmills.ai", Some("team"), Some(&u)),
            NOW,
        )
        .unwrap();
        assert_eq!(
            render(&paths, NOW + 10).as_deref(),
            Some("team 62% wk · 6d21h · 90% 5h")
        );
    }

    #[test]
    fn falls_back_to_the_alias_local_part_and_strips_unsafe_text() {
        let (_tmp, paths) = setup("amir5@sawmills.ai");
        let u = usage(0.0, 0.0);
        record(
            &paths,
            active(&paths, "amir5@sawmills.ai", None, Some(&u)),
            NOW,
        )
        .unwrap();
        assert!(render(&paths, NOW).unwrap().starts_with("amir5 100% wk"));
        // `label` refuses control characters; a hand-edited account.json
        // can still hold them, so render cleans the name too.
        let meta = paths.profiles_dir().join("amir5@sawmills.ai/account.json");
        let mut json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&meta).unwrap()).unwrap();
        json["label"] = "\u{1b}]0;evil\u{7}a-very-long-label-that-goes-on".into();
        std::fs::write(&meta, json.to_string()).unwrap();
        let line = render(&paths, NOW).unwrap();
        assert!(line.starts_with("0evila-very-long-lab "), "{line}");
        assert!(!line.contains('\u{1b}'));
    }

    #[test]
    fn is_silent_when_old_for_another_account_or_reset() {
        let (_tmp, paths) = setup("work");
        let u = usage(10.0, 38.0);
        record(&paths, active(&paths, "work", None, Some(&u)), NOW).unwrap();
        assert!(render(&paths, NOW + MAX_AGE_SECONDS).is_some());
        assert_eq!(
            render(&paths, NOW + MAX_AGE_SECONDS + 1),
            None,
            "old sample"
        );
        assert_eq!(render(&paths, NOW - 1), None, "sample from the future");
        std::fs::write(paths.active_file(), "other").unwrap();
        assert_eq!(render(&paths, NOW), None, "active account changed");
        std::fs::write(paths.active_file(), "work").unwrap();
        let past = UsageResponse {
            seven_day: Some(UsageWindow {
                utilization: Some(10.0),
                resets_at: Some(
                    chrono::DateTime::from_timestamp(NOW - 1, 0)
                        .unwrap()
                        .to_rfc3339(),
                ),
            }),
            ..UsageResponse::default()
        };
        record(&paths, active(&paths, "work", None, Some(&past)), NOW).unwrap();
        assert_eq!(render(&paths, NOW), None, "weekly reset passed");
    }

    #[test]
    fn is_silent_when_the_alias_now_holds_another_account() {
        let (_tmp, paths) = setup("work");
        let u = usage(10.0, 38.0);
        record(&paths, active(&paths, "work", None, Some(&u)), NOW).unwrap();
        assert!(render(&paths, NOW).is_some());
        save_profile(&paths, "work", "u2");
        assert_eq!(
            render(&paths, NOW),
            None,
            "alias saved again for another login"
        );
    }

    #[test]
    fn is_silent_when_the_live_login_changes_after_the_sample() {
        let (_tmp, paths) = setup("work");
        let u = usage(10.0, 38.0);
        record(&paths, active(&paths, "work", None, Some(&u)), NOW).unwrap();
        assert!(render(&paths, NOW).is_some());
        set_live_login(&paths, "u2");
        assert_eq!(render(&paths, NOW), None, "live login is another account");
        std::fs::remove_file(paths.claude_json()).unwrap();
        assert_eq!(render(&paths, NOW), None, "no live login");
    }

    #[test]
    fn a_label_change_shows_at_once() {
        let (_tmp, paths) = setup("work");
        let u = usage(10.0, 38.0);
        record(&paths, active(&paths, "work", Some("old"), Some(&u)), NOW).unwrap();
        assert!(render(&paths, NOW).unwrap().starts_with("old "));
        let store = crate::auth_store::AuthStore::file_only(paths.clone());
        crate::profile::set_label_from(&paths, &store, "work", Some("new")).unwrap();
        assert!(render(&paths, NOW).unwrap().starts_with("new "));
    }

    #[test]
    fn records_nothing_without_a_known_account() {
        let (_tmp, paths) = setup("work");
        let u = usage(10.0, 38.0);
        let unknown = Active {
            alias: "work",
            account_uuid: None,
            usage: Some(&u),
        };
        record(&paths, Some(unknown), NOW).unwrap();
        assert!(!sample_path(&paths).exists());
    }

    #[test]
    fn omits_the_five_hour_part_without_an_open_window() {
        let (_tmp, paths) = setup("work");
        let mut u = usage(10.0, 38.0);
        u.five_hour = None;
        record(&paths, active(&paths, "work", None, Some(&u)), NOW).unwrap();
        assert_eq!(render(&paths, NOW).as_deref(), Some("work 62% wk · 6d22h"));
    }

    #[test]
    fn missing_usage_or_no_active_account_removes_the_sample() {
        let (_tmp, paths) = setup("work");
        let u = usage(10.0, 38.0);
        record(&paths, active(&paths, "work", None, Some(&u)), NOW).unwrap();
        record(&paths, active(&paths, "work", None, None), NOW).unwrap();
        assert!(!sample_path(&paths).exists());
        record(&paths, active(&paths, "work", None, Some(&u)), NOW).unwrap();
        record(&paths, None, NOW).unwrap();
        assert!(!sample_path(&paths).exists());
        record(&paths, None, NOW).unwrap();
    }

    #[test]
    fn ignores_large_or_non_regular_files() {
        let (_tmp, paths) = setup("work");
        std::fs::write(sample_path(&paths), vec![b' '; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert_eq!(render(&paths, NOW), None);
        std::fs::remove_file(sample_path(&paths)).unwrap();
        std::fs::create_dir(sample_path(&paths)).unwrap();
        assert_eq!(render(&paths, NOW), None);
    }

    #[test]
    fn capped_reads_reject_more_than_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("f");
        std::fs::write(&path, b"1234").unwrap();
        assert_eq!(read_capped(&path, 4).as_deref(), Some(&b"1234"[..]));
        std::fs::write(&path, b"12345").unwrap();
        assert_eq!(read_capped(&path, 4), None);
        assert_eq!(read_capped(tmp.path(), 4), None, "a directory");
    }

    #[test]
    fn durations_read_as_days_hours_or_minutes() {
        assert_eq!(duration(6 * 86_400 + 22 * 3_600), "6d22h");
        assert_eq!(duration(5 * 3_600 + 12 * 60), "5h12m");
        assert_eq!(duration(42 * 60), "42m");
        assert_eq!(duration(10), "1m");
    }
}
