//! SAW-12610: `server run` follows the account's token revision. A provider refresh revokes
//! the token every session of the account holds, so a session restarts Claude with
//! `--resume <session>` on the new token, only at an idle point.
use std::ffi::{OsStr, OsString};

/// Idle time after the last turn before a restart (ms).
pub(super) const IDLE_AFTER_STOP_MS: i64 = 60_000;
/// No terminal input for this long before a restart (ms): protects a draft being typed.
pub(super) const TTY_IDLE_MS: i64 = 5 * 60_000;
/// At most this many restarts in one hour.
pub(super) const RESTARTS_PER_HOUR: usize = 3;

/// The monitor's clock. Debug builds honor `CLAUDECTL_TEST_RENEW_FAST=1` so the integration
/// test does not wait minutes; release builds always use the real values.
pub(super) struct Timing {
    pub tick_ms: u64,
    pub idle_after_ms: i64,
    pub tty_idle_ms: i64,
    pub hooks_wait_ms: i64,
    pub settle_ms: i64,
    pub poll_far_ms: i64,
    pub poll_near_ms: i64,
}
pub(super) fn timing() -> Timing {
    let fast =
        cfg!(debug_assertions) && std::env::var("CLAUDECTL_TEST_RENEW_FAST").as_deref() == Ok("1");
    if fast {
        Timing {
            tick_ms: 100,
            idle_after_ms: 300,
            tty_idle_ms: 0,
            hooks_wait_ms: 5_000,
            settle_ms: 0,
            poll_far_ms: 0,
            poll_near_ms: 0,
        }
    } else {
        Timing {
            tick_ms: 5_000,
            idle_after_ms: IDLE_AFTER_STOP_MS,
            tty_idle_ms: TTY_IDLE_MS,
            hooks_wait_ms: 30_000,
            settle_ms: 30_000,
            poll_far_ms: 1_800_000,
            poll_near_ms: 300_000,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum Event {
    SessionStart(String),
    Prompt,
    Stop,
    IdlePrompt,
}

/// One event per line: `{"at": <ms>, "event": "<hook event>", "session_id": "..",
/// "notification_type": ".."}`. Unknown or damaged lines are skipped.
pub(super) fn parse_events(text: &str) -> Vec<(i64, Event)> {
    text.lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|v| {
            let at = v["at"].as_i64()?;
            let event = match v["event"].as_str()? {
                "SessionStart" => Event::SessionStart(v["session_id"].as_str()?.to_string()),
                "UserPromptSubmit" => Event::Prompt,
                "Stop" => Event::Stop,
                "Notification" if v["notification_type"] == "idle_prompt" => Event::IdlePrompt,
                _ => return None,
            };
            Some((at, event))
        })
        .collect()
}

#[derive(Debug, Default, PartialEq)]
pub(super) struct Idle {
    /// The session of the latest SessionStart.
    pub session: Option<String>,
    /// Since when Claude waits for input; None while a turn runs.
    pub since: Option<i64>,
}

pub(super) fn idle_state(events: &[(i64, Event)]) -> Idle {
    let mut idle = Idle::default();
    for (at, event) in events {
        match event {
            Event::SessionStart(session) => {
                idle.session = Some(session.clone());
                idle.since = Some(*at);
            }
            Event::Prompt => idle.since = None,
            // A turn just ended: the idle time starts now.
            Event::Stop => idle.since = Some(*at),
            Event::IdlePrompt => {
                idle.since.get_or_insert(*at);
            }
        }
    }
    idle
}

/// The relaunch arguments: the user's arguments without resume, continue, session-id and
/// fork forms, plus `--resume <session>`. None for a one-shot `-p`/`--print` run.
pub(super) fn relaunch_args(args: &[OsString], session: &str) -> Option<Vec<OsString>> {
    let mut out = Vec::new();
    let mut rest = args.iter().peekable();
    while let Some(arg) = rest.next() {
        let text = arg.to_string_lossy();
        match text.as_ref() {
            "-p" | "--print" => return None,
            "--session-id" => {
                rest.next();
            }
            // `--resume`/`-r` take an optional session id; only a value that is not a flag is one.
            "--resume" | "-r" => {
                if rest.peek().is_some_and(|next| !starts_with_dash(next)) {
                    rest.next();
                }
            }
            "-c" | "--continue" | "--fork-session" => {}
            other
                if other.starts_with("--resume=")
                    || other.starts_with("--session-id=")
                    || other.starts_with("--print=") =>
            {
                if other.starts_with("--print=") {
                    return None;
                }
            }
            _ => out.push(arg.clone()),
        }
    }
    out.push("--resume".into());
    out.push(session.into());
    Some(out)
}

fn starts_with_dash(arg: &OsStr) -> bool {
    arg.to_string_lossy().starts_with('-')
}

pub(super) struct Inputs<'a> {
    pub now: i64,
    pub held_revision: &'a str,
    pub held_expires_at: i64,
    pub server_revision: &'a str,
    pub server_expires_at: i64,
    pub idle: &'a Idle,
    pub idle_after_ms: i64,
    /// Required time without terminal input.
    pub tty_gate_ms: i64,
    /// Time since the last terminal input; None without a terminal.
    pub tty_idle_ms: Option<i64>,
    pub group_grew: bool,
    pub restarts_last_hour: usize,
}

#[derive(Debug, PartialEq)]
pub(super) enum Decision {
    Keep,
    /// The held token is dead but Claude is busy: try again later.
    Wait(&'static str),
    Restart,
}

pub(super) fn decide(i: &Inputs) -> Decision {
    if i.server_revision == i.held_revision {
        return Decision::Keep;
    }
    if i.server_expires_at <= i.held_expires_at {
        return Decision::Wait("the new token does not outlive the held one");
    }
    if i.idle.session.is_none() {
        return Decision::Wait("no session id from Claude yet");
    }
    match i.idle.since {
        None => return Decision::Wait("a turn is running"),
        Some(since) if i.now - since < i.idle_after_ms => {
            return Decision::Wait("the last turn ended less than 60 s ago");
        }
        Some(_) => {}
    }
    if i.tty_idle_ms.is_some_and(|ms| ms < i.tty_gate_ms) {
        return Decision::Wait("terminal input in the last 5 min");
    }
    if i.group_grew {
        return Decision::Wait("Claude has extra processes running");
    }
    if i.restarts_last_hour >= RESTARTS_PER_HOUR {
        return Decision::Wait("restart budget used up for this hour");
    }
    Decision::Restart
}

/// Append one hook event to `<session dir>/events`. Only the event name, session id,
/// notification type and time are kept; the hook input is never stored. The directory must
/// be a session directory under this machine's sessions root.
pub(super) fn record_hook(
    sessions: &std::path::Path,
    dir: &std::path::Path,
    input: &str,
    now: i64,
) -> anyhow::Result<()> {
    use std::io::Write;
    let sessions = sessions.canonicalize()?;
    let dir = dir.canonicalize()?;
    let is_session = dir.parent() == Some(sessions.as_path())
        && dir
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("run-"));
    if !is_session {
        anyhow::bail!("not a server session directory");
    }
    let v: serde_json::Value = serde_json::from_str(input)?;
    let line = serde_json::json!({
        "at": now,
        "event": v["hook_event_name"],
        "session_id": v["session_id"],
        "notification_type": v["notification_type"],
    });
    let path = dir.join("events");
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn events_are_parsed_and_damaged_lines_skipped() {
        let text = concat!(
            r#"{"at":1,"event":"SessionStart","session_id":"s-1"}"#,
            "\n",
            r#"{"at":2,"event":"UserPromptSubmit","session_id":"s-1"}"#,
            "\nnot json\n",
            r#"{"at":3,"event":"Stop","session_id":"s-1"}"#,
            "\n",
            r#"{"at":4,"event":"Notification","notification_type":"idle_prompt"}"#,
            "\n",
            r#"{"at":5,"event":"Notification","notification_type":"permission_prompt"}"#,
            "\n",
            r#"{"at":6,"event":"PreToolUse"}"#,
        );
        assert_eq!(
            parse_events(text),
            vec![
                (1, Event::SessionStart("s-1".into())),
                (2, Event::Prompt),
                (3, Event::Stop),
                (4, Event::IdlePrompt),
            ]
        );
    }

    #[test]
    fn idle_follows_the_last_turn_and_the_latest_session() {
        use Event::*;
        let busy = [(1, SessionStart("a".into())), (2, Prompt)];
        assert_eq!(
            idle_state(&busy),
            Idle {
                session: Some("a".into()),
                since: None
            }
        );
        let idle = [(1, SessionStart("a".into())), (2, Prompt), (3, Stop)];
        assert_eq!(
            idle_state(&idle),
            Idle {
                session: Some("a".into()),
                since: Some(3)
            }
        );
        // A new session (/clear, /resume) replaces the old one and starts idle.
        let switched = [
            (1, SessionStart("a".into())),
            (2, Prompt),
            (5, SessionStart("b".into())),
        ];
        assert_eq!(
            idle_state(&switched),
            Idle {
                session: Some("b".into()),
                since: Some(5)
            }
        );
        // idle_prompt keeps the earlier idle start.
        let later = [(1, SessionStart("a".into())), (3, Stop), (9, IdlePrompt)];
        assert_eq!(idle_state(&later).since, Some(3));
        assert_eq!(idle_state(&[]), Idle::default());
    }

    #[test]
    fn relaunch_args_strip_every_resume_form_and_add_one() {
        let got = relaunch_args(
            &os(&[
                "--dangerously-skip-permissions",
                "--resume",
                "old-1",
                "--model",
                "opus",
                "-c",
                "--continue",
                "--resume=old-2",
                "--session-id",
                "fixed",
                "--session-id=fixed2",
                "--fork-session",
                "-r",
                "0b7a5c1e-1111-2222-3333-444455556666",
            ]),
            "s-9",
        )
        .unwrap();
        assert_eq!(
            got,
            os(&[
                "--dangerously-skip-permissions",
                "--model",
                "opus",
                "--resume",
                "s-9"
            ])
        );
        // A bare -r (interactive picker) takes no value; the next flag stays.
        assert_eq!(
            relaunch_args(&os(&["-r", "--verbose"]), "s").unwrap(),
            os(&["--verbose", "--resume", "s"])
        );
        // A bare --resume (interactive picker) takes no value either.
        assert_eq!(
            relaunch_args(&os(&["--resume", "--model", "opus"]), "s").unwrap(),
            os(&["--model", "opus", "--resume", "s"])
        );
        assert!(relaunch_args(&os(&["-p", "hi"]), "s").is_none());
        assert!(relaunch_args(&os(&["--print"]), "s").is_none());
    }

    fn inputs<'a>(idle: &'a Idle) -> Inputs<'a> {
        Inputs {
            now: 10_000_000,
            held_revision: "r1",
            held_expires_at: 20_000_000,
            server_revision: "r2",
            server_expires_at: 40_000_000,
            idle,
            idle_after_ms: IDLE_AFTER_STOP_MS,
            tty_gate_ms: TTY_IDLE_MS,
            tty_idle_ms: Some(TTY_IDLE_MS),
            group_grew: false,
            restarts_last_hour: 0,
        }
    }

    #[test]
    fn a_revoked_token_restarts_only_an_idle_claude() {
        let idle = Idle {
            session: Some("s".into()),
            since: Some(10_000_000 - IDLE_AFTER_STOP_MS),
        };
        assert_eq!(decide(&inputs(&idle)), Decision::Restart);
        // Same revision: the held token is still the live one.
        let mut same = inputs(&idle);
        same.server_revision = "r1";
        assert_eq!(decide(&same), Decision::Keep);
        // Busy, too recent, typing, extra processes, no session, or the budget used up.
        let busy = Idle {
            session: Some("s".into()),
            since: None,
        };
        assert!(matches!(decide(&inputs(&busy)), Decision::Wait(_)));
        let recent = Idle {
            session: Some("s".into()),
            since: Some(10_000_000 - 1_000),
        };
        assert!(matches!(decide(&inputs(&recent)), Decision::Wait(_)));
        let mut typing = inputs(&idle);
        typing.tty_idle_ms = Some(30_000);
        assert!(matches!(decide(&typing), Decision::Wait(_)));
        let mut grew = inputs(&idle);
        grew.group_grew = true;
        assert!(matches!(decide(&grew), Decision::Wait(_)));
        let nosession = Idle {
            session: None,
            since: Some(0),
        };
        assert!(matches!(decide(&inputs(&nosession)), Decision::Wait(_)));
        let mut budget = inputs(&idle);
        budget.restarts_last_hour = RESTARTS_PER_HOUR;
        assert!(matches!(decide(&budget), Decision::Wait(_)));
        // No terminal: the input gate does not apply.
        let mut headless = inputs(&idle);
        headless.tty_idle_ms = None;
        assert_eq!(decide(&headless), Decision::Restart);
    }

    #[test]
    fn a_new_revision_without_a_later_expiry_is_not_followed() {
        let idle = Idle {
            session: Some("s".into()),
            since: Some(0),
        };
        let mut older = inputs(&idle);
        older.server_expires_at = older.held_expires_at;
        assert!(matches!(decide(&older), Decision::Wait(_)));
    }
    #[test]
    fn a_hook_event_keeps_only_safe_fields() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("sessions");
        let dir = sessions.join("run-abc");
        std::fs::create_dir_all(&dir).unwrap();
        let input = r#"{"hook_event_name":"Stop","session_id":"s-1","transcript_path":"/x","prompt":"secret text","cwd":"/y"}"#;
        record_hook(&sessions, &dir, input, 42).unwrap();
        record_hook(
            &sessions,
            &dir,
            r#"{"hook_event_name":"Notification","notification_type":"idle_prompt","message":"m"}"#,
            43,
        )
        .unwrap();
        let text = std::fs::read_to_string(dir.join("events")).unwrap();
        assert!(
            !text.contains("secret") && !text.contains("transcript"),
            "{text}"
        );
        assert_eq!(
            parse_events(&text),
            vec![(42, Event::Stop), (43, Event::IdlePrompt)]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("events"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_hook_writes_only_into_a_session_directory() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("sessions");
        std::fs::create_dir_all(&sessions).unwrap();
        let outside = root.path().join("run-x");
        std::fs::create_dir_all(&outside).unwrap();
        let input = r#"{"hook_event_name":"Stop","session_id":"s"}"#;
        assert!(record_hook(&sessions, &outside, input, 1).is_err());
        assert!(record_hook(&sessions, &sessions.join("other"), input, 1).is_err());
        #[cfg(unix)]
        {
            let dir = sessions.join("run-y");
            std::fs::create_dir_all(&dir).unwrap();
            std::os::unix::fs::symlink(root.path().join("elsewhere"), dir.join("events")).unwrap();
            assert!(record_hook(&sessions, &dir, input, 1).is_err());
            assert!(!root.path().join("elsewhere").exists());
        }
    }
}
