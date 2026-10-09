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
    pub poll_far_ms: i64,
    pub poll_near_ms: i64,
    /// Wait after a failed token request.
    pub retry_ms: i64,
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
            poll_far_ms: 0,
            poll_near_ms: 0,
            retry_ms: 0,
        }
    } else {
        Timing {
            tick_ms: 5_000,
            idle_after_ms: IDLE_AFTER_STOP_MS,
            tty_idle_ms: TTY_IDLE_MS,
            hooks_wait_ms: 30_000,
            poll_far_ms: 1_800_000,
            poll_near_ms: 300_000,
            retry_ms: 30_000,
        }
    }
}

#[derive(Debug, PartialEq)]
pub(super) enum Event {
    SessionStart(String),
    Prompt,
    Stop,
    IdlePrompt,
    /// A turn failed with `rate_limit` in this session; it also ended the turn.
    Limited(String),
    /// A turn failed with `authentication_failed`: the held token is dead; it also ended the
    /// turn.
    AuthFailed,
    /// Claude ended the session (/exit, /clear, logout): it is shutting down unless a new
    /// session starts.
    SessionEnd,
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
                // A turn that failed with a usage limit can move the session to another
                // account (SAW-12693); it ended all the same.
                "StopFailure" if v["error"] == "rate_limit" => match v["session_id"].as_str() {
                    Some(session) => Event::Limited(session.to_string()),
                    None => Event::Stop,
                },
                "StopFailure" if v["error"] == "authentication_failed" => Event::AuthFailed,
                // A turn that failed (another API error) ends with
                // StopFailure: it ended all the same.
                "Stop" | "StopFailure" => Event::Stop,
                "Notification" if v["notification_type"] == "idle_prompt" => Event::IdlePrompt,
                "SessionEnd" => Event::SessionEnd,
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
    /// The session and time of the latest turn that failed with `rate_limit`, until the
    /// next prompt or session.
    pub limited: Option<(String, i64)>,
    /// When Claude ended its session with no new session since: Claude is exiting.
    pub ended: Option<i64>,
    /// When a turn last failed with `authentication_failed`: the held token is dead, so
    /// nothing the user types can succeed until a restart. A new session in the same process
    /// (`/clear`, `/resume`) keeps the token, so only a relaunch (a new event log) clears it.
    pub auth_failed: Option<i64>,
}

#[cfg(test)]
pub(super) fn idle_state(events: &[(i64, Event)]) -> Idle {
    let mut idle = Idle::default();
    fold(&mut idle, events);
    idle
}

/// Apply newly read events to the idle state (the monitor reads the log incrementally).
pub(super) fn fold(idle: &mut Idle, events: &[(i64, Event)]) {
    for (at, event) in events {
        match event {
            Event::SessionStart(session) => {
                idle.session = Some(session.clone());
                idle.since = Some(*at);
                idle.limited = None;
                idle.ended = None;
            }
            Event::SessionEnd => idle.ended = Some(*at),
            Event::Prompt => {
                idle.since = None;
                idle.limited = None;
            }
            // A turn just ended: the idle time starts now.
            Event::Stop => idle.since = Some(*at),
            Event::IdlePrompt => {
                idle.since.get_or_insert(*at);
            }
            Event::Limited(session) => {
                idle.since = Some(*at);
                idle.limited = Some((session.clone(), *at));
            }
            Event::AuthFailed => {
                idle.since = Some(*at);
                idle.auth_failed = Some(*at);
            }
        }
    }
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
    match idle_gate(i) {
        Ok(()) => Decision::Restart,
        Err(reason) => Decision::Wait(reason),
    }
}

/// Whether Claude is idle enough to be restarted. The monitor also asks the server for the
/// token only when this holds: inside the server's margin that request refreshes the grant,
/// which revokes the token a running turn uses.
pub(super) fn idle_gate(i: &Inputs) -> Result<(), &'static str> {
    if i.idle.session.is_none() {
        return Err("no session id from Claude yet");
    }
    // A clean exit (/exit) ends `server run`; it is never turned into a resume (CX-0119).
    if i.idle.ended.is_some() {
        return Err("Claude is ending the session");
    }
    // With a dead held token every turn fails, so the waits that protect a turn or a draft
    // only keep the tab dead: a user who retries resets them for good (SAW-12610 10-09).
    let dead = held_token_dead(i);
    match i.idle.since {
        None => return Err("a turn is running"),
        Some(since) if !dead && i.now - since < i.idle_after_ms => {
            return Err("the last turn ended less than 60 s ago");
        }
        Some(_) => {}
    }
    if !dead && i.tty_idle_ms.is_some_and(|ms| ms < i.tty_gate_ms) {
        return Err("terminal input in the last 5 min");
    }
    // Extra processes (an LSP, caffeinate, background shells) do not block: a restart happens
    // only when the held token was superseded or expired, so it is dead for every holder, and
    // a gate on them left idle tabs on a dead token for good (SAW-12610).
    if i.restarts_last_hour >= RESTARTS_PER_HOUR {
        return Err("restart budget used up for this hour");
    }
    Ok(())
}

/// Whether the held token can no longer work: it expired, or a turn failed with
/// `authentication_failed` (a forced rotation revokes it before expiry).
pub(super) fn held_token_dead(i: &Inputs) -> bool {
    i.now >= i.held_expires_at || i.idle.auth_failed.is_some()
}

/// The error types of a failed turn in Claude Code's StopFailure hook (2.1.295).
const TURN_ERRORS: &[&str] = &[
    "authentication_failed",
    "oauth_org_not_allowed",
    "account_on_hold",
    "verification_required",
    "billing_error",
    "rate_limit",
    "overloaded",
    "invalid_request",
    "model_not_found",
    "server_error",
    "unknown",
    "max_output_tokens",
    "cloud_credential_error",
];

/// The most hook input read; a longer input counts as a failed event.
pub(super) const HOOK_INPUT_LIMIT: usize = 1 << 20;

/// The session directory, only when it is a `run-*` directory directly under `sessions`.
fn session_dir(
    sessions: &std::path::Path,
    dir: &std::path::Path,
) -> anyhow::Result<std::path::PathBuf> {
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
    Ok(dir)
}

/// Tell the monitor its event log is incomplete: it then stops renewing this session.
fn mark_hook_error(dir: &std::path::Path) {
    let _ = std::fs::File::create(dir.join("hook-error"));
}

/// The `server hook` entry point: read the hook input (at most `HOOK_INPUT_LIMIT`) and
/// record it. Any read, size or parse failure leaves the error marker (fail closed).
pub(super) fn hook_from(
    sessions: &std::path::Path,
    dir: &std::path::Path,
    input: impl std::io::Read,
    now: i64,
) -> anyhow::Result<()> {
    use std::io::Read;
    let dir = session_dir(sessions, dir)?;
    let mut text = String::new();
    let read = input
        .take(HOOK_INPUT_LIMIT as u64 + 1)
        .read_to_string(&mut text);
    if read.is_err() || text.len() > HOOK_INPUT_LIMIT {
        mark_hook_error(&dir);
        anyhow::bail!("hook input unreadable or too large");
    }
    record_hook(sessions, &dir, &text, now)
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
    let dir = session_dir(sessions, dir)?;
    let v: serde_json::Value = match serde_json::from_str(input) {
        Ok(v) => v,
        Err(error) => {
            mark_hook_error(&dir);
            return Err(error.into());
        }
    };
    // The error type of a failed turn, only from Claude Code's known values; its details
    // and the last message are never kept.
    let error = (v["hook_event_name"] == "StopFailure").then(|| {
        let known = v["error"]
            .as_str()
            .filter(|e| TURN_ERRORS.contains(e))
            .unwrap_or("unknown");
        serde_json::Value::from(known)
    });
    let line = serde_json::json!({
        "at": now,
        "event": v["hook_event_name"],
        "session_id": v["session_id"],
        "notification_type": v["notification_type"],
        "error": error,
    });
    let path = dir.join("events");
    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let written = options
        .open(&path)
        .and_then(|mut file| writeln!(file, "{line}"));
    if let Err(error) = written {
        mark_hook_error(&dir);
        return Err(error.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn an_ended_session_is_never_restarted_until_a_new_one_starts() {
        // /exit fires SessionEnd, then Claude shuts down: never a restart (CX-0119).
        let text = [
            r#"{"at":1,"event":"SessionStart","session_id":"s"}"#,
            r#"{"at":2,"event":"Stop","session_id":"s"}"#,
            r#"{"at":3,"event":"SessionEnd","session_id":"s","reason":"prompt_input_exit"}"#,
        ]
        .join("\n");
        let ended = idle_state(&parse_events(&text));
        assert_eq!(ended.ended, Some(3));
        let mut i = inputs(&ended);
        i.now = 10_000_000;
        assert!(matches!(decide(&i), Decision::Wait(_)));
        // /clear ends the session and starts a new one: that one may follow a new token.
        let cleared = [
            (1, Event::SessionStart("s".into())),
            (3, Event::SessionEnd),
            (4, Event::SessionStart("t".into())),
        ];
        assert_eq!(idle_state(&cleared).ended, None);
    }

    use super::*;

    #[test]
    fn a_rate_limited_turn_failure_is_a_limit_event_that_also_ends_the_turn() {
        let text = concat!(
            r#"{"at":1,"event":"SessionStart","session_id":"s-1"}"#,
            "\n",
            r#"{"at":2,"event":"UserPromptSubmit","session_id":"s-1"}"#,
            "\n",
            r#"{"at":3,"event":"StopFailure","session_id":"s-1","error":"rate_limit"}"#,
            "\n",
            r#"{"at":4,"event":"StopFailure","session_id":"s-1","error":"overloaded"}"#,
        );
        assert_eq!(
            parse_events(text),
            vec![
                (1, Event::SessionStart("s-1".into())),
                (2, Event::Prompt),
                (3, Event::Limited("s-1".into())),
                (4, Event::Stop),
            ]
        );
        let events = parse_events(text);
        let idle = idle_state(&events[..3]);
        assert_eq!(idle.since, Some(3));
        assert_eq!(idle.limited, Some(("s-1".to_string(), 3)));
        // A new prompt or a new session clears it: only the latest turn counts.
        let mut idle = idle_state(&events[..3]);
        fold(&mut idle, &[(5, Event::Prompt)]);
        assert_eq!(idle.limited, None);
        let mut idle = idle_state(&events[..3]);
        fold(&mut idle, &[(5, Event::SessionStart("s-2".into()))]);
        assert_eq!(idle.limited, None);
    }

    #[test]
    fn the_hook_keeps_only_a_known_error_type_of_a_failed_turn() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("sessions");
        let dir = sessions.join("run-x");
        std::fs::create_dir_all(&dir).unwrap();
        let input = |error: &str| {
            serde_json::json!({"hook_event_name": "StopFailure", "session_id": "s-1",
                "error": error, "error_details": "secret detail",
                "last_assistant_message": "secret text"})
            .to_string()
        };
        record_hook(&sessions, &dir, &input("rate_limit"), 1).unwrap();
        record_hook(&sessions, &dir, &input("something new"), 2).unwrap();
        let stop = serde_json::json!({"hook_event_name": "Stop", "session_id": "s-1",
            "error": "rate_limit"});
        record_hook(&sessions, &dir, &stop.to_string(), 3).unwrap();
        let log = std::fs::read_to_string(dir.join("events")).unwrap();
        assert!(!log.contains("secret"), "{log}");
        let errors: Vec<serde_json::Value> = log
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["error"].clone())
            .collect();
        assert_eq!(
            errors,
            vec![
                serde_json::json!("rate_limit"),
                serde_json::json!("unknown"),
                serde_json::Value::Null
            ]
        );
    }

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
                since: None,
                limited: None,
                ended: None,
                auth_failed: None,
            }
        );
        let idle = [(1, SessionStart("a".into())), (2, Prompt), (3, Stop)];
        assert_eq!(
            idle_state(&idle),
            Idle {
                session: Some("a".into()),
                since: Some(3),
                limited: None,
                ended: None,
                auth_failed: None,
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
                since: Some(5),
                limited: None,
                ended: None,
                auth_failed: None,
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
            restarts_last_hour: 0,
        }
    }

    #[test]
    fn a_turn_that_ends_in_an_api_error_is_idle_too() {
        // Claude Code 2.1.295 ends a failed turn (a 401 on a revoked token) with
        // StopFailure, not Stop (SAW-12610 repro, 10-08 17:13).
        let text = [
            r#"{"at":1,"event":"SessionStart","session_id":"s"}"#,
            r#"{"at":2,"event":"UserPromptSubmit","session_id":"s"}"#,
            r#"{"at":3,"event":"StopFailure","session_id":"s"}"#,
        ]
        .join("\n");
        let events = parse_events(&text);
        assert_eq!(events.last(), Some(&(3, Event::Stop)));
        assert_eq!(
            idle_state(&events),
            Idle {
                session: Some("s".into()),
                since: Some(3),
                limited: None,
                ended: None,
                auth_failed: None,
            }
        );
    }

    #[test]
    fn a_revoked_token_restarts_only_an_idle_claude() {
        let idle = Idle {
            session: Some("s".into()),
            since: Some(10_000_000 - IDLE_AFTER_STOP_MS),
            limited: None,
            ended: None,
            auth_failed: None,
        };
        assert_eq!(decide(&inputs(&idle)), Decision::Restart);
        // Same revision: the held token is still the live one.
        let mut same = inputs(&idle);
        same.server_revision = "r1";
        assert_eq!(decide(&same), Decision::Keep);
        // Busy, too recent, typing, no session, or the budget used up. Extra processes in
        // Claude's group are no gate: the held token is superseded here (SAW-12610).
        let busy = Idle {
            session: Some("s".into()),
            since: None,
            limited: None,
            ended: None,
            auth_failed: None,
        };
        assert!(matches!(decide(&inputs(&busy)), Decision::Wait(_)));
        let recent = Idle {
            session: Some("s".into()),
            since: Some(10_000_000 - 1_000),
            limited: None,
            ended: None,
            auth_failed: None,
        };
        assert!(matches!(decide(&inputs(&recent)), Decision::Wait(_)));
        let mut typing = inputs(&idle);
        typing.tty_idle_ms = Some(30_000);
        assert!(matches!(decide(&typing), Decision::Wait(_)));
        let nosession = Idle {
            session: None,
            since: Some(0),
            limited: None,
            ended: None,
            auth_failed: None,
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
    fn a_dead_held_token_restarts_even_while_the_user_types() {
        // SAW-12610 10-09 19:12Z: the held token expired while the user typed; every prompt
        // failed with authentication_failed, and each try reset the 5-min input gate, so the
        // tab never restarted. A draft typed into a dead token cannot succeed.
        let idle = Idle {
            session: Some("s".into()),
            since: Some(10_000_000 - 1_000),
            limited: None,
            ended: None,
            auth_failed: None,
        };
        let mut expired = inputs(&idle);
        expired.held_expires_at = expired.now - 1;
        expired.tty_idle_ms = Some(5_000);
        assert_eq!(decide(&expired), Decision::Restart);
        // A running turn, an exiting session and the budget still hold.
        let busy = Idle {
            session: Some("s".into()),
            since: None,
            limited: None,
            ended: None,
            auth_failed: None,
        };
        let mut running = inputs(&busy);
        running.held_expires_at = running.now - 1;
        assert!(matches!(decide(&running), Decision::Wait(_)));
        let mut budget = expired;
        budget.restarts_last_hour = RESTARTS_PER_HOUR;
        assert!(matches!(decide(&budget), Decision::Wait(_)));
    }

    #[test]
    fn a_failed_authentication_marks_the_held_token_dead_for_the_process() {
        // A forced rotation revokes the held token before its expiry: the failed turn says so.
        let text = [
            r#"{"at":1,"event":"SessionStart","session_id":"s"}"#,
            r#"{"at":2,"event":"UserPromptSubmit","session_id":"s"}"#,
            r#"{"at":3,"event":"StopFailure","session_id":"s","error":"authentication_failed"}"#,
            r#"{"at":4,"event":"UserPromptSubmit","session_id":"s"}"#,
            r#"{"at":5,"event":"StopFailure","session_id":"s","error":"authentication_failed"}"#,
        ]
        .join("\n");
        let idle = idle_state(&parse_events(&text));
        assert_eq!(idle.auth_failed, Some(5));
        assert_eq!(idle.since, Some(5));
        let mut typing = inputs(&idle);
        typing.now = 6;
        typing.tty_idle_ms = Some(1_000);
        assert!(held_token_dead(&typing));
        assert_eq!(decide(&typing), Decision::Restart);
        // Same revision: the server has no newer token yet, so nothing to follow.
        typing.server_revision = "r1";
        assert_eq!(decide(&typing), Decision::Keep);
        // /clear or /resume starts a session in the same process, on the same dead token.
        let mut events = parse_events(&text);
        events.push((7, Event::SessionStart("s2".into())));
        let cleared = idle_state(&events);
        assert_eq!(cleared.auth_failed, Some(5));
        let mut still = inputs(&cleared);
        still.now = 8;
        assert!(held_token_dead(&still));
        // A relaunch on the new token starts a new event log: alive again.
        let fresh = idle_state(&parse_events(
            r#"{"at":9,"event":"SessionStart","session_id":"s"}"#,
        ));
        let mut alive = inputs(&fresh);
        alive.now = 10;
        assert!(!held_token_dead(&alive));
    }

    #[test]
    fn a_new_revision_without_a_later_expiry_is_not_followed() {
        let idle = Idle {
            session: Some("s".into()),
            since: Some(0),
            limited: None,
            ended: None,
            auth_failed: None,
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
    fn a_hook_that_cannot_record_leaves_the_error_marker() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("sessions");
        let dir = sessions.join("run-z");
        // `events` is a directory: the append fails.
        std::fs::create_dir_all(dir.join("events")).unwrap();
        let input = r#"{"hook_event_name":"UserPromptSubmit","session_id":"s"}"#;
        assert!(record_hook(&sessions, &dir, input, 1).is_err());
        assert!(dir.join("hook-error").exists());
    }

    #[test]
    fn oversized_or_malformed_hook_input_leaves_the_error_marker() {
        let root = tempfile::tempdir().unwrap();
        let sessions = root.path().join("sessions");
        for (name, input) in [
            ("run-big", vec![b'x'; HOOK_INPUT_LIMIT + 1]),
            ("run-bad", b"not json".to_vec()),
        ] {
            let dir = sessions.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            assert!(hook_from(&sessions, &dir, std::io::Cursor::new(input), 1).is_err());
            assert!(dir.join("hook-error").exists(), "{name}");
        }
        // A good event still records and leaves no marker.
        let dir = sessions.join("run-ok");
        std::fs::create_dir_all(&dir).unwrap();
        let good = br#"{"hook_event_name":"Stop","session_id":"s"}"#.to_vec();
        hook_from(&sessions, &dir, std::io::Cursor::new(good), 1).unwrap();
        assert!(!dir.join("hook-error").exists());
        // Outside the sessions root nothing is written at all.
        let outside = root.path().join("run-out");
        std::fs::create_dir_all(&outside).unwrap();
        assert!(hook_from(&sessions, &outside, std::io::Cursor::new(b"x".to_vec()), 1).is_err());
        assert!(!outside.join("hook-error").exists());
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
