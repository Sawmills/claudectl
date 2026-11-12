//! Recovery-module coverage for cron restoration after renewal or failover.
use super::*;
use std::ffi::OsStr;

struct Fixture {
    home: tempfile::TempDir,
    directory: PathBuf,
    first: PathBuf,
    second: PathBuf,
    card: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let directory = home.path().join(".claudectl/server/sessions/run-recovery");
        private_dir(&directory).unwrap();
        let card = home.path().join("Code/.fleet/example/operator.md");
        private_dir(card.parent().unwrap()).unwrap();
        let first = card.parent().unwrap().join("check prompt.txt");
        let second = card.parent().unwrap().join("deep-dive.txt");
        std::fs::write(&first, "Check the owned lanes.\n").unwrap();
        std::fs::write(&second, "Read the daily evidence.\n").unwrap();
        std::fs::write(&card, "operator_tab: w9C:tF\ncron_ids: old-one old-two\ncron_prompts: 'check prompt.txt' */5 * * * *; deep-dive.txt 24 8 * * *\nclaude_session_file: /old/session.jsonl\n").unwrap();
        Self {
            home,
            directory,
            first: first.canonicalize().unwrap(),
            second: second.canonicalize().unwrap(),
            card: card.canonicalize().unwrap(),
        }
    }
    fn prepare(&self) -> Result<Option<Recovery>> {
        Recovery::prepare_for_tab(
            self.home.path(),
            &self.directory,
            "s",
            Some(OsStr::new("w9C:tF")),
        )
    }
    fn jobs(&self) -> Value {
        json!([
            {"id":"new-one","cron":"*/5 * * * *","prompt":"Check the owned lanes.\n","recurring":true,"durable":false},
            {"id":"new-two","cron":"24 8 * * *","prompt":"Read the daily evidence.\n","recurring":true,"durable":false}
        ])
    }
    fn report(&self, recovery: &Recovery, jobs: Value, note: &str) -> String {
        let transcript = self.home.path().join("recovery.jsonl");
        let mut rows = vec![json!({"type":"user","sessionId":"s","message":{"content":note}})];
        for (number, inventory) in [json!([]), jobs].into_iter().enumerate() {
            let call = format!("list-{number}");
            let uuid = format!("assistant-{number}");
            rows.push(json!({"type":"assistant","sessionId":"s","uuid":uuid,
                "message":{"content":[{"type":"tool_use","name":"CronList","id":call,"input":{}}]}}));
            rows.push(json!({"type":"user","sessionId":"s","sourceToolAssistantUUID":uuid,
                "message":{"content":[{"type":"tool_result","tool_use_id":call,"content":"inventory"}]},
                "toolUseResult":{"jobs":inventory}}));
        }
        std::fs::write(
            &transcript,
            rows.iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                + "\n",
        )
        .unwrap();
        record_transcript(
            &self.directory,
            &json!({"hook_event_name":"Stop","session_id":"s","transcript_path":transcript}),
        )
        .unwrap();
        recovery.check(&self.directory, true).unwrap().unwrap()
    }
    fn other_card(&self, body: &str) -> PathBuf {
        let card = self.home.path().join("Code/.fleet/another/operator.md");
        private_dir(card.parent().unwrap()).unwrap();
        std::fs::write(&card, body).unwrap();
        card
    }
}

#[test]
fn repeated_owner_headers_are_one_owner() {
    let f = Fixture::new();
    let text = std::fs::read_to_string(&f.card).unwrap();
    std::fs::write(
        &f.card,
        format!(
            "hq: agent-platform hq_pane: NONE operator_tab: w9C:tF\n\
             operator_tab: w9C:tF (pane w9C:pF)\n{text}"
        ),
    )
    .unwrap();

    let recovery = f.prepare().unwrap().unwrap();
    for file in [&f.first, &f.second] {
        assert!(
            recovery
                .prompt()
                .contains(&format!("file: {}\n", file.display()))
        );
    }
}

#[test]
fn distinct_owner_headers_are_ambiguous() {
    for other in ["w9C:tOther", "w9C:tF-extra"] {
        let f = Fixture::new();
        let text = std::fs::read_to_string(&f.card).unwrap();
        std::fs::write(&f.card, format!("{text}operator_tab: {other}\n")).unwrap();

        assert_eq!(
            f.prepare().err().unwrap().to_string(),
            "cron recovery: ambiguous Operator card ownership"
        );
        assert!(!f.directory.join(ARMED).exists());
    }
}

#[test]
fn quoted_body_owner_references_do_not_count() {
    let f = Fixture::new();
    let text = std::fs::read_to_string(&f.card).unwrap();
    std::fs::write(
        &f.card,
        format!(
            "hq: guide hq_pane: NONE operator_tab: w9C:tF\n{text}\n\
             The guide quotes operator_tab: w9C:tC in its body.\n\
             > operator_tab: w9C:tC\n"
        ),
    )
    .unwrap();

    assert!(f.prepare().unwrap().is_some());
}

#[test]
fn verified_recovery_log_names_the_session_and_saved_job_count() {
    let f = Fixture::new();
    let recovery = f.prepare().unwrap().unwrap();
    let report = f.report(&recovery, f.jobs(), &recovery.prompt());
    log_notice(f.home.path(), &f.directory, &report).unwrap();

    let text = std::fs::read_to_string(f.home.path().join(".claudectl/server/cron-recovery.jsonl"))
        .unwrap();
    let rows: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(rows[0]["session"], "run-recovery");
    assert_eq!(rows[0]["message"], "crons intact: 2 jobs");
}

#[test]
fn recovery_names_saved_jobs_and_preserves_unrelated_inventory() {
    let f = Fixture::new();
    let recovery = f.prepare().unwrap().unwrap();
    let prompt = recovery.prompt();
    for expected in [
        f.first.to_str().unwrap(),
        f.second.to_str().unwrap(),
        "*/5 * * * *",
        "24 8 * * *",
        "even if CronList is empty",
        "Keep every matching listed job",
        "Preserve every other listed job",
        "cron_ids",
        "claude_session_file",
    ] {
        assert!(prompt.contains(expected), "missing {expected}");
    }
    let mut jobs = f.jobs();
    jobs.as_array_mut().unwrap().push(json!({"id":"manual","cron":"0 9 * * *","prompt":"Manual reminder.","recurring":true,"durable":false}));
    assert_eq!(f.report(&recovery, jobs, &prompt), "crons intact: 2 jobs");
}

#[test]
fn recovery_restores_only_missing_jobs_without_replaying_missed_fires() {
    let f = Fixture::new();
    let recovery = f.prepare().unwrap().unwrap();
    let prompt = recovery.prompt();
    assert!(prompt.contains("Keep every matching listed job"));
    assert!(prompt.contains("Create only missing jobs"));
    assert!(prompt.contains("Do not replay missed fires"));
    assert!(!prompt.contains("run that job's prompt ONCE now"));
}

#[test]
fn renewal_recovery_verifies_the_complete_launch_prompt() {
    let f = Fixture::new();
    let recovery = f.prepare().unwrap().unwrap();
    let prompt = recovery.prompt();
    assert!(prompt.ends_with("Then stop: do no other work."));
    assert_eq!(
        f.report(&recovery, f.jobs(), &prompt),
        "crons intact: 2 jobs"
    );
}

#[test]
fn failover_recovery_verifies_its_continuation_prompt() {
    let f = Fixture::new();
    let mut recovery = f.prepare().unwrap().unwrap();
    recovery.continue_request();
    let prompt = recovery.prompt();
    assert!(prompt.ends_with(super::super::failover::RECOVERY_PROMPT));
    assert!(!prompt.contains("Then stop: do no other work."));
    assert_eq!(
        f.report(&recovery, f.jobs(), &prompt),
        "crons intact: 2 jobs"
    );
}

fn assert_recovery_resume(continue_request: bool) {
    for (given, kept, original) in [
        (
            vec!["--add-dir", "../lib", "../shared"],
            vec!["--add-dir", "../lib", "../shared"],
            None,
        ),
        (
            vec!["--allowedTools", "Bash", "Read"],
            vec!["--allowedTools", "Bash", "Read"],
            None,
        ),
        (
            vec!["--add-dir=../lib", "../shared"],
            vec!["--add-dir=../lib", "../shared"],
            None,
        ),
        (
            vec!["--debug", "hooks", "--allowed-tools", "Bash", "Read"],
            vec!["--debug", "hooks", "--allowed-tools", "Bash", "Read"],
            None,
        ),
        (
            vec!["fix the tests", "--allowedTools", "Bash", "Read"],
            vec!["--allowedTools", "Bash", "Read"],
            Some("fix the tests"),
        ),
        (
            vec!["--model", "opus", "fix the tests"],
            vec!["--model", "opus"],
            Some("fix the tests"),
        ),
        (
            vec!["--add-dir", "../lib", "--", "-literal prompt"],
            vec!["--add-dir", "../lib"],
            Some("-literal prompt"),
        ),
    ] {
        let f = Fixture::new();
        let mut recovery = f.prepare().unwrap().unwrap();
        if continue_request {
            recovery.continue_request();
        }
        let prompt = recovery.prompt();
        let args: Vec<_> = given.iter().map(std::ffi::OsString::from).collect();
        let resumed = recovery.resume_args(&args, "s").unwrap();
        let delivered = resumed.last().unwrap().to_str().unwrap();
        assert!(delivered.contains(&prompt), "recovery omitted: {resumed:?}");
        let mut expected: Vec<_> = kept.iter().map(std::ffi::OsString::from).collect();
        expected.extend(["--resume".into(), "s".into(), "--".into()]);
        assert_eq!(&resumed[..resumed.len() - 1], expected);
        if let (true, Some(original)) = (continue_request, original) {
            assert!(delivered.ends_with(original));
            assert_eq!(delivered.matches(original).count(), 1);
        } else {
            assert_eq!(delivered, prompt);
        }
        assert_eq!(
            f.report(&recovery, f.jobs(), delivered),
            "crons intact: 2 jobs"
        );
    }
}

#[test]
fn renewal_recovery_does_not_resubmit_initial_task() {
    assert_recovery_resume(false);
}

#[test]
fn failover_recovery_preserves_initial_task_for_continuation() {
    assert_recovery_resume(true);
}

#[test]
fn a_different_positional_prompt_does_not_verify_failover_recovery() {
    let f = Fixture::new();
    let mut recovery = f.prepare().unwrap().unwrap();
    recovery.continue_request();
    recovery
        .resume_args(&["original request".into()], "s")
        .unwrap();
    assert_eq!(
        f.report(&recovery, f.jobs(), &recovery.prompt()),
        "cron recovery unverified: no post-restart CronList"
    );
}

#[test]
fn recovery_accepts_kept_jobs_with_their_existing_ids() {
    let f = Fixture::new();
    let recovery = f.prepare().unwrap().unwrap();
    let mut jobs = f.jobs();
    jobs[0]["id"] = "old-one".into();
    jobs[1]["id"] = "old-two".into();
    assert_eq!(
        f.report(&recovery, jobs, &recovery.prompt()),
        "crons intact: 2 jobs"
    );
}

#[test]
fn recovery_merges_cards_deduplicates_jobs_and_keeps_distinct_local_schedules() {
    for second_schedule in [false, true] {
        let f = Fixture::new();
        if second_schedule {
            let text = std::fs::read_to_string(&f.card).unwrap();
            std::fs::write(
                &f.card,
                format!("{text}cron_prompts: 'check prompt.txt' 0 12 * * *\n"),
            )
            .unwrap();
        } else {
            f.other_card("operator_tab: w9C:tF\ncron_prompts: '../example/./check prompt.txt' */5 * * * *; third.txt 0 12 * * *\n");
            std::fs::write(
                f.home.path().join("Code/.fleet/another/third.txt"),
                "Check the other project.\n",
            )
            .unwrap();
        }
        let recovery = f.prepare().unwrap().unwrap();
        let prompt = recovery.prompt();
        assert_eq!(
            prompt
                .matches(&format!("file: {}\n", f.first.display()))
                .count(),
            if second_schedule { 2 } else { 1 }
        );
        assert!(prompt.contains("EACH named Operator card"));
        assert!(prompt.contains("same ID on every owning card"));
        let mut jobs = f.jobs();
        jobs.as_array_mut().unwrap().push(json!({"id":"new-three","cron":"0 12 * * *","prompt":if second_schedule {"Check the owned lanes.\n"} else {"Check the other project.\n"},"recurring":true,"durable":false}));
        assert_eq!(f.report(&recovery, jobs, &prompt), "crons intact: 3 jobs");
    }
}

#[test]
fn recovery_rejects_cross_card_schedule_conflicts_and_unsupported_paths() {
    let f = Fixture::new();
    f.other_card("operator_tab: w9C:tF\ncron_prompts: '../example/check prompt.txt' 0 12 * * *\n");
    assert!(
        f.prepare()
            .err()
            .unwrap()
            .to_string()
            .contains("conflicting schedules")
    );
    for path in ["$FLEET/check.txt", "~another-user/check.txt"] {
        let f = Fixture::new();
        std::fs::write(
            &f.card,
            format!("operator_tab: w9C:tF\ncron_prompts: {path} */5 * * * *\n"),
        )
        .unwrap();
        assert!(
            f.prepare()
                .err()
                .unwrap()
                .to_string()
                .contains("unsupported saved cron path")
        );
    }
    let f = Fixture::new();
    std::fs::remove_file(&f.first).unwrap();
    assert!(f.prepare().is_err());
}

#[test]
fn empty_unrelated_or_unreadable_cards_do_not_hide_owned_saved_jobs() {
    for body in [
        "operator_tab: w9C:tF\n",
        "operator_tab: w9C:tF\ncron_prompts:\n",
        "operator_tab: w9C:tOther\n",
    ] {
        let f = Fixture::new();
        f.other_card(body);
        let recovery = f.prepare().unwrap().unwrap();
        assert!(recovery.prompt().contains(f.first.to_str().unwrap()));
    }
    let f = Fixture::new();
    let card = f.other_card("");
    std::fs::write(card, b"operator_tab: w9C:tOther\n\xff").unwrap();
    assert!(f.prepare().unwrap().is_some());
    assert!(
        Recovery::prepare_for_tab(
            f.home.path(),
            &f.directory,
            "s",
            Some(OsStr::new("w9C:tOther"))
        )
        .unwrap()
        .is_none()
    );
    std::fs::write(&f.card, "operator_tab: w9C:tF\ncron_ids:\ncron_prompts:\n").unwrap();
    assert!(f.prepare().unwrap().is_none());
}

#[test]
fn inline_and_body_owner_references_do_not_select_a_card() {
    for owner in [
        "hq: example hq_pane: w5C:t41 operator_tab: w9C:tF",
        "The guide quotes operator_tab: w9C:tF in its body.",
        "> operator_tab: w9C:tF",
        "  operator_tab: w9C:tF",
    ] {
        let f = Fixture::new();
        let text = std::fs::read_to_string(&f.card).unwrap();
        std::fs::write(&f.card, text.replace("operator_tab: w9C:tF", owner)).unwrap();
        assert!(f.prepare().unwrap().is_none(), "selected {owner}");
        assert!(!f.directory.join(ARMED).exists());
    }
}

#[test]
fn missing_and_duplicate_jobs_never_claim_verified_recovery() {
    for duplicate in [false, true] {
        let f = Fixture::new();
        let recovery = f.prepare().unwrap().unwrap();
        let mut jobs = f.jobs();
        if duplicate {
            let mut old = jobs[0].clone();
            old["id"] = "old-one".into();
            jobs.as_array_mut().unwrap().push(old);
        } else {
            jobs.as_array_mut().unwrap().pop();
        }
        let report = f.report(&recovery, jobs, &recovery.prompt());
        assert!(report.contains(if duplicate {
            "duplicate saved cron:"
        } else {
            "missing cron:"
        }));
        assert!(!report.contains("crons intact:"));
        assert!(!report.contains("Check the owned lanes."));
    }
}

#[test]
fn stale_or_previous_attempt_transcripts_do_not_verify_a_new_recovery() {
    for previous_attempt in [false, true] {
        let f = Fixture::new();
        let prior = f.prepare().unwrap().unwrap();
        let old_note = prior.prompt();
        let recovery = f.prepare().unwrap().unwrap();
        let note = if previous_attempt {
            old_note.as_str()
        } else {
            "earlier user turn"
        };
        assert_eq!(
            f.report(&recovery, f.jobs(), note),
            "cron recovery unverified: no post-restart CronList"
        );
    }
}

#[test]
fn recovery_logging_is_private_and_optional_without_prompt_contents() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let f = Fixture::new();
    let path = f.home.path().join(".claudectl/server/cron-recovery.jsonl");
    std::fs::write(&path, "").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    log_notice(f.home.path(), &f.directory, "crons intact: 2 jobs").unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let row: Value = serde_json::from_str(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    assert_eq!(row["session"], "run-recovery");
    assert!(row["at"].as_i64().unwrap() > 0);
    assert!(!row.to_string().contains("Check the owned lanes."));
    std::fs::remove_file(&path).unwrap();
    let target = f.home.path().join("untouched");
    std::fs::write(&target, "unchanged").unwrap();
    symlink(&target, &path).unwrap();
    assert!(log_notice(f.home.path(), &f.directory, "notice").is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "unchanged");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    let recovery = f.prepare().unwrap().unwrap();
    let report = f.report(&recovery, f.jobs(), &recovery.prompt());
    assert!(log_notice(f.home.path(), &f.directory, &report).is_err());
    assert_eq!(report, "crons intact: 2 jobs");
}

#[cfg(target_os = "linux")]
#[test]
fn recovery_log_never_enters_the_child_terminal_or_input() {
    const CHILD_HOME: &str = "CLAUDECTL_TEST_CRON_LOG_HOME";
    if let Some(home) = std::env::var_os(CHILD_HOME) {
        let home = PathBuf::from(home);
        log_notice(
            &home,
            &home.join(".claudectl/server/sessions/run-recovery"),
            "crons intact: 2 jobs",
        )
        .unwrap();
        // This is the isolated test child's PTY, with no user terminal attached.
        unsafe {
            let flags = libc::fcntl(0, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(libc::fcntl(0, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
            let mut byte = 0u8;
            let count = libc::read(0, (&mut byte as *mut u8).cast(), 1);
            assert!(
                count == 0
                    || (count == -1
                        && std::io::Error::last_os_error().kind()
                            == std::io::ErrorKind::WouldBlock),
                "logger entered child input"
            );
        }
        return;
    }
    let f = Fixture::new();
    let binary = std::env::current_exe().unwrap();
    let quoted = format!("'{}'", binary.display().to_string().replace('\'', "'\\''"));
    let command = format!(
        "{quoted} --exact central::crons::tests::recovery_log_never_enters_the_child_terminal_or_input --nocapture"
    );
    let output = std::process::Command::new("/usr/bin/script")
        .args(["-qec", &command, "/dev/null"])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env(CHILD_HOME, f.home.path())
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains("crons intact:"));
    }
    let text = std::fs::read_to_string(f.home.path().join(".claudectl/server/cron-recovery.jsonl"))
        .unwrap();
    assert_eq!(text.lines().count(), 1);
}

#[test]
fn a_symlinked_home_still_identifies_the_canonical_saved_prompt_files() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let container = tempfile::tempdir().unwrap();
    let alias = container.path().join("linked-home");
    symlink(f.home.path(), &alias).unwrap();
    let recovery = Recovery::prepare_for_tab(&alias, &f.directory, "s", Some(OsStr::new("w9C:tF")))
        .unwrap()
        .unwrap();
    let prompt = recovery.prompt();
    assert!(prompt.contains(&format!(
        "file: {}\n",
        f.first.canonicalize().unwrap().display()
    )));
    assert!(prompt.contains(&format!(
        "file: {}\n",
        f.second.canonicalize().unwrap().display()
    )));
    assert!(!prompt.contains(&format!("file: {}/", alias.display())));
}
