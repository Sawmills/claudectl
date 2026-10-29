//! Operator-card cron recovery for a server-token renewal. Ordinary sessions keep their
//! existing renewal note; only the owning HerdR tab can select cards with saved jobs.
use super::*;
use std::io::{Read, Seek, SeekFrom};

const ARMED: &str = "cron-recovery";
const TRANSCRIPT: &str = "cron-transcript.json";
const TRANSCRIPT_LIMIT: u64 = 8 * 1024 * 1024;

/// Recovery diagnostics must never write over Claude's live terminal. Keep them outside
/// the temporary run directory so they remain available after the session exits.
pub(super) fn log_notice(home: &Path, directory: &Path, message: &str) -> Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let path = home.join(".claudectl/server/cron-recovery.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .context("could not open cron recovery log")?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let mut record = serde_json::to_vec(&json!({
        "at": now(),
        "session": directory.file_name().and_then(|name| name.to_str()).context("run directory has no name")?,
        "message": message,
    }))?;
    record.push(b'\n');
    file.write_all(&record)
        .context("could not append cron recovery log")
}

struct Job {
    file: PathBuf,
    schedule: String,
    prompt: String,
}
impl Job {
    fn matches(&self, value: &Value) -> bool {
        value["cron"] == self.schedule
            && value["prompt"]
                .as_str()
                .is_some_and(|prompt| prompt.trim() == self.prompt.trim())
            && value["recurring"] == true
            && value["durable"] == false
            && value["id"].as_str().is_some_and(|id| !id.is_empty())
    }
}

pub(super) struct Recovery {
    cards: Vec<PathBuf>,
    jobs: Vec<Job>,
    previous: Vec<(PathBuf, u64)>,
    session_id: String,
    attempt: String,
}

impl Recovery {
    pub(super) fn prepare(home: &Path, directory: &Path, session_id: &str) -> Result<Option<Self>> {
        Self::prepare_for_tab(
            home,
            directory,
            session_id,
            std::env::var_os("HERDR_TAB_ID").as_deref(),
        )
    }

    fn prepare_for_tab(
        home: &Path,
        directory: &Path,
        session_id: &str,
        tab: Option<&std::ffi::OsStr>,
    ) -> Result<Option<Self>> {
        let mut recovery = Self::discover(home, directory, tab)?;
        if let Some(recovery) = &mut recovery {
            recovery.arm(directory, session_id)?;
        }
        Ok(recovery)
    }

    fn discover(home: &Path, run: &Path, tab: Option<&std::ffi::OsStr>) -> Result<Option<Self>> {
        let Some(tab) = tab else {
            return Ok(None);
        };
        let fleet = home.join("Code/.fleet");
        let directories = match std::fs::read_dir(fleet) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut owned = Self {
            cards: Vec::new(),
            jobs: Vec::new(),
            previous: Vec::new(),
            session_id: String::new(),
            attempt: format!("{:032x}", rand::random::<u128>()),
        };
        for directory in directories {
            let directory = directory?;
            if !directory.file_type()?.is_dir() {
                continue;
            }
            let card = directory.path().join("operator.md");
            let text = match std::fs::read_to_string(&card) {
                Ok(text) => text,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => {
                    if let Err(error) = log_notice(
                        home,
                        run,
                        &format!(
                            "cron recovery discovery skipped unreadable Operator card: {}",
                            card.display()
                        ),
                    ) {
                        // Discovery runs between children, before the replacement spawns.
                        eprintln!("claudectl: could not record cron recovery: {error:#}");
                    }
                    continue;
                }
            };
            let mut owners = Vec::new();
            for line in text.lines() {
                let mut words = line.split_whitespace();
                while let Some(word) = words.next() {
                    if word == "operator_tab:"
                        && let Some(owner) = words.next()
                    {
                        owners.push(owner);
                    }
                }
            }
            if !owners
                .iter()
                .any(|owner| std::ffi::OsStr::new(owner) == tab)
            {
                continue;
            }
            if !text.lines().any(|line| {
                line.strip_prefix("cron_prompts:")
                    .is_some_and(|value| !value.trim().is_empty())
            }) {
                continue;
            }
            if owners.len() != 1 {
                bail!("cron recovery: ambiguous Operator card ownership");
            }
            let earlier_cards = owned.jobs.len();
            for line in text
                .lines()
                .filter_map(|line| line.strip_prefix("cron_prompts:"))
            {
                if line.trim().is_empty() {
                    continue;
                }
                for entry in line.split(';') {
                    let words = shell_words::split(entry).map_err(|_| {
                        anyhow::anyhow!("cron recovery: invalid cron_prompts quoting")
                    })?;
                    if words.len() != 6 {
                        bail!("cron recovery: cron_prompts needs a file and five schedule fields");
                    }
                    let file = saved_path(home, &card, &words[0])?;
                    let file = file.canonicalize().with_context(|| {
                        format!("cron recovery: saved prompt unreadable: {}", file.display())
                    })?;
                    let schedule = words[1..].join(" ");
                    if owned.jobs[..earlier_cards]
                        .iter()
                        .any(|job| job.file == file && job.schedule != schedule)
                    {
                        bail!(
                            "cron recovery: conflicting schedules for saved prompt: {}",
                            file.display()
                        );
                    }
                    if owned
                        .jobs
                        .iter()
                        .any(|job| job.file == file && job.schedule == schedule)
                    {
                        continue;
                    }
                    let prompt = std::fs::read_to_string(&file).with_context(|| {
                        format!("cron recovery: saved prompt unreadable: {}", file.display())
                    })?;
                    if prompt.trim().is_empty() {
                        bail!("cron recovery: saved prompt is empty: {}", file.display());
                    }
                    owned.jobs.push(Job {
                        file,
                        schedule,
                        prompt,
                    });
                }
            }
            let previous = text
                .lines()
                .find_map(|line| line.strip_prefix("claude_session_file:"))
                .and_then(|value| shell_words::split(value).ok())
                .filter(|words| words.len() == 1)
                .map(|words| saved_path(home, &card, &words[0]))
                .transpose()?
                .and_then(|path| path.canonicalize().ok())
                .and_then(|path| std::fs::metadata(&path).ok().map(|info| (path, info.len())));
            owned.cards.push(card);
            owned.previous.extend(previous);
        }
        Ok((!owned.jobs.is_empty()).then_some(owned))
    }

    /// Arm only for the renewal launch. The hook records a transcript location, never its
    /// contents, and only while this private marker exists.
    fn arm(&mut self, directory: &Path, session_id: &str) -> Result<()> {
        self.session_id = session_id.to_owned();
        match std::fs::remove_file(directory.join(TRANSCRIPT)) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        atomic(&directory.join(ARMED), &true)
    }

    /// None until the restoration turn stops. On process exit, absent evidence is an
    /// explicit unverified result. Tool calls alone never prove jobs exist.
    pub(super) fn check(&self, directory: &Path, finished: bool) -> Result<Option<String>> {
        let report = self.read_report(directory, finished);
        if !matches!(&report, Ok(None)) {
            std::fs::remove_file(directory.join(ARMED))?;
        }
        report
    }

    fn read_report(&self, directory: &Path, finished: bool) -> Result<Option<String>> {
        let location = match std::fs::read(directory.join(TRANSCRIPT)) {
            Ok(bytes) => serde_json::from_slice::<Value>(&bytes)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(
                    finished.then(|| "cron recovery unverified: no post-restart CronList".into())
                );
            }
            Err(error) => return Err(error.into()),
        };
        if location["session_id"] != self.session_id {
            bail!("cron transcript belongs to another session");
        }
        let path = Path::new(
            location["path"]
                .as_str()
                .context("cron transcript path missing")?,
        )
        .canonicalize()?;
        let mut file = File::open(&path)?;
        let offset = self
            .previous
            .iter()
            .filter(|(previous, _)| previous == &path)
            .map(|(_, offset)| *offset)
            .max()
            .unwrap_or(0);
        if file.metadata()?.len() < offset {
            bail!("cron transcript was truncated");
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut bytes = Vec::new();
        file.take(TRANSCRIPT_LIMIT + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > TRANSCRIPT_LIMIT {
            bail!("cron transcript exceeds recovery read limit");
        }
        let Some(mut actual) = self.inventory(&bytes)? else {
            return Ok(Some(
                "cron recovery unverified: no post-restart CronList".into(),
            ));
        };
        let mut missing = Vec::new();
        for job in &self.jobs {
            let found = actual.iter().position(|value| job.matches(value));
            if let Some(index) = found {
                actual.remove(index);
            } else {
                missing.push(format!(
                    "missing cron: {} ({})",
                    job.file.display(),
                    job.schedule
                ));
            }
        }
        for job in &self.jobs {
            if actual.iter().any(|value| job.matches(value)) {
                missing.push(format!(
                    "duplicate saved cron: {} ({})",
                    job.file.display(),
                    job.schedule
                ));
            }
        }
        Ok(Some(if missing.is_empty() {
            format!(
                "cron recovery verified: {0}/{0} saved jobs",
                self.jobs.len()
            )
        } else {
            missing.join("; ")
        }))
    }

    fn inventory(&self, bytes: &[u8]) -> Result<Option<Vec<Value>>> {
        let prompt = self.prompt();
        let mut anchored = false;
        let mut call: Option<(String, String)> = None;
        let mut jobs = None;
        for raw in bytes.split_inclusive(|byte| *byte == b'\n') {
            if !raw.ends_with(b"\n") || raw.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let row: Value = serde_json::from_slice(raw)?;
            if row["sessionId"].as_str() != Some(self.session_id.as_str()) {
                continue;
            }
            let content = &row["message"]["content"];
            if row["type"] == "user"
                && (content.as_str() == Some(prompt.as_str())
                    || content.as_array().is_some_and(|blocks| {
                        blocks
                            .iter()
                            .any(|block| block["type"] == "text" && block["text"] == prompt)
                    }))
            {
                anchored = true;
                jobs = None;
                call = None;
                continue;
            }
            if !anchored {
                continue;
            }
            for block in content.as_array().into_iter().flatten() {
                if row["type"] == "assistant" && block["type"] == "tool_use" {
                    match block["name"].as_str() {
                        Some("CronList") => {
                            jobs = None;
                            call = Some((
                                block["id"].as_str().context("CronList id missing")?.into(),
                                row["uuid"]
                                    .as_str()
                                    .context("CronList assistant missing")?
                                    .into(),
                            ));
                        }
                        Some("CronCreate" | "CronDelete") => {
                            jobs = None;
                            call = None;
                        }
                        _ => (),
                    }
                } else if row["type"] == "user"
                    && block["type"] == "tool_result"
                    && let Some((id, assistant)) = &call
                    && block["tool_use_id"] == *id
                    && row["sourceToolAssistantUUID"] == *assistant
                {
                    if block["is_error"] == true {
                        jobs = None;
                    } else {
                        jobs = row["toolUseResult"]["jobs"].as_array().cloned();
                    }
                    call = None;
                }
            }
        }
        Ok(jobs)
    }

    pub(super) fn prompt(&self) -> String {
        let mut prompt = format!(
            "claudectl cron recovery attempt {}. claudectl restarted this session on a renewed server token. Restore the saved \
             session crons from Operator cards {} even if CronList is empty. Run CronList \
             first. Delete only card-owned IDs from the card's cron_ids, and only when \
             their schedule and prompt match the saved jobs. Preserve every other listed job. \
             Then use CronCreate for \
             EACH saved job below, recurring=true, using its exact five-field schedule and \
             the prompt read verbatim from its file (not a summary):\n",
            self.attempt,
            self.cards
                .iter()
                .map(|card| card.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        for job in &self.jobs {
            prompt.push_str(&format!(
                "file: {}\nschedule: {}\n",
                job.file.display(),
                job.schedule
            ));
        }
        prompt.push_str(
            "Run CronList again after all creations. Update cron_ids on EACH named Operator \
             card to the newly created IDs for that card's cron_prompts, in the same order. \
             A shared file and schedule uses the same new ID on every owning card. \
             Update claude_session_file on each card \
             to this session's actual transcript path. After re-creating the jobs, compare \
             each job's schedule with the time since this session's last turn. If one or more \
             fires were missed for a job, run that job's prompt ONCE now, regardless of how \
             many fires were missed. Then stop: do no other work.",
        );
        prompt
    }
}

fn saved_path(home: &Path, card: &Path, value: &str) -> Result<PathBuf> {
    for prefix in ["~/", "$HOME/", "${HOME}/"] {
        if let Some(relative) = value.strip_prefix(prefix) {
            return Ok(home.join(relative));
        }
    }
    if value.starts_with('~') || value.contains('$') {
        bail!(
            "cron recovery: unsupported saved cron path: {value}; use an absolute or relative path, ~/ or $HOME/"
        );
    }
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(card.parent().unwrap().join(path))
    }
}

pub(super) fn record_transcript(directory: &Path, event: &Value) -> Result<()> {
    if !directory.join(ARMED).exists()
        || !(event["hook_event_name"] == "Stop"
            || (event["hook_event_name"] == "Notification"
                && event["notification_type"] == "idle_prompt"))
    {
        return Ok(());
    }
    if let (Some(path), Some(session)) = (
        event["transcript_path"].as_str(),
        event["session_id"].as_str(),
    ) {
        atomic(
            &directory.join(TRANSCRIPT),
            &json!({"path":path,"session_id":session}),
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "central_crons_tests.rs"]
mod tests;
