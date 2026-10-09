//! The account model that `claudectl status`, `claudectl run` and the server dashboard
//! share (SAW-12677): how a typed name resolves, what state an account is in, and which
//! account to use. One implementation, so the terminal and the web never disagree.
use anyhow::{Result, bail};

/// One usage window: its label, percent used, and reset time (Unix seconds) when known.
#[derive(Clone, Debug, PartialEq)]
pub struct Window {
    pub name: &'static str,
    pub used: Option<f64>,
    pub resets_at: Option<i64>,
}

/// The windows of a usage response, in display order: 5h and week always, then Fable,
/// Opus and Sonnet when the response has them.
pub fn windows(usage: &crate::api::UsageResponse) -> Vec<Window> {
    let window = |name, w: Option<&crate::api::UsageWindow>| Window {
        name,
        used: w
            .and_then(|w| w.utilization)
            .filter(|n| n.is_finite() && *n >= 0.0),
        resets_at: w.and_then(crate::api::UsageWindow::reset_timestamp),
    };
    let mut out = vec![
        window("5h", usage.five_hour.as_ref()),
        window("week", usage.seven_day.as_ref()),
    ];
    if let Some(fable) = usage.fable_weekly() {
        out.push(Window {
            name: "Fable",
            used: fable.percent.filter(|n| n.is_finite() && *n >= 0.0),
            resets_at: None,
        });
    }
    if usage.seven_day_opus.is_some() {
        out.push(window("Opus", usage.seven_day_opus.as_ref()));
    }
    if usage.seven_day_sonnet.is_some() {
        out.push(window("Sonnet", usage.seven_day_sonnet.as_ref()));
    }
    out
}

/// `in 7h 52m`-style time from `now` to `at`.
pub fn until(at: i64, now: i64) -> String {
    let secs = at.saturating_sub(now);
    if secs <= 0 {
        return "now".into();
    }
    let (d, h, m) = (secs / 86_400, secs % 86_400 / 3_600, secs % 3_600 / 60);
    if d > 0 {
        format!("in {d}d {h}h")
    } else if h > 0 {
        format!("in {h}h {m}m")
    } else {
        format!("in {}m", m.max(1))
    }
}

/// One row per window for a detail view: name, percent used, and the reset as time from
/// now plus the local clock time (`in 7h 52m (Fri 08:10)`), never a raw timestamp.
pub fn detail_rows(usage: &crate::api::UsageResponse, now: i64) -> Vec<[String; 3]> {
    windows(usage)
        .into_iter()
        .map(|w| {
            let reset = w.resets_at.map_or_else(
                || "-".to_string(),
                |at| {
                    let clock = chrono::DateTime::from_timestamp(at, 0)
                        .map(|t| {
                            t.with_timezone(&chrono::Local)
                                .format("%a %H:%M")
                                .to_string()
                        })
                        .unwrap_or_default();
                    format!("{} ({clock})", until(at, now))
                },
            );
            [
                w.name.to_string(),
                w.used.map_or_else(|| "-".into(), |p| format!("{p:.0}%")),
                reset,
            ]
        })
        .collect()
}

/// Above this a window is low.
pub const LOW: f64 = 80.0;

#[derive(Clone, Debug, PartialEq)]
pub enum State {
    Ready,
    /// A window is above `LOW`.
    Low {
        window: &'static str,
    },
    /// A window is full: the account cannot be used until it resets.
    Limit {
        window: &'static str,
        resets_at: Option<i64>,
    },
    /// No figure for the 5h or the week window: partial usage is never a basis to pick.
    Unknown,
}

/// The state of an account from its windows. A full window (Fable included) is a limit;
/// otherwise a missing 5h or week figure makes the whole account unknown.
pub fn state(windows: &[Window]) -> State {
    let known: Vec<_> = windows.iter().filter(|w| w.used.is_some()).collect();
    if let Some(full) = known.iter().find(|w| w.used >= Some(100.0)) {
        return State::Limit {
            window: full.name,
            resets_at: full.resets_at,
        };
    }
    if ["5h", "week"]
        .iter()
        .any(|name| !known.iter().any(|w| w.name == *name))
    {
        return State::Unknown;
    }
    match known.iter().find(|w| w.used > Some(LOW)) {
        Some(low) => State::Low { window: low.name },
        None => State::Ready,
    }
}

/// An account as the picker sees it.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub name: String,
    pub windows: Vec<Window>,
    /// The usage figures are current enough to choose on.
    pub fresh: bool,
    /// Usage-based billing: never picked automatically.
    pub billed: bool,
}

/// The account to use: fresh, not billed, no full window; then the most room (the lowest
/// highest-window use); then the soonest week reset; then the name.
pub fn best(candidates: &[Candidate]) -> Option<usize> {
    let highest = |c: &Candidate| {
        c.windows
            .iter()
            .filter_map(|w| w.used)
            .fold(0.0_f64, f64::max)
    };
    let week_reset = |c: &Candidate| {
        c.windows
            .iter()
            .find(|w| w.name == "week")
            .and_then(|w| w.resets_at)
            .unwrap_or(i64::MAX)
    };
    candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| {
            c.fresh && !c.billed && matches!(state(&c.windows), State::Ready | State::Low { .. })
        })
        .min_by(|(_, a), (_, b)| {
            highest(a)
                .total_cmp(&highest(b))
                .then_with(|| week_reset(a).cmp(&week_reset(b)))
                .then_with(|| a.name.cmp(&b.name))
        })
        .map(|(i, _)| i)
}

fn local_part(name: &str) -> &str {
    name.split_once('@').map_or(name, |(local, _)| local)
}

/// Names without their domain when every name has the same one; else unchanged.
pub fn short_names<S: AsRef<str>>(names: &[S]) -> Vec<String> {
    let domains: Vec<_> = names
        .iter()
        .map(|n| {
            n.as_ref()
                .split_once('@')
                .map(|(_, d)| d.to_ascii_lowercase())
        })
        .collect();
    let shared = domains.first().cloned().flatten().is_some()
        && domains.windows(2).all(|pair| pair[0] == pair[1]);
    names
        .iter()
        .map(|n| {
            if shared {
                local_part(n.as_ref()).to_owned()
            } else {
                n.as_ref().to_owned()
            }
        })
        .collect()
}

fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let next = (row[j + 1] + 1)
                .min(row[j] + 1)
                .min(previous + usize::from(ca != *cb));
            previous = row[j + 1];
            row[j + 1] = next;
        }
    }
    row[b.len()]
}

/// The account `input` names: an exact name (any case), then an exact email local part
/// (`amir2` for `amir2@sawmills.ai`), then a unique prefix of either. Never a guess: an
/// unknown or ambiguous name is an error that lists the accounts.
pub fn resolve<'a, S: AsRef<str>>(input: &str, names: &'a [S]) -> Result<&'a str> {
    let input = input.trim();
    let all: Vec<&str> = names.iter().map(AsRef::as_ref).collect();
    let listed = all.join(", ");
    let pick = |hits: Vec<&'a str>| -> Result<Option<&'a str>> {
        match hits.as_slice() {
            [] => Ok(None),
            [one] => Ok(Some(*one)),
            many => bail!(
                "'{input}' matches more than one account: {}.\nTry: claudectl status",
                many.join(", ")
            ),
        }
    };
    let lower = input.to_ascii_lowercase();
    let matching = |test: &dyn Fn(&str) -> bool| -> Vec<&'a str> {
        names
            .iter()
            .map(AsRef::as_ref)
            .filter(|n| test(&n.to_ascii_lowercase()))
            .collect()
    };
    if let Some(found) = pick(matching(&|n| n == lower))? {
        return Ok(found);
    }
    if let Some(found) = pick(matching(&|n| local_part(n) == lower))? {
        return Ok(found);
    }
    if !lower.is_empty()
        && let Some(found) = pick(matching(&|n| n.starts_with(&lower)))?
    {
        return Ok(found);
    }
    // One clearly closest name (at most two edits away) is offered, never chosen.
    let mut close: Vec<(usize, &str)> = all
        .iter()
        .map(|n| {
            let n_lower = n.to_ascii_lowercase();
            (
                distance(&lower, local_part(&n_lower)).min(distance(&lower, &n_lower)),
                *n,
            )
        })
        .filter(|(d, _)| *d <= 2)
        .collect();
    close.sort();
    let hint = match close.as_slice() {
        [(d, name), rest @ ..] if rest.first().is_none_or(|(e, _)| e > d) => {
            format!("; did you mean {name}?")
        }
        _ => String::new(),
    };
    if all.is_empty() {
        bail!(
            "no account named '{input}': this machine has no accounts.\nTry: claudectl add <name>"
        );
    }
    bail!("no account named '{input}'{hint}\nAccounts: {listed}.\nTry: claudectl status")
}
