//! The browser projection, ported from the codexctl #153 dashboard. It receives only the
//! secret-free snapshot; rendering never mutates accounts.
use super::enrollment::escape;

pub(super) struct Snapshot {
    pub email: String,
    pub server_time: i64,
    pub accounts: Vec<Account>,
    pub machines: Vec<Machine>,
}
pub(super) struct Account {
    pub alias: String,
    pub available: bool,
    /// `not_migrated`, `pending`, `unrotated`, or `rotated`.
    pub migration: String,
    pub five_hour: Window,
    pub seven_day: Window,
    /// Unix seconds of the server's last usage observation.
    pub observed_at: Option<i64>,
    pub usage_stale: bool,
}
pub(super) struct Window {
    pub used_percent: Option<f64>,
    pub resets_at: Option<i64>,
}
pub(super) struct Machine {
    pub id: String,
    pub revoked: bool,
}

impl Account {
    fn used(&self) -> impl Iterator<Item = f64> + '_ {
        [self.five_hour.used_percent, self.seven_day.used_percent]
            .into_iter()
            .flatten()
    }
    fn state(&self) -> (&'static str, &'static str) {
        if !self.available {
            ("bad", "Login needs attention")
        } else if self.migration == "pending" {
            ("pending", "Migration pending")
        } else if self.usage_stale {
            ("warn", "Stale usage")
        } else if self.used().any(|n| n >= 100.0) {
            ("bad", "Exhausted")
        } else if self.used().any(|n| n > 80.0) {
            ("warn", "Nearly exhausted")
        } else {
            ("ok", "Available")
        }
    }
    fn migration(&self) -> &'static str {
        match self.migration.as_str() {
            "not_migrated" => "Signed in on the server",
            "pending" => "Migration pending",
            "unrotated" => "Migrated · old copies still valid",
            "rotated" => "Migrated",
            _ => "Migration state unknown",
        }
    }
}

fn command(id: &str, text: &str) -> String {
    let text = escape(text);
    format!(
        r#"<div class="command"><pre tabindex="0"><code id="{id}" translate="no">{text}</code></pre><button class="button primary copy" type="button" data-copy="{id}" aria-label="Copy {text}">Copy</button></div><p class="command-note">POSIX shell syntax.</p>"#
    )
}
fn date(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|t| t.format("%b %-d, %H:%M UTC").to_string())
        .unwrap_or_else(|| "Unknown time".into())
}
fn reset(at: Option<i64>, now: i64) -> String {
    let Some(at) = at else {
        return "Reset time unknown".into();
    };
    let minutes = (at.saturating_sub(now).max(0) as u64).div_ceil(60);
    let text = if minutes == 0 {
        "Reset due".into()
    } else if minutes >= 1440 {
        format!("Resets in {}d {}h", minutes / 1440, minutes % 1440 / 60)
    } else if minutes >= 60 {
        format!("Resets in {}h {}m", minutes / 60, minutes % 60)
    } else {
        format!("Resets in {minutes}m")
    };
    format!(r#"<time title="{}">{text}</time>"#, date(at))
}
fn observed(a: &Account, now: i64) -> String {
    match a.observed_at {
        Some(at) => {
            let age = now.saturating_sub(at).max(0);
            if age < 60 {
                format!("Updated {age} s ago")
            } else if age < 7200 {
                format!("Updated {} min ago", age / 60)
            } else {
                format!("Updated {}", date(at))
            }
        }
        None => "No usage data yet".into(),
    }
}
fn window(w: &Window, label: &str, now: i64) -> String {
    let left = w.used_percent.map(|n| (100.0 - n).clamp(0.0, 100.0));
    let value = left
        .map(|n| format!("{n:.0}<small>% left</small>"))
        .unwrap_or_else(|| "Unknown".into());
    let severity = if left.is_some_and(|n| n < 20.0) {
        "warn"
    } else {
        ""
    };
    let meter = match left {
        Some(n) => format!(
            r#"<progress class="meter {severity}" aria-hidden="true" max="100" value="{n}"></progress>"#
        ),
        None => r#"<div class="meter unknown" aria-hidden="true"></div>"#.into(),
    };
    let unknown = if left.is_none() { "none" } else { "" };
    // A reset time without a usage figure is an old observation; leave it out.
    let time = if left.is_some() {
        reset(w.resets_at, now)
    } else {
        String::new()
    };
    format!(
        r#"<span class="cell-label" aria-hidden="true">{label}</span><div class="usage {severity} {unknown}"><div class="usage-top"><span class="usage-value">{value}</span><span class="usage-reset">{time}</span></div>{meter}</div>"#
    )
}
fn answer(accounts: &[Account]) -> String {
    if accounts.is_empty() {
        return format!(
            r#"<h1 id="answer-title">No server accounts yet</h1><p>Move the Claude accounts saved on a connected machine to this server. Run it on a machine you connected with this Google account.</p>{}<p class="hint">Machines an operator registered on the server host belong to a separate server user, so their accounts do not show here.</p>"#,
            command(
                "cmd-migrate",
                "claudectl server migrate --all --exclusive-owner"
            )
        );
    }
    let ready = accounts
        .iter()
        .filter(|a| matches!(a.state().1, "Available" | "Nearly exhausted"))
        .count();
    format!(
        r#"<h1 id="answer-title">{ready} of {} accounts available</h1><p class="context">Usage as the server last observed it. This page refreshes every 60 seconds.</p>"#,
        accounts.len()
    )
}
fn ledger(accounts: &[Account], now: i64) -> String {
    if accounts.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<_> = accounts.iter().collect();
    sorted.sort_by_key(|a| {
        (
            match a.state().1 {
                "Available" => 0,
                "Nearly exhausted" => 1,
                "Exhausted" => 2,
                "Stale usage" => 3,
                "Migration pending" => 4,
                _ => 5,
            },
            a.alias.as_str(),
        )
    });
    let mut rows = String::new();
    for a in sorted {
        let (class, state) = a.state();
        rows += &format!(
            r#"<tr role="row" class="{}"><td role="cell" class="cell-account"><div class="account-name"><strong translate="no">{}</strong><span class="note">{}</span></div></td><td role="cell" class="cell-usage">{}</td><td role="cell" class="cell-usage">{}</td><td role="cell" class="cell-state"><div class="status"><span class="state {class}">{state}</span><span class="status-detail">{}</span></div></td></tr>"#,
            if a.usage_stale { "stale" } else { "" },
            escape(&a.alias),
            a.migration(),
            window(&a.five_hour, "5-hour", now),
            window(&a.seven_day, "7-day", now),
            observed(a, now)
        );
    }
    format!(
        r#"<section class="section" aria-labelledby="accounts-title"><div class="section-head"><h2 id="accounts-title">Accounts <span class="count">{}</span></h2><p>Refreshes every 60 seconds</p></div><table class="ledger" role="table" aria-labelledby="accounts-title"><thead role="rowgroup"><tr role="row"><th scope="col">Account</th><th scope="col" class="col-usage">5-hour window</th><th scope="col" class="col-usage">7-day window</th><th scope="col" class="col-state">State</th></tr></thead><tbody role="rowgroup">{rows}</tbody></table></section>"#,
        accounts.len()
    )
}
fn machines(snapshot: &Snapshot) -> String {
    let (mut rows, mut revoked) = (String::new(), String::new());
    let (mut count, mut revoked_count) = (0, 0);
    let mut machines: Vec<_> = snapshot.machines.iter().collect();
    machines.sort_by(|a, b| a.id.cmp(&b.id));
    for m in machines {
        // Machine IDs are "<name>-<12 hex>"; the suffix tells same-named machines apart.
        let (name, suffix) = m.id.rsplit_once('-').unwrap_or((&m.id, ""));
        if m.revoked {
            revoked_count += 1;
            revoked += &format!(
                r#"<li><b>{}</b><span class="alias" translate="no">{}</span><span>Revoked</span></li>"#,
                escape(name),
                escape(suffix)
            );
            continue;
        }
        count += 1;
        rows += &format!(
            r#"<tr role="row"><td role="cell">{}</td><td role="cell" class="cell-account"><span class="alias" translate="no">{}</span></td><td role="cell" class="cell-state"><span class="state ok">Connected</span></td></tr>"#,
            escape(name),
            escape(suffix)
        );
    }
    let disclosure = if revoked_count == 0 {
        String::new()
    } else {
        format!(
            r#"<details class="revoked" data-param="revoked" data-value="show"><summary>{revoked_count} revoked machine{}</summary><ul>{revoked}</ul></details>"#,
            if revoked_count == 1 { "" } else { "s" }
        )
    };
    let empty = if count == 0 {
        r#"<p class="machines-empty">No connected machines. Run <code translate="no">claudectl server connect</code> on a machine to add it.</p>"#
    } else {
        ""
    };
    format!(
        r#"<section class="section" aria-labelledby="machines-title"><div class="section-head"><h2 id="machines-title">Machines <span class="count">{count}</span></h2><p>Machines that receive access tokens for your accounts</p></div><table class="machines" role="table" aria-labelledby="machines-title"><thead role="rowgroup"><tr role="row"><th scope="col">Machine</th><th scope="col">ID</th><th scope="col" class="col-state">State</th></tr></thead><tbody role="rowgroup">{rows}</tbody></table>{empty}{disclosure}</section>"#
    )
}

pub(super) fn overview(snapshot: &Snapshot) -> String {
    format!(
        include_str!("accounts.html"),
        email = escape(&snapshot.email),
        has_accounts = !snapshot.accounts.is_empty(),
        answer = answer(&snapshot.accounts),
        ledger = ledger(&snapshot.accounts, snapshot.server_time),
        machines = machines(snapshot)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn account(alias: &str, five: Option<f64>, week: Option<f64>) -> Account {
        Account {
            alias: alias.into(),
            available: true,
            migration: "rotated".into(),
            five_hour: Window {
                used_percent: five,
                resets_at: Some(NOW + 2 * 3600 + 5 * 60),
            },
            seven_day: Window {
                used_percent: week,
                resets_at: Some(NOW + 6 * 86400 + 22 * 3600),
            },
            observed_at: Some(NOW - 30),
            usage_stale: false,
        }
    }
    fn snapshot(accounts: Vec<Account>, machines: Vec<Machine>) -> Snapshot {
        Snapshot {
            email: "amir@sawmills.ai".into(),
            server_time: NOW,
            accounts,
            machines,
        }
    }

    #[test]
    fn accounts_show_bars_reset_times_and_migration_state() {
        let mut pending = account("amir3", None, None);
        pending.migration = "pending".into();
        pending.observed_at = None;
        pending.usage_stale = true;
        let html = overview(&snapshot(
            vec![account("amir5", Some(93.0), Some(40.0)), pending],
            vec![],
        ));
        assert!(html.contains("1 of 2 accounts available"), "{html}");
        assert!(
            !overview(&snapshot(vec![account("x", Some(100.0), None)], vec![]))
                .contains("1 of 1 accounts available")
        );
        assert!(
            html.contains(
                r#"<progress class="meter warn" aria-hidden="true" max="100" value="7">"#
            )
        );
        assert!(html.contains("Resets in 2h 5m"));
        assert!(html.contains("Resets in 6d 22h"));
        assert!(html.contains("Nearly exhausted"));
        assert!(html.contains("Migration pending"));
        assert!(html.contains("Migrated</span>"));
        assert!(html.contains("Updated 30 s ago"));
        assert!(html.contains("No usage data yet"));
    }

    #[test]
    fn an_empty_server_shows_the_migrate_command() {
        let html = overview(&snapshot(vec![], vec![]));
        assert!(html.contains("No server accounts yet"));
        assert!(html.contains("claudectl server migrate --all --exclusive-owner"));
        // Its own class: the stylesheet hides `.machines-note` beside an empty table.
        assert!(html.contains(r#"<p class="machines-empty">No connected machines"#));
    }

    #[test]
    fn machines_split_live_and_revoked() {
        let html = overview(&snapshot(
            vec![],
            vec![
                Machine {
                    id: "mac-mini-0123456789ab".into(),
                    revoked: false,
                },
                Machine {
                    id: "old-box-ba9876543210".into(),
                    revoked: true,
                },
            ],
        ));
        assert!(html.contains("<td role=\"cell\">mac-mini</td>"), "{html}");
        assert!(html.contains("1 revoked machine<"));
        assert!(html.contains("<b>old-box</b>"));
    }

    #[test]
    fn user_text_is_escaped() {
        let mut a = account("<script>", Some(1.0), Some(1.0));
        a.alias = "<script>x</script>".into();
        let mut s = snapshot(
            vec![a],
            vec![Machine {
                id: "<img src=x>-0123".into(),
                revoked: false,
            }],
        );
        s.email = "a\"<b>@sawmills.ai".into();
        let html = overview(&s);
        assert!(!html.contains("<script>x"));
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains("a\"<b>"));
    }
}
