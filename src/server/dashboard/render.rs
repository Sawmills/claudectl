//! The browser projection for the claudectl account server. It receives only the
//! secret-free snapshot; rendering never mutates accounts.
use super::enrollment::escape;
use crate::accounts::Window;

const WORDMARK_ICON: &str = r#"<svg class="wordmark-icon" viewBox="0 0 16 16" width="15" height="15" fill="none" aria-hidden="true"><rect x="1.5" y="2.5" width="13" height="11" rx="2.5" stroke="currentColor" stroke-width="1.4"/><path d="M4.75 6.25L7 8.25L4.75 10.25M8.5 10.25H11.25" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;
const CHEVRON_ICON: &str = r#"<svg class="chev" viewBox="0 0 12 12" width="12" height="12" fill="none" aria-hidden="true"><path d="M3 4.5L6 7.5L9 4.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;
const BACK_ICON: &str = r#"<svg viewBox="0 0 14 14" width="14" height="14" fill="none" aria-hidden="true"><path d="M8.75 3.5L5.25 7L8.75 10.5" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/></svg>"#;

pub(super) struct Snapshot {
    pub email: String,
    pub server_time: i64,
    pub accounts: Vec<Account>,
    pub machines: Vec<Machine>,
    /// This session's form token, for the action forms.
    pub csrf: String,
    /// The action that just finished, from the redirect after it.
    pub done: Option<&'static str>,
    pub browser_resets: bool,
}
pub(super) struct Account {
    /// The server account ID: actions name the account by it.
    pub id: String,
    pub alias: String,
    pub available: bool,
    /// `not_migrated`, `pending`, `unrotated`, or `rotated`.
    pub migration: String,
    pub windows: Vec<Window>,
    pub limit_reset_offers: Option<crate::limit_resets::Offers>,
    /// Usable reset count from the server-sealed `reset_offers` list.
    pub usable_resets: u64,
    pub reset_grant: Option<String>,
    /// Human-safe summary of the reset offer that `POST /accounts/reset` will redeem.
    pub reset_offer_summary: Option<String>,
    /// Unix seconds of the server's last usage observation.
    pub observed_at: Option<i64>,
    pub usage_stale: bool,
    /// Extra usage is not known to be off: never the account to use.
    pub billed: bool,
}
pub(super) struct Machine {
    pub id: String,
    pub revoked: bool,
    /// The machine's last authorized request (ms).
    pub last_seen_at: Option<i64>,
}

impl Account {
    fn window(&self, name: &str) -> Option<&Window> {
        self.windows.iter().find(|w| w.name == name)
    }
    fn candidate(&self) -> crate::accounts::Candidate {
        crate::accounts::Candidate {
            name: self.alias.clone(),
            windows: self.windows.clone(),
            fresh: self.available && !self.usage_stale && self.migration != "pending",
            billed: self.billed,
        }
    }
    /// The same states the CLI shows (`crate::accounts::state`), as (CSS class, label).
    fn state(&self) -> (&'static str, String) {
        use crate::accounts::State;
        if !self.available {
            return ("bad", "Login needs attention".into());
        }
        if self.migration == "pending" {
            return ("pending", "Migration pending".into());
        }
        let state = crate::accounts::state(&self.windows);
        fn limit_label(window: &str) -> &str {
            if window == "week" { "Week" } else { window }
        }
        // A known full window stays visible, even on old data (the CLI's "(old data)").
        if let State::Limit { window, .. } = &state {
            let old = if self.usage_stale { " (old data)" } else { "" };
            return ("bad", format!("{} limit{old}", limit_label(window)));
        }
        if self.usage_stale {
            return ("warn", "Stale usage".into());
        }
        match (state, self.billed) {
            (State::Ready, false) => ("ok", "Available".into()),
            (State::Low { window }, false) => ("warn", format!("Low ({window})")),
            // Room, but never the account to use: the billing reason is visible.
            (State::Ready, true) => ("warn", "Available, may bill".into()),
            (State::Low { window }, true) => ("warn", format!("Low ({window}), may bill")),
            (State::Limit { window, .. }, _) => ("bad", format!("{} limit", limit_label(window))),
            (State::Unknown, _) => ("warn", "No usage data".into()),
        }
    }
    fn has_room(&self) -> bool {
        self.candidate().fresh
            && matches!(
                crate::accounts::state(&self.windows),
                crate::accounts::State::Ready | crate::accounts::State::Low { .. }
            )
    }
    /// A migration note only when it asks for something.
    fn migration(&self) -> &'static str {
        match self.migration.as_str() {
            "pending" => "Migration pending",
            "unrotated" => "Migrated · old copies still valid",
            _ => "",
        }
    }
}

fn command(id: &str, text: &str) -> String {
    let text = escape(text);
    format!(
        r#"<div class="command"><pre tabindex="0"><code id="{id}" translate="no">{text}</code></pre><button class="button small primary copy" type="button" data-copy="{id}" aria-label="Copy {text}">Copy</button></div>"#
    )
}
fn date(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0)
        .map(|t| t.format("%b %-d, %H:%M UTC").to_string())
        .unwrap_or_else(|| "Unknown time".into())
}
fn reset(at: Option<i64>, now: i64) -> String {
    let Some(at) = at else {
        return String::new();
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
/// `30 s ago`, `4 min ago`, or the date for anything older than two hours (Unix seconds).
fn since(at: i64, now: i64) -> String {
    let age = now.saturating_sub(at).max(0);
    if age < 60 {
        format!("{age} s ago")
    } else if age < 7200 {
        format!("{} min ago", age / 60)
    } else {
        date(at)
    }
}
fn observed(a: &Account, now: i64) -> String {
    match a.observed_at {
        Some(at) => format!("Updated {}", since(at, now)),
        None => "No usage data yet".into(),
    }
}
fn window(w: Option<&Window>, label: &str, now: i64) -> String {
    let left = w
        .and_then(|w| w.used)
        .map(|n| (100.0 - n).clamp(0.0, 100.0));
    let value = left
        .map(|n| format!("{n:.0}<small>% left</small>"))
        .unwrap_or_else(|| "Unknown".into());
    let severity = match left {
        Some(n) if n <= 0.0 => "bad",
        Some(n) if n < 20.0 => "warn",
        _ => "",
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
        reset(w.and_then(|w| w.resets_at), now)
    } else {
        String::new()
    };
    format!(
        r#"<span class="cell-label" aria-hidden="true">{label}</span><div class="usage {severity} {unknown}"><div class="usage-top"><span class="usage-value">{value}</span></div>{meter}<div class="usage-reset">{time}</div></div>"#
    )
}
fn answer(accounts: &[Account], names: &[String], now: i64) -> String {
    if accounts.is_empty() {
        return format!(
            r#"<div class="panel hero-empty"><h1 id="answer-title">No server accounts yet</h1><p>Move the Claude accounts saved on a connected machine to this server. Run it on a machine you connected with this Google account.</p>{}<p class="hint">Machines an operator registered on the server host belong to a separate server user, so their accounts do not show here.</p></div>"#,
            command(
                "cmd-migrate",
                "claudectl server migrate --all --exclusive-owner"
            )
        );
    }
    // Count included capacity; automatic selection also reserves weekly headroom.
    let room = accounts
        .iter()
        .filter(|a| a.has_room() && !a.billed)
        .count();
    let billed_room = accounts.iter().filter(|a| a.has_room() && a.billed).count();
    let more = match billed_room {
        0 => String::new(),
        n => format!(" ({n} more may bill)"),
    };
    let total_resets = accounts
        .iter()
        .filter(|a| !a.usage_stale)
        .fold(0_u64, |sum, a| sum.saturating_add(a.usable_resets));
    let resets_stat = if total_resets == 0 {
        String::new()
    } else {
        let plural = if total_resets == 1 { "" } else { "s" };
        format!(
            r#"<span class="sep" aria-hidden="true">·</span><span class="hero-resets-stat">{total_resets} reset{plural} available</span>"#
        )
    };
    let summary_bar = format!(
        r#"<div class="hero-meta"><span>{room} of {} accounts have room{more}</span>{resets_stat}</div><p class="hero-foot">Usage as the server last observed it; this page refreshes every 60 seconds.</p>"#,
        accounts.len()
    );
    let candidates: Vec<_> = accounts.iter().map(Account::candidate).collect();
    let Some(best) = crate::accounts::best(&candidates) else {
        // As the CLI Next line: name one account that may bill, never pick it.
        let may_bill: Vec<_> = candidates
            .iter()
            .map(|c| crate::accounts::Candidate {
                fresh: c.fresh && c.billed,
                billed: false,
                ..c.clone()
            })
            .collect();
        if let Some(i) = crate::accounts::best(&may_bill) {
            return format!(
                r#"<div class="panel hero-card"><div class="hero-main"><div class="hero-heading"><h1 id="answer-title">No account without billing has room</h1></div><p class="hero-meta">{} has room but may use extra usage billing, so it is never picked automatically.</p>{summary_bar}</div><div class="hero-side">{}</div></div>"#,
                escape(&names[i]),
                command(
                    "cmd-run",
                    &format!("claudectl run {}", crate::shell::arg(&names[i]))
                ),
            );
        }
        return format!(
            r#"<div class="panel hero-card"><div class="hero-main"><div class="hero-heading"><h1 id="answer-title">No account can be picked automatically</h1></div><p class="hero-meta">Automatic picks require fresh included usage and more than 5% weekly room. The table below shows the latest limits.</p>{summary_bar}</div></div>"#
        );
    };
    let a = &accounts[best];
    let name = escape(&names[best]);
    let left = |w: Option<&Window>| {
        w.and_then(|w| w.used)
            .map(|n| format!("{:.0}%", (100.0 - n).clamp(0.0, 100.0)))
            .unwrap_or_else(|| "unknown".into())
    };
    let five = a.window("5h");
    let next = five
        .and_then(|w| w.resets_at)
        .map(|at| format!(", 5h resets {}", crate::accounts::until(at, now)))
        .unwrap_or_default();
    format!(
        r#"<div class="panel hero-card"><div class="hero-main"><div class="hero-heading"><h1 id="answer-title">Use {name}</h1><span class="hero-meta">{} of the 5-hour window and {} of the week left{next}.</span></div>{summary_bar}</div><div class="hero-side">{}</div></div>"#,
        left(five),
        left(a.window("week")),
        command(
            "cmd-run",
            &format!("claudectl run {}", crate::shell::arg(&names[best]))
        ),
    )
}
fn resets_cell(a: &Account, offers: &[crate::limit_resets::Offer], now: i64) -> String {
    if offers.is_empty() {
        return r#"<span class="cell-label" aria-hidden="true">Resets</span><span class="offers-empty" aria-label="No reset offers">—</span>"#.into();
    }
    let total = a
        .limit_reset_offers
        .as_ref()
        .map(|o| o.count(now))
        .unwrap_or(0);
    let plural = if total == 1 { "" } else { "s" };
    let old = if a.usage_stale { " (old data)" } else { "" };
    let pill_label = if a.usage_stale {
        format!("{total} reset{plural} · old")
    } else if a.usable_resets == 0 {
        format!("{total} reset{plural} · unavailable")
    } else if a.usable_resets < total {
        format!("{} of {total} resets", a.usable_resets)
    } else {
        format!("{total} reset{plural}")
    };
    let items = offers
        .iter()
        .map(|offer| {
            format!(
                r#"<li class="offer-item">{}</li>"#,
                escape(&offer.summary(now))
            )
        })
        .collect::<Vec<_>>()
        .join("");
    let hint = escape(crate::limit_resets::HINT);
    format!(
        r#"<span class="cell-label" aria-hidden="true">Resets</span><details class="popover-menu offers-menu"><summary class="offer-pill"><span>{pill_label}</span>{CHEVRON_ICON}</summary><div class="popover offers-popover"><div class="popover-head"><span>Limit resets{old}:</span><span>{total}</span></div><ul class="offer-list">{items}</ul><p class="popover-hint">{hint}</p></div></details>"#
    )
}
fn reset_control(
    snapshot: &Snapshot,
    account: &Account,
    short_name: &str,
    offers: &[crate::limit_resets::Offer],
    now: i64,
) -> String {
    if !snapshot.browser_resets {
        return String::new();
    }
    let Some(_grant) = &account.reset_grant else {
        return r#"<button class="button small ghost" type="button" disabled title="No eligible reset offer">Reset</button>"#.into();
    };
    let offer_detail = account
        .reset_offer_summary
        .clone()
        .or_else(|| offers.first().map(|o| o.summary(now)))
        .unwrap_or_else(|| "Uses the earliest expiring eligible reset for this account.".into());
    format!(
        r#"<details class="popover-menu confirm-menu"><summary class="button small">Reset</summary><div class="popover confirm-popover"><div class="popover-head"><span>Reset {}?</span></div><p class="confirm-copy">{}</p><div class="confirm-actions"><button class="button small ghost" type="button" data-close-details>Cancel</button><form class="action" method="post" action="/accounts/reset"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="account" value="{}"><button class="button small primary" type="submit">Apply reset</button></form></div></div></details>"#,
        escape(short_name),
        escape(&offer_detail),
        escape(&snapshot.csrf),
        escape(&account.id),
    )
}
fn ledger(snapshot: &Snapshot, names: &[String], now: i64) -> String {
    let accounts = &snapshot.accounts;
    if accounts.is_empty() {
        return String::new();
    }
    let show_fable = accounts.iter().any(|a| a.window("Fable").is_some());
    let show_resets = snapshot.browser_resets
        || accounts.iter().any(|a| {
            a.limit_reset_offers
                .as_ref()
                .is_some_and(|o| !o.active(now).is_empty())
        });
    let candidates: Vec<_> = accounts.iter().map(Account::candidate).collect();
    let best = crate::accounts::best(&candidates);
    let mut order: Vec<usize> = (0..accounts.len()).collect();
    // The account to use first; then room, low, the rest, limits; then the most room.
    order.sort_by_key(|&i| {
        let a = &accounts[i];
        let rank = match (Some(i) == best, a.has_room(), a.state().0) {
            (true, ..) => 0,
            (_, true, "ok") => 1,
            (_, true, _) => 2,
            (_, false, "bad") => 4,
            _ => 3,
        };
        let highest = candidates[i]
            .windows
            .iter()
            .filter_map(|w| w.used)
            .fold(0.0_f64, f64::max);
        (rank, (highest * 100.0) as i64, names[i].clone())
    });
    let mut rows = String::new();
    for i in order {
        let a = &accounts[i];
        let is_best = Some(i) == best;
        let (class, state) = a.state();
        let fable = if show_fable {
            let cell = a
                .window("Fable")
                .map(|w| window(Some(w), "Fable", now))
                .unwrap_or_default();
            format!(r#"<td role="cell" class="cell-usage">{cell}</td>"#)
        } else {
            String::new()
        };
        let note = a.migration();
        let note = if note.is_empty() {
            String::new()
        } else {
            format!(r#"<span class="badge-note">{note}</span>"#)
        };
        let next_badge = if is_best {
            r#"<span class="badge-next">Next</span>"#
        } else {
            ""
        };
        let offers = a
            .limit_reset_offers
            .as_ref()
            .map(|offers| offers.active(now))
            .unwrap_or_default();
        let resets_col = if show_resets {
            format!(
                r#"<td role="cell" class="cell-resets">{}</td>"#,
                resets_cell(a, &offers, now)
            )
        } else {
            String::new()
        };
        let row_class = match (is_best, a.usage_stale) {
            (true, true) => "recommended stale",
            (true, false) => "recommended",
            (false, true) => "stale",
            (false, false) => "",
        };
        let reset_btn = reset_control(snapshot, a, &names[i], &offers, now);
        rows += &format!(
            r#"<tr role="row" class="{row_class}"><td role="cell" class="cell-account"><div class="account-cell"><div class="account-title"><strong translate="no">{}</strong>{next_badge}</div>{note}</div></td><td role="cell" class="cell-usage">{}</td><td role="cell" class="cell-usage">{}</td>{fable}{resets_col}<td role="cell" class="cell-state"><div class="status"><span class="state {class}">{state}</span><span class="status-detail">{}</span></div></td><td role="cell" class="cell-actions"><div class="row-actions">{reset_btn}<a class="button small ghost" href="/accounts/manage?account={}">Manage</a></div></td></tr>"#,
            escape(&names[i]),
            window(a.window("5h"), "5-hour", now),
            window(a.window("week"), "7-day", now),
            observed(a, now),
            escape(&a.id),
        );
    }
    let fable_head = if show_fable {
        r#"<th scope="col" class="col-usage">Fable window</th>"#
    } else {
        ""
    };
    let resets_head = if show_resets {
        r#"<th scope="col" class="col-resets">Resets</th>"#
    } else {
        ""
    };
    format!(
        r#"<section class="section" aria-labelledby="accounts-title"><div class="section-head"><h2 id="accounts-title">Accounts <span class="count">{}</span></h2><a class="button small" href="/accounts/add">Add account</a></div><div class="panel ledger-panel"><table class="ledger" role="table" aria-labelledby="accounts-title"><thead role="rowgroup"><tr role="row"><th scope="col" class="col-account">Account</th><th scope="col" class="col-usage">5-hour window</th><th scope="col" class="col-usage">7-day window</th>{fable_head}{resets_head}<th scope="col" class="col-state">State</th><th scope="col" class="col-actions">Actions</th></tr></thead><tbody role="rowgroup">{rows}</tbody></table></div></section>"#,
        accounts.len()
    )
}
/// A one-button POST form with this session's token.
fn action(path: &str, field: &str, value: &str, csrf: &str, label: &str) -> String {
    format!(
        r#"<form class="action" method="post" action="{path}"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="{field}" value="{}"><button class="button small ghost" type="submit">{label}</button></form>"#,
        escape(csrf),
        escape(value)
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
            r#"<tr role="row"><td role="cell">{}</td><td role="cell" class="cell-machine-id"><span class="alias" translate="no">{}</span></td><td role="cell" class="cell-state"><div class="status"><span class="state ok">Connected</span><span class="status-detail">{}</span></div></td><td role="cell" class="cell-actions">{}</td></tr>"#,
            escape(name),
            escape(suffix),
            match m.last_seen_at {
                Some(at) => format!("Seen {}", since(at / 1000, snapshot.server_time)),
                None => "Not seen since the upgrade".into(),
            },
            action(
                "/machines/revoke",
                "machine",
                &m.id,
                &snapshot.csrf,
                "Revoke"
            )
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
        r#"<section class="section" aria-labelledby="machines-title"><div class="section-head"><h2 id="machines-title">Machines <span class="count">{count}</span></h2><p>Machines that receive access tokens for your accounts</p></div><div class="panel"><table class="machines" role="table" aria-labelledby="machines-title"><thead role="rowgroup"><tr role="row"><th scope="col">Machine</th><th scope="col">ID</th><th scope="col" class="col-state">State</th><th scope="col" class="col-actions">Actions</th></tr></thead><tbody role="rowgroup">{rows}</tbody></table>{empty}</div>{disclosure}</section>"#
    )
}

pub(super) fn overview(snapshot: &Snapshot) -> String {
    // The same short names as the CLI: the domain goes when all accounts share it.
    let names = crate::accounts::short_names(
        &snapshot
            .accounts
            .iter()
            .map(|a| a.alias.as_str())
            .collect::<Vec<_>>(),
    );
    let done = match snapshot.done {
        Some(done) => format!(r#"<p class="flash" role="status">{done}</p>"#),
        None => String::new(),
    };
    format!(
        include_str!("accounts.html"),
        email = escape(&snapshot.email),
        has_accounts = !snapshot.accounts.is_empty(),
        answer = done + &answer(&snapshot.accounts, &names, snapshot.server_time),
        ledger = ledger(snapshot, &names, snapshot.server_time),
        machines = machines(snapshot)
    )
}

/// An action page: the top bar and one main column, never auto-refreshed.
fn frame(email: &str, title: &str, content: &str) -> String {
    format!(
        r#"<div id="action"><header class="topbar"><div class="wrap topbar-inner"><a class="wordmark" href="/accounts" translate="no" aria-label="claudectl accounts">{WORDMARK_ICON}<span>claudectl</span></a><div class="identity"><span class="email" translate="no">{}</span></div></div></header><main id="main" class="wrap"><div class="action-shell"><a class="back-link" href="/accounts">{BACK_ICON}<span>Back to accounts</span></a><section class="action-page panel"><h1>{title}</h1>{content}</section></div></main></div>"#,
        escape(email)
    )
}
fn csrf_field(csrf: &str) -> String {
    format!(
        r#"<input type="hidden" name="csrf" value="{}">"#,
        escape(csrf)
    )
}
/// Add a Claude account: its name, then the Claude sign-in.
pub(super) fn add_page(email: &str, csrf: &str) -> String {
    frame(
        email,
        "Add a Claude account",
        &format!(
            r#"<p>Name the account (for example amir8), then sign in to Claude with it.</p><form class="form" method="post" action="/accounts/add">{}<label for="alias">Account name</label><input id="alias" name="alias" required maxlength="64" autocomplete="off" spellcheck="false" placeholder="amir8"><button class="button primary" type="submit">Continue to Claude sign-in</button></form>"#,
            csrf_field(csrf)
        ),
    )
}
/// One account: Renew (a new Claude sign-in) and Remove (type the exact name).
pub(super) fn manage_page(
    email: &str,
    alias: &str,
    id: &str,
    csrf: &str,
    machines: usize,
) -> String {
    let who = match machines {
        1 => "1 connected machine uses".to_string(),
        n => format!("{n} connected machines use"),
    };
    frame(
        email,
        &escape(alias),
        &format!(
            r#"<div class="action-block"><h2>Renew sign-in</h2><p>Sign in to Claude with this account again. Use it when its login needs attention.</p><form class="form" method="post" action="/accounts/renew">{csrf}<input type="hidden" name="account" value="{id}"><button class="button" type="submit">Renew the sign-in</button></form></div><div class="action-block danger-zone"><h2>Remove account</h2><p>{who} the accounts of this server. After the removal, running sessions on this account stop at their next token renewal.</p><form class="form" method="post" action="/accounts/remove">{csrf}<input type="hidden" name="account" value="{id}"><label for="confirm">Type <strong translate="no">{alias}</strong> to remove it</label><input id="confirm" name="confirm" required autocomplete="off" spellcheck="false"><button class="button danger" type="submit">Remove the account</button></form></div>"#,
            csrf = csrf_field(csrf),
            id = escape(id),
            alias = escape(alias),
        ),
    )
}
/// The Claude sign-in of an Add or a Renew, and the field for the code it shows.
pub(super) fn login_page(
    email: &str,
    alias: &str,
    renew: bool,
    authorize_url: &str,
    login: &str,
    csrf: &str,
) -> String {
    let title = if renew { "Renew" } else { "Add" };
    frame(
        email,
        &format!("{title} {}", escape(alias)),
        &format!(
            r#"<ol><li><a href="{url}" target="_blank" rel="noopener noreferrer">Open the Claude sign-in</a> and sign in with this account.</li><li>Copy the code the page shows, then paste it here within 5 minutes.</li></ol><form class="form" method="post" action="/accounts/login">{csrf}<input type="hidden" name="login" value="{login}"><label for="code">Code from the Claude sign-in page</label><input id="code" name="code" required autocomplete="off" spellcheck="false"><button class="button primary" type="submit">Save the account</button></form>"#,
            url = escape(authorize_url),
            csrf = csrf_field(csrf),
            login = escape(login),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_machine_shows_when_it_was_last_seen() {
        let now = 1_800_000_000;
        let machine = |last_seen_at| Machine {
            id: "laptop-0123456789ab".into(),
            revoked: false,
            last_seen_at,
        };
        let page = |m| {
            let mut s = snapshot(vec![], vec![m]);
            s.server_time = now;
            machines(&s)
        };
        assert!(page(machine(Some((now - 240) * 1000))).contains("Seen 4 min ago"));
        assert!(page(machine(None)).contains("Not seen since the upgrade"));
    }

    const NOW: i64 = 1_800_000_000;

    fn account(alias: &str, five: Option<f64>, week: Option<f64>) -> Account {
        Account {
            id: alias.replace('@', "-at-"),
            alias: alias.into(),
            available: true,
            migration: "rotated".into(),
            windows: vec![
                Window {
                    name: "5h",
                    used: five,
                    resets_at: Some(NOW + 2 * 3600 + 5 * 60),
                },
                Window {
                    name: "week",
                    used: week,
                    resets_at: Some(NOW + 6 * 86400 + 22 * 3600),
                },
            ],
            limit_reset_offers: None,
            usable_resets: 0,
            reset_grant: None,
            reset_offer_summary: None,
            observed_at: Some(NOW - 30),
            usage_stale: false,
            billed: false,
        }
    }
    fn snapshot(accounts: Vec<Account>, machines: Vec<Machine>) -> Snapshot {
        Snapshot {
            email: "amir@sawmills.ai".into(),
            server_time: NOW,
            accounts,
            machines,
            csrf: "form-token".into(),
            done: None,
            browser_resets: false,
        }
    }

    #[test]
    fn accounts_show_bars_reset_times_and_actionable_migration_state() {
        let mut pending = account("amir3", None, None);
        pending.migration = "pending".into();
        pending.observed_at = None;
        pending.usage_stale = true;
        let html = overview(&snapshot(
            vec![account("amir5", Some(93.0), Some(40.0)), pending],
            vec![],
        ));
        assert!(html.contains("1 of 2 accounts have room"), "{html}");
        assert!(
            html.contains(
                r#"<progress class="meter warn" aria-hidden="true" max="100" value="7">"#
            )
        );
        assert!(html.contains("Resets in 2h 5m"));
        assert!(html.contains("Resets in 6d 22h"));
        assert!(html.contains("Low (5h)"), "{html}");
        assert!(html.contains("Migration pending"));
        // A finished migration is history, not status: no subtitle.
        assert!(!html.contains(">Migrated<"), "{html}");
        assert!(html.contains("Updated 30 s ago"));
        assert!(html.contains("No usage data yet"));
    }

    #[test]
    fn browser_reset_uses_inline_confirmation_only_for_a_qualifying_offer() {
        let mut eligible = account("amir5", Some(100.0), Some(30.0));
        eligible.reset_grant = Some("available".into());
        eligible.reset_offer_summary =
            Some("1 reset · weekly + Fable weekly · use by 2099-12-10 22:00 UTC".into());
        let mut snapshot = snapshot(
            vec![eligible, account("amir6", Some(20.0), Some(30.0))],
            vec![],
        );
        snapshot.browser_resets = true;
        let html = overview(&snapshot);
        assert_eq!(
            html.matches(r#"action="/accounts/reset""#).count(),
            1,
            "{html}"
        );
        assert!(html.contains("Reset amir5?"), "{html}");
        assert!(
            html.contains("1 reset · weekly + Fable weekly · use by 2099-12-10 22:00 UTC"),
            "{html}"
        );
        assert!(html.contains(">Apply reset</button>"), "{html}");
        assert!(
            html.contains(
                r#"type="button" disabled title="No eligible reset offer">Reset</button>"#
            ),
            "{html}"
        );
    }

    #[test]
    fn resets_column_aggregates_offers_and_shows_summary_in_hero() {
        let mut a = account("amir3", Some(0.0), Some(100.0));
        a.usable_resets = 2;
        a.limit_reset_offers = Some(
            serde_json::from_value(serde_json::json!({
                "eligible": true,
                "grants": [
                    {
                        "id": "g1",
                        "resets_left": 1,
                        "clears": ["seven_day", "seven_day_overage_included"],
                        "ends_at": "2099-12-10T22:00:00Z"
                    },
                    {
                        "id": "g2",
                        "resets_left": 1,
                        "clears": ["seven_day_overage_included"],
                        "gives_back_weekly": true,
                        "ends_at": "2100-03-09T07:59:00Z"
                    }
                ]
            }))
            .unwrap(),
        );
        let mut paused = account("amir4", Some(0.0), Some(100.0));
        paused.usable_resets = 0;
        paused.limit_reset_offers = Some(
            serde_json::from_value(serde_json::json!({
                "eligible": true,
                "grants": [{
                    "id": "g3",
                    "resets_left": 1,
                    "clears": ["seven_day"],
                    "paused": true,
                    "ends_at": "2099-12-10T22:00:00Z"
                }]
            }))
            .unwrap(),
        );
        let mut stale = account("amir5", Some(0.0), Some(100.0));
        stale.usage_stale = true;
        stale.usable_resets = 2;
        stale.limit_reset_offers = a.limit_reset_offers.clone();
        let html = overview(&snapshot(vec![a, paused, stale], vec![]));
        assert!(html.contains("2 resets available"), "{html}");
        assert!(
            html.contains(r#"<th scope="col" class="col-resets">Resets</th>"#),
            "{html}"
        );
        assert!(html.contains("<span>2 resets</span>"), "{html}");
        assert!(
            html.contains("<span>1 reset · unavailable</span>"),
            "{html}"
        );
        assert!(html.contains("<span>2 resets · old</span>"), "{html}");
        assert!(html.contains("paused"), "{html}");
        assert!(html.contains("Week limit"), "{html}");
    }

    #[test]
    fn the_hero_names_the_best_account_with_a_copyable_run_command() {
        let html = overview(&snapshot(
            vec![
                account("amir@sawmills.ai", Some(55.0), Some(76.0)),
                account("amir3@sawmills.ai", Some(2.0), Some(1.0)),
            ],
            vec![],
        ));
        assert!(
            html.contains(r#"<h1 id="answer-title">Use amir3</h1>"#),
            "{html}"
        );
        assert!(html.contains("claudectl run amir3"), "{html}");
        assert!(html.contains("2 of 2 accounts have room"), "{html}");
        // Short names: the shared domain is dropped everywhere on the page.
        assert!(!html.contains("amir3@sawmills.ai"), "{html}");
        // The account to use is the first row, then the most room.
        let row = |name: &str| {
            html.find(&format!(r#"translate="no">{name}</strong>"#))
                .unwrap()
        };
        assert!(row("amir3") < row("amir"), "{html}");
        // An unknown reset time adds no text.
        assert!(!html.contains("Reset time unknown"), "{html}");
    }

    #[test]
    fn the_copyable_command_quotes_an_account_name_a_shell_would_run() {
        let html = overview(&snapshot(
            vec![account("work; touch PWNED", Some(2.0), Some(1.0))],
            vec![],
        ));
        assert!(!html.contains("claudectl run work;"), "{html}");
        assert!(
            html.contains(&escape("claudectl run 'work; touch PWNED'")),
            "{html}"
        );
    }

    #[test]
    fn an_opus_or_sonnet_limit_is_a_limit_as_in_the_cli() {
        let mut opus = account("amir3", Some(0.0), Some(0.0));
        opus.windows.push(Window {
            name: "Opus",
            used: Some(100.0),
            resets_at: Some(NOW + 3600),
        });
        let html = overview(&snapshot(
            vec![opus, account("amir", Some(55.0), Some(76.0))],
            vec![],
        ));
        assert!(
            html.contains(r#"<h1 id="answer-title">Use amir</h1>"#),
            "{html}"
        );
        assert!(html.contains("Opus limit"), "{html}");
    }

    #[test]
    fn a_fable_limit_is_a_limit_and_billed_accounts_are_never_the_hero() {
        let mut fable = account("amir4", Some(0.0), Some(98.0));
        fable.windows.push(Window {
            name: "Fable",
            used: Some(100.0),
            resets_at: None,
        });
        let html = overview(&snapshot(vec![fable], vec![]));
        assert!(html.contains("Fable limit"), "{html}");
        assert!(html.contains("0 of 1 accounts have room"), "{html}");
        assert!(
            html.contains("No account can be picked automatically"),
            "{html}"
        );
        assert!(html.contains("Fable window"), "a Fable column: {html}");
        let mut billed = account("roomy", Some(0.0), Some(0.0));
        billed.billed = true;
        let html = overview(&snapshot(
            vec![billed, account("busy", Some(50.0), Some(50.0))],
            vec![],
        ));
        assert!(
            html.contains(r#"<h1 id="answer-title">Use busy</h1>"#),
            "{html}"
        );
        // Without any Fable limit there is no Fable column.
        assert!(!html.contains("Fable window"), "{html}");
    }

    #[test]
    fn a_billed_account_shows_may_bill_and_is_not_counted_as_room() {
        let mut billed = account("roomy", Some(0.0), Some(0.0));
        billed.billed = true;
        let html = overview(&snapshot(vec![billed], vec![]));
        assert!(html.contains("Available, may bill"), "{html}");
        assert!(!html.contains(r#"<span class="state ok">"#), "{html}");
        assert!(html.contains("0 of 1 accounts have room"), "{html}");
        assert!(html.contains("1 more may bill"), "{html}");
        // The hero names it the way the CLI Next line does, and never as the pick.
        assert!(
            html.contains(r#"<h1 id="answer-title">No account without billing has room</h1>"#),
            "{html}"
        );
        assert!(html.contains("claudectl run roomy"), "{html}");
        assert!(!html.contains("Use roomy"), "{html}");
    }

    #[test]
    fn a_missing_week_figure_is_no_usage_data_as_in_the_cli() {
        let html = overview(&snapshot(vec![account("half", Some(1.0), None)], vec![]));
        assert!(html.contains("No usage data"), "{html}");
        assert!(html.contains("0 of 1 accounts have room"), "{html}");
        assert!(!html.contains("Use half"), "{html}");
    }

    #[test]
    fn a_known_limit_shows_even_without_a_week_figure_or_with_old_data() {
        let html = overview(&snapshot(vec![account("full", Some(100.0), None)], vec![]));
        assert!(html.contains("5h limit"), "{html}");
        assert!(html.contains("0 of 1 accounts have room"), "{html}");
        let mut old = account("old", Some(100.0), Some(10.0));
        old.usage_stale = true;
        let html = overview(&snapshot(vec![old], vec![]));
        assert!(html.contains("5h limit (old data)"), "{html}");
        assert!(!html.contains("Use old"), "{html}");
    }

    #[test]
    fn notes_are_not_repeated() {
        let mut unrotated = account("a", Some(1.0), Some(1.0));
        unrotated.migration = "unrotated".into();
        let html = overview(&snapshot(vec![unrotated], vec![]));
        assert!(html.contains("old copies still valid"), "{html}");
        assert!(!html.contains("POSIX shell syntax."), "{html}");
        assert!(
            html.to_lowercase()
                .matches("refreshes every 60 seconds")
                .count()
                <= 1,
            "{html}"
        );
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
                    last_seen_at: None,
                },
                Machine {
                    id: "old-box-ba9876543210".into(),
                    revoked: true,
                    last_seen_at: None,
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
                last_seen_at: None,
            }],
        );
        s.email = "a\"<b>@sawmills.ai".into();
        let html = overview(&s);
        assert!(!html.contains("<script>x"));
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains("a\"<b>"));
    }
}
