//! Browser view for the signed-in company user: own accounts, cached usage, and own
//! machines, plus the account actions (SAW-12695): Add and Renew (a new Claude sign-in with
//! its code pasted here), Remove (type the exact name), and Revoke a machine. Every action is
//! a same-origin POST with this session's form token; Remove and Revoke also need a sign-in
//! of the last 10 minutes. Credentials never enter a page, and the pasted code is never
//! logged or shown again.
use super::{
    app::{HttpError, Server},
    enrollment,
};
use axum::{
    Form, Router,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::sync::Arc;

mod render;
use render::{Account, Machine, Snapshot, Window};

type Shared = State<Arc<Server>>;

async fn landing(State(server): Shared, headers: HeaderMap) -> Response {
    // Only a live, allowed session skips the public page.
    if matches!(
        enrollment::browser_user(&server, &headers).await,
        Ok(Some(_))
    ) {
        return ([("cache-control", "no-store")], Redirect::to("/accounts")).into_response();
    }
    let ready = server.ready().await;
    // Operator configuration validated at startup, never a request header. Quote for the
    // shell, then escape for the HTML text node.
    let public_url = server.public_url().unwrap_or_default();
    let quoted = format!("'{}'", public_url.replace('\'', "'\\''"));
    let content = include_str!("dashboard/landing.html")
        .replace("<!-- SERVER -->", &enrollment::escape(&quoted))
        .replace("<!-- READY_STATE -->", if ready { "ok" } else { "bad" })
        .replace(
            "<!-- READY_LABEL -->",
            if ready {
                "Account server ready"
            } else {
                "Account server not ready"
            },
        );
    document(&content, false)
}

/// What a finished action says on the next page (`/accounts?done=...`).
fn done_text(done: Option<&str>) -> Option<&'static str> {
    Some(match done? {
        "saved" => "Account saved.",
        "removed" => "Account removed.",
        "revoked" => "Machine revoked. Its access tokens stay valid until they expire.",
        _ => return None,
    })
}

async fn accounts(
    State(server): Shared,
    headers: HeaderMap,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let done = done_text(query.get("done").map(String::as_str));
    match snapshot(&server, &headers, done).await {
        Ok(Some(snapshot)) => document(&render::overview(&snapshot), true),
        Ok(None) => (
            [("cache-control", "no-store")],
            Redirect::to("/accounts/sign-in"),
        )
            .into_response(),
        Err(error) if error.status == StatusCode::UNAUTHORIZED => {
            // A dead session cookie: expire it and offer sign-in.
            let mut response = enrollment::dashboard_error(error);
            if let Some(cookie) = enrollment::expired_session(&server) {
                response
                    .headers_mut()
                    .append("set-cookie", cookie.parse().expect("generated cookie"));
            }
            response
        }
        Err(error) if error.status == StatusCode::FORBIDDEN => enrollment::dashboard_error(error),
        Err(error) => {
            let mut response = document(include_str!("dashboard/error.html"), true);
            *response.status_mut() = error.status;
            response
        }
    }
}

async fn snapshot(
    server: &Server,
    headers: &HeaderMap,
    done: Option<&'static str>,
) -> Result<Option<Snapshot>, HttpError> {
    let Some(browser) = enrollment::browser_session(server, headers).await? else {
        return Ok(None);
    };
    let (user, email, csrf) = (browser.user, browser.email, browser.csrf);
    let unavailable = |_| server.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable");
    let engine = server.engine();
    // The stored observations of this user's accounts, in one owner-scoped read with no
    // poll lock. A failed read, or one account that does not unseal, shows as no data and
    // is counted; it never fails the page.
    let mut usages = engine.cached_usages(&user).await.unwrap_or_else(|_| {
        server.error(StatusCode::SERVICE_UNAVAILABLE, "usage_unavailable");
        Default::default()
    });
    let mut accounts = Vec::new();
    for account in engine.accounts(&user).await.map_err(unavailable)? {
        let usage = match usages.remove(&account.account_id) {
            Some(Ok(usage)) => usage,
            Some(Err(_)) => {
                server.error(StatusCode::SERVICE_UNAVAILABLE, "usage_unavailable");
                Default::default()
            }
            None => Default::default(),
        };
        let observed = windows(&usage);
        accounts.push(Account {
            id: account.account_id.clone(),
            alias: account.alias,
            available: account.available,
            migration: account.migration.into(),
            five_hour: observed.five,
            seven_day: observed.week,
            fable: observed.fable,
            model_windows: observed.models,
            observed_at: usage.observed_at.map(|ms| ms / 1000),
            usage_stale: observed.stale,
            billed: observed.billed,
        });
    }
    let machines = server
        .store()
        .machines(&user)
        .await
        .map_err(unavailable)?
        .into_iter()
        .map(|(id, revoked)| Machine { id, revoked })
        .collect();
    // Revalidate after the awaited reads: a sign-out or a disable meanwhile wins.
    if enrollment::browser_user(server, headers).await?.is_none() {
        return Ok(None);
    }
    Ok(Some(Snapshot {
        email,
        server_time: chrono::Utc::now().timestamp(),
        accounts,
        machines,
        csrf,
        done,
    }))
}

/// The signed-in browser for an action, or the response to send instead: sign-in without
/// a session, the error page for a dead or refused one.
async fn signed_in(
    server: &Server,
    headers: &HeaderMap,
) -> Result<enrollment::Browser, Box<Response>> {
    match enrollment::browser_session(server, headers).await {
        Ok(Some(browser)) => Ok(browser),
        Ok(None) => Err(Box::new(sign_in_again())),
        Err(error) => Err(Box::new(enrollment::dashboard_error(error))),
    }
}
/// A page or a redirect after an action; never cached.
fn page(content: String) -> Response {
    document(&content, false)
}
fn after(done: &str) -> Response {
    (
        [("cache-control", "no-store")],
        Redirect::to(&format!("/accounts?done={done}")),
    )
        .into_response()
}
fn refuse(server: &Server, status: StatusCode, reason: &'static str) -> Response {
    enrollment::dashboard_error(server.error(status, reason))
}
/// This user's account with this ID.
async fn own_account(
    server: &Server,
    user: &str,
    id: &str,
) -> Result<super::engine::Account, Box<Response>> {
    let accounts = server.engine().accounts(user).await.map_err(|_| {
        refuse(
            server,
            StatusCode::SERVICE_UNAVAILABLE,
            "registry_unavailable",
        )
    })?;
    accounts
        .into_iter()
        .find(|a| a.account_id == id)
        .ok_or_else(|| Box::new(refuse(server, StatusCode::NOT_FOUND, "account_not_found")))
}
/// Remove and Revoke: a sign-in of the last 10 minutes, else a new sign-in first.
fn fresh_sign_in(browser: &enrollment::Browser) -> Result<(), Box<Response>> {
    if enrollment::recent_sign_in(browser.signed_in_at, chrono::Utc::now().timestamp_millis()) {
        Ok(())
    } else {
        Err(Box::new(sign_in_again()))
    }
}
/// To the Google sign-in, which returns to the dashboard.
fn sign_in_again() -> Response {
    (
        [("cache-control", "no-store")],
        Redirect::to("/accounts/sign-in"),
    )
        .into_response()
}

async fn add_form(State(server): Shared, headers: HeaderMap) -> Response {
    match signed_in(&server, &headers).await {
        Ok(browser) => page(render::add_page(&browser.email, &browser.csrf)),
        Err(response) => *response,
    }
}
#[derive(serde::Deserialize)]
struct ManageQuery {
    account: String,
}
async fn manage(
    State(server): Shared,
    headers: HeaderMap,
    Query(query): Query<ManageQuery>,
) -> Response {
    let browser = match signed_in(&server, &headers).await {
        Ok(browser) => browser,
        Err(response) => return *response,
    };
    let account = match own_account(&server, &browser.user, &query.account).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    let machines = match server.store().machines(&browser.user).await {
        Ok(machines) => machines.iter().filter(|(_, revoked)| !revoked).count(),
        Err(_) => {
            return refuse(
                &server,
                StatusCode::SERVICE_UNAVAILABLE,
                "registry_unavailable",
            );
        }
    };
    page(render::manage_page(
        &browser.email,
        &account.alias,
        &account.account_id,
        &browser.csrf,
        machines,
    ))
}
/// Start a Claude sign-in owned by the dashboard and show its page.
async fn start_login(
    server: &Server,
    browser: &enrollment::Browser,
    alias: &str,
    renew: bool,
) -> Response {
    match server
        .engine()
        .start_login(
            &browser.user,
            super::engine::DASHBOARD_MACHINE,
            alias,
            renew,
        )
        .await
    {
        Ok(login) => page(render::login_page(
            &browser.email,
            alias,
            renew,
            &login.authorize_url,
            &login.id,
            &browser.csrf,
        )),
        // An invalid name, or a new name that already exists.
        Err(_) => refuse(server, StatusCode::BAD_REQUEST, "login_not_started"),
    }
}
#[derive(serde::Deserialize)]
struct AddForm {
    csrf: String,
    alias: String,
}
async fn add(State(server): Shared, headers: HeaderMap, Form(form): Form<AddForm>) -> Response {
    let browser = match signed_in(&server, &headers).await {
        Ok(browser) => browser,
        Err(response) => return *response,
    };
    if let Err(error) = enrollment::check_form(&server, &headers, &browser, &form.csrf) {
        return enrollment::dashboard_error(error);
    }
    start_login(&server, &browser, form.alias.trim(), false).await
}
#[derive(serde::Deserialize)]
struct AccountForm {
    csrf: String,
    account: String,
}
async fn renew(
    State(server): Shared,
    headers: HeaderMap,
    Form(form): Form<AccountForm>,
) -> Response {
    let browser = match signed_in(&server, &headers).await {
        Ok(browser) => browser,
        Err(response) => return *response,
    };
    if let Err(error) = enrollment::check_form(&server, &headers, &browser, &form.csrf) {
        return enrollment::dashboard_error(error);
    }
    let account = match own_account(&server, &browser.user, &form.account).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    // A new Claude sign-in for the same account; never a forced token refresh.
    start_login(&server, &browser, &account.alias, true).await
}
#[derive(serde::Deserialize)]
struct LoginForm {
    csrf: String,
    login: String,
    code: String,
}
async fn finish_login(
    State(server): Shared,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let browser = match signed_in(&server, &headers).await {
        Ok(browser) => browser,
        Err(response) => return *response,
    };
    if let Err(error) = enrollment::check_form(&server, &headers, &browser, &form.csrf) {
        return enrollment::dashboard_error(error);
    }
    match server
        .engine()
        .finish_login(
            &browser.user,
            super::engine::DASHBOARD_MACHINE,
            &form.login,
            &form.code,
        )
        .await
    {
        Ok(_) => after("saved"),
        // The reason only: the code is never logged or shown again.
        Err(_) => refuse(&server, StatusCode::BAD_REQUEST, "login_not_completed"),
    }
}
#[derive(serde::Deserialize)]
struct RemoveForm {
    csrf: String,
    account: String,
    confirm: String,
}
async fn remove(
    State(server): Shared,
    headers: HeaderMap,
    Form(form): Form<RemoveForm>,
) -> Response {
    let browser = match signed_in(&server, &headers).await {
        Ok(browser) => browser,
        Err(response) => return *response,
    };
    if let Err(error) = enrollment::check_form(&server, &headers, &browser, &form.csrf) {
        return enrollment::dashboard_error(error);
    }
    if let Err(response) = fresh_sign_in(&browser) {
        return *response;
    }
    let account = match own_account(&server, &browser.user, &form.account).await {
        Ok(account) => account,
        Err(response) => return *response,
    };
    // The exact name, case included: no prefix, no short name.
    if form.confirm != account.alias {
        return refuse(&server, StatusCode::BAD_REQUEST, "confirmation_mismatch");
    }
    let actor = format!("dashboard:{}", browser.email);
    match server
        .engine()
        .remove_from_dashboard(&browser.user, &actor, &account.account_id)
        .await
    {
        Ok(()) => after("removed"),
        Err(_) => refuse(
            &server,
            StatusCode::SERVICE_UNAVAILABLE,
            "persistence_failed",
        ),
    }
}
#[derive(serde::Deserialize)]
struct RevokeForm {
    csrf: String,
    machine: String,
}
async fn revoke(
    State(server): Shared,
    headers: HeaderMap,
    Form(form): Form<RevokeForm>,
) -> Response {
    let browser = match signed_in(&server, &headers).await {
        Ok(browser) => browser,
        Err(response) => return *response,
    };
    if let Err(error) = enrollment::check_form(&server, &headers, &browser, &form.csrf) {
        return enrollment::dashboard_error(error);
    }
    if let Err(response) = fresh_sign_in(&browser) {
        return *response;
    }
    // Only a connected machine of this user: a repeated submit writes no second audit line.
    match server.store().machines(&browser.user).await {
        Ok(machines) => match machines.iter().find(|(id, _)| *id == form.machine) {
            None => return refuse(&server, StatusCode::NOT_FOUND, "machine_not_found"),
            Some((_, true)) => {
                return refuse(&server, StatusCode::CONFLICT, "machine_already_revoked");
            }
            Some((_, false)) => {}
        },
        Err(_) => {
            return refuse(
                &server,
                StatusCode::SERVICE_UNAVAILABLE,
                "registry_unavailable",
            );
        }
    }
    match server
        .store()
        .revoke_machine(&form.machine, Some(&browser.user))
        .await
    {
        Ok(true) => {}
        Ok(false) => return refuse(&server, StatusCode::NOT_FOUND, "machine_not_found"),
        Err(_) => {
            return refuse(
                &server,
                StatusCode::SERVICE_UNAVAILABLE,
                "persistence_failed",
            );
        }
    }
    let actor = format!("dashboard:{}", browser.email);
    let audited = server
        .engine()
        .audit(&super::audit::Event {
            operation: "machine_revoke",
            machine: super::engine::DASHBOARD_MACHINE,
            account: "",
            result: "ok",
            rotated: None,
            target: Some(&form.machine),
            reason: None,
            actor: Some(&actor),
        })
        .await;
    match audited {
        Ok(()) => after("revoked"),
        Err(_) => refuse(
            &server,
            StatusCode::SERVICE_UNAVAILABLE,
            "audit_unavailable",
        ),
    }
}

/// What the dashboard shows of a stored observation.
struct Observed {
    five: Window,
    week: Window,
    /// The weekly Fable limit, when the account has one.
    fable: Option<Window>,
    /// The weekly Opus and Sonnet windows, as the CLI reads them.
    models: Vec<crate::accounts::Window>,
    /// No usage figure at all, or the server marked it stale.
    stale: bool,
    /// Extra usage is not known to be off (the CLI's rule for server accounts).
    billed: bool,
}

/// The windows of a stored observation. An observation without any usage figure is
/// stale, never fresh.
fn windows(usage: &crate::server::engine::Usage) -> Observed {
    let parsed = usage
        .data
        .as_ref()
        .and_then(|d| serde_json::from_value::<crate::api::UsageResponse>(d.clone()).ok());
    let window = |w: Option<&crate::api::UsageWindow>| Window {
        used_percent: w
            .and_then(|w| w.utilization)
            .filter(|n| n.is_finite() && *n >= 0.0),
        resets_at: w.and_then(crate::api::UsageWindow::reset_timestamp),
    };
    let five = window(parsed.as_ref().and_then(|u| u.five_hour.as_ref()));
    let week = window(parsed.as_ref().and_then(|u| u.seven_day.as_ref()));
    let fable = parsed
        .as_ref()
        .and_then(crate::api::UsageResponse::fable_weekly)
        .map(|limit| Window {
            used_percent: limit.percent.filter(|n| n.is_finite() && *n >= 0.0),
            resets_at: None,
        });
    let models = parsed
        .as_ref()
        .map(crate::accounts::windows)
        .unwrap_or_default()
        .into_iter()
        .filter(|w| matches!(w.name, "Opus" | "Sonnet"))
        .collect();
    // Partial usage is not stale: `accounts::state` reads it (a known full window stays a
    // limit; otherwise it is unknown and never picked), as in the CLI.
    let empty = five.used_percent.is_none() && week.used_percent.is_none();
    let billed = parsed
        .as_ref()
        .and_then(|u| u.extra_usage.as_ref())
        .and_then(|e| e.is_enabled)
        != Some(false);
    Observed {
        five,
        week,
        fable,
        models,
        stale: usage.stale || empty,
        billed,
    }
}

fn document(content: &str, refresh: bool) -> Response {
    let styles = include_str!("dashboard/style.css");
    let script = include_str!("dashboard/copy.js");
    let style_hash = STANDARD.encode(Sha256::digest(styles.as_bytes()));
    let script_hash = STANDARD.encode(Sha256::digest(script.as_bytes()));
    let policy = format!(
        "default-src 'none'; style-src 'sha256-{style_hash}'; script-src 'sha256-{script_hash}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    let refresh = if refresh {
        // To `/accounts` itself: a finished action's note (`?done=`) shows once.
        r#"<meta http-equiv="refresh" content="60; url=/accounts">"#
    } else {
        ""
    };
    let html = include_str!("dashboard/page.html")
        .replace("<!-- ACCOUNT_REFRESH -->", refresh)
        .replace("<!-- STYLES -->", &format!("<style>{styles}</style>"))
        .replace("<!-- CONTENT -->", content)
        .replace("<!-- SCRIPT -->", &format!("<script>{script}</script>"))
        .replace("<!-- VERSION -->", env!("CARGO_PKG_VERSION"));
    (
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "same-origin"),
            ("x-content-type-options", "nosniff"),
            ("content-security-policy", policy.as_str()),
        ],
        Html(html),
    )
        .into_response()
}

pub(super) fn routes(router: Router<Arc<Server>>) -> Router<Arc<Server>> {
    router
        .route("/", get(landing))
        .route("/accounts", get(accounts))
        .route(
            "/accounts/sign-in",
            get(|state| async move {
                enrollment::sign_in(state)
                    .await
                    .unwrap_or_else(enrollment::dashboard_error)
            }),
        )
        .route("/accounts/add", get(add_form).post(add))
        .route("/accounts/manage", get(manage))
        .route("/accounts/renew", post(renew))
        .route("/accounts/login", post(finish_login))
        .route("/accounts/remove", post(remove))
        .route("/machines/revoke", post(revoke))
        .route(
            "/accounts/sign-out",
            post(|state, headers| async move {
                enrollment::sign_out(state, headers)
                    .await
                    .unwrap_or_else(enrollment::dashboard_error)
            }),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_and_revoke_send_an_old_sign_in_to_google_first() {
        let browser = |signed_in_at| enrollment::Browser {
            user: "u".into(),
            email: "a@sawmills.ai".into(),
            csrf: "t".into(),
            signed_in_at,
        };
        let now = chrono::Utc::now().timestamp_millis();
        for old in [None, Some(now - enrollment::REAUTH_MS - 1_000)] {
            let response = *fresh_sign_in(&browser(old)).unwrap_err();
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            assert_eq!(response.headers()["location"], "/accounts/sign-in");
        }
        assert!(fresh_sign_in(&browser(Some(now))).is_ok());
    }

    #[test]
    fn the_accounts_page_refreshes_to_itself_without_the_finished_action() {
        let page = document("x", true);
        let body = futures_body(page);
        assert!(body.contains(r#"content="60; url=/accounts""#), "{body}");
    }
    fn futures_body(response: Response) -> String {
        let bytes = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(axum::body::to_bytes(response.into_body(), usize::MAX))
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn partial_usage_is_unknown_but_a_known_full_window_stays_a_limit() {
        let usage = |data| crate::server::engine::Usage {
            data: Some(data),
            ..Default::default()
        };
        let state = |data| {
            let o = windows(&usage(data));
            let mut all = vec![
                crate::accounts::Window {
                    name: "5h",
                    used: o.five.used_percent,
                    resets_at: o.five.resets_at,
                },
                crate::accounts::Window {
                    name: "week",
                    used: o.week.used_percent,
                    resets_at: o.week.resets_at,
                },
            ];
            all.extend(o.models);
            (o.stale, crate::accounts::state(&all))
        };
        // The shared rule decides, not a stale flag: a partial response is unknown
        // (never picked), and a confirmed full 5h window stays a visible limit.
        let (stale, partial) = state(serde_json::json!({"seven_day": {"utilization": 1.0}}));
        assert!(!stale);
        assert_eq!(partial, crate::accounts::State::Unknown);
        let (stale, full) = state(serde_json::json!({"five_hour": {"utilization": 100.0}}));
        assert!(!stale);
        assert!(
            matches!(full, crate::accounts::State::Limit { window: "5h", .. }),
            "{full:?}"
        );
    }

    #[tokio::test]
    async fn the_landing_badge_follows_readiness_and_goes_down_during_drain() {
        let root = tempfile::tempdir().unwrap();
        let (state, key) = (root.path().join("state"), root.path().join("key"));
        crate::server::app::setup(&state, &key).unwrap();
        let server = Server::open(crate::server::app::Config {
            store: crate::server::app::StoreConfig::File(state),
            key,
            allowed_users: vec!["amir@sawmills.ai".into()],
            sso: None,
            metrics_token_hash: None,
            endpoints: crate::server::engine::Endpoints {
                api: "http://127.0.0.1:9".into(),
                token: "http://127.0.0.1:9/token".into(),
            },
        })
        .await
        .unwrap();
        let badge = |server: Arc<Server>| async move {
            let response = landing(State(server), HeaderMap::new()).await;
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            String::from_utf8(body.to_vec()).unwrap()
        };
        assert!(badge(server.clone()).await.contains("Account server ready"));
        // The same signal as /ready: a draining replica is not ready, even with a live store.
        server.begin_drain();
        assert!(!server.ready().await);
        let body = badge(server.clone()).await;
        assert!(body.contains("Account server not ready"), "{body}");
        assert!(!body.contains(r#"<span class="state ok">"#), "{body}");
    }

    #[test]
    fn a_cache_object_without_usage_figures_is_stale() {
        let usage = |data| crate::server::engine::Usage {
            data: Some(data),
            observed_at: Some(1),
            next_retry_at: i64::MAX,
            stale: false,
            ..Default::default()
        };
        for data in [
            serde_json::json!({}),
            serde_json::json!({"five_hour": null, "seven_day": {"utilization": null}}),
        ] {
            let o = windows(&usage(data));
            assert!(o.five.used_percent.is_none() && o.week.used_percent.is_none());
            assert!(o.stale, "no usage figure must not read as fresh");
        }
        let o = windows(&usage(serde_json::json!({
            "five_hour": {"utilization": 12.0, "resets_at": "2099-01-01T00:00:00Z"},
            "extra_usage": {"is_enabled": false},
            "limits": [{"kind": "weekly_scoped", "percent": 100.0,
                "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}}]
        })));
        assert_eq!(o.five.used_percent, Some(12.0));
        // No week figure: not stale; `accounts::state` reads the partial usage.
        assert!(!o.stale);
        assert_eq!(o.fable.as_ref().and_then(|w| w.used_percent), Some(100.0));
        assert!(!o.billed, "extra usage known off");
        // Missing extra-usage data is not proof: billed.
        let missing = windows(&usage(
            serde_json::json!({"five_hour": {"utilization": 1.0}}),
        ));
        assert!(missing.billed);
    }
}

#[cfg(test)]
mod preview {
    use super::*;

    /// Writes synthetic pages for screenshots: `DASHBOARD_PREVIEW_DIR=<dir> cargo test
    /// --features server --lib dashboard::preview -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn write_preview_pages() {
        let dir = std::path::PathBuf::from(std::env::var("DASHBOARD_PREVIEW_DIR").unwrap());
        let body = |r: Response| async move {
            String::from_utf8(
                axum::body::to_bytes(r.into_body(), usize::MAX)
                    .await
                    .unwrap()
                    .to_vec(),
            )
            .unwrap()
        };
        let now = chrono::Utc::now().timestamp();
        let window = |used: f64, hours: i64| Window {
            used_percent: Some(used),
            resets_at: Some(now + hours * 3600 + 300),
        };
        let account = |alias: &str, five, week, migration: &str| Account {
            id: alias.replace('@', "-at-"),
            alias: alias.into(),
            available: true,
            migration: migration.into(),
            five_hour: window(five, 2),
            seven_day: window(week, 142),
            fable: None,
            model_windows: vec![],
            observed_at: Some(now - 42),
            usage_stale: false,
            billed: false,
        };
        let mut pending = account("amir6@sawmills.ai", 0.0, 0.0, "pending");
        pending.five_hour.used_percent = None;
        pending.seven_day.used_percent = None;
        pending.observed_at = None;
        pending.usage_stale = true;
        let with_fable = |mut a: Account, used: f64| {
            a.fable = Some(Window {
                used_percent: Some(used),
                resets_at: None,
            });
            a
        };
        let full = Snapshot {
            email: "amir@sawmills.ai".into(),
            server_time: now,
            accounts: vec![
                with_fable(account("amir3@sawmills.ai", 2.0, 1.0, "rotated"), 0.0),
                with_fable(account("amir@sawmills.ai", 55.0, 76.0, "rotated"), 16.0),
                with_fable(account("amir4@sawmills.ai", 0.0, 98.0, "rotated"), 100.0),
                with_fable(account("amir5@sawmills.ai", 93.0, 88.0, "unrotated"), 40.0),
                pending,
            ],
            machines: vec![
                Machine {
                    id: "mac-mini-3f9a1c0e7b24".into(),
                    revoked: false,
                },
                Machine {
                    id: "devbox-81d0aa5c9e13".into(),
                    revoked: false,
                },
                Machine {
                    id: "old-laptop-0c4e19b2d7aa".into(),
                    revoked: true,
                },
            ],
            csrf: "preview".into(),
            done: None,
        };
        let empty = Snapshot {
            email: full.email.clone(),
            server_time: now,
            accounts: vec![],
            machines: vec![],
            csrf: "preview".into(),
            done: None,
        };
        let landing = include_str!("dashboard/landing.html")
            .replace(
                "<!-- SERVER -->",
                "'https://claudectl.ue1.staging.plat.sm-svc.com'",
            )
            .replace("<!-- READY_STATE -->", "ok")
            .replace("<!-- READY_LABEL -->", "Account server ready");
        for (name, response) in [
            ("landing", document(&landing, false)),
            ("accounts", document(&render::overview(&full), true)),
            ("empty", document(&render::overview(&empty), true)),
            ("add", page(render::add_page("amir@sawmills.ai", "preview"))),
            (
                "manage",
                page(render::manage_page(
                    "amir@sawmills.ai",
                    "amir3@sawmills.ai",
                    "preview-account",
                    "preview",
                    2,
                )),
            ),
            (
                "login",
                page(render::login_page(
                    "amir@sawmills.ai",
                    "amir8",
                    false,
                    "https://claude.com/cai/oauth/authorize?code=true",
                    "preview-login",
                    "preview",
                )),
            ),
            (
                "personal-account",
                enrollment::dashboard_error(HttpError {
                    status: StatusCode::FORBIDDEN,
                    reason: "company_identity_required",
                }),
            ),
        ] {
            std::fs::write(dir.join(format!("{name}.html")), body(response).await).unwrap();
        }
    }
}
