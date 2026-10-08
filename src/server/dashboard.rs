//! Read-only browser view for the signed-in company user: own accounts, cached usage, and
//! own machines. Credentials never enter a page, and a page never contacts Anthropic.
use super::{
    app::{HttpError, Server},
    enrollment,
};
use axum::{
    Router,
    extract::State,
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
    let ready = server.store().ready().await.is_ok();
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

async fn accounts(State(server): Shared, headers: HeaderMap) -> Response {
    match snapshot(&server, &headers).await {
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

async fn snapshot(server: &Server, headers: &HeaderMap) -> Result<Option<Snapshot>, HttpError> {
    let Some((user, email)) = enrollment::browser_user(server, headers).await? else {
        return Ok(None);
    };
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
        let (five_hour, seven_day, usage_stale) = windows(&usage);
        accounts.push(Account {
            alias: account.alias,
            available: account.available,
            migration: account.migration.into(),
            five_hour,
            seven_day,
            observed_at: usage.observed_at.map(|ms| ms / 1000),
            usage_stale,
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
    }))
}

/// The 5-hour and 7-day windows of a stored observation, and whether it is stale. An
/// observation without any usage figure is stale, never fresh.
fn windows(usage: &crate::server::engine::Usage) -> (Window, Window, bool) {
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
    let empty = five.used_percent.is_none() && week.used_percent.is_none();
    (five, week, usage.stale || empty)
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
        r#"<meta http-equiv="refresh" content="60">"#
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
            let (five, week, stale) = windows(&usage(data));
            assert!(five.used_percent.is_none() && week.used_percent.is_none());
            assert!(stale, "no usage figure must not read as fresh");
        }
        let (five, _, stale) = windows(&usage(serde_json::json!({
            "five_hour": {"utilization": 12.0, "resets_at": "2099-01-01T00:00:00Z"}
        })));
        assert_eq!(five.used_percent, Some(12.0));
        assert!(!stale);
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
            alias: alias.into(),
            available: true,
            migration: migration.into(),
            five_hour: window(five, 2),
            seven_day: window(week, 142),
            observed_at: Some(now - 42),
            usage_stale: false,
        };
        let mut pending = account("amir4", 0.0, 0.0, "pending");
        pending.five_hour.used_percent = None;
        pending.seven_day.used_percent = None;
        pending.observed_at = None;
        pending.usage_stale = true;
        let full = Snapshot {
            email: "amir@sawmills.ai".into(),
            server_time: now,
            accounts: vec![
                account("amir", 12.0, 8.0, "rotated"),
                account("amir3", 64.0, 31.0, "rotated"),
                account("amir5", 93.0, 88.0, "unrotated"),
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
        };
        let empty = Snapshot {
            email: full.email.clone(),
            server_time: now,
            accounts: vec![],
            machines: vec![],
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
