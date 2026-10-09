#![cfg(feature = "server")]
//! Company SSO against a synthetic OIDC issuer that signs real RS256 ID tokens. The
//! authorization URL always carries the `hd` hint; the server must decide on the signed
//! `hd` claim alone. No real Google account or credential.
//!
//! Test requirement: the `openssl` CLI on PATH (Linux CI and the devbox have it). It
//! generates a throwaway signing key per run, so no private key is committed.
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
};
use claudectl::server::{app, engine::Endpoints};
use openidconnect::{
    AdditionalClaims, Audience, EndUserEmail, IssuerUrl, JsonWebKeyId, Nonce, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
    core::{CoreGenderClaim, CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreRsaPrivateSigningKey},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Hd {
    #[serde(skip_serializing_if = "Option::is_none")]
    hd: Option<String>,
}
impl AdditionalClaims for Hd {}
type Claims = openidconnect::IdTokenClaims<Hd, CoreGenderClaim>;
type IdToken = openidconnect::IdToken<
    Hd,
    CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>;

/// A throwaway PKCS#1 RSA key from the system OpenSSL CLI; nothing is committed.
fn rsa_pem() -> String {
    let run = |args: &[&str]| {
        std::process::Command::new("openssl")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8(o.stdout).unwrap())
    };
    run(&["genrsa", "-traditional", "2048"])
        .or_else(|| run(&["genrsa", "2048"]))
        .expect("these tests need the openssl CLI on PATH to generate a throwaway key")
}

/// What the next ID token claims and how it is signed.
struct Token<'a> {
    email: &'a str,
    hd: Option<&'a str>,
    verified: bool,
    /// Sign with a key the issuer's JWKS does not publish.
    rogue: bool,
    /// Use this nonce instead of the login's.
    nonce: Option<&'a str>,
}
impl<'a> Token<'a> {
    fn new(email: &'a str, hd: Option<&'a str>) -> Self {
        Self {
            email,
            hd,
            verified: true,
            rogue: false,
            nonce: None,
        }
    }
}

#[derive(Clone)]
struct Issuer {
    origin: String,
    key: Arc<CoreRsaPrivateSigningKey>,
    /// Same key ID as `key`, never published.
    rogue: Arc<CoreRsaPrivateSigningKey>,
    /// The ID token the next token request returns.
    next: Arc<Mutex<Option<String>>>,
}
impl Issuer {
    /// Sign the next ID token for the pending login with `nonce`.
    fn prepare(&self, nonce: &str, token: &Token) {
        let now = chrono::Utc::now();
        let claims = Claims::new(
            IssuerUrl::new(self.origin.clone()).unwrap(),
            vec![Audience::new("test-client".into())],
            now + chrono::Duration::minutes(5),
            now,
            StandardClaims::new(SubjectIdentifier::new(format!("sub-{}", token.email)))
                .set_email(Some(EndUserEmail::new(token.email.into())))
                .set_email_verified(Some(token.verified)),
            Hd {
                hd: token.hd.map(str::to_owned),
            },
        )
        .set_nonce(Some(Nonce::new(token.nonce.unwrap_or(nonce).into())));
        let key = if token.rogue { &self.rogue } else { &self.key };
        let token = IdToken::new(
            claims,
            key.as_ref(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .unwrap();
        *self.next.lock().unwrap() = Some(token.to_string());
    }
}

async fn issuer() -> (Issuer, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let key = || {
        CoreRsaPrivateSigningKey::from_pem(&rsa_pem(), Some(JsonWebKeyId::new("k1".into())))
            .unwrap()
    };
    let issuer = Issuer {
        origin: origin.clone(),
        key: Arc::new(key()),
        rogue: Arc::new(key()),
        next: Arc::default(),
    };
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(|State(i): State<Issuer>| async move {
                Json(json!({
                    "issuer": i.origin,
                    "authorization_endpoint": format!("{}/auth", i.origin),
                    "token_endpoint": format!("{}/token", i.origin),
                    "jwks_uri": format!("{}/jwks", i.origin),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }))
            }),
        )
        .route(
            "/jwks",
            get(|State(i): State<Issuer>| async move {
                Json(CoreJsonWebKeySet::new(vec![i.key.as_verification_key()]))
            }),
        )
        .route(
            "/token",
            post(|State(i): State<Issuer>| async move {
                let id_token = i.next.lock().unwrap().take().expect("prepared ID token");
                Json(json!({"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":id_token}))
            }),
        )
        // The synthetic Claude profile: one identity per access token, for seeded accounts.
        .route(
            "/api/oauth/profile",
            get(|headers: axum::http::HeaderMap| async move {
                let token = headers["authorization"].to_str().unwrap().trim_start_matches("Bearer ");
                Json(json!({"account":{"uuid":format!("acct-{token}")},"organization":{"uuid":"org"}}))
            }),
        )
        .with_state(issuer.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (issuer, task)
}

struct Fixture {
    _root: tempfile::TempDir,
    server: Arc<app::Server>,
    origin: String,
    issuer: Issuer,
    http: reqwest::Client,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.tasks.iter().for_each(|t| t.abort());
    }
}
impl Fixture {
    async fn new() -> Self {
        let (issuer, issuer_task) = issuer().await;
        let root = tempfile::tempdir().unwrap();
        let (state, key) = (root.path().join("state"), root.path().join("key"));
        app::setup(&state, &key).unwrap();
        let secret = root.path().join("client-secret");
        std::fs::write(&secret, "test-secret").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = root.path().join("sso.json");
        std::fs::write(
            &config,
            json!({"issuer":issuer.origin,"client_id":"test-client","client_secret_file":secret,
                "allowed_domains":["sawmills.ai"],"allowed_hosted_domains":["sawmills.ai"]})
            .to_string(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let store = match claudectl::server::testing::fresh_database().await.unwrap() {
            Some(url) => app::StoreConfig::Postgres(url),
            None => app::StoreConfig::File(state),
        };
        let server = app::Server::open(app::Config {
            store,
            key,
            allowed_users: vec!["amir@sawmills.ai".into()],
            sso: Some(app::Sso {
                config,
                public_url: origin.clone(),
            }),
            metrics_token_hash: None,
            endpoints: Endpoints {
                api: issuer.origin.clone(),
                token: "http://127.0.0.1:9/token".into(),
            },
        })
        .await
        .unwrap();
        let router = app::router(server.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            _root: root,
            server,
            origin,
            issuer,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            tasks: vec![issuer_task, task],
        }
    }
    /// Start an enrollment and follow it to the issuer: the authorization URL's query.
    async fn sign_in(&self) -> std::collections::HashMap<String, String> {
        let start: Value = self
            .http
            .post(format!("{}/v1/enrollment/start", self.origin))
            .json(&json!({"name":"proof","providers":["anthropic"]}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let enroll = self
            .http
            .get(start["verificationUrl"].as_str().unwrap())
            .send()
            .await
            .unwrap();
        assert!(enroll.status().is_redirection(), "{}", enroll.status());
        let location = enroll.headers()["location"].to_str().unwrap();
        let url = reqwest::Url::parse(location).unwrap();
        assert!(location.starts_with(&format!("{}/auth", self.issuer.origin)));
        url.query_pairs().into_owned().collect()
    }
    /// Complete the callback with this ID token: (status, body).
    async fn callback(&self, token: Token<'_>) -> (u16, String) {
        let response = self.callback_response(token, None).await;
        (response.status().as_u16(), response.text().await.unwrap())
    }
    /// Complete the callback, optionally as a browser that accepts HTML.
    async fn callback_response(&self, token: Token<'_>, accept: Option<&str>) -> reqwest::Response {
        let query = self.sign_in().await;
        // The hint asks Google for the company account chooser; it is not a decision.
        assert_eq!(query.get("hd").map(String::as_str), Some("sawmills.ai"));
        self.issuer.prepare(&query["nonce"], &token);
        let mut request = self
            .http
            .get(format!("{}/auth/callback", self.origin))
            .query(&[("state", query["state"].as_str()), ("code", "c")]);
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        request.send().await.unwrap()
    }
    async fn users(&self) -> usize {
        self.server.store().users().await.unwrap().len()
    }
}

/// The approval token a successful callback page carries, if any.
fn approval(body: &str) -> Option<String> {
    let start = body.find(r#"name="approval" value=""#)? + r#"name="approval" value=""#.len();
    Some(body[start..start + body[start..].find('"')?].to_owned())
}

#[tokio::test]
async fn a_signed_company_hd_claim_reaches_approval_and_creates_the_user() {
    let f = Fixture::new().await;
    assert_eq!(f.users().await, 0);
    let (status, body) = f
        .callback(Token::new("amir@sawmills.ai", Some("sawmills.ai")))
        .await;
    assert_eq!(status, 200, "{body}");
    let token = approval(&body).expect("approval token on the callback page");
    let approve = f
        .http
        .post(format!("{}/auth/approve", f.origin))
        .form(&[("approval", token.as_str())])
        .send()
        .await
        .unwrap();
    assert_eq!(approve.status().as_u16(), 200);
    assert_eq!(f.users().await, 1, "an approved sign-in creates the user");
    // A machine enrollment never signs a browser in to the dashboard.
    assert!(set_cookie(&approve, "claudectl-session").is_none());
}

/// A refused callback carries no approval token, so no user can be created from it.
fn assert_refused(status: u16, body: &str, code: u16, reason: &str) {
    assert_eq!(status, code, "{body}");
    assert!(body.contains(reason), "{body}");
    assert!(
        approval(body).is_none(),
        "a refused sign-in offered approval"
    );
}

#[tokio::test]
async fn a_token_without_the_company_hd_claim_is_refused_despite_the_url_hint() {
    let f = Fixture::new().await;
    // A company-looking address on an account outside the Workspace: only hd is wrong.
    let (status, body) = f.callback(Token::new("amir@sawmills.ai", None)).await;
    assert_refused(status, &body, 403, "company_identity_required");
    // Another Workspace: the URL hint said sawmills.ai, the signed claim decides.
    let (status, body) = f
        .callback(Token::new("amir@sawmills.ai", Some("example.com")))
        .await;
    assert_refused(status, &body, 403, "company_identity_required");
    // A personal Gmail account: refused by the email domain already, and it has no hd.
    let (status, body) = f.callback(Token::new("someone@gmail.com", None)).await;
    assert_refused(status, &body, 403, "company_identity_required");
    assert_eq!(f.users().await, 0);
}

#[tokio::test]
async fn a_browser_gets_an_error_page_with_the_same_status() {
    let f = Fixture::new().await;
    let browser = "text/html,application/xhtml+xml,*/*;q=0.8";
    let response = f
        .callback_response(Token::new("amir@sawmills.ai", None), Some(browser))
        .await;
    assert_eq!(response.status().as_u16(), 403);
    let headers = response.headers().clone();
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html")
    );
    assert!(headers.contains_key("content-security-policy"));
    let body = response.text().await.unwrap();
    assert!(body.contains("Use your company account"), "{body}");
    assert!(
        approval(&body).is_none(),
        "a refused sign-in offered approval"
    );
    let expired = f
        .http
        .get(format!("{}/enroll?code=UNKNOWN", f.origin))
        .header("accept", browser)
        .send()
        .await
        .unwrap();
    assert_eq!(expired.status().as_u16(), 410);
    assert!(
        expired
            .text()
            .await
            .unwrap()
            .contains("This link has expired")
    );
    // CLI and API clients keep the exact JSON body and status.
    for accept in [
        None,
        Some("application/json"),
        Some("application/json, text/html;q=0"),
    ] {
        let mut request = f.http.get(format!("{}/enroll?code=UNKNOWN", f.origin));
        if let Some(accept) = accept {
            request = request.header("accept", accept);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status().as_u16(), 410);
        assert_eq!(
            response.text().await.unwrap(),
            r#"{"error":"enrollment_expired"}"#
        );
    }
    assert_eq!(f.users().await, 0);
}

#[tokio::test]
async fn an_unverified_company_email_is_refused() {
    let f = Fixture::new().await;
    let mut token = Token::new("amir@sawmills.ai", Some("sawmills.ai"));
    token.verified = false;
    let (status, body) = f.callback(token).await;
    assert_refused(status, &body, 403, "company_identity_required");
}

#[tokio::test]
async fn a_token_the_issuer_did_not_sign_or_for_another_login_is_denied() {
    let f = Fixture::new().await;
    let mut token = Token::new("amir@sawmills.ai", Some("sawmills.ai"));
    token.rogue = true;
    let (status, body) = f.callback(token).await;
    assert_refused(status, &body, 401, "sso_denied");
    let mut token = Token::new("amir@sawmills.ai", Some("sawmills.ai"));
    token.nonce = Some("another-login");
    let (status, body) = f.callback(token).await;
    assert_refused(status, &body, 401, "sso_denied");
    assert_eq!(f.users().await, 0);
}

// ---------- Browser dashboard (SAW-12585) ----------

const BROWSER: &str = "text/html,application/xhtml+xml,*/*;q=0.8";

/// The `name=value` pair a response sets for this cookie name, if any.
fn set_cookie(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{name}=")))
        .map(|v| v.split(';').next().unwrap().to_owned())
}

impl Fixture {
    fn user_id(&self, email: &str) -> String {
        claudectl::server::vault::digest(format!("{}\0sub-{email}", self.issuer.origin).as_bytes())
    }
    /// Admit one synthetic account for `user`; the access token names its Claude identity.
    async fn seed(&self, user: &str, alias: &str) {
        let grant = claudectl::server::engine::Grant {
            access_token: format!("token-{alias}"),
            refresh_token: format!("refresh-{alias}"),
            expires_at: chrono::Utc::now().timestamp_millis() + 3_600_000,
            scopes: vec!["user:inference".into(), "user:profile".into()],
        };
        self.server
            .engine()
            .admit(user, alias, &format!("seed-{alias}"), grant, None)
            .await
            .unwrap();
    }
    /// Start a browser sign-in: (login cookie, authorization query).
    async fn dashboard_sign_in(&self) -> (String, std::collections::HashMap<String, String>) {
        let response = self
            .http
            .get(format!("{}/accounts/sign-in", self.origin))
            .header("accept", BROWSER)
            .send()
            .await
            .unwrap();
        assert!(response.status().is_redirection(), "{}", response.status());
        let cookie = set_cookie(&response, "claudectl-login").expect("login cookie");
        let location = response.headers()["location"].to_str().unwrap();
        assert!(location.starts_with(&format!("{}/auth", self.issuer.origin)));
        let query = reqwest::Url::parse(location)
            .unwrap()
            .query_pairs()
            .into_owned()
            .collect();
        (cookie, query)
    }
    /// Finish a browser sign-in with this ID token and login cookie.
    async fn dashboard_callback(
        &self,
        token: Token<'_>,
        cookie: Option<&str>,
    ) -> reqwest::Response {
        let (login, query) = self.dashboard_sign_in().await;
        assert_eq!(query.get("hd").map(String::as_str), Some("sawmills.ai"));
        self.issuer.prepare(&query["nonce"], &token);
        self.http
            .get(format!("{}/auth/callback", self.origin))
            .query(&[("state", query["state"].as_str()), ("code", "c")])
            .header("accept", BROWSER)
            .header("cookie", cookie.unwrap_or(&login))
            .send()
            .await
            .unwrap()
    }
    /// A signed-in session cookie for this company account.
    async fn session(&self, email: &str) -> String {
        let response = self
            .dashboard_callback(Token::new(email, Some("sawmills.ai")), None)
            .await;
        assert_eq!(response.status().as_u16(), 303, "{}", response.status());
        assert_eq!(response.headers()["location"], "/accounts");
        let cookie = set_cookie(&response, "claudectl-session").expect("session cookie");
        assert_eq!(
            set_cookie(&response, "claudectl-login").as_deref(),
            Some("claudectl-login="),
            "the login cookie is cleared"
        );
        let header = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .find(|v| v.starts_with("claudectl-session="))
            .unwrap();
        for attribute in ["HttpOnly", "SameSite=Lax", "Path=/"] {
            assert!(header.contains(attribute), "{header}");
        }
        cookie
    }
    async fn get(&self, path: &str, cookie: Option<&str>) -> reqwest::Response {
        let mut request = self
            .http
            .get(format!("{}{path}", self.origin))
            .header("accept", BROWSER);
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        request.send().await.unwrap()
    }
}

#[tokio::test]
async fn the_home_page_offers_google_sign_in_and_accounts_needs_a_session() {
    let f = Fixture::new().await;
    let home = f.get("/", None).await;
    assert_eq!(home.status().as_u16(), 200);
    assert!(home.headers().contains_key("content-security-policy"));
    let body = home.text().await.unwrap();
    assert!(body.contains("claudectl"), "{body}");
    assert!(body.contains(r#"href="/accounts/sign-in""#), "{body}");
    assert!(body.contains("Sign in with Google"), "{body}");
    let accounts = f.get("/accounts", None).await;
    assert!(accounts.status().is_redirection(), "{}", accounts.status());
    assert_eq!(accounts.headers()["location"], "/accounts/sign-in");
    // An unknown session cookie is refused and cleared; the page offers sign-in.
    let forged = f.get("/accounts", Some("claudectl-session=forged")).await;
    assert_eq!(forged.status().as_u16(), 401);
    assert!(
        set_cookie(&forged, "claudectl-session").is_some_and(|c| c == "claudectl-session="),
        "the stale cookie is expired"
    );
    assert!(forged.text().await.unwrap().contains("/accounts/sign-in"));
    // The public page ignores it.
    assert_eq!(
        f.get("/", Some("claudectl-session=forged"))
            .await
            .status()
            .as_u16(),
        200
    );
}

#[tokio::test]
async fn a_personal_google_account_cannot_open_the_dashboard() {
    let f = Fixture::new().await;
    for token in [
        Token::new("someone@gmail.com", None),
        Token::new("amir@sawmills.ai", None),
    ] {
        let response = f.dashboard_callback(token, None).await;
        assert_eq!(response.status().as_u16(), 403);
        assert!(set_cookie(&response, "claudectl-session").is_none());
        let body = response.text().await.unwrap();
        assert!(body.contains("Use your company account"), "{body}");
    }
    assert_eq!(f.users().await, 0);
}

#[tokio::test]
async fn a_callback_from_another_browser_is_refused() {
    let f = Fixture::new().await;
    let response = f
        .dashboard_callback(
            Token::new("amir@sawmills.ai", Some("sawmills.ai")),
            Some("claudectl-login=another-browser"),
        )
        .await;
    assert_eq!(response.status().as_u16(), 401);
    assert!(set_cookie(&response, "claudectl-session").is_none());
}

#[tokio::test]
async fn a_replayed_dashboard_callback_offers_dashboard_sign_in() {
    let f = Fixture::new().await;
    let (login, query) = f.dashboard_sign_in().await;
    f.issuer.prepare(
        &query["nonce"],
        &Token::new("amir@sawmills.ai", Some("sawmills.ai")),
    );
    let callback = |cookie: String| {
        f.http
            .get(format!("{}/auth/callback", f.origin))
            .query(&[("state", query["state"].as_str()), ("code", "c")])
            .header("accept", BROWSER)
            .header("cookie", cookie)
            .send()
    };
    let first = callback(login.clone()).await.unwrap();
    assert_eq!(first.status().as_u16(), 303);
    // A browser now holds the session cookie only; the login cookie was cleared.
    let session = set_cookie(&first, "claudectl-session").unwrap();
    // The state works once. A reload or Back after sign-in, or an expired state before
    // it, stays on the dashboard path, not the machine-enrollment recovery text.
    for cookie in [session, login] {
        let replay = callback(cookie).await.unwrap();
        assert_eq!(replay.status().as_u16(), 400);
        let body = replay.text().await.unwrap();
        assert!(body.contains(r#"href="/accounts/sign-in""#), "{body}");
        assert!(!body.contains("server connect"), "{body}");
    }
}

#[tokio::test]
async fn a_dashboard_sign_in_never_offers_a_machine_approval() {
    let f = Fixture::new().await;
    let response = f
        .dashboard_callback(Token::new("amir@sawmills.ai", Some("sawmills.ai")), None)
        .await;
    assert_eq!(response.status().as_u16(), 303);
    assert!(approval(&response.text().await.unwrap()).is_none());
    assert!(
        f.server
            .store()
            .machines(&f.user_id("amir@sawmills.ai"))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn a_signed_in_user_sees_only_own_accounts_and_machines() {
    let f = Fixture::new().await;
    let amir = f.user_id("amir@sawmills.ai");
    f.seed(&amir, "amir-pilot").await;
    f.seed("someone-else", "not-yours").await;
    let store = f.server.store();
    store
        .record_user("someone-else", "other@sawmills.ai")
        .await
        .unwrap();
    claudectl::server::app::register(store, "other@sawmills.ai", "foreign-box")
        .await
        .unwrap();
    let session = f.session("amir@sawmills.ai").await;
    let page = f.get("/accounts", Some(&session)).await;
    assert_eq!(page.status().as_u16(), 200);
    let headers = page.headers().clone();
    assert_eq!(headers["cache-control"], "no-store");
    assert!(headers.contains_key("content-security-policy"));
    let body = page.text().await.unwrap();
    assert!(body.contains("amir@sawmills.ai"), "{body}");
    assert!(body.contains("amir-pilot"), "{body}");
    assert!(!body.contains("not-yours"), "{body}");
    assert!(!body.contains("foreign-box"), "{body}");
    // No credential material reaches the page.
    for secret in ["token-amir-pilot", "refresh-amir-pilot", "acct-token"] {
        assert!(!body.contains(secret), "{secret} leaked");
    }
    // A signed-in visitor to the home page goes straight to the dashboard.
    let home = f.get("/", Some(&session)).await;
    assert_eq!(home.headers()["location"], "/accounts");
}

#[tokio::test]
async fn an_empty_dashboard_shows_the_migrate_command() {
    let f = Fixture::new().await;
    let session = f.session("amir@sawmills.ai").await;
    let body = f
        .get("/accounts", Some(&session))
        .await
        .text()
        .await
        .unwrap();
    assert!(
        body.contains("claudectl server migrate --all --exclusive-owner"),
        "{body}"
    );
}

#[tokio::test]
async fn sign_out_needs_the_same_origin_and_ends_the_session() {
    let f = Fixture::new().await;
    let session = f.session("amir@sawmills.ai").await;
    let sign_out = |origin: Option<String>| {
        let mut request = f
            .http
            .post(format!("{}/accounts/sign-out", f.origin))
            .header("accept", BROWSER)
            .header("cookie", session.clone());
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        request.send()
    };
    for origin in [None, Some("https://evil.example".to_owned())] {
        let response = sign_out(origin).await.unwrap();
        assert_eq!(response.status().as_u16(), 403);
    }
    assert_eq!(
        f.get("/accounts", Some(&session)).await.status().as_u16(),
        200
    );
    let response = sign_out(Some(f.origin.clone())).await.unwrap();
    assert_eq!(response.status().as_u16(), 303);
    assert_eq!(response.headers()["location"], "/");
    let cleared = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|v| v.starts_with("claudectl-session="))
        .expect("sign-out expires the cookie");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    // The old cookie is dead on the server, not only in this browser.
    let after = f.get("/accounts", Some(&session)).await;
    assert_eq!(after.status().as_u16(), 401);
}

#[tokio::test]
async fn a_user_removed_from_the_allow_list_loses_the_dashboard() {
    let f = Fixture::new().await;
    let session = f.session("amir@sawmills.ai").await;
    claudectl::server::app::set_user(f.server.store(), "amir@sawmills.ai", false)
        .await
        .unwrap();
    let page = f.get("/accounts", Some(&session)).await;
    assert_eq!(page.status().as_u16(), 403);
}

// ---------- Dashboard actions (SAW-12695) ----------

/// The `value` of the first hidden input with this name.
fn hidden(page: &str, name: &str) -> String {
    let marker = format!(r#"name="{name}" value=""#);
    let start = page
        .find(&marker)
        .unwrap_or_else(|| panic!("no {name}: {page}"))
        + marker.len();
    page[start..].split('"').next().unwrap().to_owned()
}

impl Fixture {
    async fn post_form(
        &self,
        path: &str,
        cookie: &str,
        origin: Option<&str>,
        form: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut request = self
            .http
            .post(format!("{}{path}", self.origin))
            .header("accept", BROWSER)
            .header("cookie", cookie)
            .form(form);
        if let Some(origin) = origin {
            request = request.header("origin", origin);
        }
        request.send().await.unwrap()
    }
    async fn account_id(&self, user: &str, alias: &str) -> Option<String> {
        self.server
            .engine()
            .accounts(user)
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.alias == alias)
            .map(|a| a.account_id)
    }
    /// A connected machine of this SSO user.
    async fn machine(&self, user: &str, id: &str) {
        self.server
            .store()
            .add_machine(&claudectl::server::store::Machine {
                id: id.into(),
                user: user.into(),
                token_hash: claudectl::server::vault::digest(id.as_bytes()),
                revoked: false,
                last_seen_at: None,
            })
            .await
            .unwrap();
    }
    async fn audit_lines(&self) -> Vec<Value> {
        claudectl::server::audit::read(self.server.store(), &self._root.path().join("key"))
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn a_dashboard_action_needs_the_session_token_and_the_same_origin() {
    let f = Fixture::new().await;
    let amir = f.user_id("amir@sawmills.ai");
    f.seed(&amir, "amir-pilot").await;
    let id = f.account_id(&amir, "amir-pilot").await.unwrap();
    let session = f.session("amir@sawmills.ai").await;
    let page = f
        .get(&format!("/accounts/manage?account={id}"), Some(&session))
        .await;
    assert_eq!(page.status().as_u16(), 200);
    assert_eq!(page.headers()["cache-control"], "no-store");
    let page = page.text().await.unwrap();
    let csrf = hidden(&page, "csrf");
    let origin = f.origin.clone();
    let remove = |csrf: String, origin: Option<String>| {
        let (f, session, id) = (&f, session.clone(), id.clone());
        async move {
            f.post_form(
                "/accounts/remove",
                &session,
                origin.as_deref(),
                &[("csrf", &csrf), ("account", &id), ("confirm", "amir-pilot")],
            )
            .await
        }
    };
    for (csrf, origin) in [
        ("wrong".to_owned(), Some(origin.clone())),
        (String::new(), Some(origin.clone())),
        (csrf.clone(), None),
        (csrf.clone(), Some("https://evil.example".to_owned())),
    ] {
        let response = remove(csrf, origin).await;
        assert_eq!(response.status().as_u16(), 403);
    }
    assert!(f.account_id(&amir, "amir-pilot").await.is_some());
}

#[tokio::test]
async fn remove_needs_the_exact_name_shows_the_machines_and_is_audited() {
    let f = Fixture::new().await;
    let amir = f.user_id("amir@sawmills.ai");
    f.seed(&amir, "amir-pilot").await;
    let id = f.account_id(&amir, "amir-pilot").await.unwrap();
    let session = f.session("amir@sawmills.ai").await;
    f.machine(&amir, "laptop-0123456789ab").await;
    let page = f
        .get(&format!("/accounts/manage?account={id}"), Some(&session))
        .await
        .text()
        .await
        .unwrap();
    // The page says who loses the account before anything is removed.
    assert!(page.contains("1 connected machine"), "{page}");
    assert!(page.contains(r#"autocomplete="off""#), "{page}");
    let csrf = hidden(&page, "csrf");
    let origin = Some(f.origin.as_str());
    for typed in ["AMIR-PILOT", "amir", ""] {
        let response = f
            .post_form(
                "/accounts/remove",
                &session,
                origin,
                &[("csrf", &csrf), ("account", &id), ("confirm", typed)],
            )
            .await;
        assert_eq!(response.status().as_u16(), 400, "{typed:?}");
    }
    assert!(f.account_id(&amir, "amir-pilot").await.is_some());
    let response = f
        .post_form(
            "/accounts/remove",
            &session,
            origin,
            &[("csrf", &csrf), ("account", &id), ("confirm", "amir-pilot")],
        )
        .await;
    assert_eq!(response.status().as_u16(), 303);
    assert_eq!(response.headers()["location"], "/accounts?done=removed");
    assert!(f.account_id(&amir, "amir-pilot").await.is_none());
    let audit = f.audit_lines().await;
    let line = audit.last().unwrap();
    assert_eq!(line["operation"], "account_remove", "{line}");
    assert_eq!(line["actor"], "dashboard:amir@sawmills.ai", "{line}");
    assert_eq!(line["account"], id.as_str(), "{line}");
    let done = f
        .get("/accounts?done=removed", Some(&session))
        .await
        .text()
        .await
        .unwrap();
    assert!(done.contains("Account removed"), "{done}");
}

#[tokio::test]
async fn another_users_account_or_machine_is_not_found() {
    let f = Fixture::new().await;
    let amir = f.user_id("amir@sawmills.ai");
    f.seed(&amir, "amir-pilot").await;
    f.seed("someone-else", "not-yours").await;
    let store = f.server.store();
    store
        .record_user("someone-else", "other@sawmills.ai")
        .await
        .unwrap();
    let (foreign, _) = claudectl::server::app::register(store, "other@sawmills.ai", "foreign-box")
        .await
        .unwrap();
    let theirs = f.account_id("someone-else", "not-yours").await.unwrap();
    let session = f.session("amir@sawmills.ai").await;
    let page = f
        .get("/accounts/add", Some(&session))
        .await
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    let origin = Some(f.origin.as_str());
    let response = f
        .post_form(
            "/accounts/remove",
            &session,
            origin,
            &[
                ("csrf", &csrf),
                ("account", &theirs),
                ("confirm", "not-yours"),
            ],
        )
        .await;
    assert_eq!(response.status().as_u16(), 404);
    assert!(f.account_id("someone-else", "not-yours").await.is_some());
    let response = f
        .post_form(
            "/machines/revoke",
            &session,
            origin,
            &[("csrf", &csrf), ("machine", &foreign)],
        )
        .await;
    assert_eq!(response.status().as_u16(), 404);
    let manage = f
        .get(
            &format!("/accounts/manage?account={theirs}"),
            Some(&session),
        )
        .await;
    assert_eq!(manage.status().as_u16(), 404);
}

#[tokio::test]
async fn revoke_ends_a_machine_of_this_user_and_is_audited() {
    let f = Fixture::new().await;
    let session = f.session("amir@sawmills.ai").await;
    let amir = f.user_id("amir@sawmills.ai");
    let laptop = "laptop-0123456789ab".to_string();
    f.machine(&amir, &laptop).await;
    let page = f
        .get("/accounts", Some(&session))
        .await
        .text()
        .await
        .unwrap();
    assert!(page.contains(r#"action="/machines/revoke""#), "{page}");
    let csrf = hidden(&page, "csrf");
    let response = f
        .post_form(
            "/machines/revoke",
            &session,
            Some(&f.origin),
            &[("csrf", &csrf), ("machine", &laptop)],
        )
        .await;
    assert_eq!(response.status().as_u16(), 303);
    assert_eq!(response.headers()["location"], "/accounts?done=revoked");
    let machines = f.server.store().machines(&amir).await.unwrap();
    assert!(machines.iter().any(|m| m.id == laptop && m.revoked));
    let audit = f.audit_lines().await;
    // A second submit (back button, double click) changes nothing and writes no audit line.
    let again = f
        .post_form(
            "/machines/revoke",
            &session,
            Some(&f.origin),
            &[("csrf", &csrf), ("machine", &laptop)],
        )
        .await;
    assert_eq!(again.status().as_u16(), 409);
    assert_eq!(f.audit_lines().await.len(), audit.len());
    let line = audit.last().unwrap().clone();
    assert_eq!(line["operation"], "machine_revoke", "{line}");
    assert_eq!(line["actor"], "dashboard:amir@sawmills.ai", "{line}");
    assert_eq!(line["target"], laptop.as_str(), "{line}");
}

#[tokio::test]
async fn add_and_renew_open_a_new_sign_in_with_a_private_paste_field() {
    let f = Fixture::new().await;
    let amir = f.user_id("amir@sawmills.ai");
    f.seed(&amir, "amir-pilot").await;
    let id = f.account_id(&amir, "amir-pilot").await.unwrap();
    let session = f.session("amir@sawmills.ai").await;
    let page = f.get("/accounts/add", Some(&session)).await;
    assert_eq!(page.status().as_u16(), 200);
    let csrf = hidden(&page.text().await.unwrap(), "csrf");
    let origin = Some(f.origin.as_str());
    for (path, form) in [
        (
            "/accounts/add",
            [("csrf", csrf.as_str()), ("alias", "amir-new")],
        ),
        (
            "/accounts/renew",
            [("csrf", csrf.as_str()), ("account", id.as_str())],
        ),
    ] {
        let response = f.post_form(path, &session, origin, &form).await;
        assert_eq!(response.status().as_u16(), 200, "{path}");
        assert_eq!(response.headers()["cache-control"], "no-store", "{path}");
        let body = response.text().await.unwrap();
        assert!(
            body.contains("https://claude.com/cai/oauth/authorize?"),
            "{path}: {body}"
        );
        assert!(body.contains(r#"name="code""#), "{path}: {body}");
        assert!(body.contains(r#"autocomplete="off""#), "{path}: {body}");
        assert!(
            body.contains(r#"action="/accounts/login""#),
            "{path}: {body}"
        );
        // The sign-in belongs to the dashboard: a machine cannot finish it.
        let login = hidden(&body, "login");
        let Err(error) = f
            .server
            .engine()
            .finish_login(&amir, "laptop-0123456789ab", &login, "code#state")
            .await
        else {
            panic!("a machine finished a dashboard sign-in");
        };
        assert!(
            format!("{error:#}").contains("does not belong"),
            "{error:#}"
        );
        // A paste of another sign-in is refused, and nothing is added.
        let response = f
            .post_form(
                "/accounts/login",
                &session,
                origin,
                &[
                    ("csrf", &csrf),
                    ("login", &login),
                    ("code", "secret-code#other"),
                ],
            )
            .await;
        assert!(response.status().is_client_error(), "{path}");
        let text = response.text().await.unwrap();
        assert!(!text.contains("secret-code"), "{text}");
    }
    assert!(f.account_id(&amir, "amir-new").await.is_none());
    // Renew of an account that is not this user's is not found.
    let response = f
        .post_form(
            "/accounts/renew",
            &session,
            origin,
            &[("csrf", &csrf), ("account", &"0".repeat(64))],
        )
        .await;
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn overlapping_revokes_change_and_audit_the_machine_once() {
    let f = Fixture::new().await;
    let session = f.session("amir@sawmills.ai").await;
    let amir = f.user_id("amir@sawmills.ai");
    let laptop = "laptop-0123456789ab".to_string();
    f.machine(&amir, &laptop).await;
    let page = f
        .get("/accounts", Some(&session))
        .await
        .text()
        .await
        .unwrap();
    let csrf = hidden(&page, "csrf");
    let before = f.audit_lines().await.len();
    let mut requests = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let (http, origin, session) = (f.http.clone(), f.origin.clone(), session.clone());
        let form = [("csrf", csrf.clone()), ("machine", laptop.clone())];
        requests.spawn(async move {
            http.post(format!("{origin}/machines/revoke"))
                .header("accept", BROWSER)
                .header("cookie", session)
                .header("origin", origin)
                .form(&form)
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        });
    }
    let mut codes = requests.join_all().await;
    // The contract under the handler: one atomic active-to-revoked change, reported once.
    let other = "desk-0123456789ab";
    f.machine(&amir, other).await;
    let store = f.server.store();
    assert!(store.revoke_active_machine(other, &amir).await.unwrap());
    assert!(!store.revoke_active_machine(other, &amir).await.unwrap());
    assert!(
        !store
            .revoke_active_machine(other, "someone-else")
            .await
            .unwrap()
    );
    codes.sort_unstable();
    assert_eq!(codes, [303, 409, 409, 409, 409, 409, 409, 409]);
    let audit = f.audit_lines().await;
    let revokes = audit[before..]
        .iter()
        .filter(|l| l["operation"] == "machine_revoke")
        .count();
    assert_eq!(revokes, 1, "{audit:?}");
}

/// Every Google sign-in the provider answered leaves one audit line: who, when, result and
/// the refusal reason. Noise before the provider (another browser's callback) does not.
#[tokio::test]
async fn every_answered_google_sign_in_is_audited() {
    let f = Fixture::new().await;
    // Dashboard: one success, one personal account refused, one foreign-browser callback.
    f.session("amir@sawmills.ai").await;
    let refused = f
        .dashboard_callback(Token::new("someone@gmail.com", None), None)
        .await;
    assert_eq!(refused.status().as_u16(), 403);
    let foreign = f
        .dashboard_callback(
            Token::new("amir@sawmills.ai", Some("sawmills.ai")),
            Some("claudectl-login=another-browser"),
        )
        .await;
    assert_eq!(foreign.status().as_u16(), 401);
    // Machine enrollment: one success, one company user not on the allow list.
    let (status, body) = f
        .callback(Token::new("amir@sawmills.ai", Some("sawmills.ai")))
        .await;
    assert_eq!(status, 200, "{body}");
    let (status, body) = f
        .callback(Token::new("other@sawmills.ai", Some("sawmills.ai")))
        .await;
    assert_eq!(status, 403, "{body}");

    let lines: Vec<Value> = f
        .audit_lines()
        .await
        .into_iter()
        .filter(|l| {
            l["operation"]
                .as_str()
                .is_some_and(|o| o.ends_with("_sign_in"))
        })
        .collect();
    let find = |operation: &str, result: &str| {
        lines
            .iter()
            .find(|l| l["operation"] == operation && l["result"] == result)
            .unwrap_or_else(|| panic!("no {operation} {result} in {lines:?}"))
            .clone()
    };
    let ok = find("dashboard_sign_in", "ok");
    assert_eq!(ok["actor"], "dashboard:amir@sawmills.ai", "{ok}");
    assert!(ok["at"].is_string(), "{ok}");
    let no = find("dashboard_sign_in", "refused");
    assert_eq!(no["reason"], "company_identity_required", "{no}");
    let ok = find("enroll_sign_in", "ok");
    assert_eq!(ok["actor"], "enrollment:amir@sawmills.ai", "{ok}");
    let no = find("enroll_sign_in", "refused");
    assert_eq!(no["reason"], "user_not_allowed", "{no}");
    // The foreign-browser callback never reached the provider: no line for it.
    assert_eq!(lines.len(), 4, "{lines:?}");
    // No secret from the sign-in reaches the audit log.
    for line in &lines {
        let text = line.to_string();
        for secret in ["\"c\"", "test-secret", "id_token"] {
            assert!(!text.contains(secret), "{text}");
        }
    }
}
