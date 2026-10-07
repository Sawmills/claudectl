//! Company OIDC sign-in around a machine device-code flow. Every step's state lives in the
//! store and is consumed once, so start, poll, callback, and approve may reach any replica.
use super::{
    app::{self, HttpError, Server},
    store::EnrollmentRow,
    vault,
};
use anyhow::{Result, bail};
use axum::{
    Form, Json, Router,
    extract::{Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    core::{CoreAuthenticationFlow, CoreProviderMetadata},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc, time::Duration};
use vault::secret;

// Keep provider extension claims inside the library's signature, issuer, and nonce checks.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CompanyClaims {
    #[serde(default)]
    hd: Option<String>,
}
impl openidconnect::AdditionalClaims for CompanyClaims {}
type CompanyTokenResponse = openidconnect::StandardTokenResponse<
    openidconnect::IdTokenFields<
        CompanyClaims,
        openidconnect::EmptyExtraTokenFields,
        openidconnect::core::CoreGenderClaim,
        openidconnect::core::CoreJweContentEncryptionAlgorithm,
        openidconnect::core::CoreJwsSigningAlgorithm,
    >,
    openidconnect::core::CoreTokenType,
>;
type CompanyClient = openidconnect::Client<
    CompanyClaims,
    openidconnect::core::CoreAuthDisplay,
    openidconnect::core::CoreGenderClaim,
    openidconnect::core::CoreJweContentEncryptionAlgorithm,
    openidconnect::core::CoreJsonWebKey,
    openidconnect::core::CoreAuthPrompt,
    openidconnect::StandardErrorResponse<openidconnect::core::CoreErrorResponseType>,
    CompanyTokenResponse,
    openidconnect::core::CoreTokenIntrospectionResponse,
    openidconnect::core::CoreRevocableToken,
    openidconnect::core::CoreRevocationErrorResponse,
    openidconnect::EndpointSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointNotSet,
    openidconnect::EndpointMaybeSet,
    openidconnect::EndpointMaybeSet,
>;
const GOOGLE_ISSUER: &str = "https://accounts.google.com";
const TTL_MS: i64 = 300_000;

type Shared = State<Arc<Server>>;

fn now() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    issuer: String,
    client_id: String,
    client_secret_file: std::path::PathBuf,
    allowed_domains: Vec<String>,
    /// Google Workspace `hd` values to require. Defaults to `allowed_domains` for Google.
    #[serde(default)]
    allowed_hosted_domains: Option<Vec<String>>,
}
impl Configuration {
    /// The company email of a verified sign-in, or `None`. The email must be verified and in
    /// an allowed domain; for Google the ID token's `hd` (Workspace) claim must also match,
    /// so a personal or External-audience account with a matching address is refused.
    fn company_email<'a>(
        &self,
        email: Option<&'a str>,
        verified: Option<bool>,
        hd: Option<&str>,
    ) -> Option<&'a str> {
        let email = email.filter(|_| verified == Some(true))?;
        let (_, domain) = email.rsplit_once('@')?;
        if !self
            .allowed_domains
            .iter()
            .any(|d| d.eq_ignore_ascii_case(domain))
        {
            return None;
        }
        if let Some(domains) = self.hosted_domains()
            && !hd.is_some_and(|hd| domains.iter().any(|d| d.eq_ignore_ascii_case(hd)))
        {
            return None;
        }
        Some(email)
    }
    fn hosted_domains(&self) -> Option<&[String]> {
        self.allowed_hosted_domains
            .as_deref()
            .or_else(|| (self.issuer == GOOGLE_ISSUER).then_some(self.allowed_domains.as_slice()))
    }
}
/// A machine waiting for approval; `grant` is set once a person approves it.
#[derive(Serialize, Deserialize)]
struct Device {
    name: String,
    last_poll: Option<i64>,
    grant: Option<String>,
}
/// A browser sign-in in progress for one device.
#[derive(Serialize, Deserialize)]
struct SsoLogin {
    device: String,
    nonce: String,
    verifier: String,
}
/// A signed-in person who may approve one device.
#[derive(Serialize, Deserialize)]
struct Approval {
    device: String,
    user: String,
    email: String,
}

pub struct Sso {
    config: Configuration,
    public_url: String,
    http: reqwest::Client,
    client_secret: String,
}
impl Sso {
    pub async fn load(path: &Path, public_url: &str) -> Result<Self> {
        let config: Configuration = serde_json::from_slice(&std::fs::read(path)?)?;
        if config.allowed_domains.is_empty()
            || config
                .allowed_domains
                .iter()
                .any(|d| d.is_empty() || d.contains('@'))
        {
            bail!("SSO requires allowed company email domains");
        }
        let issuer = reqwest::Url::parse(&config.issuer)?;
        if issuer.scheme() != "https"
            && !(issuer.scheme() == "http"
                && issuer.host_str() == Some("127.0.0.1")
                && reqwest::Url::parse(public_url)?.scheme() == "http")
        {
            bail!("SSO issuer must use HTTPS");
        }
        let client_secret = String::from_utf8(vault::private_read(&config.client_secret_file)?)?;
        if client_secret.trim().is_empty() {
            bail!("SSO client secret is empty");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        let result = Self {
            config,
            public_url: public_url.trim_end_matches('/').into(),
            http,
            client_secret,
        };
        result.metadata().await?;
        Ok(result)
    }
    async fn metadata(&self) -> Result<CoreProviderMetadata> {
        let metadata = CoreProviderMetadata::discover_async(
            IssuerUrl::new(self.config.issuer.clone())?,
            &self.http,
        )
        .await
        .map_err(|_| anyhow::anyhow!("company SSO discovery failed"))?;
        let insecure = metadata.authorization_endpoint().url().scheme() != "https"
            || metadata
                .token_endpoint()
                .is_none_or(|u| u.url().scheme() != "https")
            || metadata.jwks_uri().url().scheme() != "https";
        if insecure && reqwest::Url::parse(&self.public_url)?.scheme() != "http" {
            bail!("company SSO endpoints require HTTPS");
        }
        Ok(metadata)
    }
    async fn client(&self) -> Result<CompanyClient> {
        Ok(CompanyClient::from_provider_metadata(
            self.metadata().await?,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.client_secret.trim().into())),
        )
        .set_redirect_uri(RedirectUrl::new(format!(
            "{}/auth/callback",
            self.public_url
        ))?))
    }
}
fn sso(server: &Server) -> Result<&Sso, HttpError> {
    server
        .sso
        .as_ref()
        .ok_or_else(|| server.error(StatusCode::SERVICE_UNAVAILABLE, "sso_unavailable"))
}
fn page(html: String) -> Response {
    let styles = include_str!("enrollment/style.css");
    let style_hash = STANDARD.encode(Sha256::digest(styles.as_bytes()));
    let policy = format!(
        "default-src 'none'; style-src 'sha256-{style_hash}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    );
    let document = include_str!("enrollment/page.html")
        .replace("<!-- STYLES -->", &format!("<style>{styles}</style>"))
        .replace("<!-- CONTENT -->", &html);
    (
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
            ("content-security-policy", policy.as_str()),
            ("x-content-type-options", "nosniff"),
        ],
        Html(document),
    )
        .into_response()
}
/// Browser steps show a page for an error; API clients keep the JSON body and status.
async fn browser_errors(request: Request, next: Next) -> Response {
    let html = request
        .headers()
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"));
    let response = next.run(request).await;
    if !html || !(response.status().is_client_error() || response.status().is_server_error()) {
        return response;
    }
    let (parts, body) = response.into_parts();
    let reason = axum::body::to_bytes(body, 4096)
        .await
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["error"].as_str().map(String::from))
        .unwrap_or_default();
    let mut page = error_page(&reason);
    *page.status_mut() = parts.status;
    page.extensions_mut().extend(parts.extensions);
    page
}
fn error_page(reason: &str) -> Response {
    let (title, detail) = match reason {
        "company_identity_required" => (
            "Use your company account",
            "This sign-in is not a verified company account. Run <code>claudectl server connect</code> again and pick your work account.",
        ),
        "user_not_allowed" | "user_unavailable" => (
            "No access to this server",
            "Your account is not on this server's allow list. Ask your admin for access.",
        ),
        "sso_denied" => (
            "Sign-in did not finish",
            "Your company sign-in did not confirm who you are. Run <code>claudectl server connect</code> again.",
        ),
        "enrollment_expired" | "invalid_sso_state" | "invalid_approval" => (
            "This link has expired",
            "Each link works once and only for five minutes. Run <code>claudectl server connect</code> again for a new link.",
        ),
        _ => (
            "Something went wrong",
            "The server could not finish this step. Wait a minute, then run <code>claudectl server connect</code> again.",
        ),
    };
    page(format!(
        include_str!("enrollment/error.html"),
        title = title,
        detail = detail
    ))
}
fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
impl Server {
    fn seal_row<T: Serialize>(
        &self,
        value: &T,
        lookup: Option<String>,
    ) -> Result<EnrollmentRow, HttpError> {
        Ok(EnrollmentRow {
            lookup,
            sealed: self.seal(value).map_err(|_| self.unavailable())?,
            expires_at: now() + TTL_MS,
            consumed: false,
        })
    }
    fn unavailable(&self) -> HttpError {
        self.error(StatusCode::SERVICE_UNAVAILABLE, "registry_unavailable")
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Start {
    pub name: String,
    /// Clients send `["anthropic"]`; this server serves nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<String>>,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    pub device_code: String,
    pub user_code: String,
    pub verification_url: String,
    pub expires_in: u64,
    pub interval: u64,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Poll {
    pub device_code: String,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Grant {
    pub device_token: String,
}
async fn start(State(server): Shared, Json(input): Json<Start>) -> Result<Response, HttpError> {
    let sso = sso(&server)?;
    if input.name.is_empty() || input.name.len() > 80 || input.name.chars().any(char::is_control) {
        return Err(server.error(StatusCode::BAD_REQUEST, "invalid_device_name"));
    }
    if input
        .providers
        .as_ref()
        .is_some_and(|p| p.iter().map(String::as_str).ne(["anthropic"]))
    {
        return Err(server.error(StatusCode::BAD_REQUEST, "provider_not_enabled"));
    }
    let device_code = secret();
    let user_code = secret()[..16].to_uppercase();
    let device = Device {
        name: input.name,
        last_poll: None,
        grant: None,
    };
    let row = server.seal_row(&device, Some(user_code.clone()))?;
    server
        .store()
        .put_enrollment("device", &vault::digest(device_code.as_bytes()), &row)
        .await
        .map_err(|_| server.unavailable())?;
    Ok((
        [("cache-control", "no-store")],
        Json(Challenge {
            verification_url: format!("{}/enroll?code={user_code}", sso.public_url),
            device_code,
            user_code,
            expires_in: 300,
            interval: 3,
        }),
    )
        .into_response())
}
async fn poll(State(server): Shared, Json(input): Json<Poll>) -> Result<Response, HttpError> {
    sso(&server)?;
    let key = vault::digest(input.device_code.as_bytes());
    let store = server.store();
    let row = store
        .enrollment("device", &key, now())
        .await
        .map_err(|_| server.unavailable())?
        .filter(|r| !r.consumed)
        .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
    let mut device: Device = server
        .unseal(&row.sealed)
        .map_err(|_| server.unavailable())?;
    if device.last_poll.is_some_and(|t| now() - t < 3_000) {
        return Err(server.error(StatusCode::TOO_MANY_REQUESTS, "slow_down"));
    }
    if device.grant.is_none() {
        device.last_poll = Some(now());
        let sealed = server.seal(&device).map_err(|_| server.unavailable())?;
        // Compare-and-swap: an approval that landed meanwhile is never overwritten. The next
        // poll then finds the grant.
        store
            .swap_enrollment("device", &key, &row.sealed, &sealed)
            .await
            .map_err(|_| server.unavailable())?;
        return Ok((StatusCode::ACCEPTED, Json(json!({"status":"pending"}))).into_response());
    }
    // Hand the machine token out exactly once, whichever replica answers.
    let row = store
        .consume_enrollment("device", &key, now())
        .await
        .map_err(|_| server.unavailable())?
        .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
    let device: Device = server
        .unseal(&row.sealed)
        .map_err(|_| server.unavailable())?;
    let token = device
        .grant
        .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
    Ok((
        [("cache-control", "no-store")],
        Json(Grant {
            device_token: token,
        }),
    )
        .into_response())
}
#[derive(Deserialize)]
struct Verify {
    code: String,
}
async fn verify(State(server): Shared, Query(input): Query<Verify>) -> Result<Response, HttpError> {
    let sso = sso(&server)?;
    let (device, row) = server
        .store()
        .find_enrollment("device", &input.code, now())
        .await
        .map_err(|_| server.unavailable())?
        .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
    let pending: Device = server
        .unseal(&row.sealed)
        .map_err(|_| server.unavailable())?;
    if pending.grant.is_some() {
        return Err(server.error(StatusCode::GONE, "enrollment_expired"));
    }
    let client = sso
        .client()
        .await
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "sso_unavailable"))?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut authorization = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .set_pkce_challenge(challenge);
    if let Some(domains) = sso.config.hosted_domains() {
        // This affects Google's account chooser only. The signed claim is enforced below.
        let hint = if domains.len() == 1 {
            domains[0].as_str()
        } else {
            "*"
        };
        authorization = authorization.add_extra_param("hd", hint);
    }
    let (url, state, nonce) = authorization.url();
    let login = SsoLogin {
        device,
        nonce: nonce.secret().clone(),
        verifier: verifier.secret().clone(),
    };
    let row = server.seal_row(&login, None)?;
    server
        .store()
        .put_enrollment("sso", &vault::digest(state.secret().as_bytes()), &row)
        .await
        .map_err(|_| server.unavailable())?;
    Ok((
        [
            ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"),
        ],
        Redirect::to(url.as_str()),
    )
        .into_response())
}
#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
}
async fn callback(
    State(server): Shared,
    Query(input): Query<Callback>,
) -> Result<Response, HttpError> {
    let sso = sso(&server)?;
    let denied = || server.error(StatusCode::UNAUTHORIZED, "sso_denied");
    // The SSO state works once, on any replica.
    let row = server
        .store()
        .consume_enrollment("sso", &vault::digest(input.state.as_bytes()), now())
        .await
        .map_err(|_| server.unavailable())?
        .ok_or_else(|| server.error(StatusCode::BAD_REQUEST, "invalid_sso_state"))?;
    let login: SsoLogin = server
        .unseal(&row.sealed)
        .map_err(|_| server.unavailable())?;
    let code = input.code.ok_or_else(denied)?;
    let client = sso
        .client()
        .await
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "sso_unavailable"))?;
    let tokens = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "sso_unavailable"))?
        .set_pkce_verifier(PkceCodeVerifier::new(login.verifier))
        .request_async(&sso.http)
        .await
        .map_err(|_| denied())?;
    // The verifier checks signature, issuer, audience, expiry, and nonce.
    let verifier = client.id_token_verifier();
    let id = tokens.extra_fields().id_token().ok_or_else(denied)?;
    let claims = id
        .claims(&verifier, &Nonce::new(login.nonce))
        .map_err(|_| denied())?;
    if let Some(expected) = claims.access_token_hash() {
        let actual = AccessTokenHash::from_token(
            tokens.access_token(),
            id.signing_alg().map_err(|_| denied())?,
            id.signing_key(&verifier).map_err(|_| denied())?,
        )
        .map_err(|_| denied())?;
        if actual != *expected {
            return Err(denied());
        }
    }
    let refused = || server.error(StatusCode::FORBIDDEN, "company_identity_required");
    let email = sso
        .config
        .company_email(
            claims.email().map(|e| e.as_str()),
            claims.email_verified(),
            claims.additional_claims().hd.as_deref(),
        )
        .ok_or_else(refused)?;
    if !server.allowed(email) {
        return Err(server.error(StatusCode::FORBIDDEN, "user_not_allowed"));
    }
    // Users key on (issuer, subject); an email change keeps the same user.
    let user =
        vault::digest(format!("{}\0{}", sso.config.issuer, claims.subject().as_str()).as_bytes());
    let device = server
        .store()
        .enrollment("device", &login.device, now())
        .await
        .map_err(|_| server.unavailable())?
        .filter(|r| !r.consumed)
        .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
    let lookup = device.lookup.clone().unwrap_or_default();
    let pending: Device = server
        .unseal(&device.sealed)
        .map_err(|_| server.unavailable())?;
    let approval = secret();
    let html = format!(
        include_str!("enrollment/approval.html"),
        email = escape(email),
        name = escape(&pending.name),
        code = escape(&lookup),
        approval = approval,
    );
    let row = server.seal_row(
        &Approval {
            device: login.device,
            user,
            email: email.into(),
        },
        None,
    )?;
    server
        .store()
        .put_enrollment("approval", &vault::digest(approval.as_bytes()), &row)
        .await
        .map_err(|_| server.unavailable())?;
    Ok(page(html))
}
#[derive(Deserialize)]
struct Approve {
    approval: String,
}
async fn approve(State(server): Shared, Form(input): Form<Approve>) -> Result<Response, HttpError> {
    sso(&server)?;
    let store = server.store();
    let row = store
        .consume_enrollment("approval", &vault::digest(input.approval.as_bytes()), now())
        .await
        .map_err(|_| server.unavailable())?
        .ok_or_else(|| server.error(StatusCode::BAD_REQUEST, "invalid_approval"))?;
    let approval: Approval = server
        .unseal(&row.sealed)
        .map_err(|_| server.unavailable())?;
    let device_row = store
        .enrollment("device", &approval.device, now())
        .await
        .map_err(|_| server.unavailable())?
        .filter(|r| !r.consumed)
        .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
    let mut device: Device = server
        .unseal(&device_row.sealed)
        .map_err(|_| server.unavailable())?;
    if device.grant.is_some() {
        return Err(server.error(StatusCode::GONE, "enrollment_expired"));
    }
    if !store
        .record_user(&approval.user, &approval.email)
        .await
        .map_err(|_| server.unavailable())?
    {
        return Err(server.error(StatusCode::FORBIDDEN, "user_unavailable"));
    }
    let (_, token) = app::add_machine(store, &approval.user, &device.name)
        .await
        .map_err(|_| server.error(StatusCode::SERVICE_UNAVAILABLE, "persistence_failed"))?;
    // A poll may have rewritten the row since it was read; retry against the fresh copy.
    let mut current = device_row.sealed;
    for _ in 0..5 {
        device.grant = Some(token.clone());
        let sealed = server.seal(&device).map_err(|_| server.unavailable())?;
        if store
            .swap_enrollment("device", &approval.device, &current, &sealed)
            .await
            .map_err(|_| server.unavailable())?
        {
            return Ok(page(include_str!("enrollment/connected.html").into()));
        }
        let fresh = store
            .enrollment("device", &approval.device, now())
            .await
            .map_err(|_| server.unavailable())?
            .filter(|r| !r.consumed)
            .ok_or_else(|| server.error(StatusCode::GONE, "enrollment_expired"))?;
        device = server
            .unseal(&fresh.sealed)
            .map_err(|_| server.unavailable())?;
        if device.grant.is_some() {
            return Err(server.error(StatusCode::GONE, "enrollment_expired"));
        }
        current = fresh.sealed;
    }
    Err(server.error(StatusCode::SERVICE_UNAVAILABLE, "registry_busy"))
}
pub(super) fn routes(router: Router<Arc<Server>>) -> Router<Arc<Server>> {
    router
        .route("/v1/enrollment/start", post(start))
        .route("/v1/enrollment/poll", post(poll))
        .merge(
            Router::new()
                .route("/enroll", get(verify))
                .route("/auth/callback", get(callback))
                .route("/auth/approve", post(approve))
                .route_layer(middleware::from_fn(browser_errors)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn google(hosted: Option<Vec<String>>) -> Configuration {
        Configuration {
            issuer: GOOGLE_ISSUER.into(),
            client_id: "client".into(),
            client_secret_file: "/dev/null".into(),
            allowed_domains: vec!["sawmills.ai".into()],
            allowed_hosted_domains: hosted,
        }
    }

    #[test]
    fn google_sign_in_requires_the_company_hd_claim_not_only_the_email_domain() {
        for config in [google(None), google(Some(vec!["sawmills.ai".into()]))] {
            let ok = |hd| config.company_email(Some("amir@sawmills.ai"), Some(true), hd);
            assert_eq!(ok(Some("sawmills.ai")), Some("amir@sawmills.ai"));
            assert_eq!(ok(Some("SAWMILLS.AI")), Some("amir@sawmills.ai"));
            // A company email from an External-audience client without the Workspace claim.
            assert_eq!(ok(None), None);
            assert_eq!(ok(Some("example.com")), None);
            assert_eq!(ok(Some("")), None);
        }
    }

    #[test]
    fn google_sign_in_also_requires_a_verified_company_email() {
        let config = google(None);
        let check = |email, verified| config.company_email(email, verified, Some("sawmills.ai"));
        assert_eq!(check(Some("amir@example.com"), Some(true)), None);
        assert_eq!(check(Some("amir@sawmills.ai"), Some(false)), None);
        assert_eq!(check(Some("amir@sawmills.ai"), None), None);
        assert_eq!(check(None, Some(true)), None);
    }

    #[test]
    fn an_empty_hosted_domain_list_refuses_every_google_sign_in() {
        let config = google(Some(vec![]));
        assert_eq!(
            config.company_email(Some("amir@sawmills.ai"), Some(true), Some("sawmills.ai")),
            None
        );
    }
}
