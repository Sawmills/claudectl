#![cfg(feature = "server")]
//! Company SSO against a synthetic OIDC issuer that signs real RS256 ID tokens. The
//! authorization URL always carries the `hd` hint; the server must decide on the signed
//! `hd` claim alone. No real Google account or credential.
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

/// A throwaway PKCS#1 RSA key from the system OpenSSL; nothing is committed.
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
        .expect("openssl genrsa")
}

#[derive(Clone)]
struct Issuer {
    origin: String,
    key: Arc<CoreRsaPrivateSigningKey>,
    /// The ID token the next token request returns.
    next: Arc<Mutex<Option<String>>>,
}
impl Issuer {
    /// Sign an ID token for `email` with this `hd` and the nonce of the pending login.
    fn prepare(&self, nonce: &str, email: &str, hd: Option<&str>) {
        let now = chrono::Utc::now();
        let claims = Claims::new(
            IssuerUrl::new(self.origin.clone()).unwrap(),
            vec![Audience::new("test-client".into())],
            now + chrono::Duration::minutes(5),
            now,
            StandardClaims::new(SubjectIdentifier::new(format!("sub-{email}")))
                .set_email(Some(EndUserEmail::new(email.into())))
                .set_email_verified(Some(true)),
            Hd {
                hd: hd.map(str::to_owned),
            },
        )
        .set_nonce(Some(Nonce::new(nonce.into())));
        let token = IdToken::new(
            claims,
            self.key.as_ref(),
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
    let key = CoreRsaPrivateSigningKey::from_pem(&rsa_pem(), Some(JsonWebKeyId::new("k1".into())))
        .unwrap();
    let issuer = Issuer {
        origin: origin.clone(),
        key: Arc::new(key),
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
                api: "http://127.0.0.1:9".into(),
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
    /// Complete the callback with an ID token for `email` and `hd`: (status, body).
    async fn callback(&self, email: &str, hd: Option<&str>) -> (u16, String) {
        let query = self.sign_in().await;
        // The hint asks Google for the company account chooser; it is not a decision.
        assert_eq!(query.get("hd").map(String::as_str), Some("sawmills.ai"));
        self.issuer.prepare(&query["nonce"], email, hd);
        let response = self
            .http
            .get(format!("{}/auth/callback", self.origin))
            .query(&[("state", query["state"].as_str()), ("code", "c")])
            .send()
            .await
            .unwrap();
        (response.status().as_u16(), response.text().await.unwrap())
    }
    async fn users(&self) -> usize {
        self.server.store().users().await.unwrap().len()
    }
}

#[tokio::test]
async fn a_signed_company_hd_claim_reaches_approval() {
    let f = Fixture::new().await;
    let (status, body) = f.callback("amir@sawmills.ai", Some("sawmills.ai")).await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_token_without_the_company_hd_claim_is_refused_despite_the_url_hint() {
    let f = Fixture::new().await;
    let before = f.users().await;
    // A personal Gmail account: no hd claim.
    let (status, body) = f.callback("someone@gmail.com", None).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("company_identity_required"), "{body}");
    // A company-looking address on an account outside the Workspace: no hd claim.
    let (status, body) = f.callback("amir@sawmills.ai", None).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("company_identity_required"), "{body}");
    // Another Workspace: the URL hint said sawmills.ai, the signed claim decides.
    let (status, body) = f.callback("amir@sawmills.ai", Some("example.com")).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("company_identity_required"), "{body}");
    assert_eq!(f.users().await, before, "a refused sign-in created a user");
}
