use anyhow::{Context, Result, bail};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::api::{CLIENT_ID, OauthCreds, TOKEN_URL};

pub const AUTHORIZE_URL: &str = "https://claude.ai/oauth/authorize";
pub const REDIRECT_URI: &str = "https://console.anthropic.com/oauth/code/callback";
pub const SCOPES: &str = "org:create_api_key user:profile user:inference";

pub struct PkcePair {
    pub verifier: String,
    pub challenge: String,
}

pub fn generate_pkce() -> PkcePair {
    let mut bytes = [0u8; 64];
    rand::rng().fill_bytes(&mut bytes);
    let verifier = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    PkcePair {
        challenge: challenge_for(&verifier),
        verifier,
    }
}

/// RFC 7636 S256: BASE64URL-ENCODE(SHA256(ASCII(verifier))), no padding.
pub fn challenge_for(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

pub fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn build_authorize_url(challenge: &str, state: &str) -> String {
    format!(
        "{AUTHORIZE_URL}?code=true&client_id={CLIENT_ID}&response_type=code&redirect_uri={}&scope={}&code_challenge={challenge}&code_challenge_method=S256&state={state}",
        urlencoding::encode(REDIRECT_URI),
        urlencoding::encode(SCOPES),
    )
}

/// Split the pasted "code#state" string; a missing state falls back to ours.
pub fn parse_pasted_code<'a>(input: &'a str, fallback_state: &'a str) -> (&'a str, &'a str) {
    let input = input.trim();
    match input.split_once('#') {
        Some((code, state)) if !state.is_empty() => (code, state),
        Some((code, _)) => (code, fallback_state),
        None => (input, fallback_state),
    }
}

#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
}

pub fn exchange_code(code: &str, state: &str, verifier: &str) -> Result<OauthCreds> {
    let body = serde_json::json!({
        "grant_type": "authorization_code",
        "code": code,
        "state": state,
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    });
    let resp = reqwest::blocking::Client::new()
        .post(TOKEN_URL)
        .json(&body)
        .send()
        .context("failed to reach token endpoint")?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!(
            "token exchange failed ({status}): {}\nfallback: log in with 'claude /login', then run 'claudectl save <alias>'",
            text.trim()
        );
    }
    let token: TokenResponse =
        serde_json::from_str(&text).context("failed to parse token response")?;
    Ok(creds_from_token(
        token,
        chrono::Utc::now().timestamp_millis(),
    ))
}

fn creds_from_token(token: TokenResponse, now_ms: i64) -> OauthCreds {
    OauthCreds {
        access_token: token.access_token,
        refresh_token: token.refresh_token,
        expires_at: token.expires_in.map(|s| now_ms + s * 1000),
        scopes: token
            .scope
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        subscription_type: None,
        rate_limit_tier: None,
        extra: serde_json::Map::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_matches_rfc7636_vector() {
        assert_eq!(
            challenge_for("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn generated_pkce_is_consistent() {
        let pair = generate_pkce();
        assert_eq!(pair.challenge, challenge_for(&pair.verifier));
        assert!(pair.verifier.len() >= 43);
    }

    #[test]
    fn authorize_url_contains_required_params() {
        let url = build_authorize_url("CHAL", "STATE");
        assert!(url.starts_with("https://claude.ai/oauth/authorize?"));
        for needle in [
            "code=true",
            &format!("client_id={CLIENT_ID}"),
            "response_type=code",
            "redirect_uri=https%3A%2F%2Fconsole.anthropic.com%2Foauth%2Fcode%2Fcallback",
            "code_challenge=CHAL",
            "code_challenge_method=S256",
            "state=STATE",
            "scope=org%3Acreate_api_key%20user%3Aprofile%20user%3Ainference",
        ] {
            assert!(url.contains(needle), "missing {needle} in {url}");
        }
    }

    #[test]
    fn parse_pasted_code_splits_code_and_state() {
        assert_eq!(parse_pasted_code("abc#xyz", "fb"), ("abc", "xyz"));
        assert_eq!(parse_pasted_code(" abc ", "fb"), ("abc", "fb"));
        assert_eq!(parse_pasted_code("abc#", "fb"), ("abc", "fb"));
    }

    #[test]
    fn creds_from_token_computes_expiry() {
        let token = TokenResponse {
            access_token: "at".into(),
            refresh_token: Some("rt".into()),
            expires_in: Some(3600),
            scope: Some("user:profile user:inference".into()),
        };
        let creds = creds_from_token(token, 1_000_000);
        assert_eq!(creds.expires_at, Some(1_000_000 + 3_600_000));
        assert_eq!(creds.scopes, vec!["user:profile", "user:inference"]);
    }
}
