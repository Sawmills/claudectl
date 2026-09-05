use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const CLIENT_ID: &str = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
pub const TOKEN_URL: &str = "https://console.anthropic.com/v1/oauth/token";
pub const USAGE_URL: &str = "https://api.anthropic.com/api/oauth/usage";
pub const PROFILE_URL: &str = "https://api.anthropic.com/api/oauth/profile";
pub const OAUTH_BETA_HEADER: (&str, &str) = ("anthropic-beta", "oauth-2025-04-20");

/// The `claudeAiOauth` blob Claude Code stores in the macOS Keychain and
/// ~/.claude/.credentials.json. Tokens are opaque (not JWTs); expiry comes from
/// `expiresAt` (ms epoch). Unknown fields are preserved round-trip so claudectl
/// never drops data Claude Code wrote.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OauthCreds {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Milliseconds since epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscription_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_tier: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl OauthCreds {
    pub fn expiry_secs(&self) -> Option<i64> {
        self.expires_at.map(|ms| ms / 1000)
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at
            .is_some_and(|ms| ms < chrono::Utc::now().timestamp_millis())
    }
}

/// Full credential store payload: `{"claudeAiOauth": {...}}`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CredentialsFile {
    #[serde(rename = "claudeAiOauth")]
    pub claude_ai_oauth: OauthCreds,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize, Clone)]
pub struct UsageWindow {
    pub utilization: Option<f64>,
    pub resets_at: Option<String>,
}

impl UsageWindow {
    /// `resets_at` (RFC3339) as a unix timestamp.
    pub fn reset_timestamp(&self) -> Option<i64> {
        let s = self.resets_at.as_deref()?;
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.timestamp())
    }
}

/// Response of GET /api/oauth/usage. The endpoint also returns nullable
/// experiment fields we ignore; serde skips unknown keys by default.
#[derive(Deserialize, Clone, Default)]
pub struct UsageResponse {
    pub five_hour: Option<UsageWindow>,
    pub seven_day: Option<UsageWindow>,
    pub seven_day_opus: Option<UsageWindow>,
    pub seven_day_sonnet: Option<UsageWindow>,
    pub extra_usage: Option<ExtraUsage>,
}

#[derive(Deserialize, Clone)]
pub struct ExtraUsage {
    pub is_enabled: Option<bool>,
    pub used_credits: Option<f64>,
}

/// GET /api/oauth/usage with the OAuth bearer token.
pub async fn fetch_usage_async(
    client: &reqwest::Client,
    access_token: &str,
) -> Result<UsageResponse> {
    let resp = client
        .get(USAGE_URL)
        .bearer_auth(access_token)
        .header(OAUTH_BETA_HEADER.0, OAUTH_BETA_HEADER.1)
        .send()
        .await
        .context("failed to reach usage API")?;
    let status = resp.status();
    if !status.is_success() {
        bail!(usage_http_error(status, resp.headers(), chrono::Utc::now()));
    }
    resp.json().await.context("failed to parse usage response")
}

// Use only controlled messages and parsed headers. Response bodies can contain
// sensitive data and must never reach the status table.
fn usage_http_error(
    status: reqwest::StatusCode,
    headers: &reqwest::header::HeaderMap,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    match status {
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            let delay = headers
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| {
                    value.parse::<u64>().ok().or_else(|| {
                        chrono::DateTime::parse_from_rfc2822(value)
                            .ok()
                            .map(|date| (date.timestamp() - now.timestamp()).max(0) as u64)
                    })
                });
            match delay {
                Some(seconds) => format!("rate limited (HTTP 429); retry in {seconds}s"),
                None => "rate limited (HTTP 429); try again later".into(),
            }
        }
        reqwest::StatusCode::UNAUTHORIZED => "authentication rejected (HTTP 401)".into(),
        reqwest::StatusCode::FORBIDDEN => "access denied (HTTP 403)".into(),
        _ => format!("usage API error (HTTP {})", status.as_u16()),
    }
}

#[derive(Deserialize)]
struct TokenGrantResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<i64>,
}

/// Refresh-token grant.
///
/// CALLER CONTRACT: never call for the active profile. Claude Code owns that
/// refresh token; rotating it out from under Claude Code logs the user out.
/// Non-active profiles are safe — claudectl's copy is the only holder.
pub async fn refresh_credentials_async(
    client: &reqwest::Client,
    old: &OauthCreds,
) -> Result<OauthCreds> {
    let refresh_token = old
        .refresh_token
        .as_deref()
        .context("no refresh token stored")?;
    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
    });
    let resp = client
        .post(TOKEN_URL)
        .json(&body)
        .send()
        .await
        .context("failed to reach token endpoint")?;
    let status = resp.status();
    if !status.is_success() {
        bail!("token refresh failed ({status})");
    }
    let grant: TokenGrantResponse = resp
        .json()
        .await
        .context("failed to parse refresh response")?;
    Ok(apply_token_grant(
        old,
        grant,
        chrono::Utc::now().timestamp_millis(),
    ))
}

fn apply_token_grant(old: &OauthCreds, grant: TokenGrantResponse, now_ms: i64) -> OauthCreds {
    OauthCreds {
        access_token: grant.access_token,
        refresh_token: grant.refresh_token.or_else(|| old.refresh_token.clone()),
        expires_at: grant.expires_in.map(|s| now_ms + s * 1000),
        scopes: old.scopes.clone(),
        subscription_type: old.subscription_type.clone(),
        rate_limit_tier: old.rate_limit_tier.clone(),
        extra: old.extra.clone(),
    }
}

/// GET /api/oauth/profile, mapped to the oauthAccount shape Claude Code stores
/// in ~/.claude.json. Best-effort: Ok(None) on any failure status, since
/// identity is optional for a saved login.
pub fn fetch_oauth_account(access_token: &str) -> Result<Option<serde_json::Value>> {
    let resp = reqwest::blocking::Client::new()
        .get(PROFILE_URL)
        .bearer_auth(access_token)
        .header(OAUTH_BETA_HEADER.0, OAUTH_BETA_HEADER.1)
        .send()
        .context("failed to reach profile API")?;
    if !resp.status().is_success() {
        return Ok(None);
    }
    let value: serde_json::Value = resp.json().context("failed to parse profile response")?;
    Ok(Some(map_profile_to_oauth_account(&value)))
}

fn map_profile_to_oauth_account(profile: &serde_json::Value) -> serde_json::Value {
    let account = profile.get("account");
    let org = profile.get("organization");
    let mut out = serde_json::Map::new();
    let mut put = |key: &str, value: Option<&serde_json::Value>| {
        if let Some(v) = value {
            out.insert(key.to_string(), v.clone());
        }
    };
    put("accountUuid", account.and_then(|a| a.get("uuid")));
    put(
        "emailAddress",
        account
            .and_then(|a| a.get("email_address"))
            .or_else(|| account.and_then(|a| a.get("email"))),
    );
    put("organizationUuid", org.and_then(|o| o.get("uuid")));
    put("organizationName", org.and_then(|o| o.get("name")));
    serde_json::Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_errors_distinguish_rate_limits_and_authentication() {
        use reqwest::{
            StatusCode,
            header::{HeaderMap, HeaderValue, RETRY_AFTER},
        };
        let now = chrono::DateTime::parse_from_rfc2822("Fri, 04 Sep 2026 17:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let mut headers = HeaderMap::new();
        for (value, expected) in [
            ("207", "rate limited (HTTP 429); retry in 207s"),
            (
                "Fri, 04 Sep 2026 17:03:00 GMT",
                "rate limited (HTTP 429); retry in 180s",
            ),
            (
                "Fri, 04 Sep 2026 16:00:00 GMT",
                "rate limited (HTTP 429); retry in 0s",
            ),
            ("invalid", "rate limited (HTTP 429); try again later"),
        ] {
            headers.insert(RETRY_AFTER, HeaderValue::from_str(value).unwrap());
            assert_eq!(
                usage_http_error(StatusCode::TOO_MANY_REQUESTS, &headers, now),
                expected
            );
        }
        headers.clear();
        for (code, expected) in [
            (429, "rate limited (HTTP 429); try again later"),
            (401, "authentication rejected (HTTP 401)"),
            (403, "access denied (HTTP 403)"),
            (503, "usage API error (HTTP 503)"),
        ] {
            assert_eq!(
                usage_http_error(StatusCode::from_u16(code).unwrap(), &headers, now),
                expected
            );
        }
    }

    #[test]
    fn credentials_round_trip_preserves_unknown_fields() {
        let raw = r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-x","refreshToken":"sk-ant-ort01-y","expiresAt":1781087528419,"scopes":["user:inference"],"subscriptionType":"team","rateLimitTier":"t","futureField":7}}"#;
        let parsed: CredentialsFile = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.claude_ai_oauth.access_token, "sk-ant-oat01-x");
        assert_eq!(parsed.claude_ai_oauth.expires_at, Some(1781087528419));

        let out = serde_json::to_string(&parsed).unwrap();
        let value: serde_json::Value = serde_json::from_str(&out).unwrap();
        let oauth = &value["claudeAiOauth"];
        assert_eq!(oauth["futureField"], 7);
        assert_eq!(oauth["accessToken"], "sk-ant-oat01-x");
        assert_eq!(oauth["rateLimitTier"], "t");
    }

    #[test]
    fn usage_parses_real_response() {
        // Shape captured live on 2026-06-09 (spec: Verified facts).
        let raw = r#"{"five_hour":{"utilization":6.0,"resets_at":"2026-06-10T07:30:00.792506+00:00"},"seven_day":{"utilization":1.0,"resets_at":"2026-06-14T07:00:00.792527+00:00"},"seven_day_oauth_apps":null,"seven_day_opus":null,"seven_day_sonnet":{"utilization":0.0,"resets_at":null},"seven_day_cowork":null,"tangelo":null,"extra_usage":{"is_enabled":true,"monthly_limit":null,"used_credits":0.0,"utilization":null,"currency":"USD","disabled_reason":null}}"#;
        let usage: UsageResponse = serde_json::from_str(raw).unwrap();

        let five_hour = usage.five_hour.unwrap();
        assert_eq!(five_hour.utilization, Some(6.0));
        let expected = chrono::DateTime::parse_from_rfc3339("2026-06-10T07:30:00.792506+00:00")
            .unwrap()
            .timestamp();
        assert_eq!(five_hour.reset_timestamp(), Some(expected));

        assert!(usage.seven_day_opus.is_none());
        let sonnet = usage.seven_day_sonnet.unwrap();
        assert_eq!(sonnet.utilization, Some(0.0));
        assert_eq!(sonnet.reset_timestamp(), None);
        assert_eq!(usage.extra_usage.unwrap().is_enabled, Some(true));
    }

    #[test]
    fn expired_detection() {
        let mut creds = OauthCreds {
            access_token: "t".into(),
            refresh_token: None,
            expires_at: Some(chrono::Utc::now().timestamp_millis() - 1000),
            scopes: vec![],
            subscription_type: None,
            rate_limit_tier: None,
            extra: serde_json::Map::new(),
        };
        assert!(creds.is_expired());

        creds.expires_at = Some(chrono::Utc::now().timestamp_millis() + 3_600_000);
        assert!(!creds.is_expired());

        creds.expires_at = None;
        assert!(!creds.is_expired());

        creds.expires_at = Some(1781087528419);
        assert_eq!(creds.expiry_secs(), Some(1781087528));
    }

    #[test]
    fn apply_token_grant_rotates_and_keeps_metadata() {
        let old = OauthCreds {
            access_token: "old-at".into(),
            refresh_token: Some("old-rt".into()),
            expires_at: Some(1),
            scopes: vec!["user:inference".into()],
            subscription_type: Some("team".into()),
            rate_limit_tier: Some("t".into()),
            extra: serde_json::Map::new(),
        };

        let rotated = apply_token_grant(
            &old,
            TokenGrantResponse {
                access_token: "new-at".into(),
                refresh_token: Some("new-rt".into()),
                expires_in: Some(3600),
            },
            1_000_000,
        );
        assert_eq!(rotated.access_token, "new-at");
        assert_eq!(rotated.refresh_token.as_deref(), Some("new-rt"));
        assert_eq!(rotated.expires_at, Some(1_000_000 + 3_600_000));
        assert_eq!(rotated.subscription_type.as_deref(), Some("team"));

        // Refresh token not rotated → keep the old one.
        let kept = apply_token_grant(
            &old,
            TokenGrantResponse {
                access_token: "new-at".into(),
                refresh_token: None,
                expires_in: None,
            },
            1_000_000,
        );
        assert_eq!(kept.refresh_token.as_deref(), Some("old-rt"));
        assert_eq!(kept.expires_at, None);
    }

    #[test]
    fn maps_profile_response_to_oauth_account_shape() {
        let profile = serde_json::json!({
            "account": {"uuid": "u1", "email_address": "a@x", "full_name": "A"},
            "organization": {"uuid": "o1", "name": "Org"}
        });
        let account = map_profile_to_oauth_account(&profile);
        assert_eq!(account["accountUuid"], "u1");
        assert_eq!(account["emailAddress"], "a@x");
        assert_eq!(account["organizationUuid"], "o1");
        assert_eq!(account["organizationName"], "Org");
    }
}
