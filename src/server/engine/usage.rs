use super::*;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub data: Option<Value>,
    pub observed_at: Option<i64>,
    pub next_retry_at: i64,
    pub stale: bool,
    pub error: Option<String>,
    /// Set only on the response to a fresh attempt that failed; never stored.
    #[serde(skip)]
    pub failure: Option<&'static str>,
}
/// Provider throttling shared by every account and replica.
#[derive(Default, Serialize, Deserialize)]
struct Throttle {
    last_request: i64,
    cooldown_until: i64,
    failures: u32,
}
const THROTTLE: &str = "__throttle";

impl Engine {
    async fn stored<T: serde::de::DeserializeOwned + Default>(&self, id: &str) -> Result<T> {
        match self.store.usage(id).await? {
            Some(sealed) => self.unseal(&sealed),
            None => Ok(T::default()),
        }
    }
    /// The stored observation of an account the caller already scoped to its user (from
    /// `accounts(user)`). It takes no poll lock and loads no grant, so a slow provider poll
    /// never delays it. For the dashboard.
    pub async fn cached_usage(&self, id: &str) -> Result<Usage> {
        let mut result: Usage = self.stored(id).await?;
        result.stale = result.data.is_none()
            || result.error.is_some()
            || now() >= result.next_retry_at
            || result.observed_at.is_some_and(|t| t > now() + USABLE);
        Ok(result)
    }
    /// A cached read never contacts the provider. A fresh read uses the current access token
    /// and never refreshes: without a usable token it reports `login_required`.
    pub async fn usage(&self, user: &str, id: &str, cached: bool) -> Result<Usage> {
        let loaded = self.selected(user, id).await?;
        let _poll = self.usage_poll.lock().await;
        let mut result: Usage = self.stored(id).await?;
        result.stale = result.data.is_none()
            || result.error.is_some()
            || now() >= result.next_retry_at
            || result.observed_at.is_some_and(|t| t > now() + USABLE);
        if cached || now() < result.next_retry_at {
            return Ok(result);
        }
        // One replica polls the provider at a time; the others answer from the cache. The
        // holder alone reads and writes the shared throttle state.
        let Some(lease) = self.store.acquire_lease(USAGE_LEASE, 60_000).await? else {
            return Ok(result);
        };
        let polled = self.poll_usage(&loaded, id, result).await;
        self.store.release_lease(&lease, USAGE_LEASE).await?;
        polled
    }
    async fn poll_usage(&self, loaded: &Loaded, id: &str, mut result: Usage) -> Result<Usage> {
        let mut throttle: Throttle = self.stored(THROTTLE).await?;
        if now() < throttle.cooldown_until {
            result.next_retry_at = result.next_retry_at.max(throttle.cooldown_until);
            return Ok(result);
        }
        if loaded.record.phase != Phase::Ready || loaded.record.grant.expires_at <= now() {
            result.error = Some("login_required".into());
            result.stale = true;
            result.failure = Some("usage_login_required");
            return Ok(result);
        }
        let wait = (throttle.last_request + 1000 - now()).max(0) as u64;
        if wait > 0 {
            tokio::time::sleep(Duration::from_millis(wait)).await;
        }
        throttle.last_request = now();
        let response = self
            .http
            .get(format!("{}/api/oauth/usage", self.endpoints.api))
            .bearer_auth(&loaded.record.grant.access_token)
            .header("anthropic-beta", BETA)
            .send()
            .await;
        result.next_retry_at = now() + 300_000;
        result.stale = true;
        match response {
            Ok(response) if response.status().is_success() => {
                // The same streamed 16 KiB bound as token responses; what is kept is a
                // filtered subset of at most that.
                let body = capped_body(response).await.ok();
                match body.and_then(|b| serde_json::from_slice::<Value>(&b).ok()) {
                    Some(Value::Object(value)) => {
                        let data: serde_json::Map<String, Value> = value
                            .into_iter()
                            .filter(|(k, _)| {
                                k.as_str() == "five_hour"
                                    || k.starts_with("seven_day")
                                    || matches!(k.as_str(), "limits" | "extra_usage")
                            })
                            .collect();
                        for window in ["five_hour", "seven_day"] {
                            if let Some(reset) = data
                                .get(window)
                                .and_then(|v| v.get("resets_at"))
                                .and_then(Value::as_str)
                                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                            {
                                let time = reset.timestamp_millis();
                                if time > now() {
                                    result.next_retry_at = result.next_retry_at.min(time);
                                }
                            }
                        }
                        result.data = Some(Value::Object(data));
                        result.observed_at = Some(now());
                        result.error = None;
                        result.stale = false;
                        throttle.failures = 0;
                    }
                    _ => result.error = Some("invalid_usage".into()),
                }
            }
            Ok(response) => {
                let status = response.status().as_u16();
                result.error = Some(
                    match status {
                        401 => "credential_rejected",
                        403 => "missing_scope",
                        429 => "usage_throttled",
                        _ => "usage_unavailable",
                    }
                    .into(),
                );
                if status == 429 {
                    throttle.failures = throttle.failures.saturating_add(1);
                    let delay = (300_000_i64
                        * (1_i64 << throttle.failures.saturating_sub(1).min(4)))
                    .min(3_600_000);
                    let retry = response
                        .headers()
                        .get("retry-after")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|s| {
                            s.parse::<i64>()
                                .ok()
                                .and_then(|n| n.checked_mul(1000))
                                .or_else(|| {
                                    chrono::DateTime::parse_from_rfc2822(s)
                                        .ok()
                                        .map(|t| t.timestamp_millis().saturating_sub(now()))
                                })
                        })
                        .unwrap_or(0);
                    throttle.cooldown_until = now().saturating_add(delay.max(retry));
                    result.next_retry_at = throttle.cooldown_until;
                }
            }
            Err(_) => result.error = Some("usage_unavailable".into()),
        }
        self.store
            .put_usage(THROTTLE, &self.seal(&throttle)?)
            .await?;
        // A delete in the meantime removed the account; put_usage then stores nothing.
        self.store.put_usage(id, &self.seal(&result)?).await?;
        if result.error.is_some() {
            result.failure = Some("usage_failed");
        }
        Ok(result)
    }
}
