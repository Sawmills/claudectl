use super::*;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    pub data: Option<Value>,
    pub observed_at: Option<i64>,
    pub next_retry_at: i64,
    pub stale: bool,
    pub error: Option<String>,
    /// The provider-selected reset grant is sealed separately from the display projection.
    #[serde(default)]
    pub reset_grant_id: Option<String>,
    #[serde(default)]
    pub reset_windows: Vec<String>,
    #[serde(default)]
    pub reset_at_limit: Option<bool>,
    /// Summaries derived while provider IDs are present, before the display projection
    /// removes them. This sealed cache keeps missing-ID grants out of machine listings.
    #[serde(default)]
    pub reset_offers: Vec<crate::limit_resets::OfferSummary>,
    /// Set only on the response to a fresh attempt that failed; never stored.
    #[serde(skip)]
    pub failure: Option<&'static str>,
}
impl Usage {
    fn is_stale_at(&self, at: i64) -> bool {
        self.data.is_none()
            || self.error.is_some()
            || at >= self.next_retry_at
            || self.observed_at.is_some_and(|t| t > at + USABLE)
    }
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
    pub(super) async fn stored<T: serde::de::DeserializeOwned + Default>(
        &self,
        id: &str,
    ) -> Result<T> {
        match self.store.usage(id).await? {
            Some(sealed) => self.unseal(&sealed),
            None => Ok(T::default()),
        }
    }
    /// The stored observations of `user`'s live accounts, by account ID, in one store read
    /// scoped to that user. It takes no poll lock and loads no grant, so a slow provider poll
    /// never delays it. One observation that does not unseal is that account's error only.
    /// For the dashboard.
    pub async fn cached_usages(
        &self,
        user: &str,
    ) -> Result<std::collections::BTreeMap<String, Result<Usage>>> {
        Ok(self
            .store
            .user_usage(user)
            .await?
            .into_iter()
            .map(|(id, sealed)| {
                let usage = self.unseal::<Usage>(&sealed).map(|mut u| {
                    u.stale = u.is_stale_at(now());
                    u
                });
                (id, usage)
            })
            .collect())
    }
    /// A cached read never contacts the provider. A fresh read uses the current access token.
    /// It refreshes only an expired token of a Ready account: that token is dead for every
    /// holder, so no session loses it (SAW-12610), and an idle account would otherwise report
    /// `login_required` with a good refresh grant (SAW-12870). It never refreshes a token that
    /// running sessions still use. A failed refresh is an error; without a usable token a
    /// later read reports `login_required`.
    pub async fn usage_for(
        &self,
        user: &str,
        machine: &str,
        id: &str,
        cached: bool,
    ) -> Result<Usage> {
        if !cached {
            let loaded = self.selected(user, id).await?;
            if loaded.record.phase == Phase::Ready
                && !matches!(loaded.record.rotation, Rotation::Pending { .. })
                && loaded.record.grant.expires_at <= now()
            {
                // Fail fast: a rejected or uncertain refresh, or a refresh whose audit row was
                // not stored, never ends in a usage answer. Later reads report login_required.
                self.observe_for(user, machine, id)
                    .await
                    .context(ExpiredRefreshFailed)?;
            }
        }
        self.read_usage(user, id, cached).await
    }
    pub async fn usage(&self, user: &str, id: &str, cached: bool) -> Result<Usage> {
        self.usage_for(user, "server", id, cached).await
    }
    async fn read_usage(&self, user: &str, id: &str, cached: bool) -> Result<Usage> {
        // The client allows 40 s. Reserve 3 s for optional metadata and leave room for
        // store reads/release. A late lease claim must not shorten the provider timeout.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(32);
        self.selected(user, id).await?;
        if cached {
            let mut result: Usage = self.stored(id).await?;
            result.stale = result.is_stale_at(now());
            return Ok(result);
        }
        let _poll = self.usage_poll.lock().await;
        loop {
            let mut result: Usage = self.stored(id).await?;
            result.stale = result.is_stale_at(now());
            if now() < result.next_retry_at {
                return Ok(result);
            }
            // Only the holder polls and updates the shared throttle. A live follower waits
            // for that poll's cache write, or polls its own account after an unrelated poll.
            if let Some(lease) = self.store.acquire_lease(USAGE_LEASE, 60_000).await? {
                let polled = async {
                    // The preceding holder may have committed between our read and claim.
                    let mut result: Usage = self.stored(id).await?;
                    result.stale = result.is_stale_at(now());
                    if now() < result.next_retry_at {
                        return Ok(result);
                    }
                    if deadline.saturating_duration_since(tokio::time::Instant::now())
                        < Duration::from_secs(30)
                    {
                        return Err(RefreshInProgress.into());
                    }
                    let loaded = self.selected(user, id).await?;
                    self.poll_usage(&loaded, id, result).await
                }
                .await;
                self.store.release_lease(&lease, USAGE_LEASE).await?;
                return polled;
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(RefreshInProgress.into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
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
            .query(&[("cedar_ember", "1")])
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
                        let offers = value
                            .get("cedar_ember")
                            .filter(|value| value.is_object())
                            .and_then(|value| {
                                serde_json::from_value::<crate::limit_resets::Offers>(value.clone())
                                    .ok()
                            });
                        let count = offers
                            .as_ref()
                            .map_or(0, |offers| offers.count(now() / 1000));
                        result.reset_windows = offers
                            .as_ref()
                            .map(|offers| {
                                offers
                                    .provider_exhausted()
                                    .into_iter()
                                    .map(str::to_owned)
                                    .collect()
                            })
                            .unwrap_or_default();
                        result.reset_at_limit = offers
                            .as_ref()
                            .and_then(crate::limit_resets::Offers::at_limit);
                        let selection = offers.as_ref().and_then(|offers| {
                            if offers.at_limit() == Some(false) {
                                return None;
                            }
                            let parsed = serde_json::from_value::<crate::api::UsageResponse>(
                                Value::Object(value.clone()),
                            )
                            .ok()?;
                            let mut exhausted = crate::limit_resets::exhausted_windows(&parsed);
                            for window in &result.reset_windows {
                                if !exhausted.contains(&window.as_str()) {
                                    exhausted.push(window.as_str());
                                }
                            }
                            let grant = offers
                                .closest_usable_grant_id(&exhausted, now() / 1000)
                                .map(str::to_owned);
                            Some((grant, offers.usable_summaries(&exhausted, now() / 1000)))
                        });
                        (result.reset_grant_id, result.reset_offers) =
                            selection.unwrap_or_default();
                        if self
                            .usage_offers_logged
                            .lock()
                            .unwrap()
                            .insert(id.to_owned())
                        {
                            eprintln!(
                                "{}",
                                json!({"operation":"limit_reset_offers", "present":offers.is_some(), "count":count})
                            );
                        }
                        let mut data: serde_json::Map<String, Value> = value
                            .into_iter()
                            .filter(|(k, _)| {
                                k.as_str() == "five_hour"
                                    || k.starts_with("seven_day")
                                    || matches!(k.as_str(), "limits" | "extra_usage")
                            })
                            .collect();
                        // Metadata shares the usage poll/cache lifetime. Never expose the raw
                        // profile, or label this account with a different identity's plan.
                        let previous_plan = result
                            .data
                            .as_ref()
                            .and_then(|data| data.get("subscription_type"))
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                        // The usage request has a 30 s deadline and the poll lease is 60 s.
                        // Optional metadata must not exhaust the remaining lease budget.
                        let profile = tokio::time::timeout(
                            Duration::from_secs(3),
                            self.provider_profile(&loaded.record.grant.access_token),
                        )
                        .await;
                        let plan = match profile {
                            Ok(Ok(profile))
                                if Self::profile_identity(&profile).ok().as_ref()
                                    == Some(&loaded.identity()) =>
                            {
                                crate::api::subscription_type(&profile).map(str::to_owned)
                            }
                            Ok(Ok(_)) => {
                                result.failure = Some("subscription_plan_identity_mismatch");
                                None
                            }
                            Ok(Err(_)) | Err(_) => {
                                result.failure = Some("subscription_plan_unavailable");
                                previous_plan
                            }
                        };
                        data.insert("subscription_type".into(), json!(plan));
                        if let Some(offers) = offers {
                            data.insert("cedar_ember".into(), serde_json::to_value(offers)?);
                        }
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
