//! Read-only reset offers. Provider identifiers never enter this display model.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const HINT: &str = "Use /limit-reset in Claude Code, or Settings > Usage on claude.ai.";

#[derive(Clone, Debug, Default, Serialize)]
pub struct Offers {
    #[serde(skip_serializing)]
    eligible: Option<bool>,
    #[serde(skip_serializing)]
    ineligible_reason: Option<&'static str>,
    #[serde(skip_serializing)]
    next_grant_id: Option<String>,
    #[serde(skip_serializing)]
    at_limit: Option<bool>,
    #[serde(skip_serializing)]
    exhausted: Vec<String>,
    grants: Vec<Offer>,
}

fn bounded_ineligible_reason(value: Option<&Value>) -> Option<&'static str> {
    let reason = value.and_then(Value::as_str)?;
    Some(match reason {
        "config_off" => "config_off",
        "tier" => "tier",
        "seat" => "seat",
        "mobile" => "mobile",
        "surface" => "surface",
        "cli_version" => "cli_version",
        "no_grant" => "no_grant",
        "tenure" => "tenure",
        "other_experiment" => "other_experiment",
        "unavailable" => "unavailable",
        _ => "unknown",
    })
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_true(value: &bool) -> bool {
    *value
}

#[derive(Clone, Debug, Serialize)]
pub struct Offer {
    #[serde(skip_serializing)]
    id: Option<String>,
    resets_left: u64,
    clears: Vec<String>,
    ends_at: Option<String>,
    starts_at: Option<String>,
    paused: bool,
    usable_now: Option<bool>,
    #[serde(default, skip_serializing_if = "is_false")]
    gives_back_weekly: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    use_requires_limit: bool,
}

pub fn exhausted_windows(usage: &crate::api::UsageResponse) -> Vec<&'static str> {
    let mut windows = Vec::new();
    let exhausted = |window: Option<&crate::api::UsageWindow>| {
        window
            .and_then(|window| window.utilization)
            .is_some_and(|percent| percent.is_finite() && percent >= 100.0)
    };
    for (name, window) in [
        ("five_hour", usage.five_hour.as_ref()),
        ("seven_day", usage.seven_day.as_ref()),
        ("seven_day_opus", usage.seven_day_opus.as_ref()),
        ("seven_day_sonnet", usage.seven_day_sonnet.as_ref()),
    ] {
        if exhausted(window) {
            windows.push(name);
        }
    }
    if usage
        .fable_weekly()
        .and_then(|limit| limit.percent)
        .is_some_and(|percent| percent.is_finite() && percent >= 100.0)
    {
        windows.push("seven_day_overage_included");
    }
    windows
}

fn date(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .map(|at| at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

fn window(name: &str) -> Option<&'static str> {
    Some(match name {
        "five_hour" => "5-hour",
        "seven_day" => "weekly",
        "seven_day_opus" => "Opus weekly",
        "seven_day_sonnet" => "Sonnet weekly",
        "seven_day_cowork" => "Cowork weekly",
        "seven_day_omelette" => "other weekly",
        "seven_day_oauth_apps" => "OAuth apps weekly",
        "seven_day_overage_included" => "Fable weekly",
        _ => return None,
    })
}

impl<'de> Deserialize<'de> for Offers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let eligible = value.get("eligible").and_then(Value::as_bool);
        let ineligible_reason = bounded_ineligible_reason(value.get("ineligible_reason"));
        if eligible == Some(false) {
            return Ok(Self {
                eligible,
                ineligible_reason,
                ..Self::default()
            });
        }
        let grants = value
            .get("grants")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|grant| {
                let resets_left = grant
                    .get("resets_left")?
                    .as_u64()
                    .filter(|count| *count > 0)?;
                let clears = grant
                    .get("clears")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .filter(|name| window(name).is_some())
                    .map(str::to_owned)
                    .collect();
                let blocked = grant
                    .get("blocking")
                    .and_then(Value::as_array)
                    .is_some_and(|items| !items.is_empty());
                let usable_now = if blocked {
                    Some(false)
                } else {
                    grant.get("usable_now").and_then(Value::as_bool)
                };
                Some(Offer {
                    id: grant
                        .get("id")
                        .and_then(Value::as_str)
                        .filter(|id| !id.trim().is_empty())
                        .map(str::to_owned),
                    resets_left,
                    clears,
                    ends_at: date(grant.get("ends_at")),
                    starts_at: date(grant.get("starts_at")),
                    paused: grant
                        .get("paused")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    usable_now,
                    gives_back_weekly: grant
                        .get("gives_back_weekly")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    use_requires_limit: grant
                        .get("use_requires_limit")
                        .and_then(Value::as_bool)
                        .unwrap_or(true),
                })
            })
            .collect();
        Ok(Self {
            eligible,
            ineligible_reason,
            next_grant_id: value
                .get("next_grant_id")
                .and_then(Value::as_str)
                .map(str::to_owned),
            at_limit: value.get("at_limit").and_then(Value::as_bool),
            exhausted: value
                .get("exhausted")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|name| window(name).is_some())
                .map(str::to_owned)
                .collect(),
            grants,
        })
    }
}

/// A malformed optional block cannot turn ordinary usage into an error.
pub(crate) fn optional<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Offers>, D::Error> {
    let value = Value::deserialize(deserializer)?;
    Ok(value
        .is_object()
        .then(|| serde_json::from_value(value).unwrap_or_default()))
}

impl Offers {
    fn eligible(offer: &Offer, exhausted: &[&str], at_limit: Option<bool>, now: i64) -> bool {
        if offer.resets_left == 0
            || offer.paused
            || offer.usable_now == Some(false)
            || !offer.is_started(now)
            || !offer.expiry().is_none_or(|at| at > now)
        {
            return false;
        }
        if !offer.use_requires_limit && offer.usable_now == Some(true) {
            return true;
        }
        at_limit != Some(false) && offer.clears_any(exhausted)
    }

    fn selection_key<'a>(offer: &'a Offer, exhausted: &[&str]) -> (bool, i64, Option<&'a str>) {
        (
            !offer.clears_any(exhausted),
            offer.expiry().unwrap_or(i64::MAX),
            offer.ends_at.as_deref(),
        )
    }

    pub fn eligible_flag(&self) -> Option<bool> {
        self.eligible
    }

    pub fn ineligible_reason(&self) -> Option<&'static str> {
        self.ineligible_reason
    }

    pub fn provider_exhausted(&self) -> Vec<&str> {
        self.exhausted.iter().map(String::as_str).collect()
    }

    pub fn at_limit(&self) -> Option<bool> {
        self.at_limit
    }

    pub fn active(&self, now: i64) -> Vec<Offer> {
        self.grants
            .iter()
            .filter(|offer| offer.expiry().is_none_or(|at| at > now))
            .cloned()
            .collect()
    }

    pub fn count(&self, now: i64) -> u64 {
        self.grants
            .iter()
            .filter(|offer| offer.expiry().is_none_or(|at| at > now))
            .fold(0, |count, offer| count.saturating_add(offer.resets_left))
    }

    /// Total resets currently usable for the supplied exhausted windows.
    pub fn usable_count(&self, exhausted: &[&str], now: i64) -> u64 {
        self.grants
            .iter()
            .filter(|offer| Self::eligible(offer, exhausted, self.at_limit, now))
            .fold(0, |count, offer| count.saturating_add(offer.resets_left))
    }

    /// The usable grant closest to expiry, preferring grants that clear an exhausted window.
    pub fn closest_usable_offer(&self, exhausted: &[&str], now: i64) -> Option<&Offer> {
        self.grants
            .iter()
            .filter(|offer| {
                offer.id.is_some() && Self::eligible(offer, exhausted, self.at_limit, now)
            })
            .min_by_key(|offer| Self::selection_key(offer, exhausted))
    }

    /// The usable grant closest to expiry. The provider ID stays inside the reset
    /// execution module and is never serialized for display.
    pub fn closest_usable_grant_id(&self, exhausted: &[&str], now: i64) -> Option<&str> {
        self.closest_usable_offer(exhausted, now)
            .and_then(|offer| offer.id.as_deref())
    }

    /// Safe display rows for the CLI and dashboard. Provider identifiers are omitted.
    pub fn usable_summaries(&self, exhausted: &[&str], now: i64) -> Vec<OfferSummary> {
        let mut eligible: Vec<_> = self
            .grants
            .iter()
            .filter(|offer| {
                offer.id.is_some() && Self::eligible(offer, exhausted, self.at_limit, now)
            })
            .collect();
        eligible.sort_by_key(|offer| Self::selection_key(offer, exhausted));
        eligible.into_iter().map(OfferSummary::from_offer).collect()
    }

    /// Return the provider-selected grant only when it can clear one of the
    /// exhausted windows. Kept for compatibility with older callers.
    pub fn next_usable_grant_id(&self, exhausted: &[&str], now: i64) -> Option<&str> {
        let id = self.next_grant_id.as_deref()?;
        self.grants
            .iter()
            .find(|offer| {
                offer.id.as_deref() == Some(id)
                    && Self::eligible(offer, exhausted, self.at_limit, now)
            })
            .map(|_| id)
    }

    /// Display-only eligibility check. The provider-selected grant ID is kept in the sealed
    /// usage cache for at most five minutes; provider identifiers never enter this display model.
    pub fn has_usable_offer(&self, exhausted: &[&str], now: i64) -> bool {
        self.has_usable_offer_at(exhausted, self.at_limit, now)
    }

    /// Eligibility check using an explicit `at_limit` flag from sealed server state.
    pub fn has_usable_offer_at(
        &self,
        exhausted: &[&str],
        at_limit: Option<bool>,
        now: i64,
    ) -> bool {
        self.grants
            .iter()
            .any(|offer| Self::eligible(offer, exhausted, at_limit, now))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OfferSummary {
    pub resets_left: u64,
    pub clears: Vec<String>,
    pub ends_at: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub gives_back_weekly: bool,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub use_requires_limit: bool,
}

impl OfferSummary {
    fn from_offer(offer: &Offer) -> Self {
        Self {
            resets_left: offer.resets_left,
            clears: offer.clears.clone(),
            ends_at: offer.ends_at.clone(),
            gives_back_weekly: offer.gives_back_weekly,
            use_requires_limit: offer.use_requires_limit,
        }
    }

    pub fn expiry(&self) -> Option<i64> {
        self.ends_at
            .as_deref()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.timestamp())
    }

    pub fn summary(&self) -> String {
        format_offer_summary(
            self.resets_left,
            &self.clears,
            self.ends_at.as_deref(),
            self.gives_back_weekly,
        )
    }
}

fn format_offer_summary(
    resets_left: u64,
    clears: &[String],
    ends_at: Option<&str>,
    gives_back_weekly: bool,
) -> String {
    let limits = clears
        .iter()
        .filter_map(|name| window(name))
        .collect::<Vec<_>>()
        .join(" + ");
    let limits = if limits.is_empty() {
        "limit unspecified"
    } else {
        &limits
    };
    let expiry = ends_at
        .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
        .map(|at| at.with_timezone(&chrono::Utc))
        .map(|at| format!("use by {}", at.format("%Y-%m-%d %H:%M UTC")))
        .unwrap_or_else(|| "expiry unknown".into());
    let plural = if resets_left == 1 { "" } else { "s" };
    let mut summary = format!("{resets_left} reset{plural} · {limits} · {expiry}");
    if gives_back_weekly {
        summary.push_str(" · gives back weekly");
    }
    summary
}

impl Offer {
    fn expiry(&self) -> Option<i64> {
        self.ends_at
            .as_deref()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.timestamp())
    }

    fn is_started(&self, now: i64) -> bool {
        self.starts_at.as_deref().is_none_or(|at| {
            chrono::DateTime::parse_from_rfc3339(at)
                .map(|date| date.timestamp() <= now)
                .unwrap_or(false)
        })
    }

    fn clears_any(&self, exhausted: &[&str]) -> bool {
        exhausted.iter().any(|window| {
            self.clears.iter().any(|cleared| cleared == window)
                || (*window == "seven_day" && self.gives_back_weekly)
        })
    }

    pub fn summary(&self, now: i64) -> String {
        let mut summary = format_offer_summary(
            self.resets_left,
            &self.clears,
            self.ends_at.as_deref(),
            self.gives_back_weekly,
        );
        if self.paused {
            summary.push_str(" · paused");
        }
        if self.usable_now == Some(false) {
            summary.push_str(" · not usable now");
        }
        if let Some(start) = self
            .starts_at
            .as_deref()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.with_timezone(&chrono::Utc))
            .filter(|at| at.timestamp() > now)
        {
            summary.push_str(&format!(" · starts {}", start.format("%Y-%m-%d %H:%M UTC")));
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_only_the_server_next_grant_for_an_exhausted_window() {
        let offers: Offers = serde_json::from_value(serde_json::json!({
            "eligible": true,
            "next_grant_id": "grant-1",
            "grants": [{
                "id": "grant-1",
                "resets_left": 1,
                "clears": ["five_hour"],
                "ends_at": "2099-01-01T00:00:00Z"
            }, {
                "id": "grant-2",
                "resets_left": 1,
                "clears": ["five_hour"],
                "ends_at": "2099-01-01T00:00:00Z"
            }]
        }))
        .unwrap();
        assert_eq!(
            offers.next_usable_grant_id(&["five_hour"], 1_800_000_000),
            Some("grant-1")
        );
        assert_eq!(
            offers.next_usable_grant_id(&["seven_day"], 1_800_000_000),
            None
        );
    }

    #[test]
    fn paused_or_early_offers_do_not_enable_apply() {
        let offers: Offers = serde_json::from_value(serde_json::json!({
            "eligible": true,
            "next_grant_id": "grant-1",
            "grants": [{
                "id": "grant-1",
                "resets_left": 1,
                "clears": ["five_hour"],
                "paused": true,
                "starts_at": "2099-01-01T00:00:00Z"
            }]
        }))
        .unwrap();
        assert_eq!(
            offers.next_usable_grant_id(&["five_hour"], 1_800_000_000),
            None
        );
    }

    #[test]
    fn usable_count_excludes_paused_future_and_wrong_window_grants() {
        let offers: Offers = serde_json::from_value(serde_json::json!({
            "grants": [
                {"resets_left": 2, "clears": ["five_hour"], "ends_at": "2099-01-01T00:00:00Z"},
                {"resets_left": 3, "clears": ["five_hour"], "paused": true},
                {"resets_left": 4, "clears": ["five_hour"], "starts_at": "2099-01-01T00:00:00Z"},
                {"resets_left": 5, "clears": ["seven_day"]}
            ]
        }))
        .unwrap();
        assert_eq!(offers.usable_count(&["five_hour"], 1_800_000_000), 2);
    }

    #[test]
    fn closest_usable_grant_prefers_the_earliest_expiry() {
        let offers: Offers = serde_json::from_value(serde_json::json!({
            "grants": [
                {"id": "later", "resets_left": 1, "clears": ["five_hour"], "ends_at": "2099-01-02T00:00:00Z"},
                {"id": "sooner", "resets_left": 1, "clears": ["five_hour"], "ends_at": "2099-01-01T00:00:00Z"}
            ]
        }))
        .unwrap();
        assert_eq!(
            offers.closest_usable_grant_id(&["five_hour"], 1_800_000_000),
            Some("sooner")
        );
    }

    #[test]
    fn reset_summaries_exclude_grants_without_a_redeemable_id() {
        let offers: Offers = serde_json::from_value(serde_json::json!({
            "grants": [
                {"resets_left": 7, "clears": ["five_hour"]},
                {"id": "", "resets_left": 3, "clears": ["five_hour"]},
                {"id": "valid", "resets_left": 2, "clears": ["five_hour"]}
            ]
        }))
        .unwrap();
        let summaries = offers.usable_summaries(&["five_hour"], 1_800_000_000);
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].resets_left, 2);
        assert_eq!(
            offers.closest_usable_grant_id(&["five_hour"], 1_800_000_000),
            Some("valid")
        );
        assert!(!serde_json::to_string(&summaries).unwrap().contains("valid"));
    }

    #[test]
    fn live_shape_fable_and_anytime_grants_are_retained_and_usable() {
        let usage: crate::api::UsageResponse =
            serde_json::from_str(include_str!("../tests/fixtures/limit-reset-offers-v2.json"))
                .unwrap();
        let now = 1_800_000_000;
        let offers = usage.cedar_ember.as_ref().unwrap();
        let exhausted = exhausted_windows(&usage);
        assert_eq!(exhausted, vec!["seven_day"]);
        assert_eq!(offers.usable_count(&exhausted, now), 2);
        let summaries = offers.usable_summaries(&exhausted, now);
        assert_eq!(summaries.len(), 2);
        assert_eq!(
            offers.closest_usable_grant_id(&exhausted, now),
            Some("synthetic-weekly-grant-not-for-display")
        );
        let encoded = serde_json::to_string(&summaries).unwrap();
        assert!(!encoded.contains("not-for-display"));

        // A limit-gated Fable grant (use_requires_limit=true, gives_back_weekly=true)
        // still applies when seven_day is exhausted.
        let gated_fable: Offers = serde_json::from_value(serde_json::json!({
            "eligible": true,
            "at_limit": true,
            "exhausted": ["seven_day"],
            "grants": [{
                "id": "fable-only",
                "resets_left": 1,
                "clears": ["seven_day_overage_included"],
                "gives_back_weekly": true,
                "use_requires_limit": true,
                "usable_now": true,
                "ends_at": "2100-03-09T07:59:00Z"
            }]
        }))
        .unwrap();
        assert_eq!(gated_fable.usable_count(&["seven_day"], now), 1);
        assert_eq!(
            gated_fable.closest_usable_grant_id(&["seven_day"], now),
            Some("fable-only")
        );

        // Anytime grants (use_requires_limit=false, usable_now=true) remain usable when
        // at_limit is false and no window is exhausted.
        let mut anytime_value: Value =
            serde_json::from_str(include_str!("../tests/fixtures/limit-reset-offers-v2.json"))
                .unwrap();
        anytime_value["cedar_ember"]["at_limit"] = serde_json::json!(false);
        anytime_value["cedar_ember"]["exhausted"] = serde_json::json!([]);
        let anytime_usage: crate::api::UsageResponse =
            serde_json::from_value(anytime_value).unwrap();
        let anytime = anytime_usage.cedar_ember.as_ref().unwrap();
        assert_eq!(anytime.usable_count(&[], now), 2);
        assert_eq!(anytime.usable_summaries(&[], now).len(), 2);
        assert_eq!(
            anytime.closest_usable_grant_id(&[], now),
            Some("synthetic-weekly-grant-not-for-display")
        );

        // Exhausted Fable weekly limit counts as seven_day_overage_included.
        let fable_full: crate::api::UsageResponse = serde_json::from_value(serde_json::json!({
            "five_hour": {"utilization": 5.0},
            "seven_day": {"utilization": 80.0},
            "limits": [{
                "kind": "weekly_scoped",
                "percent": 100.0,
                "scope": {"model": {"id": null, "display_name": "Fable"}, "surface": null}
            }]
        }))
        .unwrap();
        assert_eq!(
            exhausted_windows(&fable_full),
            vec!["seven_day_overage_included"]
        );

        // Blocked grants and limit-required grants with at_limit=false are excluded,
        // and exhausted-clearing grants beat earlier-expiring non-clearing anytime grants.
        let mixed: Offers = serde_json::from_value(serde_json::json!({
            "eligible": true,
            "at_limit": true,
            "grants": [
                {
                    "id": "blocked-grant",
                    "resets_left": 1,
                    "clears": ["five_hour"],
                    "blocking": ["seven_day"],
                    "usable_now": true,
                    "use_requires_limit": false,
                    "ends_at": "2099-01-01T00:00:00Z"
                },
                {
                    "id": "earlier-non-clearing-anytime",
                    "resets_left": 1,
                    "clears": ["seven_day"],
                    "usable_now": true,
                    "use_requires_limit": false,
                    "ends_at": "2099-01-02T00:00:00Z"
                },
                {
                    "id": "later-clearing-exhausted",
                    "resets_left": 1,
                    "clears": ["five_hour"],
                    "usable_now": true,
                    "use_requires_limit": false,
                    "ends_at": "2099-01-05T00:00:00Z"
                }
            ]
        }))
        .unwrap();
        assert_eq!(mixed.usable_count(&["five_hour"], now), 2);
        assert_eq!(
            mixed.closest_usable_grant_id(&["five_hour"], now),
            Some("later-clearing-exhausted")
        );
        let ordered = mixed.usable_summaries(&["five_hour"], now);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].clears, vec!["five_hour"]);
        assert_eq!(ordered[1].clears, vec!["seven_day"]);

        // Limit-gated grants (default use_requires_limit=true) stay rejected when at_limit=false.
        let not_at_limit: Offers = serde_json::from_value(serde_json::json!({
            "eligible": true,
            "at_limit": false,
            "grants": [{
                "id": "gated",
                "resets_left": 1,
                "clears": ["five_hour"],
                "usable_now": true,
                "ends_at": "2099-01-05T00:00:00Z"
            }]
        }))
        .unwrap();
        assert_eq!(not_at_limit.usable_count(&["five_hour"], now), 0);
        assert!(!not_at_limit.has_usable_offer_at(&["five_hour"], Some(false), now));

        // Round-trip through Offer serialization preserves gives_back_weekly and use_requires_limit
        // while keeping provider identifiers stripped.
        let serialized = serde_json::to_value(offers).unwrap();
        assert!(!serialized.to_string().contains("not-for-display"));
        let round_tripped: Offers = serde_json::from_value(serialized).unwrap();
        assert!(round_tripped.has_usable_offer_at(&[], Some(false), now));
        assert!(round_tripped.has_usable_offer_at(&["seven_day"], Some(true), now));

        // Surface/version rejection preserves bounded diagnostic metadata without exposing grants.
        let surface_denied: Offers = serde_json::from_value(serde_json::json!({
            "eligible": false,
            "ineligible_reason": "surface",
            "grants": [{"id": "hidden", "resets_left": 1, "clears": ["seven_day"]}]
        }))
        .unwrap();
        assert_eq!(surface_denied.eligible_flag(), Some(false));
        assert_eq!(surface_denied.ineligible_reason(), Some("surface"));
        assert_eq!(surface_denied.count(now), 0);
        assert!(
            !serde_json::to_string(&surface_denied)
                .unwrap()
                .contains("surface")
        );

        let unknown_denied: Offers = serde_json::from_value(serde_json::json!({
            "eligible": false,
            "ineligible_reason": "unbounded-provider-secret-text"
        }))
        .unwrap();
        assert_eq!(unknown_denied.ineligible_reason(), Some("unknown"));
    }
}
