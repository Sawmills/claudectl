//! Read-only reset offers. Provider identifiers never enter this display model.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const HINT: &str = "Use /limit-reset in Claude Code, or Settings > Usage on claude.ai.";

#[derive(Clone, Debug, Default, Serialize)]
pub struct Offers {
    #[serde(skip_serializing)]
    next_grant_id: Option<String>,
    #[serde(skip_serializing)]
    at_limit: Option<bool>,
    #[serde(skip_serializing)]
    exhausted: Vec<String>,
    grants: Vec<Offer>,
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
        "seven_day_overage_included" => "included overage weekly",
        _ => return None,
    })
}

impl<'de> Deserialize<'de> for Offers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        if value.get("eligible").and_then(Value::as_bool) == Some(false) {
            return Ok(Self::default());
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
                Some(Offer {
                    id: grant.get("id").and_then(Value::as_str).map(str::to_owned),
                    resets_left,
                    clears,
                    ends_at: date(grant.get("ends_at")),
                    starts_at: date(grant.get("starts_at")),
                    paused: grant
                        .get("paused")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    usable_now: grant.get("usable_now").and_then(Value::as_bool),
                })
            })
            .collect();
        Ok(Self {
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
    fn eligible(offer: &Offer, exhausted: &[&str], now: i64) -> bool {
        offer.resets_left > 0
            && !offer.paused
            && offer.usable_now != Some(false)
            && offer.starts_at.as_deref().is_none_or(|at| {
                chrono::DateTime::parse_from_rfc3339(at)
                    .map(|date| date.timestamp() <= now)
                    .unwrap_or(false)
            })
            && offer.expiry().is_none_or(|at| at > now)
            && offer
                .clears
                .iter()
                .any(|window| exhausted.contains(&window.as_str()))
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
            .filter(|offer| Self::eligible(offer, exhausted, now))
            .fold(0, |count, offer| count.saturating_add(offer.resets_left))
    }

    /// The usable grant closest to expiry. The provider ID stays inside the reset
    /// execution module and is never serialized for display.
    pub fn closest_usable_grant_id(&self, exhausted: &[&str], now: i64) -> Option<&str> {
        self.grants
            .iter()
            .filter(|offer| offer.id.is_some() && Self::eligible(offer, exhausted, now))
            .min_by_key(|offer| offer.expiry().unwrap_or(i64::MAX))
            .and_then(|offer| offer.id.as_deref())
    }

    /// Safe display rows for the CLI and dashboard. Provider identifiers are omitted.
    pub fn usable_summaries(&self, exhausted: &[&str], now: i64) -> Vec<OfferSummary> {
        let mut rows: Vec<_> = self
            .grants
            .iter()
            .filter(|offer| Self::eligible(offer, exhausted, now))
            .map(OfferSummary::from_offer)
            .collect();
        rows.sort_by(|a, b| match (&a.ends_at, &b.ends_at) {
            (Some(a), Some(b)) => a.cmp(b),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        });
        rows
    }

    /// Return the provider-selected grant only when it can clear one of the
    /// exhausted windows. Kept for compatibility with older callers.
    pub fn next_usable_grant_id(&self, exhausted: &[&str], now: i64) -> Option<&str> {
        let id = self.next_grant_id.as_deref()?;
        self.grants
            .iter()
            .find(|offer| offer.id.as_deref() == Some(id) && Self::eligible(offer, exhausted, now))
            .map(|_| id)
    }

    /// Display-only eligibility check. The provider-selected grant ID is kept in the sealed
    /// usage cache for at most five minutes; provider identifiers never enter this display model.
    pub fn has_usable_offer(&self, exhausted: &[&str], now: i64) -> bool {
        self.grants
            .iter()
            .any(|offer| Self::eligible(offer, exhausted, now))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OfferSummary {
    pub resets_left: u64,
    pub clears: Vec<String>,
    pub ends_at: Option<String>,
}

impl OfferSummary {
    fn from_offer(offer: &Offer) -> Self {
        Self {
            resets_left: offer.resets_left,
            clears: offer.clears.clone(),
            ends_at: offer.ends_at.clone(),
        }
    }
}

impl Offer {
    fn expiry(&self) -> Option<i64> {
        self.ends_at
            .as_deref()
            .and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok())
            .map(|at| at.timestamp())
    }

    pub fn summary(&self, now: i64) -> String {
        let limits = self
            .clears
            .iter()
            .filter_map(|name| window(name))
            .collect::<Vec<_>>()
            .join(" + ");
        let limits = if limits.is_empty() {
            "limit unspecified"
        } else {
            &limits
        };
        let expiry = self
            .expiry()
            .and_then(|at| chrono::DateTime::from_timestamp(at, 0))
            .map(|at| format!("use by {}", at.format("%Y-%m-%d %H:%M UTC")))
            .unwrap_or_else(|| "expiry unknown".into());
        let plural = if self.resets_left == 1 { "" } else { "s" };
        let mut summary = format!("{} reset{plural} · {limits} · {expiry}", self.resets_left);
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
}
