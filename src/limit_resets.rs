//! Read-only reset offers. Provider identifiers never enter this display model.
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const HINT: &str = "Use /limit-reset in Claude Code, or Settings > Usage on claude.ai.";

#[derive(Clone, Debug, Default, Serialize)]
pub struct Offers {
    grants: Vec<Offer>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Offer {
    resets_left: u64,
    clears: Vec<String>,
    ends_at: Option<String>,
    starts_at: Option<String>,
    paused: bool,
    usable_now: Option<bool>,
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
        Ok(Self { grants })
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
