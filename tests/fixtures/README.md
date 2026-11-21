`limit-reset-offers.json` is synthetic: its field names were reconstructed from
static inspection of Claude Code 2.1.301. It is not a captured provider response.
`limit-reset-offers-v2.json` is a sanitized synthetic fixture matching the live
`cedar_ember` shape observed on 2026-11-21 (weekly + Fable `gives_back_weekly`
and `use_requires_limit: false` grants, with synthetic sentinel IDs and labels).
The identifiers and labels are deliberate sentinels that must not reach the
stored usage or either display. Staging's `limit_reset_offers` diagnostic confirms
whether the provider returns offers through claudectl's ordinary usage request.
