//! Buyer-local bid-ceiling policy for cognition-market findings.
//!
//! This module does not authenticate the truth of a re-derivation estimate.
//! It validates that one caller-carried estimate is internally consistent with
//! the buyer's expected source, context, replay recipe, currency, and validity
//! window, then applies exact checked arithmetic. The resulting ceiling is a
//! local bidding policy, not a market quote or purchase authority.

use serde::{Deserialize, Serialize};

const BASIS_POINTS: u128 = 10_000;
const COMBINED_BASIS_POINTS_DENOMINATOR: u128 = BASIS_POINTS * BASIS_POINTS * BASIS_POINTS;
const MAX_U64_DECIMAL: u128 = u64::MAX as u128;

/// Metering-history provenance accepted by the buyer-local helper.
pub const BUYER_METERING_HISTORY_V1: &str = "buyer_metering_history_v1";
/// Fresh metered-quote provenance accepted by the buyer-local helper.
///
/// The quote remains caller-carried and unsigned. This label does not turn it
/// into an authenticated producer artifact.
pub const BUYER_FRESH_METERED_QUOTE_V1: &str = "buyer_fresh_metered_quote_v1";

/// One buyer-carried estimate of the cost of re-deriving a finding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BuyerFindingEstimate {
    pub units: String,
    pub currency: String,
    pub provenance: String,
    pub source_sha256: String,
    pub context_sha256: String,
    pub replay_recipe_sha256: String,
    pub observed_at_unix_ms: String,
    pub valid_until_unix_ms: String,
}

/// Buyer-owned discount and remaining-budget policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingBidCeilingPolicy {
    pub budget_remaining_units: String,
    pub currency: String,
    pub would_have_run_bps: String,
    pub sibling_redundancy_bps: String,
    pub guarantee_class_bps: String,
}

/// Complete input to [`finding_bid_ceiling`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingBidCeilingInput {
    pub estimate: BuyerFindingEstimate,
    pub policy: FindingBidCeilingPolicy,
    pub expected_source_sha256: String,
    pub expected_context_sha256: String,
    pub expected_replay_recipe_sha256: String,
    pub now_unix_ms: String,
}

/// Fail-closed rejections from the buyer-local bid-ceiling helper.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingBidCeilingError {
    #[error("{field} must be a canonical unsigned decimal-string integer")]
    InvalidDecimal { field: &'static str },
    #[error("{field} exceeds the Rust u64 boundary")]
    U64Overflow { field: &'static str },
    #[error("{field} basis points exceed 10000")]
    BasisPointsOutOfRange { field: &'static str },
    #[error("estimate and budget currencies differ")]
    CurrencyMismatch,
    #[error("buyer estimate provenance is not supported")]
    ProvenanceUnsupported,
    #[error("buyer estimate source digest was substituted")]
    SourceSubstituted,
    #[error("buyer estimate context digest was substituted")]
    ContextSubstituted,
    #[error("buyer estimate replay-recipe digest was substituted")]
    ReplayRecipeSubstituted,
    #[error("{field} must be canonical lowercase 64-hex")]
    DigestMalformed { field: &'static str },
    #[error("buyer estimate validity window is invalid")]
    InvalidValidityWindow,
    #[error("buyer estimate is not live at the supplied clock")]
    StaleEstimate,
    #[error("bid-ceiling wide intermediate overflowed u128")]
    IntermediateOverflow,
}

/// Compute the exact buyer-local finding bid ceiling.
///
/// All integers are canonical decimal strings. Amounts and timestamps are
/// bounded to `u64`; basis points are bounded to `0..=10_000`. The discount is
/// multiplied with checked `u128` intermediates and rounded down exactly once:
///
/// `floor(estimate * would_run * (10000 - redundancy) * guarantee / 10000^3)`
///
/// The returned decimal string is then capped by the buyer's remaining budget.
pub fn finding_bid_ceiling(
    input: &FindingBidCeilingInput,
) -> Result<String, FindingBidCeilingError> {
    validate_currency(&input.estimate.currency)?;
    validate_currency(&input.policy.currency)?;
    if input.estimate.currency != input.policy.currency {
        return Err(FindingBidCeilingError::CurrencyMismatch);
    }
    validate_provenance(&input.estimate.provenance)?;
    validate_digest(&input.estimate.source_sha256, "estimate.source_sha256")?;
    validate_digest(&input.estimate.context_sha256, "estimate.context_sha256")?;
    validate_digest(
        &input.estimate.replay_recipe_sha256,
        "estimate.replay_recipe_sha256",
    )?;
    validate_digest(&input.expected_source_sha256, "expected_source_sha256")?;
    validate_digest(&input.expected_context_sha256, "expected_context_sha256")?;
    validate_digest(
        &input.expected_replay_recipe_sha256,
        "expected_replay_recipe_sha256",
    )?;
    if input.estimate.source_sha256 != input.expected_source_sha256 {
        return Err(FindingBidCeilingError::SourceSubstituted);
    }
    if input.estimate.context_sha256 != input.expected_context_sha256 {
        return Err(FindingBidCeilingError::ContextSubstituted);
    }
    if input.estimate.replay_recipe_sha256 != input.expected_replay_recipe_sha256 {
        return Err(FindingBidCeilingError::ReplayRecipeSubstituted);
    }

    let estimate = parse_u64_decimal(&input.estimate.units, "estimate.units")?;
    let budget = parse_u64_decimal(
        &input.policy.budget_remaining_units,
        "policy.budget_remaining_units",
    )?;
    let would_run = parse_bps(
        &input.policy.would_have_run_bps,
        "policy.would_have_run_bps",
    )?;
    let redundancy = parse_bps(
        &input.policy.sibling_redundancy_bps,
        "policy.sibling_redundancy_bps",
    )?;
    let guarantee = parse_bps(
        &input.policy.guarantee_class_bps,
        "policy.guarantee_class_bps",
    )?;
    let observed = parse_u64_decimal(
        &input.estimate.observed_at_unix_ms,
        "estimate.observed_at_unix_ms",
    )?;
    let valid_until = parse_u64_decimal(
        &input.estimate.valid_until_unix_ms,
        "estimate.valid_until_unix_ms",
    )?;
    let now = parse_u64_decimal(&input.now_unix_ms, "now_unix_ms")?;
    if observed >= valid_until {
        return Err(FindingBidCeilingError::InvalidValidityWindow);
    }
    if now < observed || now >= valid_until {
        return Err(FindingBidCeilingError::StaleEstimate);
    }

    let retained = BASIS_POINTS
        .checked_sub(redundancy)
        .ok_or(FindingBidCeilingError::IntermediateOverflow)?;
    let discounted = estimate
        .checked_mul(would_run)
        .and_then(|value| value.checked_mul(retained))
        .and_then(|value| value.checked_mul(guarantee))
        .ok_or(FindingBidCeilingError::IntermediateOverflow)?
        / COMBINED_BASIS_POINTS_DENOMINATOR;
    Ok(discounted.min(budget).to_string())
}

fn validate_provenance(value: &str) -> Result<(), FindingBidCeilingError> {
    if matches!(
        value,
        BUYER_METERING_HISTORY_V1 | BUYER_FRESH_METERED_QUOTE_V1
    ) {
        Ok(())
    } else {
        Err(FindingBidCeilingError::ProvenanceUnsupported)
    }
}

fn validate_currency(value: &str) -> Result<(), FindingBidCeilingError> {
    if !value.is_empty()
        && value.len() <= 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        Ok(())
    } else {
        Err(FindingBidCeilingError::CurrencyMismatch)
    }
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), FindingBidCeilingError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(FindingBidCeilingError::DigestMalformed { field })
    }
}

fn parse_bps(value: &str, field: &'static str) -> Result<u128, FindingBidCeilingError> {
    let parsed = parse_u64_decimal(value, field)?;
    if parsed > BASIS_POINTS {
        Err(FindingBidCeilingError::BasisPointsOutOfRange { field })
    } else {
        Ok(parsed)
    }
}

fn parse_u64_decimal(value: &str, field: &'static str) -> Result<u128, FindingBidCeilingError> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(FindingBidCeilingError::InvalidDecimal { field });
    }
    let parsed = value
        .parse::<u128>()
        .map_err(|_| FindingBidCeilingError::U64Overflow { field })?;
    if parsed > MAX_U64_DECIMAL {
        return Err(FindingBidCeilingError::U64Overflow { field });
    }
    Ok(parsed)
}
