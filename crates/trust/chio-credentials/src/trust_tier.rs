//! Trust-tier synthesis for Agent Passports.
//!
//! Collapses the compliance score from `chio_kernel::compliance_score`
//! and the behavioral-anomaly signal from
//! `chio_kernel::operator_report::behavioral_anomaly_score` into a single
//! coarse tier that relying parties can gate access on without needing
//! to reason about the full factor breakdown.
//!
//! The mapping is deliberately conservative and deterministic:
//!
//! | Compliance score           | Anomaly | Tier        |
//! |----------------------------|---------|-------------|
//! | score < 300                |  any    | Unverified  |
//! | 300 <= score < 700         |  any    | Attested    |
//! | 700 <= score < 900         |  any    | Verified    |
//! | score >= 900, anomaly=true |         | Verified    |
//! | score >= 900, anomaly=false|         | Premier     |
//!
//! A behavioral anomaly can never lift a low compliance score into a
//! higher tier, but it does block the jump from `Verified` to `Premier`.
//! This keeps the tier monotone in compliance and defensively pessimistic
//! in the presence of live behavioral alerts.

use serde::{Deserialize, Serialize};

/// Inclusive lower bound for the `Attested` tier. Scores below this
/// threshold are `Unverified`.
pub const TRUST_TIER_ATTESTED_MIN: u32 = 300;
/// Inclusive lower bound for the `Verified` tier.
pub const TRUST_TIER_VERIFIED_MIN: u32 = 700;
/// Inclusive lower bound for the `Premier` tier (behavioral anomaly must
/// also be clear).
pub const TRUST_TIER_PREMIER_MIN: u32 = 900;

/// Coarse trust tier derived from an agent's compliance score and
/// behavioral anomaly status.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum TrustTier {
    /// Score below `TRUST_TIER_ATTESTED_MIN`. Relying parties should
    /// treat this agent as untrusted and require step-up evidence.
    Unverified,
    /// Score in `[TRUST_TIER_ATTESTED_MIN, TRUST_TIER_VERIFIED_MIN)`.
    /// Baseline attestation is present but neither the compliance nor
    /// behavioral signals cross the "verified" threshold.
    Attested,
    /// Score in `[TRUST_TIER_VERIFIED_MIN, TRUST_TIER_PREMIER_MIN)`, or
    /// `score >= TRUST_TIER_PREMIER_MIN` with an active behavioral
    /// anomaly.
    Verified,
    /// Score `>= TRUST_TIER_PREMIER_MIN` with no active behavioral
    /// anomaly.
    Premier,
}

impl TrustTier {
    /// Human-readable kebab-case label matching the serde encoding.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Attested => "attested",
            Self::Verified => "verified",
            Self::Premier => "premier",
        }
    }
}

/// Synthesize a [`TrustTier`] from a compliance score (0..=1000) and a
/// behavioral anomaly flag.
///
/// The function is pure: it depends only on its inputs. Scores are
/// clamped below the maximum so callers that feed in wider integer
/// ranges (e.g. the uncapped factor sum during debugging) still get
/// a well-defined tier.
#[must_use]
pub fn synthesize_trust_tier(compliance_score: u32, behavioral_anomaly: bool) -> TrustTier {
    if compliance_score >= TRUST_TIER_PREMIER_MIN && !behavioral_anomaly {
        TrustTier::Premier
    } else if compliance_score >= TRUST_TIER_VERIFIED_MIN {
        TrustTier::Verified
    } else if compliance_score >= TRUST_TIER_ATTESTED_MIN {
        TrustTier::Attested
    } else {
        TrustTier::Unverified
    }
}
