//! Typed denial vocabulary for the injected finding verifier seams.
//!
//! Every verifier behind [`crate::finding_purchase::FindingPurchaseVerifier`],
//! [`crate::finding_purchase::FindingStatusProofVerifier`], and
//! [`crate::finding_recovery::FindingRecoveryVerifier`] denies with a
//! [`FindingDenial`]: a closed machine-readable family plus operator prose.
//! The code is the stable matching surface for telemetry and evidence
//! consumers; the prose is free to evolve and is never matched on.

use std::fmt;

/// Closed denial families for the finding purchase, status, and recovery
/// seams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingDenialCode {
    /// The carrier or an embedded artifact failed to decode or parse.
    CarrierInvalid,
    /// A signature, authority pin, operator authorization, or service bond
    /// failed verification or is not live.
    AuthorityInvalid,
    /// Verified fields do not bind the request, grant, capability, or the
    /// matching durable record.
    BindingMismatch,
    /// Freshness, floor monotonicity, or rollback admission failed.
    StaleOrSuperseded,
    /// The authoritative status feed denies the finding: retraction is
    /// pending or published.
    StatusDenied,
    /// A durable attempt quota is exhausted.
    QuotaExhausted,
    /// A durable store, clock, or required verifier capability was
    /// unavailable; the seam fails closed.
    Unavailable,
}

impl FindingDenialCode {
    /// Stable snake_case identifier for telemetry and evidence keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CarrierInvalid => "carrier_invalid",
            Self::AuthorityInvalid => "authority_invalid",
            Self::BindingMismatch => "binding_mismatch",
            Self::StaleOrSuperseded => "stale_or_superseded",
            Self::StatusDenied => "status_denied",
            Self::QuotaExhausted => "quota_exhausted",
            Self::Unavailable => "unavailable",
        }
    }
}

impl fmt::Display for FindingDenialCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One denial from an injected finding verifier.
///
/// Displays as its prose detail so existing receipt and log text is
/// unchanged; consumers that need the family match on [`Self::code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingDenial {
    code: FindingDenialCode,
    detail: String,
}

impl FindingDenial {
    #[must_use]
    pub fn new(code: FindingDenialCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// The closed denial family.
    #[must_use]
    pub const fn code(&self) -> FindingDenialCode {
        self.code
    }

    /// Operator prose. Never a matching surface.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Name the gate this denial passed through without losing its family.
    ///
    /// A gate that adds context to a verifier's prose keeps the code the
    /// verifier chose, so the reason a request was denied survives the
    /// distance between the seam that decided it and the evidence that
    /// records it.
    #[must_use]
    pub fn prefixed(self, prefix: &str) -> Self {
        Self {
            code: self.code,
            detail: format!("{prefix}: {}", self.detail),
        }
    }

    #[must_use]
    pub fn carrier_invalid(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::CarrierInvalid, detail)
    }

    #[must_use]
    pub fn authority_invalid(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::AuthorityInvalid, detail)
    }

    #[must_use]
    pub fn binding_mismatch(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::BindingMismatch, detail)
    }

    #[must_use]
    pub fn stale_or_superseded(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::StaleOrSuperseded, detail)
    }

    #[must_use]
    pub fn status_denied(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::StatusDenied, detail)
    }

    #[must_use]
    pub fn quota_exhausted(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::QuotaExhausted, detail)
    }

    #[must_use]
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(FindingDenialCode::Unavailable, detail)
    }
}

impl fmt::Display for FindingDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for FindingDenial {}

impl From<FindingDenial> for String {
    fn from(denial: FindingDenial) -> Self {
        denial.detail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_detail_only() {
        let denial = FindingDenial::status_denied("finding is retracted");
        assert_eq!(denial.to_string(), "finding is retracted");
        assert_eq!(denial.code(), FindingDenialCode::StatusDenied);
        assert_eq!(denial.code().as_str(), "status_denied");
    }

    #[test]
    fn a_prefix_keeps_the_family_and_extends_the_prose() {
        let denial = FindingDenial::binding_mismatch("payer key does not match")
            .prefixed("purchase context rejected");
        assert_eq!(denial.code(), FindingDenialCode::BindingMismatch);
        assert_eq!(
            denial.to_string(),
            "purchase context rejected: payer key does not match"
        );
    }

    #[test]
    fn string_conversion_preserves_detail() {
        let denial = FindingDenial::unavailable("store offline");
        assert_eq!(String::from(denial), "store offline");
    }
}
