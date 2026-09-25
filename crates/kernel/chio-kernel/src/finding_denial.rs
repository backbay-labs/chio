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

/// Record a denial family on a receipt's admission metadata.
///
/// The receipt already carries an optional metadata object, so the family
/// travels inside the signed body without changing the decision's shape.
/// An offline verifier can classify the refusal without parsing prose,
/// which the reason field alone never allowed.
#[must_use]
pub fn record_finding_denial(
    metadata: Option<serde_json::Value>,
    code: FindingDenialCode,
) -> Option<serde_json::Value> {
    let mut object = match metadata {
        Some(serde_json::Value::Object(object)) => object,
        // A non-object metadata value belongs to whoever set it; the
        // family is dropped rather than overwriting another record.
        Some(other) => return Some(other),
        None => serde_json::Map::new(),
    };
    object.insert(
        FINDING_DENIAL_METADATA_KEY.to_owned(),
        serde_json::Value::String(code.as_str().to_owned()),
    );
    Some(serde_json::Value::Object(object))
}

/// Metadata key naming the denial family on a receipt.
pub const FINDING_DENIAL_METADATA_KEY: &str = "findingDenial";

/// Borrowing form of [`record_finding_denial`] for a deny path that still
/// needs its metadata afterwards.
#[must_use]
pub fn denied_metadata(
    metadata: &Option<serde_json::Value>,
    denial: &FindingDenial,
) -> Option<serde_json::Value> {
    record_finding_denial(metadata.clone(), denial.code())
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
    fn a_recorded_denial_joins_the_metadata_the_receipt_already_carries() {
        let existing = serde_json::json!({"runtimeAdmission": "durable"});
        let recorded = record_finding_denial(Some(existing), FindingDenialCode::StatusDenied)
            .expect("metadata is present");
        assert_eq!(recorded["runtimeAdmission"], "durable");
        assert_eq!(recorded[FINDING_DENIAL_METADATA_KEY], "status_denied");

        let created = record_finding_denial(None, FindingDenialCode::QuotaExhausted)
            .expect("metadata is created");
        assert_eq!(created[FINDING_DENIAL_METADATA_KEY], "quota_exhausted");
    }

    #[test]
    fn a_non_object_metadata_value_is_left_to_its_owner() {
        let opaque = serde_json::json!("opaque");
        assert_eq!(
            record_finding_denial(Some(opaque.clone()), FindingDenialCode::Unavailable),
            Some(opaque)
        );
    }

    #[test]
    fn string_conversion_preserves_detail() {
        let denial = FindingDenial::unavailable("store offline");
        assert_eq!(String::from(denial), "store offline");
    }
}
