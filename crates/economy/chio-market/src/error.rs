//! Typed validation errors for liability-market artifacts.
//!
//! Every artifact validator in this crate denies with a [`MarketError`]: a
//! closed machine-readable family plus operator prose. The code is the
//! stable matching surface for telemetry and evidence consumers; the prose
//! is free to evolve and is never matched on.

use std::fmt;

/// Closed error families for liability-market artifact validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MarketErrorCode {
    /// The artifact carries an unsupported schema identifier.
    SchemaUnsupported,
    /// An embedded signed envelope or authority-step proof failed
    /// signature verification.
    SignatureInvalid,
    /// A field is missing, empty, malformed, duplicated, or present where
    /// the artifact shape forbids it.
    FieldInvalid,
    /// A monetary amount is zero or violates a declared bound.
    AmountOutOfBounds,
    /// A currency differs between artifacts that must settle in one
    /// currency.
    CurrencyMismatch,
    /// Cross-artifact fields that must agree do not, or a required
    /// counterpart entry is absent.
    BindingMismatch,
    /// A validity window is empty, expired, stale, or an event falls
    /// outside it.
    WindowInvalid,
    /// A referenced artifact is not in the lifecycle or reconciliation
    /// state this operation requires.
    StateInvalid,
}

impl MarketErrorCode {
    /// Stable snake_case identifier for telemetry and evidence keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SchemaUnsupported => "schema_unsupported",
            Self::SignatureInvalid => "signature_invalid",
            Self::FieldInvalid => "field_invalid",
            Self::AmountOutOfBounds => "amount_out_of_bounds",
            Self::CurrencyMismatch => "currency_mismatch",
            Self::BindingMismatch => "binding_mismatch",
            Self::WindowInvalid => "window_invalid",
            Self::StateInvalid => "state_invalid",
        }
    }
}

impl fmt::Display for MarketErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One artifact-validation denial.
///
/// Displays as its prose detail so existing receipt and log text is
/// unchanged; consumers that need the family match on [`Self::code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarketError {
    code: MarketErrorCode,
    detail: String,
}

impl MarketError {
    /// Build a denial from an explicit family and prose detail.
    #[must_use]
    pub fn new(code: MarketErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// The closed error family.
    #[must_use]
    pub const fn code(&self) -> MarketErrorCode {
        self.code
    }

    /// Operator prose. Never a matching surface.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The artifact schema identifier is not one this crate validates.
    #[must_use]
    pub fn schema_unsupported(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::SchemaUnsupported, detail)
    }

    /// A signature or envelope failed cryptographic verification.
    #[must_use]
    pub fn signature_invalid(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::SignatureInvalid, detail)
    }

    /// A required field is missing, empty, malformed, or duplicated.
    #[must_use]
    pub fn field_invalid(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::FieldInvalid, detail)
    }

    /// A monetary amount is zero or violates a declared bound.
    #[must_use]
    pub fn amount_out_of_bounds(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::AmountOutOfBounds, detail)
    }

    /// Two amounts that must share a currency do not.
    #[must_use]
    pub fn currency_mismatch(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::CurrencyMismatch, detail)
    }

    /// Cross-artifact fields that must agree do not.
    #[must_use]
    pub fn binding_mismatch(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::BindingMismatch, detail)
    }

    /// A validity window is empty, expired, or excludes the event.
    #[must_use]
    pub fn window_invalid(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::WindowInvalid, detail)
    }

    /// A lifecycle prerequisite for this operation does not hold.
    #[must_use]
    pub fn state_invalid(detail: impl Into<String>) -> Self {
        Self::new(MarketErrorCode::StateInvalid, detail)
    }
}

impl fmt::Display for MarketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for MarketError {}

impl From<MarketError> for String {
    fn from(error: MarketError) -> Self {
        error.detail
    }
}

/// Closed failure families for the injected insurance seams.
///
/// The seams reach outside this crate for premium inputs, receipt
/// evidence, and settlement execution. Their failures are integration
/// failures rather than artifact-validation failures, so they carry their
/// own family instead of borrowing [`MarketErrorCode`], whose variants
/// describe malformed artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InsuranceSeamErrorCode {
    /// The upstream is unreachable, unconfigured, or declined to answer.
    Unavailable,
    /// The referenced subject does not exist upstream.
    NotFound,
    /// The upstream answered, and the answer does not verify.
    EvidenceInvalid,
    /// The upstream understood the request and refused it.
    Rejected,
}

impl InsuranceSeamErrorCode {
    /// Stable snake_case identifier for telemetry and evidence keys.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::NotFound => "not_found",
            Self::EvidenceInvalid => "evidence_invalid",
            Self::Rejected => "rejected",
        }
    }
}

impl fmt::Display for InsuranceSeamErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One failure from an injected insurance seam.
///
/// Displays as its prose detail so existing operator text is unchanged;
/// consumers that need the family match on [`Self::code`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsuranceSeamError {
    code: InsuranceSeamErrorCode,
    detail: String,
}

impl InsuranceSeamError {
    /// Construct a seam failure in the given family.
    #[must_use]
    pub fn new(code: InsuranceSeamErrorCode, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// The closed failure family.
    #[must_use]
    pub const fn code(&self) -> InsuranceSeamErrorCode {
        self.code
    }

    /// Operator prose. Never a matching surface.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// The upstream is unreachable, unconfigured, or declined to answer.
    #[must_use]
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(InsuranceSeamErrorCode::Unavailable, detail)
    }

    /// The referenced subject does not exist upstream.
    #[must_use]
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(InsuranceSeamErrorCode::NotFound, detail)
    }

    /// The upstream answered, and the answer does not verify.
    #[must_use]
    pub fn evidence_invalid(detail: impl Into<String>) -> Self {
        Self::new(InsuranceSeamErrorCode::EvidenceInvalid, detail)
    }

    /// The upstream understood the request and refused it.
    #[must_use]
    pub fn rejected(detail: impl Into<String>) -> Self {
        Self::new(InsuranceSeamErrorCode::Rejected, detail)
    }

    /// Name the call this failure came from without losing its family.
    #[must_use]
    pub fn prefixed(self, prefix: &str) -> Self {
        Self {
            code: self.code,
            detail: format!("{prefix}: {}", self.detail),
        }
    }
}

impl fmt::Display for InsuranceSeamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for InsuranceSeamError {}

impl From<InsuranceSeamError> for String {
    fn from(error: InsuranceSeamError) -> Self {
        error.detail
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_detail_only() {
        let error = MarketError::currency_mismatch("premium currency must match policy currency");
        assert_eq!(
            error.to_string(),
            "premium currency must match policy currency"
        );
        assert_eq!(error.code(), MarketErrorCode::CurrencyMismatch);
        assert_eq!(error.code().as_str(), "currency_mismatch");
    }

    #[test]
    fn a_seam_failure_displays_its_detail_and_matches_on_its_family() {
        let error = InsuranceSeamError::not_found("receipt is unknown to the store");
        assert_eq!(error.to_string(), "receipt is unknown to the store");
        assert_eq!(error.code(), InsuranceSeamErrorCode::NotFound);
        assert_eq!(error.code().as_str(), "not_found");
    }

    #[test]
    fn string_conversion_preserves_detail() {
        let error = MarketError::window_invalid("quote expired");
        assert_eq!(String::from(error), "quote expired");
    }
}
