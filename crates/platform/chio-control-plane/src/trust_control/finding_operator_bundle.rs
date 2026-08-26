//! Closed public-artifact bundle for the single-operator purchase runtime.

use chio_finding::{
    signed_envelope_sha256, verify_finding, verify_signed_admission, verify_signed_bond_backing,
    verify_signed_market_terms, verify_signed_profile, verify_signed_seller_authorization,
    verify_signed_verifier_report, Finding, SignedFindingAdmission, SignedFindingBondBacking,
    SignedFindingChallengeVerifierProfile, SignedFindingMarketTerms,
    SignedFindingSellerAuthorization, SignedFindingVerifierReport,
};
use chio_open_market::fee_schedule::SignedOpenMarketFeeSchedule;
use chio_open_market::fiscal_adapter::signed_fee_schedule_digest;
use chio_open_market::listing::{ensure_generic_listing_signed_by_namespace_owner, Listing};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::FindingMarketConfig;

pub const FINDING_OPERATOR_BUNDLE_SCHEMA: &str = "chio.finding.operator-bundle.v1";

/// Exact artifacts required to mint a purchase ask, verify admission, build
/// the reveal carrier, and return a buyer proof bundle after restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingOperatorBundle {
    pub schema: String,
    pub finding: Finding,
    pub listing: Listing,
    pub admission: SignedFindingAdmission,
    pub market_terms: SignedFindingMarketTerms,
    pub seller_authorization: SignedFindingSellerAuthorization,
    pub verifier_profile: SignedFindingChallengeVerifierProfile,
    pub bond_backing: SignedFindingBondBacking,
    pub verifier_report: SignedFindingVerifierReport,
    pub fee_schedule: SignedOpenMarketFeeSchedule,
}

#[derive(Debug, Error)]
pub enum FindingOperatorBundleError {
    #[error("unsupported finding operator bundle schema")]
    UnsupportedSchema,
    #[error("finding operator bundle artifact failed verification: {0}")]
    Artifact(String),
    #[error("finding operator bundle binding mismatch: {0}")]
    Binding(&'static str),
    #[error("finding operator bundle is outside its validity window: {0}")]
    Expired(&'static str),
    #[error("finding operator bundle canonicalization failed")]
    Canonicalization,
}

impl FindingOperatorBundle {
    /// Verify signatures, configured authority pins, digest bindings, and
    /// current liveness before the bundle can drive a new purchase.
    pub fn verify_at(
        &self,
        config: &FindingMarketConfig,
        now: u64,
    ) -> Result<(), FindingOperatorBundleError> {
        if self.schema != FINDING_OPERATOR_BUNDLE_SCHEMA {
            return Err(FindingOperatorBundleError::UnsupportedSchema);
        }
        verify_finding(&self.finding)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;

        let venue = config
            .venue
            .key()
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        verify_signed_admission(&self.admission, &venue, &config.venue_id)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        let listing_key = config
            .listing
            .key()
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        ensure_generic_listing_signed_by_namespace_owner(
            &self.listing.listing,
            "finding operator listing",
        )
        .map_err(FindingOperatorBundleError::Artifact)?;
        if self
            .listing
            .listing
            .body
            .namespace_ownership
            .signer_public_key
            != listing_key
        {
            return Err(FindingOperatorBundleError::Binding("listing authority"));
        }
        self.listing
            .pricing
            .body
            .validate()
            .map_err(FindingOperatorBundleError::Artifact)?;
        if self.listing.pricing.signer_key != listing_key
            || !self
                .listing
                .pricing
                .verify_signature()
                .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?
        {
            return Err(FindingOperatorBundleError::Binding("pricing authority"));
        }

        verify_signed_seller_authorization(&self.seller_authorization)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        verify_signed_market_terms(&self.market_terms)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        let governance = config
            .governance_root
            .key()
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        verify_signed_profile(&self.verifier_profile, &governance)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        let collateral = config
            .collateral
            .key()
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        verify_signed_bond_backing(&self.bond_backing, &collateral)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        let verifier = config
            .verifier_report
            .key()
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        verify_signed_verifier_report(&self.verifier_report, &verifier)
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?;
        self.fee_schedule
            .body
            .validate()
            .map_err(FindingOperatorBundleError::Artifact)?;
        if !self
            .fee_schedule
            .verify_signature()
            .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?
            || !config
                .fee_schedule_operators()
                .map_err(|error| FindingOperatorBundleError::Artifact(error.to_string()))?
                .contains(&self.fee_schedule.signer_key)
        {
            return Err(FindingOperatorBundleError::Binding(
                "fee schedule authority",
            ));
        }

        self.verify_bindings()?;
        self.verify_liveness(now)
    }

    fn verify_bindings(&self) -> Result<(), FindingOperatorBundleError> {
        let admission = &self.admission.body;
        if admission.finding_id != self.finding.finding_id
            || self.market_terms.body.finding_id != self.finding.finding_id
            || self.seller_authorization.body.finding_id != self.finding.finding_id
            || self.bond_backing.body.finding_id != self.finding.finding_id
            || self.verifier_report.body.finding_id != self.finding.finding_id
        {
            return Err(FindingOperatorBundleError::Binding("finding identity"));
        }
        let finding_sha256 = canonical_sha256(&self.finding)?;
        if admission.finding_artifact_sha256 != finding_sha256
            || self.market_terms.body.finding_artifact_sha256 != finding_sha256
            || self.seller_authorization.body.finding_artifact_sha256 != finding_sha256
            || self.verifier_report.body.finding_artifact_sha256 != finding_sha256
        {
            return Err(FindingOperatorBundleError::Binding("finding artifact"));
        }
        if admission.listing_id != self.listing.listing.body.listing_id
            || admission.listing_id != self.listing.pricing.body.listing_id
            || admission.listing_id != self.market_terms.body.listing_id
            || admission.listing_id != self.seller_authorization.body.listing_id
            || admission.listing_id != self.bond_backing.body.listing_id
        {
            return Err(FindingOperatorBundleError::Binding("listing identity"));
        }
        let checks = [
            (
                admission.listing_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.listing.listing)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "listing envelope",
            ),
            (
                admission.pricing_hint_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.listing.pricing)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "pricing envelope",
            ),
            (
                admission.seller_authorization_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.seller_authorization)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "seller authorization envelope",
            ),
            (
                admission.terms_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.market_terms)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "terms envelope",
            ),
            (
                admission.profile_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.verifier_profile)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "profile envelope",
            ),
            (
                admission.backing_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.bond_backing)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "backing envelope",
            ),
            (
                admission.verifier_report_envelope_sha256.as_str(),
                signed_envelope_sha256(&self.verifier_report)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "verifier report envelope",
            ),
            (
                admission.fee_schedule_envelope_sha256.as_str(),
                signed_fee_schedule_digest(&self.fee_schedule)
                    .map_err(|_| FindingOperatorBundleError::Canonicalization)?,
                "fee schedule envelope",
            ),
        ];
        for (expected, actual, label) in checks {
            if expected != actual {
                return Err(FindingOperatorBundleError::Binding(label));
            }
        }
        if admission.backing_allocation_id != self.bond_backing.body.allocation_id
            || admission.verifier_report_id != self.verifier_report.body.report_id
            || admission.capability_scope != format!("finding:{}", self.finding.finding_id)
            || admission.server_id != self.seller_authorization.body.provider_server_id
        {
            return Err(FindingOperatorBundleError::Binding(
                "admission constituents",
            ));
        }
        Ok(())
    }

    fn verify_liveness(&self, now: u64) -> Result<(), FindingOperatorBundleError> {
        let windows = [
            (self.finding.issued_at, self.finding.expires_at, "finding"),
            (
                self.admission.body.issued_at,
                self.admission.body.expires_at,
                "admission",
            ),
            (
                self.market_terms.body.issued_at,
                self.market_terms.body.expires_at,
                "market terms",
            ),
            (
                self.seller_authorization.body.issued_at,
                self.seller_authorization.body.expires_at,
                "seller authorization",
            ),
            (
                self.verifier_profile.body.issued_at,
                self.verifier_profile.body.expires_at,
                "verifier profile",
            ),
            (
                self.bond_backing.body.issued_at,
                self.bond_backing.body.expires_at,
                "bond backing",
            ),
            (
                self.listing.pricing.body.issued_at,
                self.listing.pricing.body.expires_at,
                "pricing hint",
            ),
        ];
        for (issued_at, expires_at, label) in windows {
            if now < issued_at || now >= expires_at {
                return Err(FindingOperatorBundleError::Expired(label));
            }
        }
        if !self.listing.is_admissible_at(now) {
            return Err(FindingOperatorBundleError::Expired("listing"));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<Vec<u8>, FindingOperatorBundleError> {
        chio_core::canonical_json_bytes(self)
            .map_err(|_| FindingOperatorBundleError::Canonicalization)
    }
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, FindingOperatorBundleError> {
    chio_core::canonical_json_bytes(value)
        .map(|bytes| chio_core::sha256_hex(&bytes))
        .map_err(|_| FindingOperatorBundleError::Canonicalization)
}
