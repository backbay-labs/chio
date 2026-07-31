//! `chio.finding.market-terms.v1`: seller-signed sale terms for one
//! finding listing.
//!
//! Terms bind the canonical backing REQUIREMENT and policy, never the
//! later backing-envelope digest: backing may bind terms, so the reverse
//! edge would be a hash cycle. The envelope signer must equal the embedded
//! seller key.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::types::FindingGuaranteeClass;
use crate::validate::{
    require_bounded_id, require_currency, require_hex64, require_i_json_u64, require_max_items,
    require_nonzero, require_window, FindingError, MAX_FINDING_ARTIFACT_ITEMS,
};

/// Seller-signed market terms.
pub const FINDING_MARKET_TERMS_SCHEMA_V1: &str =
    chio_core_types::CHIO_FINDING_MARKET_TERMS_V1_SCHEMA;

/// The single payout policy the settlement math implements. The policy
/// vocabulary is closed here: a distribution computed under one policy
/// must never settle terms that promised another, so terms naming any
/// other policy reject at validation.
pub const FINDING_PAYOUT_POLICY_PRO_RATA_CAPPED_V1: &str = "pro_rata_capped_v1";

/// Canonical backing requirement the admission sizing check enforces
/// against the exact signed fee schedule:
/// `listing_requirement.required_amount >= base_finding_stake +
/// maximum_sale_exposure`, checked arithmetic, exact currency equality.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingBackingRequirement {
    pub base_finding_stake: MonetaryAmount,
    pub maximum_sale_exposure: MonetaryAmount,
    /// Collateral policy vocabulary; the only defined value today is
    /// `venue_ledger_exclusive_v1`.
    pub collateral_policy: String,
}

impl FindingBackingRequirement {
    fn validate(&self) -> Result<(), FindingError> {
        require_nonzero(
            self.base_finding_stake.units,
            "backing_requirement.base_finding_stake",
        )?;
        require_currency(
            &self.base_finding_stake.currency,
            "backing_requirement.base_finding_stake.currency",
        )?;
        require_nonzero(
            self.maximum_sale_exposure.units,
            "backing_requirement.maximum_sale_exposure",
        )?;
        require_currency(
            &self.maximum_sale_exposure.currency,
            "backing_requirement.maximum_sale_exposure.currency",
        )?;
        if self.base_finding_stake.currency != self.maximum_sale_exposure.currency {
            return Err(FindingError::CurrencyMismatch("backing_requirement"));
        }
        require_bounded_id(
            &self.collateral_policy,
            "backing_requirement.collateral_policy",
        )?;
        Ok(())
    }

    /// Total promised backing with checked arithmetic.
    pub fn required_backing_units(&self) -> Result<u64, FindingError> {
        self.base_finding_stake
            .units
            .checked_add(self.maximum_sale_exposure.units)
            .ok_or(FindingError::AmountOverflow("backing_requirement"))
    }
}

/// Guarantee-class-specific challenge bond limits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingChallengeBondLimit {
    pub guarantee_class: FindingGuaranteeClass,
    pub min_bond: MonetaryAmount,
    pub max_bond: MonetaryAmount,
}

impl FindingChallengeBondLimit {
    fn validate(&self) -> Result<(), FindingError> {
        require_nonzero(self.min_bond.units, "challenge_bond_limits[].min_bond")?;
        require_currency(
            &self.min_bond.currency,
            "challenge_bond_limits[].min_bond.currency",
        )?;
        require_i_json_u64(self.max_bond.units, "challenge_bond_limits[].max_bond")?;
        require_currency(
            &self.max_bond.currency,
            "challenge_bond_limits[].max_bond.currency",
        )?;
        if self.min_bond.currency != self.max_bond.currency {
            return Err(FindingError::CurrencyMismatch("challenge_bond_limits[]"));
        }
        if self.max_bond.units < self.min_bond.units {
            return Err(FindingError::InvalidField("challenge_bond_limits[]"));
        }
        Ok(())
    }
}

/// Seller-signed market terms body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingMarketTerms {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with `terms_id`
    /// cleared.
    pub terms_id: String,
    pub finding_id: String,
    /// Digest of the exact canonical signed Finding artifact (the finding
    /// family signs inline, so artifact bytes are the identity).
    pub finding_artifact_sha256: String,
    pub listing_id: String,
    /// Seller (or delegate) that must sign the enclosing envelope.
    pub seller: PublicKey,
    pub backing_requirement: FindingBackingRequirement,
    pub filing_window_secs: u64,
    pub claim_window_secs: u64,
    pub appeal_window_secs: u64,
    /// Recurring participation-fee cadence; epoch 0 starts at
    /// activation.
    pub audit_epoch_length_secs: u64,
    pub audit_eligible: bool,
    pub decision_rule_refs: Vec<String>,
    /// Envelope digest of the ALREADY admitted reusable verifier profile.
    pub verifier_profile_envelope_sha256: String,
    pub challenge_bond_limits: Vec<FindingChallengeBondLimit>,
    /// Deterministic payout policy vocabulary; the only defined value
    /// today is `pro_rata_capped_v1`.
    pub payout_policy: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Seller-signed envelope for the terms.
pub type SignedFindingMarketTerms = SignedExportEnvelope<FindingMarketTerms>;

impl FindingMarketTerms {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_MARKET_TERMS_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.terms_id, "terms_id")?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_hex64(&self.finding_artifact_sha256, "finding_artifact_sha256")?;
        require_bounded_id(&self.listing_id, "listing_id")?;
        require_ed25519(&self.seller, "seller")?;
        self.backing_requirement.validate()?;
        require_nonzero(self.filing_window_secs, "filing_window_secs")?;
        require_nonzero(self.claim_window_secs, "claim_window_secs")?;
        require_nonzero(self.appeal_window_secs, "appeal_window_secs")?;
        require_nonzero(self.audit_epoch_length_secs, "audit_epoch_length_secs")?;
        if self.decision_rule_refs.is_empty() {
            return Err(FindingError::MissingEntry("decision_rule_refs"));
        }
        require_max_items(
            self.decision_rule_refs.len(),
            "decision_rule_refs",
            MAX_FINDING_ARTIFACT_ITEMS,
        )?;
        let mut rules = std::collections::BTreeSet::new();
        for rule in &self.decision_rule_refs {
            require_bounded_id(rule, "decision_rule_refs[]")?;
            if !rules.insert(rule.as_str()) {
                return Err(FindingError::DuplicateEntry("decision_rule_refs[]"));
            }
        }
        require_hex64(
            &self.verifier_profile_envelope_sha256,
            "verifier_profile_envelope_sha256",
        )?;
        if self.challenge_bond_limits.is_empty() {
            return Err(FindingError::MissingEntry("challenge_bond_limits"));
        }
        let mut classes = std::collections::BTreeSet::new();
        for limit in &self.challenge_bond_limits {
            limit.validate()?;
            if !classes.insert(limit.guarantee_class as u8) {
                return Err(FindingError::DuplicateEntry("challenge_bond_limits[]"));
            }
        }
        if self.payout_policy != FINDING_PAYOUT_POLICY_PRO_RATA_CAPPED_V1 {
            return Err(FindingError::InvalidField("payout_policy"));
        }
        require_window(self.issued_at, self.expires_at, "issued_at", "expires_at")?;
        self.verify_terms_id()
    }

    /// Recompute and compare the content-addressed terms id.
    pub fn verify_terms_id(&self) -> Result<(), FindingError> {
        let expected = compute_terms_id(self)?;
        if expected == self.terms_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("terms_id"))
        }
    }
}

/// Content-addressed terms id: sha256 over the canonical body with
/// `terms_id` cleared.
pub fn compute_terms_id(terms: &FindingMarketTerms) -> Result<String, FindingError> {
    let mut body = terms.clone();
    body.terms_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed terms envelope: the signer must equal the embedded
/// seller and verify strictly.
pub fn verify_signed_market_terms(signed: &SignedFindingMarketTerms) -> Result<(), FindingError> {
    signed.body.validate()?;
    crate::envelope::verify_pinned_envelope(signed, &signed.body.seller, "market_terms")
}
