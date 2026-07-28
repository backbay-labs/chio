//! `chio.finding.bond-backing.v1`: the collateral-authority-signed live
//! allocation that replaces the transient bond-proof toggle.
//!
//! An opaque `bond_ref` or a transient `BondBacked` evaluation is not
//! collateral. This artifact names one exclusive, non-reusable allocation
//! dedicated to one finding listing; the venue collateral store enforces
//! exclusivity and lifecycle, and the admission sizing check enforces
//! `listing_requirement.required_amount >= base_finding_stake +
//! maximum_sale_exposure` against the exact signed fee schedule.

use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use serde::{Deserialize, Serialize};

use crate::envelope::require_ed25519;
use crate::validate::{
    require_currency, require_hex64, require_non_empty, require_nonzero, require_window,
    FindingError,
};

/// Collateral-authority-signed bond backing allocation.
pub const FINDING_BOND_BACKING_SCHEMA_V1: &str = "chio.finding.bond-backing.v1";

/// Bond class this allocation backs. The wedge admits `Listing` only;
/// the closed enum keeps unknown classes failing at parse time.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingBondClass {
    Listing,
}

/// Concrete vault backing the locked amount. Closed enum: unknown vault
/// kinds fail at parse time. The M2 wedge ships the venue-ledger variant
/// only; chain vaults arrive with their owning milestones and their own
/// verifiers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingCollateralVault {
    VenueLedger {
        ledger_account: String,
        operator_epoch: u64,
    },
}

impl FindingCollateralVault {
    fn validate(&self) -> Result<(), FindingError> {
        match self {
            FindingCollateralVault::VenueLedger {
                ledger_account,
                operator_epoch,
            } => {
                require_non_empty(ledger_account, "vault.ledger_account")?;
                require_nonzero(*operator_epoch, "vault.operator_epoch")
            }
        }
    }
}

/// Bond-backing allocation body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingBondBacking {
    pub schema: String,
    /// Content-addressed: sha256 of the canonical body with
    /// `allocation_id` cleared. Uniqueness (one live allocation per
    /// listing, no reuse) is a store invariant.
    pub allocation_id: String,
    /// Collateral authority that must sign the enclosing envelope; the
    /// deployment pin must agree.
    pub collateral_authority: PublicKey,
    pub seller: PublicKey,
    pub authorization_envelope_sha256: String,
    pub finding_id: String,
    pub listing_id: String,
    pub terms_envelope_sha256: String,
    pub profile_envelope_sha256: String,
    /// Digest of the exact canonical `OpenMarketBondRequirement` row this
    /// allocation satisfies (the requirement has no native id).
    pub fee_requirement_sha256: String,
    /// Envelope digest of the exact signed fee schedule carrying that row.
    pub fee_schedule_envelope_sha256: String,
    pub bond_class: FindingBondClass,
    pub locked_amount: MonetaryAmount,
    pub maximum_sale_exposure: MonetaryAmount,
    pub claim_horizon_secs: u64,
    pub audit_horizon_secs: u64,
    pub appeal_horizon_secs: u64,
    pub settlement_buffer_secs: u64,
    pub vault: FindingCollateralVault,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Collateral-authority-signed envelope for the backing.
pub type SignedFindingBondBacking = SignedExportEnvelope<FindingBondBacking>;

impl FindingBondBacking {
    pub fn validate(&self) -> Result<(), FindingError> {
        if self.schema != FINDING_BOND_BACKING_SCHEMA_V1 {
            return Err(FindingError::UnsupportedSchema(self.schema.clone()));
        }
        require_hex64(&self.allocation_id, "allocation_id")?;
        require_ed25519(&self.collateral_authority, "collateral_authority")?;
        require_ed25519(&self.seller, "seller")?;
        require_hex64(
            &self.authorization_envelope_sha256,
            "authorization_envelope_sha256",
        )?;
        require_hex64(&self.finding_id, "finding_id")?;
        require_non_empty(&self.listing_id, "listing_id")?;
        require_hex64(&self.terms_envelope_sha256, "terms_envelope_sha256")?;
        require_hex64(&self.profile_envelope_sha256, "profile_envelope_sha256")?;
        require_hex64(&self.fee_requirement_sha256, "fee_requirement_sha256")?;
        require_hex64(
            &self.fee_schedule_envelope_sha256,
            "fee_schedule_envelope_sha256",
        )?;
        require_nonzero(self.locked_amount.units, "locked_amount")?;
        require_currency(&self.locked_amount.currency, "locked_amount.currency")?;
        require_nonzero(self.maximum_sale_exposure.units, "maximum_sale_exposure")?;
        require_currency(
            &self.maximum_sale_exposure.currency,
            "maximum_sale_exposure.currency",
        )?;
        if self.locked_amount.currency != self.maximum_sale_exposure.currency {
            return Err(FindingError::CurrencyMismatch("bond_backing"));
        }
        if self.maximum_sale_exposure.units > self.locked_amount.units {
            return Err(FindingError::InvalidField("maximum_sale_exposure"));
        }
        require_nonzero(self.claim_horizon_secs, "claim_horizon_secs")?;
        require_nonzero(self.audit_horizon_secs, "audit_horizon_secs")?;
        require_nonzero(self.appeal_horizon_secs, "appeal_horizon_secs")?;
        require_nonzero(self.settlement_buffer_secs, "settlement_buffer_secs")?;
        self.vault.validate()?;
        require_window(self.issued_at, self.expires_at, "issued_at", "expires_at")?;
        self.verify_allocation_id()
    }

    /// Recompute and compare the content-addressed allocation id.
    pub fn verify_allocation_id(&self) -> Result<(), FindingError> {
        let expected = compute_allocation_id(self)?;
        if expected == self.allocation_id {
            Ok(())
        } else {
            Err(FindingError::ArtifactIdMismatch("allocation_id"))
        }
    }
}

/// Content-addressed allocation id: sha256 over the canonical body with
/// `allocation_id` cleared.
pub fn compute_allocation_id(backing: &FindingBondBacking) -> Result<String, FindingError> {
    let mut body = backing.clone();
    body.allocation_id = String::new();
    let bytes =
        chio_core_types::canonical_json_bytes(&body).map_err(|_| FindingError::Canonicalization)?;
    Ok(chio_core_types::crypto::sha256_hex(&bytes))
}

/// Verify a signed bond backing against the externally pinned collateral
/// authority: body authority, envelope signer, and pinned key must all
/// agree, and the signature must verify strictly.
pub fn verify_signed_bond_backing(
    signed: &SignedFindingBondBacking,
    pinned_collateral_authority: &PublicKey,
) -> Result<(), FindingError> {
    signed.body.validate()?;
    if signed.body.collateral_authority != *pinned_collateral_authority {
        return Err(FindingError::AuthorityMismatch("bond_backing"));
    }
    crate::envelope::verify_pinned_envelope(signed, pinned_collateral_authority, "bond_backing")
}
