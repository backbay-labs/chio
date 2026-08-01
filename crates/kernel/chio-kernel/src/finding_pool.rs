//! Kernel boundary for authenticated cognition-market pool debits.
//!
//! The hard-ceiling entry point accepts only a backend that explicitly
//! implements [`QualifiedFindingPoolLedger`]. Implementations must provide an
//! atomic or linearizable debit and durable exact replay. Advisory remote
//! budget views must not implement the marker trait.

use chio_core_types::crypto::PublicKey;
use chio_swarm_authority::finding_pool::{
    verify_finding_pool_allocation, SignedFindingPoolAllocation,
};
use chio_swarm_authority::SwarmBudgetPool;

use crate::finding_purchase::VerifiedFindingPurchase;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPoolDebitReceipt {
    pub purchase_id: String,
    pub allocation_id: String,
    pub allocation_envelope_sha256: String,
    pub amount_units: u64,
    pub currency: String,
    pub spent_after_units: u64,
    pub remaining_after_units: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingPoolLedgerError {
    #[error("finding pool debit conflicts with a prior purchase id")]
    ReplayConflict,
    #[error("finding pool signed amount is exhausted")]
    AmountExceeded,
    #[error("finding pool id is already bound to another signed allocation")]
    PoolBindingConflict,
    #[error("finding pool ledger storage failed: {0}")]
    Storage(String),
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingPoolDebitError {
    #[error("finding pool allocation rejected: {0}")]
    Allocation(String),
    #[error("finding pool allocation envelope digest mismatch")]
    EnvelopeDigestMismatch,
    #[error("finding pool purchaser identity or key mismatch")]
    PurchaserMismatch,
    #[error("finding pool debit currency mismatch")]
    CurrencyMismatch,
    #[error("finding pool debit amount must be positive")]
    ZeroAmount,
    #[error("finding pool debit {0} is invalid")]
    InvalidField(&'static str),
    #[error(transparent)]
    Ledger(#[from] FindingPoolLedgerError),
}

pub struct FindingPoolDebitRequest<'a> {
    pub allocation: &'a SignedFindingPoolAllocation,
    pub pool: &'a SwarmBudgetPool,
    pub pinned_authority: &'a PublicKey,
    pub expected_allocation_envelope_sha256: &'a str,
    pub purchaser_id: &'a str,
    /// Purchase facts returned by the kernel's installed strict purchase
    /// verifier and cross-checked against the selected grant.
    pub verified_purchase: &'a VerifiedFindingPurchase,
    pub now_unix_ms: u64,
}

/// Fully verified debit handed to the qualifying backend.
///
/// Fields are private so callers cannot bypass the artifact verifier and
/// manufacture an authorized debit.
#[derive(Debug, Clone)]
pub struct AuthorizedFindingPoolDebit {
    purchase_id: String,
    allocation_id: String,
    allocation_envelope_sha256: String,
    pool_id: String,
    pool_sha256: String,
    purchaser_id: String,
    purchaser_key: PublicKey,
    finding_id: String,
    listing_id: String,
    reservation_id: String,
    authoritative_payment_operation_id: String,
    accepted_bid_envelope_sha256: String,
    venue_admission_envelope_sha256: String,
    currency: String,
    signed_amount_units: u64,
    debit_amount_units: u64,
    allocation_expires_at_unix_ms: u64,
}

impl AuthorizedFindingPoolDebit {
    #[must_use]
    pub fn purchase_id(&self) -> &str {
        &self.purchase_id
    }

    #[must_use]
    pub fn allocation_id(&self) -> &str {
        &self.allocation_id
    }

    #[must_use]
    pub fn allocation_envelope_sha256(&self) -> &str {
        &self.allocation_envelope_sha256
    }

    #[must_use]
    pub fn pool_id(&self) -> &str {
        &self.pool_id
    }

    #[must_use]
    pub fn pool_sha256(&self) -> &str {
        &self.pool_sha256
    }

    #[must_use]
    pub fn purchaser_id(&self) -> &str {
        &self.purchaser_id
    }

    #[must_use]
    pub fn purchaser_key(&self) -> &PublicKey {
        &self.purchaser_key
    }

    #[must_use]
    pub fn finding_id(&self) -> &str {
        &self.finding_id
    }

    #[must_use]
    pub fn listing_id(&self) -> &str {
        &self.listing_id
    }

    #[must_use]
    pub fn reservation_id(&self) -> &str {
        &self.reservation_id
    }

    #[must_use]
    pub fn authoritative_payment_operation_id(&self) -> &str {
        &self.authoritative_payment_operation_id
    }

    #[must_use]
    pub fn accepted_bid_envelope_sha256(&self) -> &str {
        &self.accepted_bid_envelope_sha256
    }

    #[must_use]
    pub fn venue_admission_envelope_sha256(&self) -> &str {
        &self.venue_admission_envelope_sha256
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub fn signed_amount_units(&self) -> u64 {
        self.signed_amount_units
    }

    #[must_use]
    pub fn debit_amount_units(&self) -> u64 {
        self.debit_amount_units
    }

    #[must_use]
    pub fn allocation_expires_at_unix_ms(&self) -> u64 {
        self.allocation_expires_at_unix_ms
    }
}

pub trait FindingPoolLedger: Send + Sync {
    fn debit(
        &self,
        debit: &AuthorizedFindingPoolDebit,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError>;
}

/// Marker for an audited atomic or linearizable durable backend.
///
/// Advisory or eventually consistent remote budget views must not implement
/// this trait and therefore cannot use the hard-ceiling entry point.
pub trait QualifiedFindingPoolLedger: FindingPoolLedger {}

pub fn debit_finding_pool_purchase<L: QualifiedFindingPoolLedger + ?Sized>(
    ledger: &L,
    request: FindingPoolDebitRequest<'_>,
) -> Result<FindingPoolDebitReceipt, FindingPoolDebitError> {
    let purchase = request.verified_purchase;
    require_identifier(&purchase.purchase_intent_id, "purchase_intent_id")?;
    require_identifier(&purchase.reservation_id, "reservation_id")?;
    require_identifier(
        &purchase.authoritative_payment_operation_id,
        "authoritative_payment_operation_id",
    )?;
    require_hex64(&purchase.finding_id, "finding_id")?;
    require_identifier(&purchase.listing_id, "listing_id")?;
    require_hex64(
        &purchase.accepted_bid_envelope_sha256,
        "accepted_bid_envelope_sha256",
    )?;
    require_hex64(
        &purchase.venue_admission_envelope_sha256,
        "venue_admission_envelope_sha256",
    )?;
    require_hex64(
        request.expected_allocation_envelope_sha256,
        "expected_allocation_envelope_sha256",
    )?;
    if purchase.accepted_price.units == 0 {
        return Err(FindingPoolDebitError::ZeroAmount);
    }
    let payer_key = PublicKey::from_hex(&purchase.payer_key_hex)
        .map_err(|_| FindingPoolDebitError::InvalidField("payer_key_hex"))?;
    let verified = verify_finding_pool_allocation(
        request.allocation,
        request.pool,
        request.pinned_authority,
        request.now_unix_ms,
    )
    .map_err(|error| FindingPoolDebitError::Allocation(error.runtime_detail()))?;
    if verified.envelope_sha256 != request.expected_allocation_envelope_sha256 {
        return Err(FindingPoolDebitError::EnvelopeDigestMismatch);
    }
    if verified.purchaser_id != request.purchaser_id || verified.purchaser_key != payer_key {
        return Err(FindingPoolDebitError::PurchaserMismatch);
    }
    if verified.currency != purchase.accepted_price.currency {
        return Err(FindingPoolDebitError::CurrencyMismatch);
    }
    ledger
        .debit(&AuthorizedFindingPoolDebit {
            purchase_id: purchase.purchase_intent_id.clone(),
            allocation_id: verified.allocation_id,
            allocation_envelope_sha256: verified.envelope_sha256,
            pool_id: verified.pool_id,
            pool_sha256: verified.pool_sha256,
            purchaser_id: verified.purchaser_id,
            purchaser_key: verified.purchaser_key,
            finding_id: purchase.finding_id.clone(),
            listing_id: purchase.listing_id.clone(),
            reservation_id: purchase.reservation_id.clone(),
            authoritative_payment_operation_id: purchase.authoritative_payment_operation_id.clone(),
            accepted_bid_envelope_sha256: purchase.accepted_bid_envelope_sha256.clone(),
            venue_admission_envelope_sha256: purchase.venue_admission_envelope_sha256.clone(),
            currency: verified.currency,
            signed_amount_units: verified.amount_units,
            debit_amount_units: purchase.accepted_price.units,
            allocation_expires_at_unix_ms: verified.expires_at_unix_ms,
        })
        .map_err(FindingPoolDebitError::Ledger)
}

fn require_identifier(value: &str, field: &'static str) -> Result<(), FindingPoolDebitError> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err(FindingPoolDebitError::InvalidField(field))
    } else {
        Ok(())
    }
}

fn require_hex64(value: &str, field: &'static str) -> Result<(), FindingPoolDebitError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(FindingPoolDebitError::InvalidField(field))
    }
}
