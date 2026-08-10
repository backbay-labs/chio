//! Kernel boundary for authenticated cognition-market pool reservations.
//!
//! The deployment pins one backend that explicitly implements
//! [`QualifiedFindingPoolLedger`]. Implementations must provide atomic or
//! linearizable reservation, terminal settlement, and durable exact replay.
//! Advisory remote budget views must not implement the marker trait.

use chio_core_types::crypto::PublicKey;
use chio_core_types::receipt::body::ChioReceipt;
use chio_swarm_authority::finding_pool::{
    verify_finding_pool_allocation, SignedFindingPoolAllocation,
};
use chio_swarm_authority::SwarmBudgetPool;

use crate::finding_purchase::FindingPurchaseContextView;
use crate::ChioKernel;

/// Maximum time a pool reservation may remain unclaimed before a durable
/// purchase admission must take ownership of it.
pub const FINDING_POOL_CLAIM_WINDOW_MS: u64 = 30_000;
pub const FINDING_POOL_MUTATION_SCHEMA_V1: &str = "chio.finding.pool-mutation.v1";

/// Exact state transition committed by a qualified finding-pool ledger.
///
/// Numeric values are decimal strings so the attestation remains I-JSON safe
/// over the complete `u64` domain. A qualifying backend stores the signed Chio
/// receipt for this value in the same transaction as the mutation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPoolMutation {
    pub schema: String,
    pub kind: FindingPoolMutationKind,
    pub purchase_id: String,
    pub allocation_id: String,
    pub allocation_envelope_sha256: String,
    pub amount_units: String,
    pub currency: String,
    pub state: FindingPoolDebitState,
    pub reserved_after_units: String,
    pub spent_after_units: String,
    pub remaining_after_units: String,
    pub occurred_at_unix_ms: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingPoolMutationKind {
    Reserve,
    Claim,
    Finalize,
    Release,
    ExpiredRelease,
}

pub type FindingPoolMutationAttestor<'a> =
    dyn Fn(&FindingPoolMutation) -> Result<ChioReceipt, FindingPoolLedgerError> + 'a;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingPoolDebitReceipt {
    pub purchase_id: String,
    pub allocation_id: String,
    pub allocation_envelope_sha256: String,
    pub amount_units: u64,
    pub currency: String,
    pub state: FindingPoolDebitState,
    pub reserved_after_units: u64,
    pub spent_after_units: u64,
    pub remaining_after_units: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingPoolDebitState {
    Reserved,
    Finalized,
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingPoolLedgerError {
    #[error("finding pool debit conflicts with a prior purchase id")]
    ReplayConflict,
    #[error("finding pool signed amount is exhausted")]
    AmountExceeded,
    #[error("finding pool allocation is not live for a new debit")]
    AllocationNotLive,
    #[error("finding pool id is already bound to another signed allocation")]
    PoolBindingConflict,
    #[error("finding pool purchase has no durable reservation")]
    ReservationMissing,
    #[error("finding pool reservation conflicts with its recorded terminal")]
    TerminalConflict,
    #[error("finding pool reservation expired before durable admission claimed it")]
    ClaimDeadlineElapsed,
    #[error("finding pool ledger is already configured for this kernel")]
    AlreadyConfigured,
    #[error("finding pool mutation receipt authority is not configured")]
    ReceiptAuthorityMissing,
    #[error("finding pool mutation receipt authority is already configured for this kernel")]
    ReceiptAuthorityAlreadyConfigured,
    #[error("finding pool mutation receipts require a durable ordinary receipt store")]
    DurableReceiptStoreMissing,
    #[error("finding pool ledger storage failed: {0}")]
    Storage(String),
    #[error("finding pool mutation receipt failed: {0}")]
    Receipt(String),
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
    #[error("finding pool allocation authority is not configured")]
    AllocationAuthorityMissing,
    #[error("qualified finding pool ledger is not configured")]
    LedgerMissing,
    #[error("finding pool debit {0} is invalid")]
    InvalidField(&'static str),
    #[error(transparent)]
    Ledger(#[from] FindingPoolLedgerError),
}

pub struct FindingPoolDebitRequest<'a> {
    pub allocation: &'a SignedFindingPoolAllocation,
    pub pool: &'a SwarmBudgetPool,
    pub expected_allocation_envelope_sha256: &'a str,
    pub purchaser_id: &'a str,
    /// Exact purchase inputs handed to the verifier.
    pub purchase_context: FindingPurchaseContextView<'a>,
    /// Canonical portable status proof required whenever the kernel has an
    /// M6 status verifier installed. An exact committed replay does not need
    /// a fresh proof because it cannot consume the pool twice.
    pub status_proof_b64: Option<&'a str>,
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
    allocation_issued_at_unix_ms: u64,
    allocation_expires_at_unix_ms: u64,
    debit_requested_at_unix_ms: u64,
    claim_deadline_unix_ms: u64,
}

/// Kernel-authenticated claim that moves a short-lived pool reservation into
/// the durable purchase lifecycle immediately before tool dispatch.
#[derive(Debug, Clone)]
pub struct AuthorizedFindingPoolClaim {
    purchase_id: String,
    finding_id: String,
    listing_id: String,
    reservation_id: String,
    authoritative_payment_operation_id: String,
    accepted_bid_envelope_sha256: String,
    venue_admission_envelope_sha256: String,
    amount_units: u64,
    currency: String,
    claimed_at_unix_ms: u64,
}

/// Kernel-authenticated delivery terminal for a prior pool reservation.
///
/// Fields are private so callers cannot manufacture a successful or failed
/// delivery decision. Qualified backends can inspect the exact purchase
/// binding through the accessors below.
#[derive(Debug, Clone)]
pub struct AuthorizedFindingPoolTerminal {
    purchase_id: String,
    finding_id: String,
    listing_id: String,
    reservation_id: String,
    authoritative_payment_operation_id: String,
    amount_units: u64,
    currency: String,
    decision: FindingPoolTerminalDecision,
    occurred_at_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingPoolTerminalDecision {
    Finalize,
    Release,
}

impl AuthorizedFindingPoolTerminal {
    #[must_use]
    pub fn purchase_id(&self) -> &str {
        &self.purchase_id
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
    pub fn amount_units(&self) -> u64 {
        self.amount_units
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub fn decision(&self) -> FindingPoolTerminalDecision {
        self.decision
    }

    #[must_use]
    pub fn occurred_at_unix_ms(&self) -> u64 {
        self.occurred_at_unix_ms
    }
}

impl AuthorizedFindingPoolClaim {
    #[must_use]
    pub fn purchase_id(&self) -> &str {
        &self.purchase_id
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
    pub fn amount_units(&self) -> u64 {
        self.amount_units
    }

    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    #[must_use]
    pub fn claimed_at_unix_ms(&self) -> u64 {
        self.claimed_at_unix_ms
    }
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

    #[must_use]
    pub fn allocation_issued_at_unix_ms(&self) -> u64 {
        self.allocation_issued_at_unix_ms
    }

    #[must_use]
    pub fn debit_requested_at_unix_ms(&self) -> u64 {
        self.debit_requested_at_unix_ms
    }

    #[must_use]
    pub fn claim_deadline_unix_ms(&self) -> u64 {
        self.claim_deadline_unix_ms
    }
}

pub trait FindingPoolLedger: Send + Sync {
    /// Whether `purchase_id` already has a durable reservation. A `true`
    /// result only selects the replay path; [`Self::debit`] must still compare every
    /// authenticated field before returning the prior receipt.
    fn contains_purchase(&self, purchase_id: &str) -> Result<bool, FindingPoolLedgerError>;

    fn debit(
        &self,
        debit: &AuthorizedFindingPoolDebit,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError>;

    /// Claim a pending reservation for the durable purchase lifecycle.
    /// Exact replay is idempotent. A timed-out or terminal reservation rejects.
    fn claim(
        &self,
        claim: &AuthorizedFindingPoolClaim,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError>;

    /// Finalize or release a reservation from the kernel's durable delivery
    /// terminal. Exact replay must return the recorded terminal, while an
    /// attempted opposite terminal must fail closed.
    fn settle(
        &self,
        terminal: &AuthorizedFindingPoolTerminal,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError>;

    /// Signed mutation receipts not yet copied into the kernel's ordinary
    /// receipt log. The durable outbox itself remains append-only after ack.
    fn pending_mutation_receipts(&self) -> Result<Vec<ChioReceipt>, FindingPoolLedgerError>;

    /// Mark an outbox receipt as copied to the ordinary receipt log.
    fn acknowledge_mutation_receipt(
        &self,
        receipt_id: &str,
        acknowledged_at_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError>;
}

/// Marker for an audited atomic or linearizable durable backend.
///
/// Advisory or eventually consistent remote budget views must not implement
/// this trait and therefore cannot use the hard-ceiling entry point.
pub trait QualifiedFindingPoolLedger: FindingPoolLedger {}

impl ChioKernel {
    /// Reserve a signed finding pool allocation through this deployment's
    /// configured ledger, verifiers, trust roots, and trusted wall clock.
    pub fn debit_finding_pool_purchase(
        &self,
        request: FindingPoolDebitRequest<'_>,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolDebitError> {
        self.debit_finding_pool_purchase_at(request, crate::kernel::current_unix_timestamp_ms())
    }

    fn debit_finding_pool_purchase_at(
        &self,
        request: FindingPoolDebitRequest<'_>,
        trusted_now_unix_ms: u64,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolDebitError> {
        let ledger = self
            .finding_pool_ledger()
            .ok_or(FindingPoolDebitError::LedgerMissing)?;
        let allocation = &request.allocation.body;
        let allocation_is_live = trusted_now_unix_ms >= allocation.issued_at_unix_ms
            && trusted_now_unix_ms < allocation.expires_at_unix_ms;
        let purchase = self
            .verify_purchase_context_for_pool(&request.purchase_context)
            .map_err(FindingPoolDebitError::Allocation)?;
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
        let structural_time = if allocation.issued_at_unix_ms < allocation.expires_at_unix_ms {
            trusted_now_unix_ms.clamp(
                allocation.issued_at_unix_ms,
                allocation.expires_at_unix_ms - 1,
            )
        } else {
            trusted_now_unix_ms
        };
        let allocation_authority = self
            .finding_pool_allocation_authority()
            .ok_or(FindingPoolDebitError::AllocationAuthorityMissing)?;
        let verified = verify_finding_pool_allocation(
            request.allocation,
            request.pool,
            allocation_authority,
            structural_time,
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
        let debit = AuthorizedFindingPoolDebit {
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
            allocation_issued_at_unix_ms: allocation.issued_at_unix_ms,
            allocation_expires_at_unix_ms: verified.expires_at_unix_ms,
            debit_requested_at_unix_ms: trusted_now_unix_ms,
            claim_deadline_unix_ms: trusted_now_unix_ms
                .saturating_add(FINDING_POOL_CLAIM_WINDOW_MS)
                .min(verified.expires_at_unix_ms),
        };
        if ledger
            .contains_purchase(debit.purchase_id())
            .map_err(FindingPoolDebitError::Ledger)?
        {
            return self
                .commit_finding_pool_debit(ledger, &debit)
                .map_err(FindingPoolDebitError::Ledger);
        }
        if !allocation_is_live {
            return Err(FindingPoolLedgerError::AllocationNotLive.into());
        }
        if let Err(reason) = self.verify_purchase_admission_for_pool(
            &request.purchase_context,
            &purchase,
            trusted_now_unix_ms / 1_000,
        ) {
            if ledger
                .contains_purchase(debit.purchase_id())
                .map_err(FindingPoolDebitError::Ledger)?
            {
                return self
                    .commit_finding_pool_debit(ledger, &debit)
                    .map_err(FindingPoolDebitError::Ledger);
            }
            return Err(FindingPoolDebitError::Allocation(reason));
        }
        if let Err(reason) = self.verify_finding_status_for_pool(
            request.status_proof_b64,
            &purchase.finding_id,
            trusted_now_unix_ms / 1_000,
        ) {
            if ledger
                .contains_purchase(debit.purchase_id())
                .map_err(FindingPoolDebitError::Ledger)?
            {
                return self
                    .commit_finding_pool_debit(ledger, &debit)
                    .map_err(FindingPoolDebitError::Ledger);
            }
            return Err(FindingPoolDebitError::Allocation(reason));
        }
        self.commit_finding_pool_debit(ledger, &debit)
            .map_err(FindingPoolDebitError::Ledger)
    }

    fn commit_finding_pool_debit(
        &self,
        ledger: &dyn QualifiedFindingPoolLedger,
        debit: &AuthorizedFindingPoolDebit,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let attestor = |mutation: &FindingPoolMutation| {
            self.build_finding_pool_mutation_receipt(mutation)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
        };
        let result = ledger.debit(debit, &attestor);
        self.flush_finding_pool_mutation_receipts(ledger)?;
        result
    }

    fn flush_finding_pool_mutation_receipts(
        &self,
        ledger: &dyn QualifiedFindingPoolLedger,
    ) -> Result<(), FindingPoolLedgerError> {
        let durable_store_configured = self
            .with_receipt_store(|_| Ok(()))
            .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?
            .is_some();
        if !durable_store_configured {
            return Err(FindingPoolLedgerError::DurableReceiptStoreMissing);
        }
        for receipt in ledger.pending_mutation_receipts()? {
            self.record_chio_receipt(&receipt)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
            ledger.acknowledge_mutation_receipt(
                &receipt.id,
                crate::kernel::current_unix_timestamp_ms(),
            )?;
        }
        Ok(())
    }

    /// Transfer a pending pool reservation into the durable delivery
    /// lifecycle. This runs only after all immediate dispatch revalidation.
    pub(crate) fn claim_finding_pool_delivery(
        &self,
        purchase: &crate::finding_purchase::VerifiedFindingPurchase,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError> {
        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(());
        };
        if !ledger.contains_purchase(&purchase.purchase_intent_id)? {
            return Ok(());
        }
        let claim = AuthorizedFindingPoolClaim {
            purchase_id: purchase.purchase_intent_id.clone(),
            finding_id: purchase.finding_id.clone(),
            listing_id: purchase.listing_id.clone(),
            reservation_id: purchase.reservation_id.clone(),
            authoritative_payment_operation_id: purchase.authoritative_payment_operation_id.clone(),
            accepted_bid_envelope_sha256: purchase.accepted_bid_envelope_sha256.clone(),
            venue_admission_envelope_sha256: purchase.venue_admission_envelope_sha256.clone(),
            amount_units: purchase.accepted_price.units,
            currency: purchase.accepted_price.currency.clone(),
            claimed_at_unix_ms: trusted_now_unix_ms,
        };
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let attestor = |mutation: &FindingPoolMutation| {
            self.build_finding_pool_mutation_receipt(mutation)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
        };
        // The claim and its signed outbox receipt are one backend transaction.
        // Do not copy the outbox into the ordinary receipt log here: that copy
        // is fallible work after the claim and before tool dispatch. The next
        // pool operation drains it, while the durable signed outbox already
        // preserves the audit record across a crash.
        ledger.claim(&claim, &attestor)
    }

    /// Apply the pool reservation terminal derived from the kernel's frozen
    /// post-delivery settlement decision. Purchases that did not use the
    /// configured pool ledger are left unchanged.
    pub(crate) fn settle_finding_pool_delivery(
        &self,
        purchase: &crate::finding_purchase::VerifiedFindingPurchase,
        disposition: &crate::tool_outcome::SettlementDispositionV1,
    ) -> Result<(), FindingPoolLedgerError> {
        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(());
        };
        if !ledger.contains_purchase(&purchase.purchase_intent_id)? {
            return Ok(());
        }
        let decision = match disposition {
            crate::tool_outcome::SettlementDispositionV1::Capture { amount }
                if amount == &purchase.accepted_price =>
            {
                FindingPoolTerminalDecision::Finalize
            }
            crate::tool_outcome::SettlementDispositionV1::ContractualZeroCharge { currency }
                if currency == &purchase.accepted_price.currency =>
            {
                FindingPoolTerminalDecision::Release
            }
            crate::tool_outcome::SettlementDispositionV1::Capture { .. }
            | crate::tool_outcome::SettlementDispositionV1::ContractualZeroCharge { .. }
            | crate::tool_outcome::SettlementDispositionV1::NotApplicable => {
                return Err(FindingPoolLedgerError::TerminalConflict);
            }
        };
        let terminal = AuthorizedFindingPoolTerminal {
            purchase_id: purchase.purchase_intent_id.clone(),
            finding_id: purchase.finding_id.clone(),
            listing_id: purchase.listing_id.clone(),
            reservation_id: purchase.reservation_id.clone(),
            authoritative_payment_operation_id: purchase.authoritative_payment_operation_id.clone(),
            amount_units: purchase.accepted_price.units,
            currency: purchase.accepted_price.currency.clone(),
            decision,
            occurred_at_unix_ms: crate::kernel::current_unix_timestamp_ms(),
        };
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let attestor = |mutation: &FindingPoolMutation| {
            self.build_finding_pool_mutation_receipt(mutation)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
        };
        let result = ledger.settle(&terminal, &attestor);
        self.flush_finding_pool_mutation_receipts(ledger)?;
        result?;
        Ok(())
    }

    pub(crate) fn settle_finding_pool_delivery_terminal(
        &self,
        purchase: &crate::finding_purchase::VerifiedFindingPurchase,
        disposition: &crate::tool_outcome::SettlementDispositionV1,
    ) -> Result<(), crate::KernelError> {
        self.settle_finding_pool_delivery(purchase, disposition)
            .map_err(|error| {
                crate::KernelError::DurableAdmission(format!(
                    "finding pool terminal could not be committed: {error}"
                ))
            })
    }
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

#[cfg(test)]
#[path = "finding_pool_tests.rs"]
mod tests;
