//! Kernel boundary for authenticated cognition-market pool reservations.
//!
//! The deployment pins one backend that explicitly implements
//! [`QualifiedFindingPoolLedger`]. Implementations must provide atomic or
//! linearizable reservation, terminal settlement, and durable exact replay.
//! Advisory remote budget views must not implement the marker trait.

use chio_core_types::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::lineage::SignedExportEnvelope;
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
pub const FINDING_POOL_DEBIT_AUTHORIZATION_SCHEMA_V1: &str =
    "chio.finding.pool-debit-authorization.v1";

/// Purchaser-signed proof of possession for one exact pool reservation.
///
/// The body binds the immutable purchase context to the concrete runtime
/// request and signed allocation. A copied capability and purchase context
/// therefore cannot create or expire a reservation without the purchaser key.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingPoolDebitAuthorization {
    pub schema: String,
    pub purchase_id: String,
    pub allocation_envelope_sha256: String,
    pub purchaser_id: String,
    pub purchase_context_sha256: String,
    pub capability_id: String,
    pub server_id: String,
    pub tool_name: String,
    pub arguments_sha256: String,
    pub expected_output_digest: String,
    /// Decimal-string trusted-time deadline for starting a new reservation.
    pub expires_at_unix_ms: String,
}

pub type SignedFindingPoolDebitAuthorization = SignedExportEnvelope<FindingPoolDebitAuthorization>;

/// Stable subset of a debit authorization that must remain identical across
/// response-loss retries. The trusted-time expiry may be renewed, but no
/// request, capability, allocation, or purchaser binding may change.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
struct FindingPoolDebitReplayBinding<'a> {
    schema: &'a str,
    purchase_id: &'a str,
    allocation_envelope_sha256: &'a str,
    purchaser_id: &'a str,
    purchase_context_sha256: &'a str,
    capability_id: &'a str,
    server_id: &'a str,
    tool_name: &'a str,
    arguments_sha256: &'a str,
    expected_output_digest: &'a str,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_admission_operation_id: Option<String>,
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
    #[error("finding pool allocation is bound to another qualified ledger domain")]
    LedgerDomainMismatch,
    #[error("finding pool ledger is bound to another durable receipt sink")]
    ReceiptSinkMismatch,
    #[error("finding pool durable receipt sink identity is invalid")]
    InvalidReceiptSink,
    #[error("finding pool purchase has no durable reservation")]
    ReservationMissing,
    #[error("finding pool reservation conflicts with its recorded terminal")]
    TerminalConflict,
    #[error("finding pool reservation expired before durable admission claimed it")]
    ClaimDeadlineElapsed,
    #[error("finding pool dispatch requires durable admission coverage")]
    DurableAdmissionRequired,
    #[error("finding pool ledger is already configured for this kernel")]
    AlreadyConfigured,
    #[error("finding pool ledger cannot be configured after durable startup reconciliation")]
    StartupAlreadyReconciled,
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
    #[error("finding pool mutation receipt outbox flush lock is poisoned")]
    MutationReceiptFlushPoisoned,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FindingPoolDebitError {
    #[error("kernel emergency stop blocks finding pool debits")]
    EmergencyStopped,
    #[error("finding pool allocation rejected: {0}")]
    Allocation(String),
    #[error("finding pool allocation envelope digest mismatch")]
    EnvelopeDigestMismatch,
    #[error("finding pool purchaser identity or key mismatch")]
    PurchaserMismatch,
    #[error("finding pool purchaser authorization rejected: {0}")]
    PurchaserAuthorization(String),
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
    /// Purchaser proof of possession over this exact debit request.
    pub purchaser_authorization: &'a SignedFindingPoolDebitAuthorization,
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
    debit_request_binding_sha256: String,
    ledger_domain: String,
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

/// Exact, already-committed debit identity authenticated without consulting
/// mutable purchase-verifier trust roots.
///
/// Fields are private so only the kernel can construct this after verifying
/// the retained allocation signer and purchaser authorization. The ledger
/// compares the allocation envelope and stable signed-request digest with the
/// durable reservation before it returns a prior receipt.
pub struct AuthorizedFindingPoolDebitReplay {
    purchase_id: String,
    allocation_envelope_sha256: String,
    debit_request_binding_sha256: String,
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
    durable_admission_operation_id: String,
}

/// Kernel-authenticated release for a pool claim whose durable admission has
/// verified that no provider effect occurred.
#[derive(Debug, Clone)]
pub struct AuthorizedFindingPoolRecoveryRelease {
    durable_admission_operation_id: String,
    released_at_unix_ms: u64,
}

/// Kernel-authenticated finalization for a claimed reservation whose durable
/// admission reached dispatch commitment but has no recoverable tool outcome.
#[derive(Debug, Clone)]
pub struct AuthorizedFindingPoolUnknownDispatchTerminal {
    durable_admission_operation_id: String,
    finalized_at_unix_ms: u64,
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

    #[must_use]
    pub fn durable_admission_operation_id(&self) -> &str {
        &self.durable_admission_operation_id
    }
}

impl AuthorizedFindingPoolRecoveryRelease {
    #[must_use]
    pub fn durable_admission_operation_id(&self) -> &str {
        &self.durable_admission_operation_id
    }

    #[must_use]
    pub fn released_at_unix_ms(&self) -> u64 {
        self.released_at_unix_ms
    }
}

impl AuthorizedFindingPoolUnknownDispatchTerminal {
    #[must_use]
    pub fn durable_admission_operation_id(&self) -> &str {
        &self.durable_admission_operation_id
    }

    #[must_use]
    pub fn finalized_at_unix_ms(&self) -> u64 {
        self.finalized_at_unix_ms
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
    pub fn debit_request_binding_sha256(&self) -> &str {
        &self.debit_request_binding_sha256
    }

    #[must_use]
    pub fn ledger_domain(&self) -> &str {
        &self.ledger_domain
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

impl AuthorizedFindingPoolDebitReplay {
    #[must_use]
    pub fn purchase_id(&self) -> &str {
        &self.purchase_id
    }

    #[must_use]
    pub fn allocation_envelope_sha256(&self) -> &str {
        &self.allocation_envelope_sha256
    }

    #[must_use]
    pub fn debit_request_binding_sha256(&self) -> &str {
        &self.debit_request_binding_sha256
    }
}

pub trait FindingPoolLedger: Send + Sync {
    /// Whether `purchase_id` already has a durable reservation. A `true`
    /// result only selects the replay path; [`Self::debit`] must still compare every
    /// authenticated field before returning the prior receipt.
    fn contains_purchase(&self, purchase_id: &str) -> Result<bool, FindingPoolLedgerError>;

    /// Return an exact committed debit only when the immutable allocation and
    /// signed purchase context match the durable reservation.
    fn replay_debit(
        &self,
        replay: &AuthorizedFindingPoolDebitReplay,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError>;

    /// Lists claimed, nonterminal pool reservations by their durable admission
    /// operation id. Results must be strictly ascending, start after the
    /// optional cursor, and contain at most `limit` entries.
    fn list_claimed_admission_operations(
        &self,
        after_operation_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>, FindingPoolLedgerError>;

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

    /// Release a claim when its bound durable admission is compensated before
    /// dispatch. Exact replay is idempotent; another terminal fails closed.
    fn release_claimed_before_dispatch(
        &self,
        release: &AuthorizedFindingPoolRecoveryRelease,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError>;

    /// Release a dispatch-committed claim after the kernel durably verifies a
    /// typed no-effect transport result. Backends use the same idempotent
    /// release transition as pre-dispatch compensation.
    fn release_claimed_after_verified_no_effect(
        &self,
        release: &AuthorizedFindingPoolRecoveryRelease,
        attestor: &FindingPoolMutationAttestor<'_>,
    ) -> Result<(), FindingPoolLedgerError> {
        self.release_claimed_before_dispatch(release, attestor)
    }

    /// Finalize a claimed reservation when its durable admission is terminally
    /// outcome-unknown after dispatch commitment. Exact replay is idempotent;
    /// a prior release fails closed. An operation with no pool claim is a no-op.
    fn finalize_claimed_after_unknown_dispatch(
        &self,
        terminal: &AuthorizedFindingPoolUnknownDispatchTerminal,
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

    /// Transactionally claim a bounded set of signed mutation receipts that
    /// are not yet copied into the kernel's ordinary receipt log. A backend
    /// shared by several kernel instances must serialize this claim in durable
    /// storage so only one receipt sink can deliver a row during the lease.
    fn claim_pending_mutation_receipts(
        &self,
        claimant_id: &str,
        claimed_at_unix_ms: u64,
        lease_ms: u64,
        limit: usize,
    ) -> Result<Vec<ChioReceipt>, FindingPoolLedgerError>;

    /// Mark a claimed outbox receipt as copied to the ordinary receipt log.
    fn acknowledge_mutation_receipt(
        &self,
        receipt_id: &str,
        claimant_id: &str,
        acknowledged_at_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError>;
}

/// Marker for an audited atomic or linearizable durable backend.
///
/// Advisory or eventually consistent remote budget views must not implement
/// this trait and therefore cannot use the hard-ceiling entry point.
pub trait QualifiedFindingPoolLedger: FindingPoolLedger {
    /// Stable authority-selected namespace for the one ledger deployment that
    /// may account for a signed allocation.
    fn ledger_domain(&self) -> &str;

    /// Bind this ledger to the one durable ordinary receipt sink that receives
    /// every signed mutation receipt. Reopening with the same sink is
    /// idempotent; a different sink fails closed before any mutation can run.
    fn bind_receipt_sink(&self, receipt_sink_id: &str) -> Result<(), FindingPoolLedgerError>;
}

impl ChioKernel {
    fn require_finding_pool_debit_active(&self) -> Result<(), FindingPoolDebitError> {
        if self.is_emergency_stopped() {
            Err(FindingPoolDebitError::EmergencyStopped)
        } else {
            Ok(())
        }
    }

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
        self.require_finding_pool_debit_active()?;
        let ledger = self
            .finding_pool_ledger()
            .ok_or(FindingPoolDebitError::LedgerMissing)?;
        let allocation = &request.allocation.body;
        let allocation_is_live = trusted_now_unix_ms >= allocation.issued_at_unix_ms
            && trusted_now_unix_ms < allocation.expires_at_unix_ms;
        require_hex64(
            request.expected_allocation_envelope_sha256,
            "expected_allocation_envelope_sha256",
        )?;
        let candidate_purchase_id = &request.purchaser_authorization.body.purchase_id;
        require_identifier(candidate_purchase_id, "authorization.purchase_id")?;
        let committed_purchase = ledger
            .contains_purchase(candidate_purchase_id)
            .map_err(FindingPoolDebitError::Ledger)?;
        let structural_time = if allocation.issued_at_unix_ms < allocation.expires_at_unix_ms {
            trusted_now_unix_ms.clamp(
                allocation.issued_at_unix_ms,
                allocation.expires_at_unix_ms - 1,
            )
        } else {
            trusted_now_unix_ms
        };
        // A committed replay is authenticated again under the exact signer
        // carried by its immutable envelope, then compared field-for-field by
        // the durable ledger. A new debit must use the deployment's current
        // allocation authority. This preserves response-loss recovery across
        // key rotation without authorizing new spend under a retired key.
        let allocation_authority = if committed_purchase {
            &request.allocation.signer_key
        } else {
            self.finding_pool_allocation_authority()
                .ok_or(FindingPoolDebitError::AllocationAuthorityMissing)?
        };
        let verified = verify_finding_pool_allocation(
            request.allocation,
            request.pool,
            allocation_authority,
            ledger.ledger_domain(),
            structural_time,
        )
        .map_err(|error| FindingPoolDebitError::Allocation(error.runtime_detail()))?;
        if verified.envelope_sha256 != request.expected_allocation_envelope_sha256 {
            return Err(FindingPoolDebitError::EnvelopeDigestMismatch);
        }
        if verified.purchaser_id != request.purchaser_id
            || verified.purchaser_key != request.purchase_context.capability.subject
        {
            return Err(FindingPoolDebitError::PurchaserMismatch);
        }
        let (authorization_expires_at, debit_request_binding_sha256) =
            verify_purchaser_authorization(
                &request,
                candidate_purchase_id,
                &verified.purchaser_key,
            )?;
        if committed_purchase {
            let replay = AuthorizedFindingPoolDebitReplay {
                purchase_id: candidate_purchase_id.clone(),
                allocation_envelope_sha256: verified.envelope_sha256,
                debit_request_binding_sha256,
            };
            return self
                .replay_finding_pool_debit(ledger, &replay)
                .map_err(FindingPoolDebitError::Ledger);
        }
        if trusted_now_unix_ms >= authorization_expires_at {
            return Err(FindingPoolDebitError::PurchaserAuthorization(
                "authorization expired before reservation".to_owned(),
            ));
        }
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
        if purchase.accepted_price.units == 0 {
            return Err(FindingPoolDebitError::ZeroAmount);
        }
        let payer_key = PublicKey::from_hex(&purchase.payer_key_hex)
            .map_err(|_| FindingPoolDebitError::InvalidField("payer_key_hex"))?;
        if purchase.purchase_intent_id != *candidate_purchase_id
            || payer_key != verified.purchaser_key
        {
            return Err(FindingPoolDebitError::PurchaserMismatch);
        }
        if verified.currency != purchase.accepted_price.currency {
            return Err(FindingPoolDebitError::CurrencyMismatch);
        }
        let debit = AuthorizedFindingPoolDebit {
            purchase_id: purchase.purchase_intent_id.clone(),
            allocation_id: verified.allocation_id,
            allocation_envelope_sha256: verified.envelope_sha256,
            debit_request_binding_sha256,
            ledger_domain: verified.ledger_domain,
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
            &purchase.expected_status_feed_id,
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

    fn replay_finding_pool_debit(
        &self,
        ledger: &dyn QualifiedFindingPoolLedger,
        replay: &AuthorizedFindingPoolDebitReplay,
    ) -> Result<FindingPoolDebitReceipt, FindingPoolLedgerError> {
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let result = ledger.replay_debit(replay);
        self.flush_finding_pool_mutation_receipts(ledger)?;
        result
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
        const DELIVERY_LEASE_MS: u64 = 60_000;
        const MAX_RECEIPTS_PER_FLUSH: usize = 200;
        for _ in 0..MAX_RECEIPTS_PER_FLUSH {
            let claimed_at = crate::kernel::current_unix_timestamp_ms();
            let mut claimed = ledger.claim_pending_mutation_receipts(
                &self.finding_pool_outbox_worker_id,
                claimed_at,
                DELIVERY_LEASE_MS,
                1,
            )?;
            let Some(receipt) = claimed.pop() else {
                break;
            };
            self.record_chio_receipt_without_settlement(&receipt)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))?;
            ledger.acknowledge_mutation_receipt(
                &receipt.id,
                &self.finding_pool_outbox_worker_id,
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
        durable_admission_operation_id: Option<&str>,
    ) -> Result<(), FindingPoolLedgerError> {
        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(());
        };
        if !ledger.contains_purchase(&purchase.purchase_intent_id)? {
            return Ok(());
        }
        let durable_admission_operation_id = durable_admission_operation_id
            .filter(|operation_id| !operation_id.is_empty())
            .ok_or(FindingPoolLedgerError::DurableAdmissionRequired)?;
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
            durable_admission_operation_id: durable_admission_operation_id.to_owned(),
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

    /// Release any pool claim bound to an admission that is durably
    /// compensated before dispatch. The pool release is committed first so a
    /// failed release leaves the admission recoverable for the next sweep.
    pub(crate) fn release_finding_pool_claim_before_dispatch(
        &self,
        durable_admission_operation_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError> {
        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(());
        };
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let release = AuthorizedFindingPoolRecoveryRelease {
            durable_admission_operation_id: durable_admission_operation_id.to_owned(),
            released_at_unix_ms: trusted_now_unix_ms,
        };
        let attestor = |mutation: &FindingPoolMutation| {
            self.build_finding_pool_mutation_receipt(mutation)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
        };
        ledger.release_claimed_before_dispatch(&release, &attestor)?;
        self.flush_finding_pool_mutation_receipts(ledger)
    }

    /// Release a pool claim after a dispatch-committed admission proves that
    /// the provider requested URL elicitation before any tool effect.
    pub(crate) fn release_finding_pool_claim_after_verified_no_effect(
        &self,
        durable_admission_operation_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError> {
        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(());
        };
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let release = AuthorizedFindingPoolRecoveryRelease {
            durable_admission_operation_id: durable_admission_operation_id.to_owned(),
            released_at_unix_ms: trusted_now_unix_ms,
        };
        let attestor = |mutation: &FindingPoolMutation| {
            self.build_finding_pool_mutation_receipt(mutation)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
        };
        ledger.release_claimed_after_verified_no_effect(&release, &attestor)?;
        self.flush_finding_pool_mutation_receipts(ledger)
    }

    /// Consume a claimed reservation before an outcome-unknown admission
    /// becomes terminal. The conservative finalization prevents ambiguous
    /// dispatch from authorizing the same allocation units again.
    pub(crate) fn finalize_finding_pool_claim_after_unknown_dispatch(
        &self,
        durable_admission_operation_id: &str,
        trusted_now_unix_ms: u64,
    ) -> Result<(), FindingPoolLedgerError> {
        let Some(ledger) = self.finding_pool_ledger() else {
            return Ok(());
        };
        self.flush_finding_pool_mutation_receipts(ledger)?;
        let terminal = AuthorizedFindingPoolUnknownDispatchTerminal {
            durable_admission_operation_id: durable_admission_operation_id.to_owned(),
            finalized_at_unix_ms: trusted_now_unix_ms,
        };
        let attestor = |mutation: &FindingPoolMutation| {
            self.build_finding_pool_mutation_receipt(mutation)
                .map_err(|error| FindingPoolLedgerError::Receipt(error.to_string()))
        };
        ledger.finalize_claimed_after_unknown_dispatch(&terminal, &attestor)?;
        self.flush_finding_pool_mutation_receipts(ledger)
    }

    /// Check that the frozen post-delivery settlement decision can terminate
    /// the pool reservation. Purchases that did not use the configured pool
    /// ledger are left unchanged.
    pub(crate) fn require_finding_pool_delivery_disposition(
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
        Self::finding_pool_terminal_decision(purchase, disposition).map(|_| ())
    }

    fn finding_pool_terminal_decision(
        purchase: &crate::finding_purchase::VerifiedFindingPurchase,
        disposition: &crate::tool_outcome::SettlementDispositionV1,
    ) -> Result<FindingPoolTerminalDecision, FindingPoolLedgerError> {
        match disposition {
            crate::tool_outcome::SettlementDispositionV1::Capture { amount }
                if amount == &purchase.accepted_price =>
            {
                Ok(FindingPoolTerminalDecision::Finalize)
            }
            crate::tool_outcome::SettlementDispositionV1::ContractualZeroCharge { currency }
                if currency == &purchase.accepted_price.currency =>
            {
                Ok(FindingPoolTerminalDecision::Release)
            }
            crate::tool_outcome::SettlementDispositionV1::Capture { .. }
            | crate::tool_outcome::SettlementDispositionV1::ContractualZeroCharge { .. }
            | crate::tool_outcome::SettlementDispositionV1::NotApplicable => {
                Err(FindingPoolLedgerError::TerminalConflict)
            }
        }
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
        let decision = Self::finding_pool_terminal_decision(purchase, disposition)?;
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

    pub(crate) fn require_finding_pool_delivery_terminal(
        &self,
        purchase: &crate::finding_purchase::VerifiedFindingPurchase,
        disposition: &crate::tool_outcome::SettlementDispositionV1,
    ) -> Result<(), crate::KernelError> {
        self.require_finding_pool_delivery_disposition(purchase, disposition)
            .map_err(|error| {
                crate::KernelError::DurableAdmission(format!(
                    "finding pool terminal conflicts before payment settlement: {error}"
                ))
            })
    }
}

fn verify_purchaser_authorization(
    request: &FindingPoolDebitRequest<'_>,
    expected_purchase_id: &str,
    payer_key: &PublicKey,
) -> Result<(u64, String), FindingPoolDebitError> {
    let authorization = request.purchaser_authorization;
    let body = &authorization.body;
    if body.schema != FINDING_POOL_DEBIT_AUTHORIZATION_SCHEMA_V1 {
        return Err(FindingPoolDebitError::PurchaserAuthorization(
            "unsupported schema".to_owned(),
        ));
    }
    require_identifier(&body.purchase_id, "authorization.purchase_id")?;
    require_hex64(
        &body.allocation_envelope_sha256,
        "authorization.allocation_envelope_sha256",
    )?;
    require_identifier(&body.purchaser_id, "authorization.purchaser_id")?;
    require_hex64(
        &body.purchase_context_sha256,
        "authorization.purchase_context_sha256",
    )?;
    require_identifier(&body.capability_id, "authorization.capability_id")?;
    require_identifier(&body.server_id, "authorization.server_id")?;
    require_identifier(&body.tool_name, "authorization.tool_name")?;
    require_hex64(&body.arguments_sha256, "authorization.arguments_sha256")?;
    require_hex64(
        &body.expected_output_digest,
        "authorization.expected_output_digest",
    )?;
    let expires_at_unix_ms = body.expires_at_unix_ms.parse::<u64>().map_err(|_| {
        FindingPoolDebitError::PurchaserAuthorization(
            "expires_at_unix_ms is not canonical u64 decimal".to_owned(),
        )
    })?;
    if expires_at_unix_ms.to_string() != body.expires_at_unix_ms {
        return Err(FindingPoolDebitError::PurchaserAuthorization(
            "expires_at_unix_ms is not canonical u64 decimal".to_owned(),
        ));
    }
    if authorization.signer_key != *payer_key {
        return Err(FindingPoolDebitError::PurchaserMismatch);
    }
    match payer_key.verify_canonical_strict(body, &authorization.signature) {
        Ok(true) => {}
        _ => {
            return Err(FindingPoolDebitError::PurchaserAuthorization(
                "signature is invalid".to_owned(),
            ));
        }
    }
    let arguments_sha256 = sha256_hex(
        &canonical_json_bytes(request.purchase_context.arguments).map_err(|_| {
            FindingPoolDebitError::PurchaserAuthorization(
                "request arguments are not canonicalizable".to_owned(),
            )
        })?,
    );
    if body.purchase_id != expected_purchase_id
        || body.allocation_envelope_sha256 != request.expected_allocation_envelope_sha256
        || body.purchaser_id != request.purchaser_id
        || body.purchase_context_sha256
            != sha256_hex(request.purchase_context.context_b64.as_bytes())
        || body.capability_id != request.purchase_context.capability.id
        || body.server_id != request.purchase_context.server_id
        || body.tool_name != request.purchase_context.tool_name
        || body.arguments_sha256 != arguments_sha256
        || body.expected_output_digest != request.purchase_context.expected_output_digest
    {
        return Err(FindingPoolDebitError::PurchaserAuthorization(
            "authorization does not bind the debit request".to_owned(),
        ));
    }
    let replay_binding = FindingPoolDebitReplayBinding {
        schema: &body.schema,
        purchase_id: &body.purchase_id,
        allocation_envelope_sha256: &body.allocation_envelope_sha256,
        purchaser_id: &body.purchaser_id,
        purchase_context_sha256: &body.purchase_context_sha256,
        capability_id: &body.capability_id,
        server_id: &body.server_id,
        tool_name: &body.tool_name,
        arguments_sha256: &body.arguments_sha256,
        expected_output_digest: &body.expected_output_digest,
    };
    let replay_binding_sha256 =
        sha256_hex(&canonical_json_bytes(&replay_binding).map_err(|_| {
            FindingPoolDebitError::PurchaserAuthorization(
                "replay binding is not canonicalizable".to_owned(),
            )
        })?);
    Ok((expires_at_unix_ms, replay_binding_sha256))
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
pub(crate) mod tests;
