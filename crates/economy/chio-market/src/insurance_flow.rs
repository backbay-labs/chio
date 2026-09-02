//! End-to-end insurance flow on top of the liability market.
//!
//! This module connects the three shipped economic primitives:
//!
//! 1. `chio-underwriting::price_fiscal_premium` -- governed risk-based premium quote.
//! 2. `chio-market` -- binds the quote into a [`BoundPolicy`].
//! 3. `chio-settle` -- receives a [`ClaimSettlementRequest`] (field-compatible
//!    with `chio_settle::SettlementCommitment`) after a claim is approved
//!    against receipt evidence.
//!
//! The flow is intentionally small: [`quote_and_bind`] accepts a
//! [`PremiumSource`] (typically computed on the kernel side from
//! `ComplianceReport` / `BehavioralFeedReport`) and produces a
//! [`BoundPolicy`]. [`BoundPolicy::file_claim`] takes a
//! [`ClaimEvidence`] payload plus a [`ReceiptEvidenceSource`] that
//! re-verifies the referenced receipts against the kernel's signing key,
//! and a [`ClaimSettlementSink`] which, on approval, receives a
//! [`ClaimSettlementRequest`] (which embeds the same five required
//! fields as `chio_settle::SettlementCommitment`).
//!
//! **Crate graph note.** chio-settle depends on chio-core which (via
//! chio-autonomy) depends on chio-market, so chio-market cannot take a hard
//! dependency on chio-settle without creating a cycle. Callers sitting at
//! the top of the graph (for example chio-kernel) implement
//! [`ClaimSettlementSink`] to bridge the insurance-flow approval into an
//! `chio_settle::SettlementCommitment`. The fields on
//! [`ClaimSettlementRequest`] match `SettlementCommitment` 1:1 so the
//! bridge is a straight field copy.
//!
//! Traits are used instead of directly importing chio-kernel for the same
//! reason (`chio-kernel -> chio-market -> chio-underwriting` today; adding
//! a back-edge would create a cycle). Callers with chio-kernel in scope
//! populate the [`PremiumSource`] and [`ReceiptEvidenceSource`] using
//! the already-exposed kernel APIs (`compliance_score`,
//! `behavioral_anomaly_score`, and the receipt store).

use serde::{Deserialize, Serialize};

use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::capability::scope::MonetaryAmount;
use chio_core_types::crypto::{sha256_hex, PublicKey, Signature};
use chio_fiscal::FiscalResolver;
use chio_underwriting::{price_fiscal_premium, LookbackWindow, PremiumInputs, PremiumQuote};

use crate::validate_positive_money;

/// Lane identifier used for insurance-flow settlement commitments. Matches
/// the `lane_kind` convention used elsewhere in the chio-settle stack.
pub const INSURANCE_CLAIM_LANE_KIND: &str = "chio.insurance.claim.v1";

/// Error surface for the insurance flow.
#[derive(Debug, thiserror::Error)]
pub enum InsuranceFlowError {
    /// The premium source rejected the request or the underwriter declined
    /// the quote.
    #[error("premium declined: {0}")]
    PremiumDeclined(String),
    /// The bound policy is not in a state that can accept claims (expired,
    /// cancelled, or the policy id does not match).
    #[error("policy unavailable: {0}")]
    PolicyUnavailable(String),
    /// The claim could not be verified because receipt evidence either
    /// could not be fetched or failed cryptographic verification.
    #[error("claim evidence invalid: {0}")]
    InvalidEvidence(String),
    /// The settlement sink rejected the approved settlement.
    #[error("settlement submission failed: {0}")]
    SettlementFailed(String),
    /// Malformed inputs that cannot be satisfied.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

/// Identifier for a receipt plus its cryptographic fingerprint, used by
/// [`ClaimEvidence`] and re-verified via [`ReceiptEvidenceSource`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptFingerprint {
    /// Stable receipt id (matches the kernel receipt store key).
    pub receipt_id: String,
    /// SHA-256 of the canonical receipt body. Used for tamper-evidence
    /// in the evidence bundle.
    pub body_sha256: String,
}

impl ReceiptFingerprint {
    /// Validate that the fingerprint can be used as a stable evidence key.
    pub fn validate(&self) -> Result<(), InsuranceFlowError> {
        validate_clean_required(
            &self.receipt_id,
            "claim evidence receipt fingerprint receipt_id",
        )?;
        validate_clean_required(
            &self.body_sha256,
            "claim evidence receipt fingerprint body_sha256",
        )
    }
}

/// Trait implemented by callers (typically the kernel-side control plane)
/// to supply premium inputs for an agent+scope.
pub trait PremiumSource {
    /// Produce risk inputs for pricing a premium. Implementations MUST
    /// fail closed: on any error (kernel unavailable, missing compliance
    /// report, etc.) return an `Err` and [`quote_and_bind`] will surface
    /// it as `PremiumDeclined`.
    fn premium_inputs(
        &self,
        agent_id: &str,
        scope: &str,
        lookback_window: LookbackWindow,
    ) -> Result<PremiumInputs, String>;
}

/// Simple pass-through [`PremiumSource`] useful for tests and callers
/// that have already computed inputs via chio-kernel.
#[derive(Debug, Clone)]
pub struct StaticPremiumSource {
    inputs: PremiumInputs,
}

impl StaticPremiumSource {
    /// Construct a [`StaticPremiumSource`] that returns the same inputs
    /// for every `(agent_id, scope)` pair.
    #[must_use]
    pub fn new(inputs: PremiumInputs) -> Self {
        Self { inputs }
    }
}

impl PremiumSource for StaticPremiumSource {
    fn premium_inputs(
        &self,
        _agent_id: &str,
        _scope: &str,
        _lookback_window: LookbackWindow,
    ) -> Result<PremiumInputs, String> {
        Ok(self.inputs.clone())
    }
}

/// Trait implemented by callers to resolve claim-referenced receipts back
/// to the canonical evidence held in the kernel receipt store. The
/// implementation is responsible for:
///
/// * Returning the canonical body digest (SHA-256 of the canonical JSON
///   of the receipt body), so that [`BoundPolicy::file_claim`] can match
///   it against the fingerprint embedded in the [`ClaimEvidence`].
/// * Returning the kernel's current signer key, so that the claim flow
///   can verify the receipt signature end-to-end.
/// * Returning the signature recorded for the receipt (so the flow can
///   verify the referenced receipt actually came from the kernel).
pub trait ReceiptEvidenceSource {
    /// Resolve a receipt id to its cryptographic evidence.
    fn resolve(&self, receipt_id: &str) -> Result<ResolvedReceiptEvidence, String>;
}

/// Evidence bundle returned by [`ReceiptEvidenceSource::resolve`].
#[derive(Debug, Clone)]
pub struct ResolvedReceiptEvidence {
    /// SHA-256 of the canonical JSON of the receipt body.
    pub body_sha256: String,
    /// The kernel signer key that signed the receipt.
    pub signer_key: PublicKey,
    /// Signature over the canonical body produced by the signer key.
    pub signature: Signature,
    /// The canonical JSON bytes of the receipt body. Held so the
    /// insurance flow can verify the signature against the kernel's
    /// signing key end-to-end.
    pub canonical_body: Vec<u8>,
}

/// Trait implemented by callers to submit approved claims to
/// `chio-settle`. Implementations typically convert the
/// [`ClaimSettlementRequest`] into an `chio_settle::SettlementCommitment`
/// (fields are 1:1) and dispatch via the settlement runtime. On
/// success, return a stable settlement reference that callers can later
/// reconcile.
pub trait ClaimSettlementSink {
    /// Submit a [`ClaimSettlementRequest`] for execution. Returns the
    /// settlement reference assigned by the underlying rail (for example
    /// an on-chain tx hash or bond lock id).
    fn submit(&self, request: ClaimSettlementRequest) -> Result<String, String>;
}

/// Coverage limit attached to a [`BoundPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CoverageLimit {
    /// Amount in the smallest currency unit (cents for USD).
    pub amount_cents: u64,
    /// ISO 4217 three-letter uppercase currency code.
    pub currency: String,
}

impl CoverageLimit {
    /// Construct a [`CoverageLimit`] from a premium quote. The default
    /// coverage is 100x the quoted premium, a common rule of thumb for
    /// liability pricing. Callers can override via
    /// [`BoundPolicy::new_with_coverage`].
    #[must_use]
    pub fn default_from_premium(quoted_cents: u64, currency: &str) -> Self {
        Self {
            amount_cents: quoted_cents.saturating_mul(100),
            currency: currency.to_ascii_uppercase(),
        }
    }

    /// Convert to a `MonetaryAmount` for hand-off to downstream rails.
    #[must_use]
    pub fn to_monetary(&self) -> MonetaryAmount {
        MonetaryAmount {
            units: self.amount_cents,
            currency: self.currency.clone(),
        }
    }
}

/// Lifecycle state of a [`BoundPolicy`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    /// Policy is in-force and can accept claims within the effective window.
    Active,
    /// Policy has expired and cannot accept new claims.
    Expired,
    /// Policy was cancelled before expiry (for example after settling a
    /// total-loss claim).
    Cancelled,
}

/// A bound insurance policy produced by [`quote_and_bind`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct BoundPolicy {
    /// Stable, deterministic policy id derived from the agent, scope, and
    /// quote via canonical-JSON hashing.
    pub policy_id: String,
    /// Agent the policy insures.
    pub agent_id: String,
    /// Scope / coverage identifier the policy applies to.
    pub scope: String,
    /// The underwriting premium quote that was bound into this policy.
    pub premium_quote: PremiumQuote,
    /// Maximum payable coverage for any single claim against the policy.
    pub coverage_limit: CoverageLimit,
    /// Unix-seconds timestamp at which the policy became effective.
    pub effective_at: u64,
    /// Unix-seconds timestamp at which the policy expires (exclusive).
    pub expires_at: u64,
    /// Current lifecycle state.
    pub status: PolicyStatus,
}

impl BoundPolicy {
    fn new(
        agent_id: &str,
        scope: &str,
        premium_quote: PremiumQuote,
        coverage_limit: CoverageLimit,
        effective_at: u64,
        expires_at: u64,
    ) -> Result<Self, InsuranceFlowError> {
        if expires_at <= effective_at {
            return Err(InsuranceFlowError::InvalidInput(format!(
                "policy expires_at ({expires_at}) must be greater than effective_at ({effective_at})"
            )));
        }
        let policy_id =
            compute_policy_id(agent_id, scope, &premium_quote, effective_at, expires_at)?;
        Ok(Self {
            policy_id,
            agent_id: agent_id.to_string(),
            scope: scope.to_string(),
            premium_quote,
            coverage_limit,
            effective_at,
            expires_at,
            status: PolicyStatus::Active,
        })
    }

    /// Construct a policy from an already-computed premium quote with an
    /// explicit coverage limit. Used when callers want to override the
    /// default `100x quoted` rule.
    pub fn new_with_coverage(
        agent_id: &str,
        scope: &str,
        premium_quote: PremiumQuote,
        coverage_limit: CoverageLimit,
        effective_at: u64,
        expires_at: u64,
    ) -> Result<Self, InsuranceFlowError> {
        Self::new(
            agent_id,
            scope,
            premium_quote,
            coverage_limit,
            effective_at,
            expires_at,
        )
    }

    /// Return whether the policy is currently in-force at `now`.
    #[must_use]
    pub fn is_in_force(&self, now: u64) -> bool {
        matches!(self.status, PolicyStatus::Active)
            && self.effective_at <= now
            && now < self.expires_at
    }

    /// File a claim against this policy.
    ///
    /// * `evidence` -- the claim payload identifying the covered incident
    ///   and the receipts that support it.
    /// * `now` -- the wall-clock timestamp used for coverage-window and
    ///   claim-timestamp checks.
    /// * `receipts` -- resolves receipt ids to signed evidence so the
    ///   claim flow can verify the signature against the kernel's signing
    ///   key.
    /// * `settlement_sink` -- on approval, receives a settlement request
    ///   in chio-settle's `SettlementCommitment` shape.
    ///
    /// The claim is fail-closed: any evidence that fails to resolve or
    /// verify produces a denied [`ClaimDecision`] rather than an implicit
    /// approval.
    pub fn file_claim(
        &self,
        evidence: &ClaimEvidence,
        now: u64,
        receipts: &dyn ReceiptEvidenceSource,
        settlement_sink: &dyn ClaimSettlementSink,
    ) -> Result<ClaimDecision, InsuranceFlowError> {
        evidence.validate()?;
        if evidence.policy_id != self.policy_id {
            return Err(InsuranceFlowError::PolicyUnavailable(format!(
                "claim evidence policy_id `{}` does not match policy `{}`",
                evidence.policy_id, self.policy_id
            )));
        }
        if !self.is_in_force(now) {
            return Ok(ClaimDecision::Denied {
                policy_id: self.policy_id.clone(),
                claim_id: evidence.claim_id.clone(),
                reason: ClaimDenialReason::PolicyNotInForce,
                justification: format!(
                    "policy status {:?} at {now}, effective_at={}, expires_at={}",
                    self.status, self.effective_at, self.expires_at
                ),
            });
        }
        if evidence.requested_amount.currency != self.coverage_limit.currency {
            return Ok(ClaimDecision::Denied {
                policy_id: self.policy_id.clone(),
                claim_id: evidence.claim_id.clone(),
                reason: ClaimDenialReason::CurrencyMismatch,
                justification: format!(
                    "claim currency `{}` does not match policy currency `{}`",
                    evidence.requested_amount.currency, self.coverage_limit.currency
                ),
            });
        }
        if evidence.supporting_receipts.is_empty() {
            return Ok(ClaimDecision::Denied {
                policy_id: self.policy_id.clone(),
                claim_id: evidence.claim_id.clone(),
                reason: ClaimDenialReason::InsufficientEvidence,
                justification: "claim evidence did not reference any supporting receipts"
                    .to_string(),
            });
        }

        // Resolve and verify each referenced receipt against the kernel's
        // signing key. Fail-closed: a single unresolved or tampered
        // receipt denies the claim.
        for fingerprint in &evidence.supporting_receipts {
            let resolved = match receipts.resolve(&fingerprint.receipt_id) {
                Ok(resolved) => resolved,
                Err(error) => {
                    return Ok(ClaimDecision::Denied {
                        policy_id: self.policy_id.clone(),
                        claim_id: evidence.claim_id.clone(),
                        reason: ClaimDenialReason::EvidenceUnresolvable,
                        justification: format!(
                            "receipt `{}` could not be resolved: {error}",
                            fingerprint.receipt_id
                        ),
                    });
                }
            };
            if resolved.body_sha256 != fingerprint.body_sha256 {
                return Ok(ClaimDecision::Denied {
                    policy_id: self.policy_id.clone(),
                    claim_id: evidence.claim_id.clone(),
                    reason: ClaimDenialReason::EvidenceDigestMismatch,
                    justification: format!(
                        "receipt `{}` body digest does not match evidence fingerprint",
                        fingerprint.receipt_id
                    ),
                });
            }
            if !resolved
                .signer_key
                .verify(&resolved.canonical_body, &resolved.signature)
            {
                return Ok(ClaimDecision::Denied {
                    policy_id: self.policy_id.clone(),
                    claim_id: evidence.claim_id.clone(),
                    reason: ClaimDenialReason::SignatureInvalid,
                    justification: format!(
                        "kernel signature on receipt `{}` failed verification",
                        fingerprint.receipt_id
                    ),
                });
            }
        }

        // Cap the payout at the coverage limit.
        let payable_cents = evidence
            .requested_amount
            .units
            .min(self.coverage_limit.amount_cents);
        let payable_amount = MonetaryAmount {
            units: payable_cents,
            currency: self.coverage_limit.currency.clone(),
        };

        let receipt_reference = evidence
            .supporting_receipts
            .first()
            .map(|fingerprint| fingerprint.receipt_id.clone())
            .unwrap_or_default();
        let request = ClaimSettlementRequest {
            chain_id: evidence.settlement_chain_id.clone(),
            lane_kind: INSURANCE_CLAIM_LANE_KIND.to_string(),
            capability_commitment: self.policy_id.clone(),
            receipt_reference,
            operator_identity: format!("chio-market:insurance-flow:{}", self.agent_id),
            settlement_amount: payable_amount.clone(),
        };
        request.validate()?;

        let settlement_reference = settlement_sink
            .submit(request.clone())
            .map_err(InsuranceFlowError::SettlementFailed)?;

        Ok(ClaimDecision::Approved {
            policy_id: self.policy_id.clone(),
            claim_id: evidence.claim_id.clone(),
            payable_amount,
            settlement: Box::new(ClaimSettlement {
                request,
                settlement_reference,
            }),
            justification: format!(
                "{} supporting receipt(s) verified against kernel signing key; \
                 payout capped at coverage limit",
                evidence.supporting_receipts.len()
            ),
        })
    }
}

/// Evidence payload for a claim filed against a [`BoundPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClaimEvidence {
    /// Stable claim identifier chosen by the filer.
    pub claim_id: String,
    /// Policy this claim is filed against.
    pub policy_id: String,
    /// Amount the filer is requesting (may exceed the coverage limit;
    /// payouts are capped at the policy's coverage limit).
    pub requested_amount: MonetaryAmount,
    /// Human-readable description of the incident.
    pub incident_description: String,
    /// Receipts that support the claim. Each one is re-verified against
    /// the kernel's signing key before approval.
    pub supporting_receipts: Vec<ReceiptFingerprint>,
    /// Chain id the settlement should be dispatched on. The insurance
    /// flow itself is chain-agnostic; the settle runtime routes
    /// according to this value.
    pub settlement_chain_id: String,
}

impl ClaimEvidence {
    /// Validate fields that must be well-formed before receipt lookup or
    /// settlement handoff can be attempted.
    pub fn validate(&self) -> Result<(), InsuranceFlowError> {
        validate_clean_required(&self.claim_id, "claim evidence claim_id")?;
        validate_clean_required(&self.policy_id, "claim evidence policy_id")?;
        validate_positive_money(&self.requested_amount, "claim evidence requested_amount")
            .map_err(|error| InsuranceFlowError::InvalidInput(String::from(error)))?;
        if self.incident_description.trim().is_empty() {
            return Err(InsuranceFlowError::InvalidInput(
                "claim evidence incident_description must be non-empty".to_string(),
            ));
        }
        validate_clean_required(
            &self.settlement_chain_id,
            "claim evidence settlement_chain_id",
        )?;
        for fingerprint in &self.supporting_receipts {
            fingerprint.validate()?;
        }
        Ok(())
    }
}

/// Resolution of a filed claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub enum ClaimDecision {
    /// Claim was approved; settlement has been submitted.
    Approved {
        /// Policy the claim was filed against.
        policy_id: String,
        /// Claim identifier.
        claim_id: String,
        /// Actual payable amount (capped at coverage limit).
        payable_amount: MonetaryAmount,
        /// Settlement request and reference returned by the sink. Boxed so
        /// the enum stays cheap to move between the chio-market and
        /// chio-kernel boundaries.
        settlement: Box<ClaimSettlement>,
        /// Human-readable justification for the approval.
        justification: String,
    },
    /// Claim was denied; no settlement was submitted.
    Denied {
        /// Policy the claim was filed against.
        policy_id: String,
        /// Claim identifier.
        claim_id: String,
        /// Machine-readable denial reason.
        reason: ClaimDenialReason,
        /// Human-readable justification for the denial.
        justification: String,
    },
}

impl ClaimDecision {
    /// `true` when the claim was approved.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        matches!(self, ClaimDecision::Approved { .. })
    }

    /// Return the approved settlement record, if any.
    #[must_use]
    pub fn settlement(&self) -> Option<&ClaimSettlement> {
        match self {
            ClaimDecision::Approved { settlement, .. } => Some(settlement.as_ref()),
            ClaimDecision::Denied { .. } => None,
        }
    }
}

/// Machine-readable denial reason for a [`ClaimDecision::Denied`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimDenialReason {
    /// The policy is cancelled or expired.
    PolicyNotInForce,
    /// The claim currency did not match the coverage currency.
    CurrencyMismatch,
    /// No receipts were provided to support the claim.
    InsufficientEvidence,
    /// A referenced receipt could not be resolved in the receipt store.
    EvidenceUnresolvable,
    /// A referenced receipt's body digest did not match its fingerprint.
    EvidenceDigestMismatch,
    /// The kernel signature on a referenced receipt failed verification.
    SignatureInvalid,
}

/// Field-compatible projection of `chio_settle::SettlementCommitment`.
///
/// Because chio-settle depends on chio-core which depends on chio-market,
/// chio-market cannot take a hard dependency on chio-settle. Callers at
/// the top of the graph convert a [`ClaimSettlementRequest`] into an
/// `chio_settle::SettlementCommitment` by copying the five fields. The
/// field names and types are identical.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClaimSettlementRequest {
    /// Chain identifier the settlement should be dispatched on.
    pub chain_id: String,
    /// Settlement lane. Claim-payout dispatches use
    /// [`INSURANCE_CLAIM_LANE_KIND`].
    pub lane_kind: String,
    /// Capability / policy commitment (the policy id).
    pub capability_commitment: String,
    /// Receipt the claim is anchored to.
    pub receipt_reference: String,
    /// Operator identity dispatching the settlement.
    pub operator_identity: String,
    /// Amount to settle, in minor units + currency.
    pub settlement_amount: MonetaryAmount,
}

impl ClaimSettlementRequest {
    /// Validate the settlement-shaped handoff before it leaves chio-market.
    pub fn validate(&self) -> Result<(), InsuranceFlowError> {
        validate_clean_required(&self.chain_id, "claim settlement request chain_id")?;
        if self.lane_kind != INSURANCE_CLAIM_LANE_KIND {
            return Err(InsuranceFlowError::InvalidInput(format!(
                "claim settlement request lane_kind must be {INSURANCE_CLAIM_LANE_KIND}"
            )));
        }
        validate_clean_required(
            &self.capability_commitment,
            "claim settlement request capability_commitment",
        )?;
        validate_clean_required(
            &self.receipt_reference,
            "claim settlement request receipt_reference",
        )?;
        validate_clean_required(
            &self.operator_identity,
            "claim settlement request operator_identity",
        )?;
        validate_positive_money(
            &self.settlement_amount,
            "claim settlement request settlement_amount",
        )
        .map_err(|error| InsuranceFlowError::InvalidInput(String::from(error)))
    }
}

/// Settlement artifact returned when a claim is approved. Wraps the
/// [`ClaimSettlementRequest`] submitted to `chio-settle` and the
/// sink-assigned settlement reference so callers can reconcile the
/// dispatched settlement against its on-chain observation later.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClaimSettlement {
    /// The request submitted to the settlement sink.
    pub request: ClaimSettlementRequest,
    /// Reference returned by the settlement sink (for example, a tx hash).
    pub settlement_reference: String,
}

/// Quote a premium for `agent_id`+`scope` using `premium_source` and the
/// verified fiscal `resolver`, then bind the quote into a [`BoundPolicy`]
/// with the provided effective window.
///
/// Returns `Err(InsuranceFlowError::PremiumDeclined)` if the premium
/// source is unavailable or the underwriter declines the quote. This
/// pathway is fail-closed: missing risk signals never produce a silent
/// approval.
pub fn quote_and_bind(
    agent_id: &str,
    scope: &str,
    lookback_window: LookbackWindow,
    premium_source: &dyn PremiumSource,
    resolver: &FiscalResolver<'_>,
    effective_at: u64,
    policy_duration_secs: u64,
) -> Result<BoundPolicy, InsuranceFlowError> {
    if agent_id.trim().is_empty() {
        return Err(InsuranceFlowError::InvalidInput(
            "agent_id must not be empty".to_string(),
        ));
    }
    if scope.trim().is_empty() {
        return Err(InsuranceFlowError::InvalidInput(
            "scope must not be empty".to_string(),
        ));
    }
    if policy_duration_secs == 0 {
        return Err(InsuranceFlowError::InvalidInput(
            "policy_duration_secs must be greater than zero".to_string(),
        ));
    }

    let inputs = premium_source
        .premium_inputs(agent_id, scope, lookback_window)
        .map_err(|error| {
            InsuranceFlowError::PremiumDeclined(format!(
                "premium source failed for agent `{agent_id}` scope `{scope}`: {error}"
            ))
        })?;

    let quote = price_fiscal_premium(agent_id, scope, lookback_window, &inputs, resolver).map_err(
        |reason| {
            InsuranceFlowError::PremiumDeclined(format!(
                "fiscal premium resolution denied: {reason:?}"
            ))
        },
    )?;
    let (quoted_cents, currency) = match &quote {
        PremiumQuote::Quoted {
            quoted_cents,
            currency,
            ..
        } => (*quoted_cents, currency.clone()),
        PremiumQuote::Declined {
            reason,
            justification,
            ..
        } => {
            return Err(InsuranceFlowError::PremiumDeclined(format!(
                "{reason:?}: {justification}"
            )));
        }
    };

    let coverage_limit = CoverageLimit::default_from_premium(quoted_cents, &currency);
    let expires_at = effective_at
        .checked_add(policy_duration_secs)
        .ok_or_else(|| {
            InsuranceFlowError::InvalidInput(format!(
                "effective_at ({effective_at}) + policy_duration_secs ({policy_duration_secs}) overflows u64"
            ))
        })?;
    BoundPolicy::new(
        agent_id,
        scope,
        quote,
        coverage_limit,
        effective_at,
        expires_at,
    )
}

fn compute_policy_id(
    agent_id: &str,
    scope: &str,
    quote: &PremiumQuote,
    effective_at: u64,
    expires_at: u64,
) -> Result<String, InsuranceFlowError> {
    let canonical = canonical_json_bytes(&(
        "chio.market.insurance-policy.v1",
        agent_id,
        scope,
        quote,
        effective_at,
        expires_at,
    ))
    .map_err(|error| {
        InsuranceFlowError::InvalidInput(format!("failed to canonicalize policy identity: {error}"))
    })?;
    Ok(format!("insp-{}", sha256_hex(&canonical)))
}

fn validate_clean_required(value: &str, field_name: &str) -> Result<(), InsuranceFlowError> {
    if value.trim().is_empty() {
        return Err(InsuranceFlowError::InvalidInput(format!(
            "{field_name} must be non-empty"
        )));
    }
    if value.trim() != value {
        return Err(InsuranceFlowError::InvalidInput(format!(
            "{field_name} must not contain surrounding whitespace"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use chio_core_types::canonical::canonical_json_bytes;
    use chio_core_types::crypto::Keypair;
    use chio_fiscal::{
        FiscalActivationHistory, FiscalAuthorityState, FiscalBootstrapState, FiscalCharterRegistry,
        FiscalContinuitySnapshot, FiscalGenesisPolicy, FiscalRuntimeAdapter,
        FiscalRuntimeAdapterRegistry, SignedFiscalCharter, SignedFiscalContinuityCheckpoint,
        SignedFiscalRuntimeReadiness, SignedFiscalSchedule, VerifiedFiscalCharter,
        VerifiedFiscalContinuityCheckpoint, VerifiedFiscalRuntimeReadiness,
        FISCAL_RUNTIME_ADAPTER_COUNT,
    };

    struct FiscalTestState {
        policy: FiscalGenesisPolicy,
        readiness: VerifiedFiscalRuntimeReadiness,
        checkpoint: VerifiedFiscalContinuityCheckpoint,
        activation_history: FiscalActivationHistory,
        authority: FiscalAuthorityState,
        charters: FiscalCharterRegistry,
        schedules: Vec<SignedFiscalSchedule>,
    }

    impl FiscalTestState {
        fn new() -> Self {
            let fixture = |name: &str| {
                let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
                    "../../../spec/schemas/chio-fiscal/v1/fixtures/{name}.positive.json"
                ));
                std::fs::read(path).unwrap()
            };
            let policy: FiscalGenesisPolicy =
                serde_json::from_slice(&fixture("genesis-policy")).unwrap();
            let charter = VerifiedFiscalCharter::verify(
                serde_json::from_slice::<SignedFiscalCharter>(&fixture("charter")).unwrap(),
            )
            .unwrap();
            let charters = FiscalCharterRegistry::new(vec![charter.signed().clone()]).unwrap();
            let registry = FiscalRuntimeAdapterRegistry::new(
                "build-1".to_owned(),
                "chio.fiscal.runtime.v1".to_owned(),
                (0..FISCAL_RUNTIME_ADAPTER_COUNT)
                    .map(|index| {
                        FiscalRuntimeAdapter::new(format!("adapter-{index}"), format!("1.{index}"))
                            .unwrap()
                    })
                    .collect(),
            )
            .unwrap();
            let readiness = VerifiedFiscalRuntimeReadiness::verify(
                serde_json::from_slice::<SignedFiscalRuntimeReadiness>(&fixture(
                    "consumer-readiness",
                ))
                .unwrap(),
                &policy,
                registry,
            )
            .unwrap();
            let checkpoint = VerifiedFiscalContinuityCheckpoint::verify(
                serde_json::from_slice::<SignedFiscalContinuityCheckpoint>(&fixture(
                    "continuity-checkpoint",
                ))
                .unwrap(),
                &policy,
                &charters,
            )
            .unwrap();
            let authority = FiscalAuthorityState::from_checkpoint(
                &policy,
                &checkpoint,
                FiscalBootstrapState::CharterPinned,
            )
            .unwrap();
            Self {
                policy,
                readiness,
                checkpoint,
                activation_history: FiscalActivationHistory::new(Vec::new()).unwrap(),
                authority,
                charters,
                schedules: Vec::new(),
            }
        }

        fn resolver(&self) -> FiscalResolver<'_> {
            FiscalResolver {
                continuity: FiscalContinuitySnapshot::Verified(&self.checkpoint),
                policy: &self.policy,
                readiness: &self.readiness,
                activation_history: &self.activation_history,
                authority: &self.authority,
                charters: &self.charters,
                schedules: &self.schedules,
                verify_at: self.checkpoint.body().trusted_clock_high_water,
            }
        }
    }

    fn test_quote_and_bind(
        agent_id: &str,
        scope: &str,
        lookback_window: LookbackWindow,
        premium_source: &dyn PremiumSource,
        effective_at: u64,
        policy_duration_secs: u64,
    ) -> Result<BoundPolicy, InsuranceFlowError> {
        let fiscal = FiscalTestState::new();
        quote_and_bind(
            agent_id,
            scope,
            lookback_window,
            premium_source,
            &fiscal.resolver(),
            effective_at,
            policy_duration_secs,
        )
    }

    fn window() -> LookbackWindow {
        LookbackWindow::new(1_000_000, 1_000_600).unwrap()
    }

    fn static_source(score: u32) -> StaticPremiumSource {
        StaticPremiumSource::new(PremiumInputs::new(Some(score), None, 1_000, "USD"))
    }

    struct RejectingSource;
    impl PremiumSource for RejectingSource {
        fn premium_inputs(
            &self,
            _agent_id: &str,
            _scope: &str,
            _lookback_window: LookbackWindow,
        ) -> Result<PremiumInputs, String> {
            Err("kernel unavailable".to_string())
        }
    }

    /// Minimal `ReceiptEvidenceSource` that stores signed canonical
    /// bodies in memory.
    struct InMemoryReceiptSource {
        entries: std::collections::BTreeMap<String, ResolvedReceiptEvidence>,
    }

    impl ReceiptEvidenceSource for InMemoryReceiptSource {
        fn resolve(&self, receipt_id: &str) -> Result<ResolvedReceiptEvidence, String> {
            self.entries
                .get(receipt_id)
                .cloned()
                .ok_or_else(|| format!("receipt `{receipt_id}` not found"))
        }
    }

    /// Capturing settlement sink that records every submitted request.
    struct CapturingSink {
        events: std::sync::Mutex<Vec<ClaimSettlementRequest>>,
    }

    impl CapturingSink {
        fn new() -> Self {
            Self {
                events: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<ClaimSettlementRequest> {
            self.events.lock().unwrap().clone()
        }
    }

    impl ClaimSettlementSink for CapturingSink {
        fn submit(&self, request: ClaimSettlementRequest) -> Result<String, String> {
            let mut events = self.events.lock().map_err(|error| error.to_string())?;
            let reference = format!("settle-ref-{}", events.len());
            events.push(request);
            Ok(reference)
        }
    }

    fn fake_receipt(
        keypair: &Keypair,
        receipt_id: &str,
    ) -> (ReceiptFingerprint, ResolvedReceiptEvidence) {
        // A canonical body can be any serializable value, so a tuple
        // stands in for a full receipt fixture.
        let body = ("chio.receipt.fixture.v1", receipt_id, 1_000_000u64);
        let canonical = canonical_json_bytes(&body).unwrap();
        let body_sha256 = sha256_hex(&canonical);
        let signature = keypair.sign(&canonical);
        let signer_key = keypair.public_key();
        (
            ReceiptFingerprint {
                receipt_id: receipt_id.to_string(),
                body_sha256: body_sha256.clone(),
            },
            ResolvedReceiptEvidence {
                body_sha256,
                signer_key,
                signature,
                canonical_body: canonical,
            },
        )
    }

    #[test]
    fn clean_agent_binds_policy_with_quoted_premium() {
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap();
        assert_eq!(policy.agent_id, "agent-clean");
        assert!(policy.premium_quote.is_quoted());
        assert_eq!(policy.status, PolicyStatus::Active);
        assert!(policy.policy_id.starts_with("insp-"));
        // Coverage defaults to 100x the quoted premium.
        assert_eq!(policy.coverage_limit.amount_cents, 2_000 * 100);
    }

    #[test]
    fn denial_below_floor_returns_premium_declined() {
        let error = test_quote_and_bind(
            "agent-bad",
            "tool:exec",
            window(),
            &static_source(200),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap_err();
        assert!(matches!(error, InsuranceFlowError::PremiumDeclined(_)));
    }

    #[test]
    fn rejecting_source_surfaces_fail_closed_decline() {
        let error = test_quote_and_bind(
            "agent",
            "tool:exec",
            window(),
            &RejectingSource,
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap_err();
        match error {
            InsuranceFlowError::PremiumDeclined(message) => {
                assert!(message.contains("kernel unavailable"));
            }
            other => panic!("expected PremiumDeclined, got {other:?}"),
        }
    }

    #[test]
    fn file_claim_with_verified_receipt_is_approved_and_submits_settlement() {
        let keypair = Keypair::generate();
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap();
        let (fingerprint, resolved) = fake_receipt(&keypair, "rcpt-1");
        let receipts = InMemoryReceiptSource {
            entries: std::collections::BTreeMap::from([(fingerprint.receipt_id.clone(), resolved)]),
        };
        let sink = CapturingSink::new();
        let evidence = ClaimEvidence {
            claim_id: "claim-1".to_string(),
            policy_id: policy.policy_id.clone(),
            requested_amount: MonetaryAmount {
                units: 100_000,
                currency: "USD".to_string(),
            },
            incident_description: "tool execution caused downstream loss".to_string(),
            supporting_receipts: vec![fingerprint],
            settlement_chain_id: "ethereum-mainnet".to_string(),
        };

        let decision = policy
            .file_claim(&evidence, 1_001_000, &receipts, &sink)
            .unwrap();
        assert!(decision.is_approved(), "decision={decision:?}");
        let settlement = decision.settlement().unwrap();
        assert_eq!(settlement.request.lane_kind, INSURANCE_CLAIM_LANE_KIND);
        assert_eq!(settlement.request.capability_commitment, policy.policy_id);
        let events = sink.events();
        assert_eq!(
            events.len(),
            1,
            "one settlement request should be submitted"
        );
        assert_eq!(events[0].settlement_amount.currency, "USD");
    }

    #[test]
    fn claim_settlement_request_validation_rejects_non_claim_or_empty_handoff() {
        let request = ClaimSettlementRequest {
            chain_id: "ethereum-mainnet".to_string(),
            lane_kind: INSURANCE_CLAIM_LANE_KIND.to_string(),
            capability_commitment: "policy-1".to_string(),
            receipt_reference: "rcpt-1".to_string(),
            operator_identity: "chio-market:insurance-flow:agent-1".to_string(),
            settlement_amount: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
        };
        request.validate().unwrap();

        let mut wrong_lane = request.clone();
        wrong_lane.lane_kind = "evm_dual_signature".to_string();
        let error = wrong_lane.validate().unwrap_err();
        assert!(matches!(error, InsuranceFlowError::InvalidInput(_)));
        assert!(error.to_string().contains("lane_kind"));

        let mut empty_receipt = request.clone();
        empty_receipt.receipt_reference = " ".to_string();
        let error = empty_receipt.validate().unwrap_err();
        assert!(matches!(error, InsuranceFlowError::InvalidInput(_)));
        assert!(error.to_string().contains("receipt_reference"));

        let mut zero_amount = request;
        zero_amount.settlement_amount.units = 0;
        let error = zero_amount.validate().unwrap_err();
        assert!(matches!(error, InsuranceFlowError::InvalidInput(_)));
        assert!(error.to_string().contains("settlement_amount"));
    }

    #[test]
    fn file_claim_rejects_malformed_evidence_before_settlement_sink() {
        let keypair = Keypair::generate();
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap();
        let (fingerprint, resolved) = fake_receipt(&keypair, "rcpt-malformed");
        let receipts = InMemoryReceiptSource {
            entries: std::collections::BTreeMap::from([(fingerprint.receipt_id.clone(), resolved)]),
        };

        let valid_evidence = ClaimEvidence {
            claim_id: "claim-valid".to_string(),
            policy_id: policy.policy_id.clone(),
            requested_amount: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            incident_description: "covered incident".to_string(),
            supporting_receipts: vec![fingerprint],
            settlement_chain_id: "ethereum-mainnet".to_string(),
        };

        let cases = [
            (
                "padded claim id",
                ClaimEvidence {
                    claim_id: " claim-valid".to_string(),
                    ..valid_evidence.clone()
                },
            ),
            (
                "zero requested amount",
                ClaimEvidence {
                    requested_amount: MonetaryAmount {
                        units: 0,
                        currency: "USD".to_string(),
                    },
                    ..valid_evidence.clone()
                },
            ),
            (
                "empty settlement chain",
                ClaimEvidence {
                    settlement_chain_id: String::new(),
                    ..valid_evidence.clone()
                },
            ),
            (
                "empty receipt fingerprint",
                ClaimEvidence {
                    supporting_receipts: vec![ReceiptFingerprint {
                        receipt_id: String::new(),
                        body_sha256: "sha256-body".to_string(),
                    }],
                    ..valid_evidence
                },
            ),
        ];

        for (label, evidence) in cases {
            let sink = CapturingSink::new();
            let error = policy
                .file_claim(&evidence, 1_001_000, &receipts, &sink)
                .unwrap_err();
            assert!(
                matches!(error, InsuranceFlowError::InvalidInput(_)),
                "{label}: unexpected error {error:?}"
            );
            assert!(sink.events().is_empty(), "{label}: sink should not run");
        }
    }

    #[test]
    fn file_claim_denies_when_receipt_cannot_be_resolved() {
        let keypair = Keypair::generate();
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap();
        let (fingerprint, _resolved) = fake_receipt(&keypair, "rcpt-missing");
        let receipts = InMemoryReceiptSource {
            entries: std::collections::BTreeMap::new(),
        };
        let sink = CapturingSink::new();
        let evidence = ClaimEvidence {
            claim_id: "claim-miss".to_string(),
            policy_id: policy.policy_id.clone(),
            requested_amount: MonetaryAmount {
                units: 100_000,
                currency: "USD".to_string(),
            },
            incident_description: "missing receipt".to_string(),
            supporting_receipts: vec![fingerprint],
            settlement_chain_id: "ethereum-mainnet".to_string(),
        };
        let decision = policy
            .file_claim(&evidence, 1_001_000, &receipts, &sink)
            .unwrap();
        match decision {
            ClaimDecision::Denied { reason, .. } => {
                assert_eq!(reason, ClaimDenialReason::EvidenceUnresolvable);
            }
            ClaimDecision::Approved { .. } => panic!("expected denial for missing evidence"),
        }
        assert!(sink.events().is_empty());
    }

    #[test]
    fn file_claim_denies_when_receipt_signature_is_tampered() {
        let real = Keypair::generate();
        let imposter = Keypair::generate();
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap();
        let (fingerprint, mut resolved) = fake_receipt(&real, "rcpt-tampered");
        // Swap the signature with one produced by the imposter key --
        // signer key still matches the real one, but signature won't verify.
        resolved.signature = imposter.sign(&resolved.canonical_body);
        let receipts = InMemoryReceiptSource {
            entries: std::collections::BTreeMap::from([(fingerprint.receipt_id.clone(), resolved)]),
        };
        let sink = CapturingSink::new();
        let evidence = ClaimEvidence {
            claim_id: "claim-tamper".to_string(),
            policy_id: policy.policy_id.clone(),
            requested_amount: MonetaryAmount {
                units: 100_000,
                currency: "USD".to_string(),
            },
            incident_description: "tampered receipt".to_string(),
            supporting_receipts: vec![fingerprint],
            settlement_chain_id: "ethereum-mainnet".to_string(),
        };
        let decision = policy
            .file_claim(&evidence, 1_001_000, &receipts, &sink)
            .unwrap();
        match decision {
            ClaimDecision::Denied { reason, .. } => {
                assert_eq!(reason, ClaimDenialReason::SignatureInvalid);
            }
            ClaimDecision::Approved { .. } => panic!("expected denial for tampered evidence"),
        }
        assert!(sink.events().is_empty());
    }

    #[test]
    fn file_claim_caps_payout_at_coverage_limit() {
        let keypair = Keypair::generate();
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60 * 60 * 24 * 30,
        )
        .unwrap();
        let (fingerprint, resolved) = fake_receipt(&keypair, "rcpt-huge");
        let receipts = InMemoryReceiptSource {
            entries: std::collections::BTreeMap::from([(fingerprint.receipt_id.clone(), resolved)]),
        };
        let sink = CapturingSink::new();
        let huge_request = policy.coverage_limit.amount_cents.saturating_mul(10);
        let evidence = ClaimEvidence {
            claim_id: "claim-big".to_string(),
            policy_id: policy.policy_id.clone(),
            requested_amount: MonetaryAmount {
                units: huge_request,
                currency: "USD".to_string(),
            },
            incident_description: "oversized loss".to_string(),
            supporting_receipts: vec![fingerprint],
            settlement_chain_id: "ethereum-mainnet".to_string(),
        };
        let decision = policy
            .file_claim(&evidence, 1_001_000, &receipts, &sink)
            .unwrap();
        match decision {
            ClaimDecision::Approved { payable_amount, .. } => {
                assert_eq!(payable_amount.units, policy.coverage_limit.amount_cents);
            }
            ClaimDecision::Denied { reason, .. } => {
                panic!("expected approval with capped payout, got {reason:?}")
            }
        }
    }

    #[test]
    fn file_claim_denies_after_policy_expires() {
        let keypair = Keypair::generate();
        let policy = test_quote_and_bind(
            "agent-clean",
            "tool:exec",
            window(),
            &static_source(950),
            1_000_600,
            60,
        )
        .unwrap();
        let (fingerprint, resolved) = fake_receipt(&keypair, "rcpt-late");
        let receipts = InMemoryReceiptSource {
            entries: std::collections::BTreeMap::from([(fingerprint.receipt_id.clone(), resolved)]),
        };
        let sink = CapturingSink::new();
        let evidence = ClaimEvidence {
            claim_id: "claim-late".to_string(),
            policy_id: policy.policy_id.clone(),
            requested_amount: MonetaryAmount {
                units: 100,
                currency: "USD".to_string(),
            },
            incident_description: "too late".to_string(),
            supporting_receipts: vec![fingerprint],
            settlement_chain_id: "ethereum-mainnet".to_string(),
        };
        // `now` is well past `expires_at = effective_at + 60`.
        let decision = policy
            .file_claim(&evidence, 1_000_600 + 3_600, &receipts, &sink)
            .unwrap();
        match decision {
            ClaimDecision::Denied { reason, .. } => {
                assert_eq!(reason, ClaimDenialReason::PolicyNotInForce);
            }
            ClaimDecision::Approved { .. } => panic!("expected denial after expiry"),
        }
        assert!(sink.events().is_empty());
    }
}
