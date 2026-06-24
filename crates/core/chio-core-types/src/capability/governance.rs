use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{
    is_default_optional_algorithm, sha256_hex, sign_canonical_with_backend, Keypair, PublicKey,
    Signature, SigningAlgorithm, SigningBackend,
};
use crate::error::{Error, Result};
use crate::schema_binding::ensure_schema_matches;
use crate::session::SessionAnchorReference;
use crate::signer_binding::{
    ensure_backend_matches_embedded_key, ensure_keypair_matches_embedded_key,
};

use super::runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence};
use super::scope::MonetaryAmount;

/// Explicit governed autonomy tier requested for one economically sensitive action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedAutonomyTier {
    #[default]
    Direct,
    Delegated,
    Autonomous,
}

impl GovernedAutonomyTier {
    #[must_use]
    pub fn requires_delegation_bond(self) -> bool {
        !matches!(self, Self::Direct)
    }

    #[must_use]
    pub fn requires_call_chain(self) -> bool {
        !matches!(self, Self::Direct)
    }

    #[must_use]
    pub fn minimum_runtime_assurance(self) -> RuntimeAssuranceTier {
        match self {
            Self::Direct => RuntimeAssuranceTier::None,
            Self::Delegated => RuntimeAssuranceTier::Attested,
            Self::Autonomous => RuntimeAssuranceTier::Verified,
        }
    }
}

/// Policy-visible settlement posture for quoted metered billing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeteredSettlementMode {
    /// The action should not execute unless the quoted amount is prepaid.
    MustPrepay,
    /// The action may execute against a hold and settle later via capture/release.
    HoldCapture,
    /// The action may execute first and settle later with truthful pending state.
    AllowThenSettle,
}

/// Stable quote describing pre-execution metered billing expectations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingQuote {
    /// Stable quote identifier from the billing or metering authority.
    pub quote_id: String,
    /// Billing or metering provider that issued the quote.
    pub provider: String,
    /// Billing unit used to interpret `quoted_units` (for example `1k_tokens`).
    pub billing_unit: String,
    /// Quoted number of billable units for the pre-execution estimate.
    pub quoted_units: u64,
    /// Quoted monetary amount for the estimate.
    pub quoted_cost: MonetaryAmount,
    /// Unix timestamp (seconds) when the quote was issued.
    pub issued_at: u64,
    /// Optional Unix timestamp (seconds) when the quote expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl MeteredBillingQuote {
    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && self.expires_at.is_none_or(|expires_at| now < expires_at)
    }
}

/// Generic metered-billing context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MeteredBillingContext {
    /// Settlement posture expected for this metered tool action.
    pub settlement_mode: MeteredSettlementMode,
    /// Pre-execution quote bound to the governed request.
    pub quote: MeteredBillingQuote,
    /// Optional explicit upper bound on billable units for the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_billed_units: Option<u64>,
}

/// Delegated call-chain context bound into a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainContext {
    /// Stable identifier for the delegated transaction or call chain.
    pub chain_id: String,
    /// Upstream parent request identifier inside the trusted domain.
    pub parent_request_id: String,
    /// Optional upstream parent receipt identifier when already available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Root or originating subject for the governed chain.
    pub origin_subject: String,
    /// Immediate delegator subject that handed control to the current subject.
    pub delegator_subject: String,
}

/// Reserved key inside `GovernedTransactionIntent.context` for legacy upstream call-chain proofs.
pub const GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY: &str = "callChainUpstreamProof";

/// Signable upstream proof for delegated governed call-chain provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedUpstreamCallChainProofBody {
    /// Public key that authenticated the upstream delegated handoff.
    pub signer: PublicKey,
    /// Capability subject key this handoff was issued to.
    pub subject: PublicKey,
    /// Stable identifier for the delegated transaction or call chain.
    pub chain_id: String,
    /// Upstream parent request identifier inside the trusted domain.
    pub parent_request_id: String,
    /// Optional upstream parent receipt identifier when already available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    /// Root or originating subject for the governed chain.
    pub origin_subject: String,
    /// Immediate delegator subject that handed control to the current subject.
    pub delegator_subject: String,
    /// Unix timestamp (seconds) when this proof was issued.
    pub issued_at: u64,
    /// Unix timestamp (seconds) when this proof expires.
    pub expires_at: u64,
}

/// Signed upstream proof Chio can validate and promote to verified provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedUpstreamCallChainProof {
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    pub origin_subject: String,
    pub delegator_subject: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

impl GovernedUpstreamCallChainProof {
    #[must_use]
    pub fn body(&self) -> GovernedUpstreamCallChainProofBody {
        GovernedUpstreamCallChainProofBody {
            signer: self.signer.clone(),
            subject: self.subject.clone(),
            chain_id: self.chain_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            origin_subject: self.origin_subject.clone(),
            delegator_subject: self.delegator_subject.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub fn sign(body: GovernedUpstreamCallChainProofBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(&body.signer, keypair, "call-chain proof", "signer")?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            signer: body.signer,
            subject: body.subject,
            chain_id: body.chain_id,
            parent_request_id: body.parent_request_id,
            parent_receipt_id: body.parent_receipt_id,
            origin_subject: body.origin_subject,
            delegator_subject: body.delegator_subject,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    /// Verify the signature AND enforce the validity window in one pass.
    ///
    /// Sanctioned entry point when freshness matters: fails closed on expiry /
    /// not-yet-valid proofs, which the bare
    /// [`GovernedUpstreamCallChainProof::verify_signature`] does not check. A
    /// clock is threaded explicitly via `now` (unix seconds).
    ///
    /// Fail-closed ordering: the signature is checked FIRST. A proof with an
    /// invalid signature is rejected before the time window is consulted.
    /// Returns `Ok(true)` only when the signature verifies and `now` is within
    /// `[issued_at, expires_at)`.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_context(&self, context: &GovernedCallChainContext) -> bool {
        self.chain_id == context.chain_id
            && self.parent_request_id == context.parent_request_id
            && self.parent_receipt_id == context.parent_receipt_id
            && self.origin_subject == context.origin_subject
            && self.delegator_subject == context.delegator_subject
    }
}

/// Reserved key inside `GovernedTransactionIntent.context` for continuation tokens.
pub const GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY: &str = "callChainContinuation";
/// Versioned schema identifier for continuation tokens.
pub const CHIO_CALL_CHAIN_CONTINUATION_SCHEMA: &str = "chio.call_chain_continuation.v1";

/// Audience binding for a continuation token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationAudience {
    pub server_id: String,
    pub tool_name: String,
}

/// Stronger cross-kernel continuation artifact for governed provenance transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationTokenBody {
    pub schema: String,
    pub token_id: String,
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_anchor: Option<SessionAnchorReference>,
    pub current_subject: String,
    pub delegator_subject: String,
    pub origin_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_link_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CallChainContinuationAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Signed continuation token used to move governed provenance across kernels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallChainContinuationToken {
    pub schema: String,
    pub token_id: String,
    pub signer: PublicKey,
    pub subject: PublicKey,
    pub chain_id: String,
    pub parent_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_receipt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_session_anchor: Option<SessionAnchorReference>,
    pub current_subject: String,
    pub delegator_subject: String,
    pub origin_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_capability_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_link_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<CallChainContinuationAudience>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: Signature,
}

impl CallChainContinuationToken {
    #[must_use]
    pub fn body(&self) -> CallChainContinuationTokenBody {
        CallChainContinuationTokenBody {
            schema: self.schema.clone(),
            token_id: self.token_id.clone(),
            signer: self.signer.clone(),
            subject: self.subject.clone(),
            chain_id: self.chain_id.clone(),
            parent_request_id: self.parent_request_id.clone(),
            parent_receipt_id: self.parent_receipt_id.clone(),
            parent_receipt_hash: self.parent_receipt_hash.clone(),
            parent_session_anchor: self.parent_session_anchor.clone(),
            current_subject: self.current_subject.clone(),
            delegator_subject: self.delegator_subject.clone(),
            origin_subject: self.origin_subject.clone(),
            parent_capability_id: self.parent_capability_id.clone(),
            delegation_link_hash: self.delegation_link_hash.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            audience: self.audience.clone(),
            nonce: self.nonce.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }

    pub fn sign(body: CallChainContinuationTokenBody, keypair: &Keypair) -> Result<Self> {
        ensure_schema_matches(
            &body.schema,
            CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
            "call-chain continuation token",
        )?;
        ensure_keypair_matches_embedded_key(&body.signer, keypair, "continuation token", "signer")?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            schema: body.schema,
            token_id: body.token_id,
            signer: body.signer,
            subject: body.subject,
            chain_id: body.chain_id,
            parent_request_id: body.parent_request_id,
            parent_receipt_id: body.parent_receipt_id,
            parent_receipt_hash: body.parent_receipt_hash,
            parent_session_anchor: body.parent_session_anchor,
            current_subject: body.current_subject,
            delegator_subject: body.delegator_subject,
            origin_subject: body.origin_subject,
            parent_capability_id: body.parent_capability_id,
            delegation_link_hash: body.delegation_link_hash,
            governed_intent_hash: body.governed_intent_hash,
            audience: body.audience,
            nonce: body.nonce,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        ensure_schema_matches(
            &self.schema,
            CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
            "call-chain continuation token",
        )?;
        let body = self.body();
        self.signer.verify_canonical(&body, &self.signature)
    }

    /// Verify the signature AND enforce the validity window in one pass.
    ///
    /// Sanctioned entry point when freshness matters: fails closed on expiry /
    /// not-yet-valid tokens, which the bare
    /// [`CallChainContinuationToken::verify_signature`] does not check. A clock
    /// is threaded explicitly via `now` (unix seconds).
    ///
    /// Fail-closed ordering: schema + signature are checked FIRST. A token with
    /// an invalid signature (or schema) is rejected before the time window is
    /// consulted. Returns `Ok(true)` only when the signature verifies and `now`
    /// is within `[issued_at, expires_at)`.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    #[must_use]
    pub fn matches_context(&self, context: &GovernedCallChainContext) -> bool {
        self.chain_id == context.chain_id
            && self.parent_request_id == context.parent_request_id
            && self.parent_receipt_id == context.parent_receipt_id
            && self.origin_subject == context.origin_subject
            && self.delegator_subject == context.delegator_subject
    }

    #[must_use]
    pub fn matches_session_anchor(&self, session_anchor: &SessionAnchorReference) -> bool {
        self.parent_session_anchor.as_ref() == Some(session_anchor)
    }

    #[must_use]
    pub fn matches_target(&self, server_id: &str, tool_name: &str) -> bool {
        self.audience.as_ref().is_some_and(|audience| {
            audience.server_id == server_id && audience.tool_name == tool_name
        })
    }

    #[must_use]
    pub fn matches_intent_hash(&self, intent_hash: &str) -> bool {
        self.governed_intent_hash.as_deref() == Some(intent_hash)
    }

    #[must_use]
    pub fn matches_subject(&self, subject: &PublicKey) -> bool {
        &self.subject == subject
    }
}

/// Evidence class describing how Chio learned or validated provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GovernedProvenanceEvidenceClass {
    /// Caller-asserted provenance bound into the request, but not independently checked yet.
    #[default]
    Asserted,
    /// Provenance observed by Chio or a trusted subsystem, but not fully verified end-to-end.
    Observed,
    /// Provenance verified against authoritative evidence such as receipt linkage or signatures.
    Verified,
}

/// Generic evidence class used across Chio provenance artifacts.
pub type ProvenanceEvidenceClass = GovernedProvenanceEvidenceClass;

/// Authoritative local evidence Chio used to corroborate governed call-chain metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedCallChainEvidenceSource {
    /// The call-chain parent request matched an authenticated parent request in the live session.
    SessionParentRequestLineage,
    /// The optional parent receipt identifier matched a receipt Chio already recorded locally.
    LocalParentReceiptLinkage,
    /// The asserted delegator subject matched the validated capability delegation source.
    CapabilityDelegatorSubject,
    /// The asserted origin subject matched the root delegator visible in capability lineage.
    CapabilityOriginSubject,
    /// Chio validated a signed upstream handoff against the capability's delegator key.
    UpstreamDelegatorProof,
}

/// Typed provenance envelope for delegated governed call-chain metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedCallChainProvenance {
    /// Evidence class describing how strongly Chio should treat this provenance.
    #[serde(default)]
    pub evidence_class: GovernedProvenanceEvidenceClass,
    /// Specific authoritative local evidence Chio used when it upgraded the caller assertion.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_sources: Vec<GovernedCallChainEvidenceSource>,
    /// Optional signed upstream proof Chio validated before upgrading to verified provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_proof: Option<GovernedUpstreamCallChainProof>,
    /// Optional preserved caller assertion when Chio upgraded or rewrote the effective context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asserted_context: Option<GovernedCallChainContext>,
    /// Optional continuation token identifier that backed a verified upgrade.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_token_id: Option<String>,
    /// Optional session-anchor identifier that scoped the verified lineage edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_anchor_id: Option<String>,
    /// Optional receipt-lineage statement identifier that authenticated the receipt edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_lineage_statement_id: Option<String>,
    /// The delegated call-chain details carried with the governed request or receipt.
    #[serde(flatten)]
    pub context: GovernedCallChainContext,
}

impl GovernedCallChainProvenance {
    #[must_use]
    pub fn new(
        context: GovernedCallChainContext,
        evidence_class: GovernedProvenanceEvidenceClass,
    ) -> Self {
        Self {
            evidence_class,
            evidence_sources: Vec::new(),
            upstream_proof: None,
            asserted_context: None,
            continuation_token_id: None,
            session_anchor_id: None,
            receipt_lineage_statement_id: None,
            context,
        }
    }

    #[must_use]
    pub fn with_evidence_sources(
        mut self,
        evidence_sources: impl IntoIterator<Item = GovernedCallChainEvidenceSource>,
    ) -> Self {
        self.evidence_sources = evidence_sources.into_iter().collect();
        self
    }

    #[must_use]
    pub fn with_upstream_proof(mut self, upstream_proof: GovernedUpstreamCallChainProof) -> Self {
        self.upstream_proof = Some(upstream_proof);
        self
    }

    #[must_use]
    pub fn with_asserted_context(mut self, asserted_context: GovernedCallChainContext) -> Self {
        self.asserted_context = Some(asserted_context);
        self
    }

    #[must_use]
    pub fn with_continuation_token_id(mut self, continuation_token_id: impl Into<String>) -> Self {
        self.continuation_token_id = Some(continuation_token_id.into());
        self
    }

    #[must_use]
    pub fn with_session_anchor_id(mut self, session_anchor_id: impl Into<String>) -> Self {
        self.session_anchor_id = Some(session_anchor_id.into());
        self
    }

    #[must_use]
    pub fn with_receipt_lineage_statement_id(
        mut self,
        receipt_lineage_statement_id: impl Into<String>,
    ) -> Self {
        self.receipt_lineage_statement_id = Some(receipt_lineage_statement_id.into());
        self
    }

    #[must_use]
    pub fn asserted(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Asserted)
    }

    #[must_use]
    pub fn observed(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Observed)
    }

    #[must_use]
    pub fn verified(context: GovernedCallChainContext) -> Self {
        Self::new(context, GovernedProvenanceEvidenceClass::Verified)
    }

    #[must_use]
    pub fn is_asserted(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Asserted
        )
    }

    #[must_use]
    pub fn is_observed(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Observed
        )
    }

    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(
            self.evidence_class,
            GovernedProvenanceEvidenceClass::Verified
        )
    }

    #[must_use]
    pub fn as_context(&self) -> &GovernedCallChainContext {
        &self.context
    }

    #[must_use]
    pub fn asserted_context(&self) -> Option<&GovernedCallChainContext> {
        self.asserted_context
            .as_ref()
            .or_else(|| self.is_asserted().then_some(&self.context))
    }

    #[must_use]
    pub fn verified_context(&self) -> Option<&GovernedCallChainContext> {
        self.is_verified().then_some(&self.context)
    }

    #[must_use]
    pub fn into_inner(self) -> GovernedCallChainContext {
        self.context
    }
}

impl From<GovernedCallChainContext> for GovernedCallChainProvenance {
    fn from(context: GovernedCallChainContext) -> Self {
        Self::asserted(context)
    }
}

impl core::ops::Deref for GovernedCallChainProvenance {
    type Target = GovernedCallChainContext;

    fn deref(&self) -> &Self::Target {
        self.as_context()
    }
}

/// Explicit autonomy and delegation-bond context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernedAutonomyContext {
    /// Requested autonomy tier for this one governed action.
    pub tier: GovernedAutonomyTier,
    /// Optional signed delegation-bond artifact that backs higher-risk execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_bond_id: Option<String>,
}

/// Canonical intent attached to a governed transaction request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernedTransactionIntent {
    /// Unique intent identifier (UUIDv7 recommended).
    pub id: String,
    /// Target tool server for this governed action.
    pub server_id: String,
    /// Target tool name for this governed action.
    pub tool_name: String,
    /// Human or policy-readable purpose for the governed action.
    pub purpose: String,
    /// Optional maximum amount explicitly approved for this intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_amount: Option<MonetaryAmount>,
    /// Optional commerce approval context for seller-scoped payment rails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commerce: Option<GovernedCommerceContext>,
    /// Optional metered-billing quote and settlement context for non-rail tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metered_billing: Option<MeteredBillingContext>,
    /// Optional runtime attestation evidence bound to this governed request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<RuntimeAttestationEvidence>,
    /// Optional delegated call-chain context for upstream transaction provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_chain: Option<GovernedCallChainContext>,
    /// Optional explicit autonomy tier and delegation-bond attachment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autonomy: Option<GovernedAutonomyContext>,
    /// Optional structured context for downstream policy or operator inspection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl GovernedTransactionIntent {
    /// Compute a stable canonical hash for approval-token binding and receipts.
    pub fn binding_hash(&self) -> Result<String> {
        let canonical = canonical_json_bytes(self)?;
        Ok(sha256_hex(&canonical))
    }

    /// Extract the reserved upstream call-chain proof from the optional context object.
    pub fn upstream_call_chain_proof(&self) -> Result<Option<GovernedUpstreamCallChainProof>> {
        let Some(context) = self.context.as_ref() else {
            return Ok(None);
        };
        let Some(object) = context.as_object() else {
            return Ok(None);
        };
        let Some(value) = object.get(GOVERNED_CALL_CHAIN_UPSTREAM_PROOF_CONTEXT_KEY) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(value.clone())?))
    }

    /// Extract an explicitly attached continuation token without legacy fallback.
    pub fn explicit_continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        let Some(context) = self.context.as_ref() else {
            return Ok(None);
        };
        let Some(object) = context.as_object() else {
            return Ok(None);
        };

        let Some(value) = object.get(GOVERNED_CALL_CHAIN_CONTINUATION_CONTEXT_KEY) else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }

        Ok(Some(serde_json::from_value(value.clone())?))
    }

    /// Extract the explicit continuation token, if present.
    pub fn continuation_token(&self) -> Result<Option<CallChainContinuationToken>> {
        self.explicit_continuation_token()
    }
}

/// Seller-scoped commerce approval context attached to a governed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedCommerceContext {
    /// Seller or payee identifier that the approval is bound to.
    pub seller: String,
    /// Shared payment token or equivalent external commerce approval reference.
    pub shared_payment_token_id: String,
}

/// Decision encoded by a governed approval token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernedApprovalDecision {
    Approved,
    Denied,
}

/// Signable body of a governed approval token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedApprovalTokenBody {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
}

/// Signed approval artifact bound to one governed intent and one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernedApprovalToken {
    pub id: String,
    pub approver: PublicKey,
    pub subject: PublicKey,
    pub governed_intent_hash: String,
    pub request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub decision: GovernedApprovalDecision,
    /// Signing algorithm. Absent means Ed25519 (the default).
    ///
    /// Informational: verification dispatches off the algorithm encoded in
    /// [`GovernedApprovalToken::signature`] and [`GovernedApprovalToken::approver`].
    #[serde(default, skip_serializing_if = "is_default_optional_algorithm")]
    pub algorithm: Option<SigningAlgorithm>,
    pub signature: Signature,
}

impl GovernedApprovalToken {
    #[must_use]
    pub fn body(&self) -> GovernedApprovalTokenBody {
        GovernedApprovalTokenBody {
            id: self.id.clone(),
            approver: self.approver.clone(),
            subject: self.subject.clone(),
            governed_intent_hash: self.governed_intent_hash.clone(),
            request_id: self.request_id.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            decision: self.decision,
        }
    }

    /// Sign a governed approval token body with the given Ed25519 keypair.
    pub fn sign(body: GovernedApprovalTokenBody, keypair: &Keypair) -> Result<Self> {
        ensure_keypair_matches_embedded_key(
            &body.approver,
            keypair,
            "governed approval token",
            "approver",
        )?;
        let (signature, _bytes) = keypair.sign_canonical(&body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            algorithm: None,
            signature,
        })
    }

    /// Sign a governed approval token body with an arbitrary [`SigningBackend`].
    ///
    /// `body.approver` must equal `backend.public_key()`.
    pub fn sign_with_backend(
        body: GovernedApprovalTokenBody,
        backend: &dyn SigningBackend,
    ) -> Result<Self> {
        ensure_backend_matches_embedded_key(
            &body.approver,
            backend,
            "governed approval token",
            "approver",
        )?;
        let (signature, _bytes) = sign_canonical_with_backend(backend, &body)?;
        Ok(Self {
            id: body.id,
            approver: body.approver,
            subject: body.subject,
            governed_intent_hash: body.governed_intent_hash,
            request_id: body.request_id,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            decision: body.decision,
            algorithm: Some(backend.algorithm()),
            signature,
        })
    }

    pub fn verify_signature(&self) -> Result<bool> {
        let body = self.body();
        self.approver.verify_canonical(&body, &self.signature)
    }

    /// Verify the signature AND enforce the approval-token validity window in
    /// one pass.
    ///
    /// Sanctioned entry point when freshness matters (settlement lanes that
    /// must assert approval expiry, per the dependent C2/C3 work): fails closed
    /// on expiry / not-yet-valid approvals, which the bare
    /// [`GovernedApprovalToken::verify_signature`] does not check. A clock is
    /// threaded explicitly via `now` (unix seconds).
    ///
    /// Fail-closed ordering: the signature is checked FIRST. An approval with an
    /// invalid signature is rejected before the time window is consulted.
    /// Returns `Ok(true)` only when the signature verifies and `now` is within
    /// `[issued_at, expires_at)`.
    pub fn verify_signature_at(&self, now: u64) -> Result<bool> {
        if !self.verify_signature()? {
            return Ok(false);
        }
        self.validate_time(now)?;
        Ok(true)
    }

    #[must_use]
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.issued_at && now < self.expires_at
    }

    pub fn validate_time(&self, now: u64) -> Result<()> {
        if now < self.issued_at {
            return Err(Error::CapabilityNotYetValid {
                not_before: self.issued_at,
            });
        }
        if now >= self.expires_at {
            return Err(Error::CapabilityExpired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }
}
