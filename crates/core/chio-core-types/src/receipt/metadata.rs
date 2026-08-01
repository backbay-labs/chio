use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::capability::{
    governance::ProvenanceEvidenceClass,
    scope::{ModelMetadata, ModelSafetyTier},
};
use crate::error::{Error, Result};

use super::decision::Decision;
use super::kinds::{BoundaryClass, ObservationOutcome, ReceiptKind, RedactionMode, ToolOrigin};
use super::validation::{require_exact, require_lowercase_hex_chars, require_wire_identifier};

/// Actor reference carried by signed receipt semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ActorRef {
    pub actor_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_kind: Option<String>,
}

/// Signed v1 semantic fields used by UI, SIEM, and bridge admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ReceiptSemanticFields {
    pub receipt_kind: ReceiptKind,
    pub boundary_class: BoundaryClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation_outcome: Option<ObservationOutcome>,
    pub tool_origin: ToolOrigin,
    pub redaction_mode: RedactionMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actor_chain: Vec<ActorRef>,
}

impl ReceiptSemanticFields {
    #[must_use]
    pub fn mediated_prevent() -> Self {
        Self {
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn trace_detect_only() -> Self {
        Self {
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::HostExecutedProviderReported,
            redaction_mode: RedactionMode::Summary,
            actor_chain: Vec::new(),
        }
    }

    #[must_use]
    pub fn advisory_only() -> Self {
        Self {
            receipt_kind: ReceiptKind::AdvisoryEvaluation,
            boundary_class: BoundaryClass::AdvisoryOnly,
            observation_outcome: Some(ObservationOutcome::Evaluated),
            tool_origin: ToolOrigin::HostExecutedUnmediated,
            redaction_mode: RedactionMode::Redacted,
            actor_chain: Vec::new(),
        }
    }

    /// Strict decision compatibility check for v1 signed semantics.
    pub fn validate_decision(&self, decision: Option<&Decision>) -> Result<()> {
        if self.boundary_class == BoundaryClass::CannotSee {
            return Err(Error::CanonicalJson(format!(
                "{} receipts cannot use cannot_see as a signed runtime boundary",
                self.receipt_kind.as_str()
            )));
        }
        match (
            self.receipt_kind,
            self.boundary_class,
            self.observation_outcome,
            decision,
        ) {
            (ReceiptKind::MediatedDecision, BoundaryClass::Prevent, None, Some(_)) => Ok(()),
            (ReceiptKind::MediatedDecision, _, _, _) => Err(Error::CanonicalJson(
                "mediated_decision receipts require a prevent boundary, no observation outcome, and a decision"
                    .to_string(),
            )),
            (
                ReceiptKind::TraceObservation,
                BoundaryClass::DetectOnly,
                Some(_),
                None,
            ) => Ok(()),
            (ReceiptKind::TraceObservation, _, _, Some(decision)) => {
                Err(Error::CanonicalJson(format!(
                    "trace_observation receipts must not carry {:?} as an authorization decision",
                    decision
                )))
            }
            (ReceiptKind::TraceObservation, _, _, None) => Err(Error::CanonicalJson(
                "trace_observation receipts require detect_only boundary and observation outcome"
                    .to_string(),
            )),
            (
                ReceiptKind::AdvisoryEvaluation,
                BoundaryClass::AdvisoryOnly,
                Some(_),
                None,
            ) => Ok(()),
            (ReceiptKind::AdvisoryEvaluation, _, _, Some(decision)) => {
                Err(Error::CanonicalJson(format!(
                    "advisory_evaluation receipts must not carry {:?} as an authorization decision",
                    decision
                )))
            }
            (ReceiptKind::AdvisoryEvaluation, _, _, None) => Err(Error::CanonicalJson(
                "advisory_evaluation receipts require advisory_only boundary and observation outcome"
                    .to_string(),
            )),
        }
    }

    #[must_use]
    pub fn is_authorized(&self, decision: Option<&Decision>) -> bool {
        self.receipt_kind == ReceiptKind::MediatedDecision
            && self.boundary_class == BoundaryClass::Prevent
            && self.observation_outcome.is_none()
            && matches!(decision, Some(Decision::Allow))
    }

    #[must_use]
    pub fn result_label(&self, decision: Option<&Decision>) -> &'static str {
        if self.is_authorized(decision) {
            return "Authorized";
        }
        match self.receipt_kind {
            ReceiptKind::TraceObservation => "Observed",
            ReceiptKind::AdvisoryEvaluation => "Advisory",
            ReceiptKind::MediatedDecision => match decision {
                Some(Decision::Allow) => "Allowed",
                Some(Decision::Deny { .. }) => "Denied",
                Some(Decision::Cancelled { .. }) => "Cancelled",
                Some(Decision::Incomplete { .. }) => "Incomplete",
                None => "Invalid",
            },
        }
    }
}

/// Explicit model-routing context attached to a receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub struct ModelMetadataReceiptMetadata {
    pub model_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safety_tier: Option<ModelSafetyTier>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    pub provenance_class: ProvenanceEvidenceClass,
}

impl From<&ModelMetadata> for ModelMetadataReceiptMetadata {
    fn from(value: &ModelMetadata) -> Self {
        Self {
            model_id: value.model_id.clone(),
            safety_tier: value.safety_tier,
            provider: value.provider.clone(),
            provenance_class: value.provenance_class,
        }
    }
}

/// Evidence from a single guard's evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardEvidence {
    /// Name of the guard (e.g. "ForbiddenPathGuard").
    pub guard_name: String,
    /// Whether the guard passed (true) or denied (false).
    pub verdict: bool,
    /// Optional details about the guard's decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

// Reserved top-level keys in the `ChioReceipt::metadata` object.
//
// ADR-0018 item 7 makes this registry normative: the kernel merges its typed
// blocks under these keys last and rejects a pre-existing collision from caller
// or hook metadata, so a downstream reader can trust that a block found under a
// reserved key was written by the kernel and is covered by the receipt
// signature. These consts are the `chio-core-types` reader-side source of
// truth; the human-readable table lives in `spec/PROTOCOL.md` 6.4.

/// Financial attribution and settlement metadata block key.
pub const FINANCIAL_METADATA_KEY: &str = "financial";

/// Governed-transaction intent and approval metadata block key.
pub const GOVERNED_TRANSACTION_METADATA_KEY: &str = "governed_transaction";

/// Streamed-output channel accounting metadata block key.
pub const CHANNEL_METADATA_KEY: &str = "channel";

/// Budget-authority lineage metadata block key for monetary receipts.
pub const BUDGET_AUTHORITY_METADATA_KEY: &str = "budget_authority";

/// Delivery-contract evidence metadata block key (ADR-0018 item 7).
pub const DELIVERY_CONTRACT_METADATA_KEY: &str = "delivery_contract";

/// Schema identifier pinned by every `delivery_contract` block.
pub const DELIVERY_CONTRACT_SCHEMA: &str = "chio.delivery-contract.v1";

/// Whether the delivered output matched the frozen expected digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryResult {
    /// The delivered output hashed to the expected digest.
    Matched,
    /// The delivered output did not hash to the expected digest.
    Mismatched,
}

/// Generic delivery evidence for a receipt whose grant carried an output-digest
/// constraint (`Constraint::OutputDigestSha256`).
///
/// The block is authenticated by the enclosing receipt, not by a signature of
/// its own: it feeds the receipt id and the signing body. It is present only on
/// a digest-constrained request (its presence would otherwise change every
/// receipt id): `matched` on an Allow, `mismatched` on the persisted zero-charge
/// Deny. The typed struct lives here rather than in `chio-kernel` so that M4/M5
/// evidence consumers and portable verifiers outside the kernel can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct DeliveryContract {
    /// Schema identifier; always [`DELIVERY_CONTRACT_SCHEMA`].
    pub schema: String,
    /// Canonical lowercase 64-hex SHA-256 digest the grant fixed in advance.
    pub expected_digest: String,
    /// Receipt-visible canonical lowercase 64-hex SHA-256 commitment. For a
    /// match this is the delivered output digest. For a mismatch it is the
    /// kernel's domain-separated redaction commitment keyed by the expected
    /// digest; the actual digest stays in privileged durable outcome evidence
    /// so the public Deny is not a payload confirmation oracle.
    pub observed_digest: String,
    /// Whether the observed digest matched the expected digest.
    pub result: DeliveryResult,
}

impl DeliveryContract {
    /// Validate the closed shape: the schema is pinned to
    /// [`DELIVERY_CONTRACT_SCHEMA`] and both digests are canonical lowercase
    /// 64-character hex. Returns a typed error otherwise.
    ///
    /// This does not assert `result` against the digests; that binding is the
    /// kernel terminal's responsibility. A portable reader uses this to reject
    /// a malformed block before trusting either digest.
    pub fn validate(&self) -> Result<()> {
        require_exact(
            &self.schema,
            DELIVERY_CONTRACT_SCHEMA,
            "delivery_contract.schema",
        )?;
        require_lowercase_hex_chars(
            &self.expected_digest,
            64,
            "delivery_contract.expected_digest",
        )?;
        require_lowercase_hex_chars(
            &self.observed_digest,
            64,
            "delivery_contract.observed_digest",
        )?;
        Ok(())
    }
}

/// Finding-delivery overlay metadata block key.
pub const FINDING_DELIVERY_METADATA_KEY: &str = "finding_delivery";

/// Schema identifier pinned by every `finding_delivery` block.
pub const FINDING_DELIVERY_SCHEMA: &str = "chio.finding.delivery.v1";

/// Transform profile the kernel proved for a purchased finding reveal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingTransformProfile {
    /// The delivered output is the unmutated seller-origin envelope: the
    /// post-invocation hook plan was empty and frozen at admission.
    Identity,
}

/// Outcome of the reveal-envelope media-type comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingMediaTypeCheck {
    /// The envelope media type equals the signed finding's advertised type.
    Matched,
    /// The envelope media type differs from the advertised type.
    Mismatched,
    /// The comparison did not run because an earlier check already denied.
    NotEvaluated,
}

/// Settlement rail the purchase was admitted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingDeliverySettlementMode {
    /// Single-operator reversible hold: capture only after the digest and
    /// media checks pass, release on any failure.
    LocalReversibleHold,
}

/// Kernel-verified live-status evidence attached to an M6-qualified finding
/// delivery. All digest and root fields derive from the exact canonical
/// portable proof and its embedded signed epoch, never from caller metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingStatusProofMetadata {
    /// Governance-pinned feed identity.
    pub feed_id: String,
    /// Fixed numeric key domain used by the sparse map.
    pub key_domain_nonce: u64,
    /// Monotonic signed map generation accepted by the durable floor.
    pub map_epoch: u64,
    /// Digest of the exact canonical signed status epoch envelope.
    pub status_epoch_artifact_sha256: String,
    /// Digest of the exact canonical portable proof input.
    pub proof_sha256: String,
    /// Sparse root committed by the signed epoch.
    pub root_hash: String,
    /// Trusted-time observation bound by the verified non-inclusion proof.
    pub non_inclusion_checked_at: u64,
}

impl FindingStatusProofMetadata {
    /// Validate the closed receipt-side representation.
    pub fn validate(&self) -> Result<()> {
        require_wire_identifier(&self.feed_id, 512, "finding_delivery.status_proof.feed_id")?;
        if self.key_domain_nonce == 0 || self.map_epoch == 0 || self.non_inclusion_checked_at == 0 {
            return Err(Error::CanonicalJson(
                "finding delivery status proof numeric fields must be nonzero".to_string(),
            ));
        }
        for (value, field) in [
            (
                &self.status_epoch_artifact_sha256,
                "finding_delivery.status_proof.status_epoch_artifact_sha256",
            ),
            (
                &self.proof_sha256,
                "finding_delivery.status_proof.proof_sha256",
            ),
            (&self.root_hash, "finding_delivery.status_proof.root_hash"),
        ] {
            require_lowercase_hex_chars(value, 64, field)?;
        }
        Ok(())
    }
}

/// Finding-specific delivery overlay for a receipt whose grant carried a
/// provider-signed purchase marker (`Constraint::RequireFindingPurchase`).
///
/// Attached alongside the generic `delivery_contract` block only when the
/// purchase context arrived through verified signed artifacts; every field
/// derives from kernel-verified state, never from caller-asserted values.
/// Like its generic sibling it is authenticated by the enclosing receipt and
/// lives here so evidence consumers and portable verifiers outside the
/// kernel can read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingDelivery {
    /// Schema identifier; always [`FINDING_DELIVERY_SCHEMA`].
    pub schema: String,
    /// Content-addressed id of the finding that was sold, stamped from the
    /// verified signed finding, never from request arguments.
    pub finding_id: String,
    /// Listing the sale was admitted under.
    pub listing_id: String,
    /// Kernel-proved transform profile for the delivered output.
    pub transform_profile: FindingTransformProfile,
    /// Kernel comparison of the delivered digest against the committed one.
    pub digest_check: DeliveryResult,
    /// Kernel comparison of the reveal-envelope media type against the
    /// signed finding's advertised type.
    pub media_type_check: FindingMediaTypeCheck,
    /// Settlement rail the admitted selector named.
    pub settlement_mode: FindingDeliverySettlementMode,
    /// Canonical SHA-256 digest of the signed accepted-bid envelope.
    pub accepted_bid_envelope_sha256: String,
    /// Canonical SHA-256 digest of the venue-signed admission envelope.
    pub venue_admission_envelope_sha256: String,
    /// Authoritative reservation the purchase resolved through.
    pub reservation_id: String,
    /// Coordinator-preallocated purchase intent identity.
    pub purchase_intent_id: String,
    /// Coordinator-preallocated payment operation identity.
    pub authoritative_payment_operation_id: String,
    /// Portable non-inclusion evidence for M6-qualified receipts. Optional
    /// only so previously issued M4 receipts continue to decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_proof: Option<FindingStatusProofMetadata>,
}

impl FindingDelivery {
    /// Validate the closed shape: pinned schema, canonical 64-hex envelope
    /// digests, and non-empty identity fields.
    ///
    /// This does not re-derive any comparison result; those bindings are the
    /// kernel terminal's responsibility. A portable reader uses this to
    /// reject a malformed block before trusting its fields.
    pub fn validate(&self) -> Result<()> {
        require_exact(
            &self.schema,
            FINDING_DELIVERY_SCHEMA,
            "finding_delivery.schema",
        )?;
        require_lowercase_hex_chars(
            &self.accepted_bid_envelope_sha256,
            64,
            "finding_delivery.accepted_bid_envelope_sha256",
        )?;
        require_lowercase_hex_chars(
            &self.venue_admission_envelope_sha256,
            64,
            "finding_delivery.venue_admission_envelope_sha256",
        )?;
        for (value, field) in [
            (&self.finding_id, "finding_delivery.finding_id"),
            (&self.listing_id, "finding_delivery.listing_id"),
            (&self.reservation_id, "finding_delivery.reservation_id"),
            (
                &self.purchase_intent_id,
                "finding_delivery.purchase_intent_id",
            ),
            (
                &self.authoritative_payment_operation_id,
                "finding_delivery.authoritative_payment_operation_id",
            ),
        ] {
            require_wire_identifier(value, 512, field)?;
        }
        if let Some(status_proof) = self.status_proof.as_ref() {
            status_proof.validate()?;
        }
        Ok(())
    }
}

/// Finding-recovery receipt metadata block key.
pub const FINDING_RECOVERY_METADATA_KEY: &str = "finding_recovery";

/// Schema identifier pinned by every `finding_recovery` block.
pub const FINDING_RECOVERY_SCHEMA: &str = "chio.finding.recovery.v1";

/// Kernel-owned lineage for a no-charge finding redelivery.
///
/// The block is authenticated by the recovery receipt. It points back to the
/// successful paid delivery and its settled purchase record without turning
/// either artifact into bearer authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct FindingRecovery {
    /// Schema identifier; always [`FINDING_RECOVERY_SCHEMA`].
    pub schema: String,
    /// Deterministic durable recovery and quota identity.
    pub recovery_id: String,
    /// Content-addressed finding id redelivered by this receipt.
    pub finding_id: String,
    /// Capability id used for the original paid delivery.
    pub original_capability_id: String,
    /// Signed Allow receipt for the original paid delivery.
    pub original_delivery_receipt_id: String,
    /// Derived key of the purchase-authority-signed settlement record.
    pub purchase_key: String,
}

impl FindingRecovery {
    /// Validate the closed recovery lineage shape.
    pub fn validate(&self) -> Result<()> {
        require_exact(
            &self.schema,
            FINDING_RECOVERY_SCHEMA,
            "finding_recovery.schema",
        )?;
        for (value, field) in [
            (&self.recovery_id, "finding_recovery.recovery_id"),
            (&self.finding_id, "finding_recovery.finding_id"),
            (&self.purchase_key, "finding_recovery.purchase_key"),
        ] {
            require_lowercase_hex_chars(value, 64, field)?;
        }
        for (value, field) in [
            (
                &self.original_capability_id,
                "finding_recovery.original_capability_id",
            ),
            (
                &self.original_delivery_receipt_id,
                "finding_recovery.original_delivery_receipt_id",
            ),
        ] {
            require_wire_identifier(value, 512, field)?;
        }
        Ok(())
    }
}

/// Universal receipt-side attribution for capability context.
///
/// This metadata gives downstream analytics a deterministic local join path
/// from a receipt to the capability subject and, when available, the matched
/// grant within the capability scope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptAttributionMetadata {
    /// Hex-encoded subject public key of the capability holder.
    pub subject_key: String,
    /// Hex-encoded issuer public key of the capability issuer.
    pub issuer_key: String,
    /// Delegation depth of the capability used for this receipt.
    pub delegation_depth: u32,
    /// Index of the matched grant when the request resolved to a specific grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_index: Option<u32>,
}
