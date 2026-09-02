//! Delivery-contract evaluation shared by the durable finalizer and the
//! replay lane.
//!
//! The digest compare enforces `Constraint::OutputDigestSha256` for every
//! grant that commits an output digest; the reveal-envelope and media-type
//! checks apply only to purchase-marked deliveries. Both lanes derive
//! identical receipts from identical durable state, so everything here is a
//! pure function of its inputs.

use base64::Engine as _;
use serde::Deserialize;

/// Strict two-field reveal envelope a purchased delivery must resolve to.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevealEnvelopeWire {
    media_type: String,
    payload_b64: String,
}

/// Outcome of the reveal-envelope shape and media-type comparison run by
/// the durable finalizer after the digest compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RevealEnvelopeCheck {
    /// The delivered value is the exact envelope and its media type
    /// equals the advertised type.
    Matched,
    /// The delivered value is not the strict two-field envelope with
    /// valid base64 payload bytes.
    EnvelopeMalformed,
    /// The envelope parsed but advertises a different media type.
    MediaTypeMismatched,
}

/// Strict-parse the resolved canonical output as the reveal envelope and
/// compare its media type against the advertised one. The digest compare
/// has already bound these bytes to the seller's commitment; this check
/// decides whether that commitment was over a well-formed envelope of the
/// advertised type.
pub(crate) fn check_reveal_envelope(
    canonical_content: &[u8],
    advertised_media_type: &str,
) -> RevealEnvelopeCheck {
    let Ok(envelope) = serde_json::from_slice::<RevealEnvelopeWire>(canonical_content) else {
        return RevealEnvelopeCheck::EnvelopeMalformed;
    };
    if envelope.media_type.is_empty()
        || base64::engine::general_purpose::STANDARD
            .decode(envelope.payload_b64.as_bytes())
            .is_err()
    {
        return RevealEnvelopeCheck::EnvelopeMalformed;
    }
    if envelope.media_type != advertised_media_type {
        return RevealEnvelopeCheck::MediaTypeMismatched;
    }
    RevealEnvelopeCheck::Matched
}

/// One delivery denial: the projected reason, the receipt decision text,
/// and the guard that owns the denial.
pub(crate) struct DeliveryDenial {
    pub(crate) reason: crate::admission_operation::DeliveryDenialReason,
    pub(crate) message: &'static str,
    pub(crate) guard: &'static str,
}

pub(crate) fn finding_status_delivery_denial() -> DeliveryDenial {
    DeliveryDenial {
        reason: crate::admission_operation::DeliveryDenialReason::FindingStatusChanged,
        message: "finding status changed before durable output release",
        guard: "finding_status",
    }
}

/// Make a persisted delivery denial monotonic across replay. Deterministic
/// delivery checks are recomputed first; if they now allow while the signed
/// terminal receipt denied, the only mutable gate was current finding status.
/// Preserve that denial instead of upgrading the terminal to Allow.
#[cfg(feature = "finding-market")]
pub(crate) fn preserve_terminal_delivery_denial(
    retained_decision: Option<&chio_core::receipt::decision::Decision>,
    evaluation: &mut DeliveryEvaluation,
) {
    if evaluation.denial.is_none()
        && matches!(
            retained_decision,
            Some(chio_core::receipt::decision::Decision::Deny { .. })
        )
    {
        evaluation.denial = Some(finding_status_delivery_denial());
    }
}

/// The complete delivery verdict for one resolved output, shared by the
/// durable finalizer and the replay lane so both derive identical
/// receipts from identical durable state.
pub(crate) struct DeliveryEvaluation {
    /// The digest compare failed against the committed output digest.
    pub(crate) digest_mismatched: bool,
    /// The reveal-envelope check, run only for a purchase-marked delivery
    /// whose digest matched.
    pub(crate) reveal_check: Option<RevealEnvelopeCheck>,
    /// The denial that terminates this delivery, if any.
    pub(crate) denial: Option<DeliveryDenial>,
}

/// Evaluate the delivery contract for a resolved output: the digest
/// compare for any committed digest, then the strict reveal-envelope and
/// media-type checks for a purchase-marked delivery. Runs after the
/// post-invocation transform and before any money decision.
///
/// `delivered_value` records whether the final post-transform output is a
/// single canonical JSON value, the only representation a digest can be
/// committed against. A streamed delivery never satisfies a committed
/// digest: its content hash is derived from per-chunk digests the
/// provider authors, not from the committed payload bytes, so a
/// constraint over it denies even when the hashes collide.
pub(crate) fn evaluate_delivery(
    expected_output_digest: Option<&str>,
    resolved_output_digest: &str,
    delivered_value: bool,
    canonical_content: &[u8],
    purchase: Option<&crate::finding_purchase::VerifiedFindingPurchase>,
) -> DeliveryEvaluation {
    use crate::admission_operation::DeliveryDenialReason;

    let digest_mismatched = chio_kernel_core::formal_core::delivery_denies_settlement(
        expected_output_digest,
        resolved_output_digest,
        delivered_value,
    );
    if digest_mismatched {
        let message = if delivered_value {
            "delivered output does not match the committed output digest"
        } else {
            "a committed output digest admits only a single value delivery"
        };
        return DeliveryEvaluation {
            digest_mismatched,
            reveal_check: None,
            denial: Some(DeliveryDenial {
                reason: DeliveryDenialReason::DigestMismatch,
                message,
                guard: "delivery_contract",
            }),
        };
    }
    let Some(binding) = purchase else {
        return DeliveryEvaluation {
            digest_mismatched,
            reveal_check: None,
            denial: None,
        };
    };
    let reveal_check = check_reveal_envelope(canonical_content, &binding.payload_media_type);
    let denial = match reveal_check {
        RevealEnvelopeCheck::Matched => None,
        RevealEnvelopeCheck::EnvelopeMalformed => Some(DeliveryDenial {
            reason: DeliveryDenialReason::EnvelopeMalformed,
            message: "delivered output is not a canonical reveal envelope",
            guard: "finding_delivery",
        }),
        RevealEnvelopeCheck::MediaTypeMismatched => Some(DeliveryDenial {
            reason: DeliveryDenialReason::MediaTypeMismatch,
            message: "delivered reveal envelope media type does not match the advertised type",
            guard: "finding_delivery",
        }),
    };
    DeliveryEvaluation {
        digest_mismatched,
        reveal_check: Some(reveal_check),
        denial,
    }
}

/// Build the finding-delivery overlay block from kernel-verified facts.
pub(crate) fn finding_delivery_block(
    binding: &crate::finding_purchase::VerifiedFindingPurchase,
    evaluation: &DeliveryEvaluation,
) -> chio_core::receipt::metadata::FindingDelivery {
    use chio_core::receipt::metadata::{
        DeliveryResult, FindingDelivery, FindingDeliverySettlementMode, FindingMediaTypeCheck,
        FindingTransformProfile, FINDING_DELIVERY_SCHEMA,
    };

    FindingDelivery {
        schema: FINDING_DELIVERY_SCHEMA.to_owned(),
        finding_id: binding.finding_id.clone(),
        listing_id: binding.listing_id.clone(),
        transform_profile: FindingTransformProfile::Identity,
        digest_check: if evaluation.digest_mismatched {
            DeliveryResult::Mismatched
        } else {
            DeliveryResult::Matched
        },
        media_type_check: match evaluation.reveal_check {
            Some(RevealEnvelopeCheck::Matched) => FindingMediaTypeCheck::Matched,
            Some(RevealEnvelopeCheck::MediaTypeMismatched) => FindingMediaTypeCheck::Mismatched,
            Some(RevealEnvelopeCheck::EnvelopeMalformed) | None => {
                FindingMediaTypeCheck::NotEvaluated
            }
        },
        settlement_mode: FindingDeliverySettlementMode::LocalReversibleHold,
        accepted_bid_envelope_sha256: binding.accepted_bid_envelope_sha256.clone(),
        venue_admission_envelope_sha256: binding.venue_admission_envelope_sha256.clone(),
        reservation_id: binding.reservation_id.clone(),
        purchase_intent_id: binding.purchase_intent_id.clone(),
        authoritative_payment_operation_id: binding.authoritative_payment_operation_id.clone(),
        status_proof: binding.status_proof.as_ref().map(|status| {
            chio_core::receipt::metadata::FindingStatusProofMetadata {
                feed_id: status.feed_id.clone(),
                key_domain_nonce: status.key_domain_nonce,
                map_epoch: status.map_epoch,
                status_epoch_artifact_sha256: status.status_epoch_artifact_sha256.clone(),
                proof_sha256: status.proof_sha256.clone(),
                root_hash: status.root_hash.clone(),
                non_inclusion_checked_at: status.non_inclusion_checked_at,
            }
        }),
    }
}

/// Recovery admission verified before dispatch: the re-verified recovery
/// facts plus the live-status proof admitted for this redelivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedFindingRecoveryAdmission {
    pub(crate) recovery: crate::finding_recovery::VerifiedFindingRecovery,
    pub(crate) status: crate::finding_purchase::VerifiedFindingStatusProof,
}

impl crate::kernel::dispatch::VerifiedFindingDispatchAdmission {
    pub(crate) fn recovery_binding(
        &self,
    ) -> Option<&crate::finding_recovery::VerifiedFindingRecovery> {
        self.recovery.as_ref().map(|admission| &admission.recovery)
    }

    pub(crate) fn recovery_status(
        &self,
    ) -> Option<&crate::finding_purchase::VerifiedFindingStatusProof> {
        self.recovery.as_ref().map(|admission| &admission.status)
    }
}

pub(crate) fn attach_finding_recovery_metadata(
    metadata: Option<serde_json::Value>,
    recovery: Option<&crate::finding_recovery::VerifiedFindingRecovery>,
) -> Option<serde_json::Value> {
    let Some(recovery) = recovery else {
        return metadata;
    };
    crate::receipt_support::merge_metadata_objects(
        metadata,
        Some(serde_json::json!({
            chio_core::receipt::metadata::FINDING_RECOVERY_METADATA_KEY:
                finding_recovery_block(recovery)
        })),
    )
}

/// Build the finding-recovery overlay block from kernel-verified facts.
pub(crate) fn finding_recovery_block(
    binding: &crate::finding_recovery::VerifiedFindingRecovery,
) -> chio_core::receipt::metadata::FindingRecovery {
    chio_core::receipt::metadata::FindingRecovery {
        schema: chio_core::receipt::metadata::FINDING_RECOVERY_SCHEMA.to_owned(),
        recovery_id: binding.recovery_id.clone(),
        finding_id: binding.finding_id.clone(),
        original_capability_id: binding.original_capability_id.clone(),
        original_delivery_receipt_id: binding.original_delivery_receipt_id.clone(),
        purchase_key: binding.purchase_key.clone(),
    }
}
