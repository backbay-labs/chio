//! Purchase-marked admission checks shared by both evaluation lanes and
//! the durable finalizer.

use base64::Engine as _;
use chio_core::capability::scope::{
    Constraint, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount, ToolGrant,
};
use serde::Deserialize;

use crate::finding_purchase::{
    FindingPurchaseContextView, FindingStatusProofContextView, VerifiedFindingPurchase,
    FINDING_ESCROW_WITNESS_CONTEXT_KEY, FINDING_PURCHASE_CONTEXT_KEY,
    FINDING_STATUS_PROOF_CONTEXT_KEY, MAX_FINDING_STATUS_PROOF_B64_BYTES,
};
use crate::runtime::ToolCallRequest;

use super::ChioKernel;

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

/// The purchase marker and its paired output digest recovered from one
/// selected grant, before context verification.
pub(crate) struct PurchaseMarkedGrant<'a> {
    pub(crate) marker: &'a FindingPurchaseMarkerV1,
    pub(crate) expected_output_digest: &'a str,
}

/// Recover the purchase marker from a selected grant, enforcing the
/// closed delivery profile: exactly one marker, exactly one paired output
/// digest, the local settlement rail, a mandatory proof-of-possession
/// binding, and a single authorized invocation.
pub(crate) fn purchase_marked_grant(
    grant: &ToolGrant,
) -> Result<Option<PurchaseMarkedGrant<'_>>, String> {
    let mut markers = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::RequireFindingPurchase(marker) = constraint {
            Some(marker.as_ref())
        } else {
            None
        }
    });
    let Some(marker) = markers.next() else {
        return Ok(None);
    };
    if markers.next().is_some() {
        return Err("purchase-marked grant carries more than one purchase marker".to_owned());
    }
    match &marker.settlement {
        FindingSettlementSelector::LocalReversibleHold => {}
        FindingSettlementSelector::CrossOrgEscrow { .. } => {
            return Err(
                "purchase-marked delivery requires the local reversible-hold settlement rail"
                    .to_owned(),
            );
        }
    }
    let mut digests = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::OutputDigestSha256(digest) = constraint {
            Some(digest.as_str())
        } else {
            None
        }
    });
    let (Some(expected_output_digest), None) = (digests.next(), digests.next()) else {
        return Err(
            "purchase-marked grant requires exactly one committed output digest".to_owned(),
        );
    };
    if grant.dpop_required != Some(true) {
        return Err(
            "purchase-marked delivery requires a mandatory proof-of-possession grant".to_owned(),
        );
    }
    if grant.max_invocations != Some(1) {
        return Err("purchase-marked grant must authorize exactly one invocation".to_owned());
    }
    Ok(Some(PurchaseMarkedGrant {
        marker,
        expected_output_digest,
    }))
}

impl ChioKernel {
    /// Deterministically verify the purchase context for a marked grant
    /// and cross-check the result against the grant, the request, and the
    /// paying capability. Returns `Ok(None)` for an unmarked grant; every
    /// error denies.
    ///
    /// This half is replayed by the durable finalizer from the frozen
    /// request, so it must not consult clocks or mutable state.
    pub(crate) fn verify_purchase_context(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
    ) -> Result<Option<VerifiedFindingPurchase>, String> {
        let Some(marked) = purchase_marked_grant(grant)? else {
            return Ok(None);
        };
        let context = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                "purchase-marked delivery requires a governed purchase context".to_owned()
            })?;
        if context.contains_key(FINDING_ESCROW_WITNESS_CONTEXT_KEY) {
            return Err(
                "an escrow witness is not admissible on the local settlement rail".to_owned(),
            );
        }
        let context_b64 = context
            .get(FINDING_PURCHASE_CONTEXT_KEY)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "purchase-marked delivery requires a governed purchase context".to_owned()
            })?;
        let Some(verifier) = self.finding_purchase_verifier.as_ref() else {
            return Err(
                "purchase-marked delivery requires a configured purchase verifier".to_owned(),
            );
        };
        let view = FindingPurchaseContextView {
            marker: marked.marker,
            context_b64,
            capability: &request.capability,
            server_id: &request.server_id,
            tool_name: &request.tool_name,
            arguments: &request.arguments,
            expected_output_digest: marked.expected_output_digest,
        };
        let mut verified = verifier
            .verify_purchase(&view)
            .map_err(|error| format!("purchase context rejected: {error}"))?;
        if verified.finding_id != marked.marker.finding_id
            || verified.listing_id != marked.marker.listing_id
        {
            return Err("purchase context does not bind the marked finding sale".to_owned());
        }
        if verified.payload_sha256 != marked.expected_output_digest {
            return Err("purchase context commits a different payload digest".to_owned());
        }
        if verified.payload_media_type.is_empty() {
            return Err("purchase context omits the advertised reveal media type".to_owned());
        }
        if verified.payer_key_hex != request.capability.subject.to_hex() {
            return Err("purchase reservation binds a different payer".to_owned());
        }
        let exact = |amount: &Option<MonetaryAmount>| {
            amount.as_ref().is_some_and(|amount| {
                amount.units == verified.accepted_price.units
                    && amount.currency == verified.accepted_price.currency
            })
        };
        if !exact(&grant.max_cost_per_invocation) || !exact(&grant.max_total_cost) {
            return Err("purchase grant ceilings do not equal the accepted price".to_owned());
        }
        let status_proof_b64 = context
            .get(FINDING_STATUS_PROOF_CONTEXT_KEY)
            .map(|value| {
                value.as_str().ok_or_else(|| {
                    "finding status proof carrier must be a base64 string".to_owned()
                })
            })
            .transpose()?;
        match (
            self.finding_status_proof_verifier.as_ref(),
            status_proof_b64,
        ) {
            (Some(status_verifier), Some(proof_b64)) => {
                if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
                    return Err(
                        "finding status proof carrier exceeds the kernel size bound".to_owned()
                    );
                }
                let status = status_verifier
                    .verify_status_proof(&FindingStatusProofContextView {
                        proof_b64,
                        expected_finding_id: &verified.finding_id,
                    })
                    .map_err(|error| format!("finding status proof rejected: {error}"))?;
                verified.status_proof = Some(status);
            }
            (Some(_), None) => {
                return Err(
                    "M6-qualified finding purchase requires a portable status proof".to_owned(),
                );
            }
            (None, Some(_)) => {
                return Err("finding status proof requires a configured kernel verifier".to_owned());
            }
            (None, None) => {}
        }
        Ok(Some(verified))
    }

    /// Full admission gate for a purchase-marked grant: the deterministic
    /// verification plus the admission-time checks (finding liveness and
    /// authoritative reservation state) and the identity-pipeline
    /// requirement. Returns `Ok(None)` for an unmarked grant.
    pub(crate) fn verify_purchase_admission(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingPurchase>, String> {
        let Some(verified) = self.verify_purchase_context(grant, request)? else {
            return Ok(None);
        };
        if !self.post_invocation_pipeline.is_empty() {
            return Err(
                "purchase-marked delivery requires an empty post-invocation pipeline".to_owned(),
            );
        }
        let Some(marked) = purchase_marked_grant(grant)? else {
            return Err("purchase marker disappeared during admission".to_owned());
        };
        let Some(verifier) = self.finding_purchase_verifier.as_ref() else {
            return Err(
                "purchase-marked delivery requires a configured purchase verifier".to_owned(),
            );
        };
        let context_b64 = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .and_then(|context| context.get(FINDING_PURCHASE_CONTEXT_KEY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                "purchase-marked delivery requires a governed purchase context".to_owned()
            })?;
        let view = FindingPurchaseContextView {
            marker: marked.marker,
            context_b64,
            capability: &request.capability,
            server_id: &request.server_id,
            tool_name: &request.tool_name,
            arguments: &request.arguments,
            expected_output_digest: marked.expected_output_digest,
        };
        verifier
            .verify_purchase_admission(&view, &verified, now_unix_secs)
            .map_err(|error| format!("purchase admission rejected: {error}"))?;
        if let Some(status) = verified.status_proof.as_ref() {
            let proof_b64 = request
                .governed_intent
                .as_ref()
                .and_then(|intent| intent.context.as_ref())
                .and_then(serde_json::Value::as_object)
                .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| "verified finding status proof carrier disappeared".to_owned())?;
            let Some(status_verifier) = self.finding_status_proof_verifier.as_ref() else {
                return Err("finding status verifier disappeared during admission".to_owned());
            };
            status_verifier
                .verify_status_admission(
                    &FindingStatusProofContextView {
                        proof_b64,
                        expected_finding_id: &verified.finding_id,
                    },
                    status,
                    now_unix_secs,
                )
                .map_err(|error| format!("finding status admission rejected: {error}"))?;
        }
        Ok(Some(verified))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn a_committed_digest_admits_only_a_matching_value_delivery() {
        let unconstrained_stream = evaluate_delivery(None, DIGEST, false, b"{}", None);
        assert!(unconstrained_stream.denial.is_none());
        assert!(!unconstrained_stream.digest_mismatched);

        let matching_value = evaluate_delivery(Some(DIGEST), DIGEST, true, b"{}", None);
        assert!(matching_value.denial.is_none());
        assert!(!matching_value.digest_mismatched);

        // A stream whose derived content hash collides with the committed
        // digest still denies: the commitment is over canonical value
        // bytes, and a stream hash is provider-authored chunk metadata.
        let colliding_stream = evaluate_delivery(Some(DIGEST), DIGEST, false, b"{}", None);
        assert!(colliding_stream.digest_mismatched);
        let denial = colliding_stream
            .denial
            .as_ref()
            .filter(|denial| denial.guard == "delivery_contract");
        assert!(
            denial.is_some_and(|denial| denial.message.contains("single value delivery")),
            "a stream delivery must deny under a committed digest"
        );
    }
}
