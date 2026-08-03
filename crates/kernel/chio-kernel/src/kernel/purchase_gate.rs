//! Purchase-marked admission checks shared by both evaluation lanes and
//! the durable finalizer.

use base64::Engine as _;
use chio_core::capability::scope::{
    Constraint, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount, ToolGrant,
};
#[cfg(feature = "cognition-market-experimental")]
use chio_core::crypto::PublicKey;
use serde::Deserialize;

use crate::finding_purchase::{
    FindingCurrentStatusContextView, FindingPurchaseContextView, FindingPurchaseReplaySnapshotV1,
    FindingStatusProofContextView, VerifiedFindingPurchase, FINDING_ESCROW_WITNESS_CONTEXT_KEY,
    FINDING_PURCHASE_CONTEXT_KEY, FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA,
    FINDING_STATUS_PROOF_CONTEXT_KEY, MAX_FINDING_STATUS_PROOF_B64_BYTES,
};
use crate::request_matching::resolve_required_matching_grants;
use crate::runtime::ToolCallRequest;

use super::{ChioKernel, KernelError};

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

/// The purchase marker and its paired output digest recovered from one
/// selected grant, before context verification.
pub(crate) struct PurchaseMarkedGrant<'a> {
    pub(crate) marker: &'a FindingPurchaseMarkerV1,
    pub(crate) expected_output_digest: &'a str,
}

fn validate_verified_purchase_binding(
    marked: &PurchaseMarkedGrant<'_>,
    grant: &ToolGrant,
    request: &ToolCallRequest,
    verified: &VerifiedFindingPurchase,
) -> Result<(), String> {
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
    Ok(())
}

fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
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
    /// Pin the single qualified pool ledger for this deployment kernel.
    /// Once installed it cannot be replaced, preventing callers from routing
    /// successive debits for one signed allocation through disjoint ledgers.
    #[cfg(feature = "cognition-market-experimental")]
    pub fn set_finding_pool_ledger(
        &mut self,
        ledger: std::sync::Arc<dyn crate::finding_pool::QualifiedFindingPoolLedger>,
    ) -> Result<(), crate::finding_pool::FindingPoolLedgerError> {
        if self.finding_pool_ledger.is_some() {
            return Err(crate::finding_pool::FindingPoolLedgerError::AlreadyConfigured);
        }
        self.finding_pool_ledger = Some(ledger);
        Ok(())
    }

    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) fn finding_pool_allocation_authority(&self) -> Option<&PublicKey> {
        self.finding_pool_allocation_authority.as_ref()
    }

    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) fn finding_pool_ledger(
        &self,
    ) -> Option<&dyn crate::finding_pool::QualifiedFindingPoolLedger> {
        self.finding_pool_ledger.as_deref()
    }

    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) fn verify_finding_status_for_pool(
        &self,
        proof_b64: Option<&str>,
        expected_finding_id: &str,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        match (self.finding_status_proof_verifier.as_ref(), proof_b64) {
            (Some(status_verifier), Some(proof_b64)) => {
                if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
                    return Err(
                        "finding status proof carrier exceeds the kernel size bound".to_owned()
                    );
                }
                let view = FindingStatusProofContextView {
                    proof_b64,
                    expected_finding_id,
                };
                let verified = status_verifier
                    .verify_status_proof(&view)
                    .map_err(|error| format!("finding status proof rejected: {error}"))?;
                status_verifier
                    .verify_status_admission(&view, &verified, now_unix_secs)
                    .map_err(|error| format!("finding status admission rejected: {error}"))
            }
            (Some(_), None) => {
                Err("M6-qualified finding pool debit requires a portable status proof".to_owned())
            }
            (None, Some(_)) => {
                Err("finding status proof requires a configured kernel verifier".to_owned())
            }
            (None, None) => Ok(()),
        }
    }

    #[cfg(feature = "cognition-market-experimental")]
    pub(crate) fn verify_purchase_context_for_pool(
        &self,
        view: &FindingPurchaseContextView<'_>,
        now_unix_secs: u64,
        require_live_admission: bool,
    ) -> Result<VerifiedFindingPurchase, String> {
        let verifier = self.finding_purchase_verifier.as_ref().ok_or_else(|| {
            "finding pool debit requires the kernel's configured purchase verifier".to_owned()
        })?;
        let verified = verifier
            .verify_purchase(view)
            .map_err(|error| format!("purchase context rejected: {error}"))?;
        if verified.finding_id != view.marker.finding_id
            || verified.listing_id != view.marker.listing_id
            || verified.payload_sha256 != view.expected_output_digest
            || verified.payer_key_hex != view.capability.subject.to_hex()
        {
            return Err("purchase context does not bind the pool debit request".to_owned());
        }
        if require_live_admission {
            verifier
                .verify_purchase_admission(view, &verified, now_unix_secs)
                .map_err(|error| format!("purchase admission rejected: {error}"))?;
        }
        Ok(verified)
    }

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
        validate_verified_purchase_binding(&marked, grant, request, &verified)?;
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
                        expected_feed_id: &verified.expected_status_feed_id,
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
            (None, None) => {
                return Err(
                    "purchase-marked delivery requires a configured finding status verifier"
                        .to_owned(),
                );
            }
        }
        Ok(Some(verified))
    }

    /// Validate an admission-verified purchase snapshot recovered from the
    /// authenticated raw tool return. This path deliberately does not consult
    /// the current status verifier: authority rotation after dispatch cannot
    /// invalidate the historical authorization captured with that return.
    pub(crate) fn validate_purchase_replay_snapshot(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        snapshot: FindingPurchaseReplaySnapshotV1,
    ) -> Result<Option<VerifiedFindingPurchase>, String> {
        let Some(marked) = purchase_marked_grant(grant)? else {
            return Err("an unmarked durable return carries a purchase snapshot".to_owned());
        };
        if snapshot.schema != FINDING_PURCHASE_REPLAY_SNAPSHOT_SCHEMA {
            return Err("durable purchase snapshot schema is invalid".to_owned());
        }
        let verified = snapshot.purchase;
        validate_verified_purchase_binding(&marked, grant, request, &verified)?;
        let status = verified.status_proof.as_ref().ok_or_else(|| {
            "M6 durable purchase snapshot has no verified status binding".to_owned()
        })?;
        if status.feed_id != verified.expected_status_feed_id
            || status.key_domain_nonce == 0
            || status.map_epoch == 0
            || status.non_inclusion_checked_at == 0
            || !is_lower_hex64(&status.status_epoch_id)
            || !is_lower_hex64(&status.status_epoch_artifact_sha256)
            || !is_lower_hex64(&status.proof_sha256)
            || !is_lower_hex64(&status.root_hash)
            || !is_lower_hex64(&status.operator_authorization_sha256)
            || !is_lower_hex64(&status.service_bond_evidence_sha256)
        {
            return Err("durable purchase status snapshot is malformed".to_owned());
        }
        let proof_b64 = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "durable purchase request lost its status proof".to_owned())?;
        if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
            return Err("durable purchase status proof exceeds the kernel size bound".to_owned());
        }
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(proof_b64)
            .map_err(|_| "durable purchase status proof is not valid base64".to_owned())?;
        if chio_core::crypto::sha256_hex(&proof_bytes) != status.proof_sha256 {
            return Err("durable purchase snapshot binds a different status proof".to_owned());
        }
        Ok(Some(verified))
    }

    pub(crate) fn capture_purchase_replay_metadata(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        verified_purchase: Option<&VerifiedFindingPurchase>,
    ) -> Result<Option<serde_json::Value>, KernelError> {
        let matching_grants = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(|error| KernelError::DurableAdmission(error.to_string()))?;
        let selected_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .ok_or_else(|| {
                KernelError::DurableAdmission(
                    "durable tool return lost its matched grant".to_owned(),
                )
            })?;
        let is_purchase = purchase_marked_grant(selected_grant.grant)
            .map_err(KernelError::DurableAdmission)?
            .is_some();
        match (is_purchase, verified_purchase) {
            (true, Some(purchase)) => {
                let snapshot = FindingPurchaseReplaySnapshotV1::new(purchase.clone());
                self.validate_purchase_replay_snapshot(
                    selected_grant.grant,
                    request,
                    snapshot.clone(),
                )
                .map_err(|reason| {
                    KernelError::DurableAdmission(format!(
                        "purchase replay snapshot could not be captured: {reason}"
                    ))
                })?;
                serde_json::to_value(snapshot)
                    .map(|snapshot| {
                        Some(serde_json::json!({
                            crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY:
                                snapshot
                        }))
                    })
                    .map_err(|error| KernelError::DurableAdmission(error.to_string()))
            }
            (true, None) => Err(KernelError::DurableAdmission(
                "M6 durable purchase return has no frozen dispatch snapshot".to_owned(),
            )),
            (false, Some(_)) => Err(KernelError::DurableAdmission(
                "unmarked durable return carries a frozen purchase snapshot".to_owned(),
            )),
            (false, None) => Ok(None),
        }
    }

    pub(crate) fn restore_purchase_replay_snapshot(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<VerifiedFindingPurchase>, KernelError> {
        let snapshot = metadata
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| {
                metadata.get(crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY)
            })
            .cloned();
        let is_purchase = purchase_marked_grant(grant)
            .map_err(KernelError::DurableAdmission)?
            .is_some();
        match (is_purchase, snapshot) {
            (true, Some(snapshot)) => {
                let snapshot: FindingPurchaseReplaySnapshotV1 = serde_json::from_value(snapshot)
                    .map_err(|error| {
                        KernelError::DurableAdmission(format!(
                            "durable purchase snapshot is malformed: {error}"
                        ))
                    })?;
                self.validate_purchase_replay_snapshot(grant, request, snapshot)
                    .map_err(|reason| {
                        KernelError::DurableAdmission(format!(
                            "durable purchase snapshot was rejected: {reason}"
                        ))
                    })
            }
            (true, None) => Err(KernelError::DurableAdmission(
                "M6 durable purchase return has no frozen authority snapshot".to_owned(),
            )),
            (false, Some(_)) => Err(KernelError::DurableAdmission(
                "unmarked durable return carries a purchase snapshot".to_owned(),
            )),
            (false, None) => Ok(None),
        }
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
                        expected_feed_id: &verified.expected_status_feed_id,
                    },
                    status,
                    now_unix_secs,
                )
                .map_err(|error| format!("finding status admission rejected: {error}"))?;
        }
        Ok(Some(verified))
    }

    /// Recheck the purchased Finding against the current authenticated feed
    /// floor before a durable terminal captures payment or releases output.
    pub(crate) fn revalidate_completed_purchase_status(
        &self,
        purchase: Option<&VerifiedFindingPurchase>,
        now_unix_secs: u64,
    ) -> Result<(), String> {
        let Some(purchase) = purchase else {
            return Ok(());
        };
        let status = purchase.status_proof.as_ref().ok_or_else(|| {
            "completed purchase has no admission-verified status binding".to_owned()
        })?;
        if status.feed_id != purchase.expected_status_feed_id {
            return Err("completed purchase status feed changed after admission".to_owned());
        }
        let verifier = self.finding_status_proof_verifier.as_ref().ok_or_else(|| {
            "finding status verifier disappeared before terminalization".to_owned()
        })?;
        verifier
            .verify_current_status_admission(
                &FindingCurrentStatusContextView {
                    expected_finding_id: &purchase.finding_id,
                    expected_feed_id: &purchase.expected_status_feed_id,
                    minimum_map_epoch: status.map_epoch,
                    minimum_non_inclusion_checked_at: status.non_inclusion_checked_at,
                },
                now_unix_secs,
            )
            .map_err(|error| format!("completed purchase status admission rejected: {error}"))
    }

    /// Preserve a retained terminal denial and apply the current status gate
    /// before replaying a purchased delivery.
    pub(crate) fn revalidate_replayed_purchase_delivery(
        &self,
        retained_decision: Option<&chio_core::receipt::decision::Decision>,
        evaluation: &mut DeliveryEvaluation,
        purchase: Option<&VerifiedFindingPurchase>,
        now_unix_secs: u64,
    ) -> Option<String> {
        preserve_terminal_delivery_denial(retained_decision, evaluation);
        if evaluation.denial.is_some() {
            return None;
        }
        self.revalidate_completed_purchase_status(purchase, now_unix_secs)
            .err()
            .inspect(|_| evaluation.denial = Some(finding_status_delivery_denial()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use chio_core::capability::governance::{
        GovernedTransactionIntent, GovernedTransactionIntentBody,
    };
    use chio_core::capability::scope::{ChioScope, Operation};
    use chio_core::crypto::Keypair;

    use crate::finding_purchase::{FindingStatusProofVerifier, VerifiedFindingStatusProof};
    use crate::{HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig};

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    struct RotatedStatusVerifier {
        calls: AtomicU64,
    }

    impl FindingStatusProofVerifier for RotatedStatusVerifier {
        fn verify_status_proof(
            &self,
            _view: &FindingStatusProofContextView<'_>,
        ) -> Result<VerifiedFindingStatusProof, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("the prior status operator is no longer current".to_owned())
        }

        fn verify_status_admission(
            &self,
            _view: &FindingStatusProofContextView<'_>,
            _verified: &VerifiedFindingStatusProof,
            _now_unix_secs: u64,
        ) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("the prior status operator is no longer current".to_owned())
        }

        fn verify_current_status_admission(
            &self,
            _view: &FindingCurrentStatusContextView<'_>,
            _now_unix_secs: u64,
        ) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("finding is pending retraction".to_owned())
        }
    }

    #[test]
    fn durable_purchase_snapshot_survives_status_operator_rotation() {
        let kernel_key = Keypair::from_seed(&[91; 32]);
        let buyer = Keypair::from_seed(&[92; 32]);
        let marker = FindingPurchaseMarkerV1 {
            finding_id: "finding-1".to_owned(),
            listing_id: "listing-1".to_owned(),
            settlement: FindingSettlementSelector::LocalReversibleHold,
        };
        let price = MonetaryAmount {
            units: 7,
            currency: "USD".to_owned(),
        };
        let grant = ToolGrant {
            server_id: "finding-server".to_owned(),
            tool_name: "finding.reveal".to_owned(),
            operations: vec![Operation::Invoke],
            constraints: vec![
                Constraint::RequireFindingPurchase(Box::new(marker)),
                Constraint::OutputDigestSha256(DIGEST.to_owned()),
            ],
            max_invocations: Some(1),
            max_cost_per_invocation: Some(price.clone()),
            max_total_cost: Some(price.clone()),
            dpop_required: Some(true),
        };
        let mut kernel = ChioKernel::new(KernelConfig {
            keypair: kernel_key,
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "purchase-snapshot-test".to_owned(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: crate::DEFAULT_MAX_STREAM_DURATION_SECS,
            max_stream_total_bytes: crate::DEFAULT_MAX_STREAM_TOTAL_BYTES,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: 0,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: HotPathDeadlineConfig::default(),
        });
        let capability = kernel
            .issue_capability(
                &buyer.public_key(),
                ChioScope {
                    grants: vec![grant.clone()],
                    ..ChioScope::default()
                },
                300,
            )
            .expect("issue purchase capability");
        let proof_bytes = b"frozen-prior-operator-status-proof";
        let proof_b64 = base64::engine::general_purpose::STANDARD.encode(proof_bytes);
        let request = ToolCallRequest {
            request_id: "purchase-snapshot-rotation".to_owned(),
            capability: capability.clone(),
            tool_name: "finding.reveal".to_owned(),
            server_id: "finding-server".to_owned(),
            agent_id: capability.subject.to_hex(),
            arguments: serde_json::json!({"finding_id": "finding-1"}),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "intent-purchase-snapshot-rotation".to_owned(),
                server_id: "finding-server".to_owned(),
                tool_name: "finding.reveal".to_owned(),
                purpose: "complete an admitted purchase after key rotation".to_owned(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    FINDING_STATUS_PROOF_CONTEXT_KEY: proof_b64,
                })),
                body: GovernedTransactionIntentBody::ToolInvocation,
            }),
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        };
        let frozen_purchase = VerifiedFindingPurchase {
            finding_id: "finding-1".to_owned(),
            listing_id: "listing-1".to_owned(),
            payload_sha256: DIGEST.to_owned(),
            payload_media_type: "application/json".to_owned(),
            expected_status_feed_id: "status-feed/market".to_owned(),
            accepted_price: price,
            payer_key_hex: buyer.public_key().to_hex(),
            reservation_id: "reservation-1".to_owned(),
            purchase_intent_id: "purchase-intent-1".to_owned(),
            authoritative_payment_operation_id: "payment-operation-1".to_owned(),
            accepted_bid_envelope_sha256: "1".repeat(64),
            venue_admission_envelope_sha256: "2".repeat(64),
            status_proof: Some(VerifiedFindingStatusProof {
                feed_id: "status-feed/market".to_owned(),
                key_domain_nonce: 3_318_287_169_837_494,
                map_epoch: 7,
                status_epoch_id: "3".repeat(64),
                status_epoch_artifact_sha256: "4".repeat(64),
                proof_sha256: chio_core::crypto::sha256_hex(proof_bytes),
                root_hash: "5".repeat(64),
                non_inclusion_checked_at: 1_750_000_000,
                operator_authorization_sha256: "6".repeat(64),
                service_bond_evidence_sha256: "7".repeat(64),
            }),
        };
        let rotated = Arc::new(RotatedStatusVerifier {
            calls: AtomicU64::new(0),
        });
        kernel.set_finding_status_proof_verifier(rotated.clone());

        let recovered = kernel
            .validate_purchase_replay_snapshot(
                &grant,
                &request,
                FindingPurchaseReplaySnapshotV1::new(frozen_purchase.clone()),
            )
            .expect("frozen historical authority remains replayable")
            .expect("purchase snapshot remains present");
        assert_eq!(recovered, frozen_purchase);
        let captured = kernel
            .capture_purchase_replay_metadata(&request, 0, Some(&frozen_purchase))
            .expect("the dispatch-frozen purchase remains recordable")
            .expect("the durable return carries a purchase snapshot");
        assert!(captured
            .get(crate::finding_purchase::FINDING_PURCHASE_REPLAY_SNAPSHOT_METADATA_KEY)
            .is_some());
        assert_eq!(rotated.calls.load(Ordering::SeqCst), 0);
        let error = kernel
            .revalidate_completed_purchase_status(Some(&frozen_purchase), 1_800_000_000)
            .expect_err("terminal release must consult the current status floor");
        assert!(error.contains("pending retraction"));
        assert_eq!(rotated.calls.load(Ordering::SeqCst), 1);
    }

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

    #[test]
    fn retained_terminal_deny_never_replays_as_allow() {
        let mut evaluation = evaluate_delivery(None, DIGEST, true, b"{}", None);
        assert!(evaluation.denial.is_none());
        preserve_terminal_delivery_denial(
            Some(&chio_core::receipt::decision::Decision::Deny {
                reason: "finding status changed before durable output release".to_owned(),
                guard: "finding_status".to_owned(),
            }),
            &mut evaluation,
        );
        let denial = evaluation.denial.expect("retained denial");
        assert_eq!(
            denial.message,
            "finding status changed before durable output release"
        );
        assert_eq!(denial.guard, "finding_status");
    }
}
