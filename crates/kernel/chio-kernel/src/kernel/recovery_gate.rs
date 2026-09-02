//! First-class no-charge finding-recovery admission and receipt metadata.

use base64::Engine as _;
use chio_core::capability::scope::{Constraint, FindingRecoveryMarkerV1, ToolGrant};

use crate::finding_denial::FindingDenial;
use crate::finding_purchase::{
    FindingCurrentStatusContextView, FindingStatusProofContextView, VerifiedFindingStatusProof,
    FINDING_STATUS_PROOF_CONTEXT_KEY, MAX_FINDING_STATUS_PROOF_B64_BYTES,
};
use crate::finding_recovery::{
    FindingRecoveryContextView, FindingRecoveryReplaySnapshotV1, VerifiedFindingRecovery,
    FINDING_RECOVERY_CONTEXT_ARGUMENT, FINDING_RECOVERY_REPLAY_SNAPSHOT_SCHEMA,
};
use crate::request_matching::resolve_required_matching_grants;
use crate::runtime::ToolCallRequest;

use super::ChioKernel;

pub(crate) struct RecoveryMarkedGrant<'a> {
    marker: &'a FindingRecoveryMarkerV1,
    expected_output_digest: &'a str,
}

pub(crate) use super::delivery_contract::VerifiedFindingRecoveryAdmission;

#[derive(serde::Serialize)]
struct FindingRecoveryRequestBinding<'a> {
    schema: &'static str,
    selected_grant: &'a ToolGrant,
    request: &'a ToolCallRequest,
}

const FINDING_RECOVERY_REQUEST_BINDING_SCHEMA: &str = "chio.finding.recovery-request-binding.v1";

fn is_lower_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn recovery_status_proof_view<'a>(
    request: &'a ToolCallRequest,
    verified: &'a VerifiedFindingRecovery,
) -> Result<FindingStatusProofContextView<'a>, FindingDenial> {
    let proof_b64 = request
        .governed_intent
        .as_ref()
        .and_then(|intent| intent.context.as_ref())
        .and_then(serde_json::Value::as_object)
        .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            FindingDenial::carrier_invalid("finding recovery requires a portable status proof")
        })?;
    if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
        return Err(FindingDenial::carrier_invalid(
            "finding status proof carrier exceeds the kernel size bound",
        ));
    }
    Ok(FindingStatusProofContextView {
        proof_b64,
        expected_finding_id: &verified.finding_id,
        expected_feed_id: &verified.expected_status_feed_id,
    })
}

/// Recover and validate the closed recovery grant profile.
pub(crate) fn recovery_marked_grant(
    grant: &ToolGrant,
) -> Result<Option<RecoveryMarkedGrant<'_>>, FindingDenial> {
    if grant.constraints.iter().any(|constraint| {
        matches!(constraint, Constraint::Custom(key, _)
            if matches!(key.as_str(), "recovery_of_receipt_id" | "recovery_of_capability_id"))
    }) {
        return Err(FindingDenial::carrier_invalid(
            "legacy Custom-only recovery authority is forbidden; use RequireFindingRecovery",
        ));
    }
    let mut markers = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::RequireFindingRecovery(marker) = constraint {
            Some(marker.as_ref())
        } else {
            None
        }
    });
    let Some(marker) = markers.next() else {
        return Ok(None);
    };
    if markers.next().is_some() {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant carries more than one recovery marker",
        ));
    }
    if grant.operations.as_slice() != [chio_core::capability::scope::Operation::Invoke] {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant permits only the Invoke operation",
        ));
    }
    if grant.constraints.len() != 2 {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant requires exactly its recovery marker and output digest",
        ));
    }
    if grant
        .constraints
        .iter()
        .any(|constraint| matches!(constraint, Constraint::RequireFindingPurchase(_)))
    {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant must not carry a purchase marker",
        ));
    }
    let mut digests = grant.constraints.iter().filter_map(|constraint| {
        if let Constraint::OutputDigestSha256(digest) = constraint {
            Some(digest.as_str())
        } else {
            None
        }
    });
    let (Some(expected_output_digest), None) = (digests.next(), digests.next()) else {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant requires exactly one committed output digest",
        ));
    };
    if marker.max_recoveries == 0 || marker.max_recoveries > 8 {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant retry budget must be between 1 and 8",
        ));
    }
    if grant.max_invocations != Some(marker.max_recoveries) {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant invocation budget must equal its durable retry budget",
        ));
    }
    if grant.max_cost_per_invocation.is_some() || grant.max_total_cost.is_some() {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant must not carry monetary ceilings",
        ));
    }
    if grant.dpop_required != Some(true) {
        return Err(FindingDenial::carrier_invalid(
            "recovery grant requires mandatory proof of possession",
        ));
    }
    Ok(Some(RecoveryMarkedGrant {
        marker,
        expected_output_digest,
    }))
}

fn validate_recovery_capability_profile(
    capability: &chio_core::capability::token::CapabilityToken,
) -> Result<(), FindingDenial> {
    let carries_recovery_authority = capability.scope.grants.iter().any(|grant| {
        grant.constraints.iter().any(|constraint| {
            matches!(constraint, Constraint::RequireFindingRecovery(_))
                || matches!(constraint, Constraint::Custom(key, _)
                    if matches!(key.as_str(), "recovery_of_receipt_id" | "recovery_of_capability_id" | "require_finding_recovery"))
        })
    });
    if !carries_recovery_authority {
        return Ok(());
    }
    if capability.scope.grants.len() != 1
        || !capability.scope.resource_grants.is_empty()
        || !capability.scope.prompt_grants.is_empty()
        || capability.aggregate_invocation_budget.is_some()
        || !capability.delegation_chain.is_empty()
    {
        return Err(FindingDenial::carrier_invalid(
            "finding recovery requires an undelegated, single-grant capability",
        ));
    }
    Ok(())
}

fn recovery_request_binding_sha256(
    grant: &ToolGrant,
    request: &ToolCallRequest,
) -> Result<String, FindingDenial> {
    let bytes = crate::canonical_json_bytes(&FindingRecoveryRequestBinding {
        schema: FINDING_RECOVERY_REQUEST_BINDING_SCHEMA,
        selected_grant: grant,
        request,
    })
    .map_err(|error| {
        FindingDenial::carrier_invalid(format!(
            "finding recovery request binding is not canonical: {error}"
        ))
    })?;
    Ok(chio_core::crypto::sha256_hex(&bytes))
}

fn validate_frozen_recovery_binding(
    grant: &ToolGrant,
    request: &ToolCallRequest,
    expected: &VerifiedFindingRecovery,
) -> Result<(), FindingDenial> {
    validate_recovery_capability_profile(&request.capability)?;
    let Some(marked) = recovery_marked_grant(grant)? else {
        return Err(FindingDenial::carrier_invalid(
            "durable recovery snapshot has no marked grant",
        ));
    };
    let arguments = request.arguments.as_object().ok_or_else(|| {
        FindingDenial::carrier_invalid("finding recovery requires a top-level argument object")
    })?;
    let finding_id = arguments
        .get("finding_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            FindingDenial::carrier_invalid("finding recovery requires a top-level finding_id")
        })?;
    if finding_id != marked.marker.finding_id {
        return Err(FindingDenial::binding_mismatch(
            "finding recovery targets a different finding",
        ));
    }
    let context_b64 = arguments
        .get(FINDING_RECOVERY_CONTEXT_ARGUMENT)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            FindingDenial::carrier_invalid("finding recovery requires its evidence carrier")
        })?;
    if context_b64.is_empty() {
        return Err(FindingDenial::carrier_invalid(
            "finding recovery evidence carrier is empty",
        ));
    }
    if expected.recovery_id != marked.marker.recovery_id
        || expected.finding_id != marked.marker.finding_id
        || expected.listing_id != marked.marker.listing_id
        || expected.original_capability_id != marked.marker.original_capability_id
        || expected.original_delivery_receipt_id != marked.marker.original_delivery_receipt_id
        || expected.purchase_key != marked.marker.purchase_key
    {
        return Err(FindingDenial::binding_mismatch(
            "durable recovery snapshot does not match its signed marker",
        ));
    }
    if expected.payload_sha256 != marked.expected_output_digest {
        return Err(FindingDenial::binding_mismatch(
            "durable recovery snapshot commits a different payload digest",
        ));
    }
    if expected.original_subject_key_hex != request.capability.subject.to_hex() {
        return Err(FindingDenial::binding_mismatch(
            "durable recovery snapshot binds a different original subject",
        ));
    }
    Ok(())
}

impl ChioKernel {
    /// Deterministically re-derive a recovery binding from the frozen request.
    pub(crate) fn verify_recovery_context(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
    ) -> Result<Option<VerifiedFindingRecovery>, FindingDenial> {
        validate_recovery_capability_profile(&request.capability)?;
        let Some(marked) = recovery_marked_grant(grant)? else {
            return Ok(None);
        };
        if !self.post_invocation_pipeline.is_empty() {
            return Err(FindingDenial::carrier_invalid(
                "finding recovery requires an empty post-invocation pipeline",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            FindingDenial::carrier_invalid("finding recovery requires a top-level argument object")
        })?;
        let finding_id = arguments
            .get("finding_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid("finding recovery requires a top-level finding_id")
            })?;
        if finding_id != marked.marker.finding_id {
            return Err(FindingDenial::binding_mismatch(
                "finding recovery targets a different finding",
            ));
        }
        let context_b64 = arguments
            .get(FINDING_RECOVERY_CONTEXT_ARGUMENT)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid("finding recovery requires its evidence carrier")
            })?;
        let Some(verifier) = self.finding_recovery_verifier.as_ref() else {
            return Err(FindingDenial::unavailable(
                "finding recovery requires a configured recovery verifier",
            ));
        };
        let verified = verifier
            .verify_recovery(&FindingRecoveryContextView {
                marker: marked.marker,
                context_b64,
                recovery_capability: &request.capability,
                server_id: &request.server_id,
                tool_name: &request.tool_name,
                arguments: &request.arguments,
                expected_output_digest: marked.expected_output_digest,
            })
            .map_err(|denial| denial.prefixed("finding recovery context rejected"))?;
        if verified.recovery_id != marked.marker.recovery_id
            || verified.finding_id != marked.marker.finding_id
            || verified.listing_id != marked.marker.listing_id
            || verified.original_capability_id != marked.marker.original_capability_id
            || verified.original_delivery_receipt_id != marked.marker.original_delivery_receipt_id
            || verified.purchase_key != marked.marker.purchase_key
        {
            return Err(FindingDenial::binding_mismatch(
                "finding recovery carrier does not match its signed marker",
            ));
        }
        if verified.payload_sha256 != marked.expected_output_digest {
            return Err(FindingDenial::binding_mismatch(
                "finding recovery commits a different payload digest",
            ));
        }
        if verified.original_subject_key_hex != request.capability.subject.to_hex() {
            return Err(FindingDenial::binding_mismatch(
                "finding recovery binds a different original subject",
            ));
        }
        Ok(Some(verified))
    }

    /// Verify the carrier and atomically reserve one durable attempt before
    /// dispatch. Re-evaluating the same request id is idempotent.
    pub(crate) fn verify_recovery_admission(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingRecovery>, FindingDenial> {
        let Some(admission) =
            self.verify_recovery_status_admission(grant, request, now_unix_secs)?
        else {
            return Ok(None);
        };
        let verified = admission.recovery;
        let Some(marked) = recovery_marked_grant(grant)? else {
            return Err(FindingDenial::unavailable(
                "finding recovery marker disappeared during admission",
            ));
        };
        let Some(verifier) = self.finding_recovery_verifier.as_ref() else {
            return Err(FindingDenial::unavailable(
                "finding recovery requires a configured recovery verifier",
            ));
        };
        verifier
            .reserve_recovery_attempt(
                &verified,
                &request.request_id,
                marked.marker.max_recoveries,
                now_unix_secs,
            )
            .map_err(|denial| denial.prefixed("finding recovery quota rejected"))?;
        Ok(Some(verified))
    }

    /// Recheck mutable finding status without consuming recovery quota.
    ///
    /// Initial admission calls this before reserving an attempt. The dispatch
    /// boundary calls it again so a concurrent pending or retracted transition
    /// cannot redeliver quarantined bytes using an earlier live proof.
    pub(crate) fn verify_recovery_status_admission(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        now_unix_secs: u64,
    ) -> Result<Option<VerifiedFindingRecoveryAdmission>, FindingDenial> {
        let Some(verified) = self.verify_recovery_context(grant, request)? else {
            return Ok(None);
        };
        // Recovery is another delivery of the purchased bytes, so it must
        // cross the same current status floor before consuming retry quota.
        let Some(status_verifier) = self.finding_status_proof_verifier.as_ref() else {
            return Err(FindingDenial::unavailable(
                "finding recovery requires a configured finding status verifier",
            ));
        };
        let status_view = recovery_status_proof_view(request, &verified)?;
        let status = status_verifier
            .verify_status_proof(&status_view)
            .map_err(|denial| denial.prefixed("finding recovery status proof rejected"))?;
        status_verifier
            .verify_status_admission(&status_view, &status, now_unix_secs)
            .map_err(|denial| denial.prefixed("finding recovery status admission rejected"))?;
        Ok(Some(VerifiedFindingRecoveryAdmission {
            recovery: verified,
            status,
        }))
    }

    fn validate_recovery_replay_snapshot(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        snapshot: FindingRecoveryReplaySnapshotV1,
    ) -> Result<Option<VerifiedFindingRecoveryAdmission>, FindingDenial> {
        if snapshot.schema != FINDING_RECOVERY_REPLAY_SNAPSHOT_SCHEMA {
            return Err(FindingDenial::carrier_invalid(
                "durable recovery snapshot schema is unsupported",
            ));
        }
        if !self.post_invocation_pipeline.is_empty() {
            return Err(FindingDenial::carrier_invalid(
                "finding recovery requires an empty post-invocation pipeline",
            ));
        }
        if !is_lower_hex64(&snapshot.request_binding_sha256)
            || snapshot.request_binding_sha256 != recovery_request_binding_sha256(grant, request)?
        {
            return Err(FindingDenial::binding_mismatch(
                "durable recovery snapshot binds a different request or grant",
            ));
        }
        validate_frozen_recovery_binding(grant, request, &snapshot.recovery)?;
        let status = &snapshot.status;
        if status.feed_id != snapshot.recovery.expected_status_feed_id
            || status.map_epoch == 0
            || status.non_inclusion_checked_at == 0
            || !is_lower_hex64(&status.status_epoch_id)
            || !is_lower_hex64(&status.status_epoch_artifact_sha256)
            || !is_lower_hex64(&status.proof_sha256)
            || !is_lower_hex64(&status.root_hash)
            || !is_lower_hex64(&status.operator_authorization_sha256)
            || !is_lower_hex64(&status.service_bond_evidence_sha256)
        {
            return Err(FindingDenial::carrier_invalid(
                "durable recovery status snapshot is malformed",
            ));
        }
        let proof_b64 = request
            .governed_intent
            .as_ref()
            .and_then(|intent| intent.context.as_ref())
            .and_then(serde_json::Value::as_object)
            .and_then(|context| context.get(FINDING_STATUS_PROOF_CONTEXT_KEY))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                FindingDenial::carrier_invalid("durable recovery request lost its status proof")
            })?;
        if proof_b64.is_empty() || proof_b64.len() > MAX_FINDING_STATUS_PROOF_B64_BYTES {
            return Err(FindingDenial::carrier_invalid(
                "durable recovery status proof exceeds the kernel size bound",
            ));
        }
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(proof_b64)
            .map_err(|_| {
                FindingDenial::carrier_invalid("durable recovery status proof is not valid base64")
            })?;
        if chio_core::crypto::sha256_hex(&proof_bytes) != status.proof_sha256 {
            return Err(FindingDenial::binding_mismatch(
                "durable recovery snapshot binds a different status proof",
            ));
        }
        Ok(Some(VerifiedFindingRecoveryAdmission {
            recovery: snapshot.recovery,
            status: snapshot.status,
        }))
    }

    pub(crate) fn capture_recovery_replay_metadata(
        &self,
        request: &ToolCallRequest,
        matched_grant_index: usize,
        verified_recovery: Option<&VerifiedFindingRecoveryAdmission>,
    ) -> Result<Option<serde_json::Value>, super::KernelError> {
        let matching_grants = resolve_required_matching_grants(
            &request.capability,
            &request.tool_name,
            &request.server_id,
            &request.arguments,
            request.model_metadata.as_ref(),
        )
        .map_err(|error| super::KernelError::DurableAdmission(error.to_string()))?;
        let selected_grant = matching_grants
            .iter()
            .find(|matching| matching.index == matched_grant_index)
            .ok_or_else(|| {
                super::KernelError::FindingDenied(FindingDenial::unavailable(
                    "durable tool return lost its matched grant",
                ))
            })?;
        let is_recovery = recovery_marked_grant(selected_grant.grant)
            .map_err(super::KernelError::FindingDenied)?
            .is_some();
        match (is_recovery, verified_recovery) {
            (true, Some(admission)) => {
                let snapshot = FindingRecoveryReplaySnapshotV1::new(
                    recovery_request_binding_sha256(selected_grant.grant, request)
                        .map_err(super::KernelError::FindingDenied)?,
                    admission.recovery.clone(),
                    admission.status.clone(),
                );
                self.validate_recovery_replay_snapshot(
                    selected_grant.grant,
                    request,
                    snapshot.clone(),
                )
                .map_err(|reason| {
                    super::KernelError::DurableAdmission(format!(
                        "recovery replay snapshot could not be captured: {reason}"
                    ))
                })?;
                serde_json::to_value(snapshot)
                    .map(|snapshot| {
                        Some(serde_json::json!({
                            crate::finding_recovery::FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY:
                                snapshot
                        }))
                    })
                    .map_err(|error| super::KernelError::DurableAdmission(error.to_string()))
            }
            (true, None) => Err(super::KernelError::FindingDenied(
                FindingDenial::unavailable(
                    "durable recovery return has no frozen dispatch snapshot",
                ),
            )),
            (false, Some(_)) => Err(super::KernelError::FindingDenied(
                FindingDenial::binding_mismatch(
                    "unmarked durable return carries a frozen recovery snapshot",
                ),
            )),
            (false, None) => Ok(None),
        }
    }

    pub(crate) fn restore_recovery_replay_snapshot(
        &self,
        grant: &ToolGrant,
        request: &ToolCallRequest,
        metadata: Option<&serde_json::Value>,
    ) -> Result<Option<VerifiedFindingRecoveryAdmission>, super::KernelError> {
        let snapshot = metadata
            .and_then(serde_json::Value::as_object)
            .and_then(|metadata| {
                metadata.get(crate::finding_recovery::FINDING_RECOVERY_REPLAY_SNAPSHOT_METADATA_KEY)
            })
            .cloned();
        let is_recovery = recovery_marked_grant(grant)
            .map_err(super::KernelError::FindingDenied)?
            .is_some();
        match (is_recovery, snapshot) {
            (true, Some(snapshot)) => {
                let snapshot: FindingRecoveryReplaySnapshotV1 = serde_json::from_value(snapshot)
                    .map_err(|error| {
                        super::KernelError::DurableAdmission(format!(
                            "durable recovery snapshot is malformed: {error}"
                        ))
                    })?;
                self.validate_recovery_replay_snapshot(grant, request, snapshot)
                    .map_err(|reason| {
                        super::KernelError::DurableAdmission(format!(
                            "durable recovery snapshot was rejected: {reason}"
                        ))
                    })
            }
            (true, None) => Err(super::KernelError::FindingDenied(
                FindingDenial::unavailable("durable recovery return has no frozen status snapshot"),
            )),
            (false, Some(_)) => Err(super::KernelError::FindingDenied(
                FindingDenial::binding_mismatch(
                    "unmarked durable return carries a recovery snapshot",
                ),
            )),
            (false, None) => Ok(None),
        }
    }

    /// Recheck mutable status before any durable recovery response releases
    /// its retained payload. This does not reserve another recovery attempt.
    pub(crate) fn revalidate_completed_recovery_status(
        &self,
        matched_grant_index: usize,
        request: &ToolCallRequest,
        expected: Option<&VerifiedFindingRecovery>,
        admitted_status: Option<&VerifiedFindingStatusProof>,
        now_unix_secs: u64,
    ) -> Result<(), FindingDenial> {
        let (Some(expected), Some(admitted_status)) = (expected, admitted_status) else {
            return if expected.is_none() && admitted_status.is_none() {
                Ok(())
            } else {
                Err(FindingDenial::unavailable(
                    "completed recovery lost its dispatch-frozen status baseline",
                ))
            };
        };
        let grant = request
            .capability
            .scope
            .grants
            .get(matched_grant_index)
            .ok_or_else(|| {
                FindingDenial::unavailable("completed recovery grant index is out of bounds")
            })?;
        if !self.post_invocation_pipeline.is_empty() {
            return Err(FindingDenial::carrier_invalid(
                "finding recovery requires an empty post-invocation pipeline",
            ));
        }
        validate_frozen_recovery_binding(grant, request, expected)?;
        let Some(status_verifier) = self.finding_status_proof_verifier.as_ref() else {
            return Err(FindingDenial::unavailable(
                "finding recovery requires a configured finding status verifier",
            ));
        };
        if admitted_status.feed_id != expected.expected_status_feed_id {
            return Err(FindingDenial::stale_or_superseded(
                "completed recovery status feed changed after dispatch",
            ));
        }
        status_verifier
            .verify_current_status_admission(
                &FindingCurrentStatusContextView {
                    expected_finding_id: &expected.finding_id,
                    expected_feed_id: &expected.expected_status_feed_id,
                    minimum_map_epoch: admitted_status.map_epoch,
                    minimum_non_inclusion_checked_at: admitted_status.non_inclusion_checked_at,
                },
                now_unix_secs,
            )
            .map_err(|denial| {
                denial.prefixed("finding recovery current status admission rejected")
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding_denial::FindingDenialCode;
    use crate::finding_purchase::{FindingStatusProofVerifier, VerifiedFindingStatusProof};
    use crate::finding_recovery::{FindingRecoveryVerifier, VerifiedFindingRecovery};
    use crate::{HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig};
    use chio_core::capability::governance::GovernedTransactionIntent;
    use chio_core::capability::scope::{
        ChioScope, FindingPurchaseMarkerV1, FindingSettlementSelector, MonetaryAmount, Operation,
        PromptGrant, ResourceGrant,
    };
    use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
    use chio_core::crypto::Keypair;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    struct TestRecoveryVerifier {
        reservations: Arc<AtomicU64>,
        receipts: Arc<AtomicU64>,
        deny_verification: Arc<AtomicBool>,
        fail_receipts: Arc<AtomicBool>,
    }

    impl FindingRecoveryVerifier for TestRecoveryVerifier {
        fn verify_recovery(
            &self,
            view: &FindingRecoveryContextView<'_>,
        ) -> Result<VerifiedFindingRecovery, crate::finding_denial::FindingDenial> {
            if self.deny_verification.load(Ordering::SeqCst) {
                return Err(crate::finding_denial::FindingDenial::authority_invalid(
                    "historical recovery authority has rotated",
                ));
            }
            Ok(VerifiedFindingRecovery {
                recovery_id: view.marker.recovery_id.clone(),
                finding_id: view.marker.finding_id.clone(),
                listing_id: view.marker.listing_id.clone(),
                payload_sha256: view.expected_output_digest.to_owned(),
                expected_status_feed_id: "feed-1".to_owned(),
                original_capability_id: view.marker.original_capability_id.clone(),
                original_delivery_receipt_id: view.marker.original_delivery_receipt_id.clone(),
                purchase_key: view.marker.purchase_key.clone(),
                original_subject_key_hex: view.recovery_capability.subject.to_hex(),
            })
        }

        fn reserve_recovery_attempt(
            &self,
            _verified: &VerifiedFindingRecovery,
            _request_id: &str,
            _max_recoveries: u32,
            _now_unix_secs: u64,
        ) -> Result<(), crate::finding_denial::FindingDenial> {
            self.reservations.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn record_recovery_receipt(
            &self,
            _verified: &VerifiedFindingRecovery,
            _recovery_receipt_id: &str,
            _recorded_at: u64,
        ) -> Result<(), crate::finding_denial::FindingDenial> {
            self.receipts.fetch_add(1, Ordering::SeqCst);
            if self.fail_receipts.load(Ordering::SeqCst) {
                Err(crate::finding_denial::FindingDenial::unavailable(
                    "recovery lineage backend unavailable",
                ))
            } else {
                Ok(())
            }
        }
    }

    struct MutableStatusVerifier {
        portable_deny: Arc<AtomicBool>,
        current_deny: Arc<AtomicBool>,
        current_checks: Arc<AtomicU64>,
    }

    impl FindingStatusProofVerifier for MutableStatusVerifier {
        fn verify_status_proof(
            &self,
            _view: &FindingStatusProofContextView<'_>,
        ) -> Result<VerifiedFindingStatusProof, crate::finding_denial::FindingDenial> {
            if self.portable_deny.load(Ordering::SeqCst) {
                return Err(crate::finding_denial::FindingDenial::status_denied(
                    "finding is pending retraction under the old operator",
                ));
            }
            Ok(VerifiedFindingStatusProof {
                feed_id: "feed-1".to_owned(),
                key_domain_nonce: 1,
                map_epoch: 1,
                status_epoch_id: "6".repeat(64),
                status_epoch_artifact_sha256: "1".repeat(64),
                proof_sha256: chio_core::crypto::sha256_hex(b"status-proof"),
                root_hash: "3".repeat(64),
                non_inclusion_checked_at: 1,
                operator_authorization_sha256: "4".repeat(64),
                service_bond_evidence_sha256: "5".repeat(64),
            })
        }

        fn verify_status_admission(
            &self,
            _view: &FindingStatusProofContextView<'_>,
            _verified: &VerifiedFindingStatusProof,
            _now_unix_secs: u64,
        ) -> Result<(), crate::finding_denial::FindingDenial> {
            if self.portable_deny.load(Ordering::SeqCst) {
                Err(crate::finding_denial::FindingDenial::status_denied(
                    "finding is pending retraction",
                ))
            } else {
                Ok(())
            }
        }

        fn verify_current_status_admission(
            &self,
            _view: &FindingCurrentStatusContextView<'_>,
            _now_unix_secs: u64,
        ) -> Result<(), crate::finding_denial::FindingDenial> {
            self.current_checks.fetch_add(1, Ordering::SeqCst);
            if self.current_deny.load(Ordering::SeqCst) {
                Err(crate::finding_denial::FindingDenial::status_denied(
                    "finding is pending retraction",
                ))
            } else {
                Ok(())
            }
        }
    }

    fn marker() -> FindingRecoveryMarkerV1 {
        FindingRecoveryMarkerV1 {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "c".repeat(64),
            max_recoveries: 2,
        }
    }

    fn grant(extra: Vec<Constraint>) -> ToolGrant {
        let mut constraints = vec![
            Constraint::OutputDigestSha256("d".repeat(64)),
            Constraint::RequireFindingRecovery(Box::new(marker())),
        ];
        constraints.extend(extra);
        ToolGrant {
            server_id: "srv".to_owned(),
            tool_name: "read_finding".to_owned(),
            operations: vec![Operation::Invoke],
            constraints,
            max_invocations: Some(2),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }
    }

    fn capability() -> CapabilityToken {
        let key = Keypair::from_seed(&[9; 32]);
        CapabilityToken::sign(
            CapabilityTokenBody {
                id: "recovery-capability".to_owned(),
                issuer: key.public_key(),
                subject: key.public_key(),
                scope: ChioScope {
                    grants: vec![grant(Vec::new())],
                    resource_grants: Vec::new(),
                    prompt_grants: Vec::new(),
                },
                issued_at: 1,
                expires_at: 2,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            &key,
        )
        .expect("sign recovery capability")
    }

    fn kernel() -> ChioKernel {
        ChioKernel::new(KernelConfig {
            keypair: Keypair::from_seed(&[8; 32]),
            ca_public_keys: Vec::new(),
            max_delegation_depth: 5,
            policy_hash: "test-policy".to_owned(),
            allow_sampling: false,
            allow_sampling_tool_use: false,
            allow_elicitation: false,
            max_stream_duration_secs: 60,
            max_stream_total_bytes: 1_048_576,
            require_web3_evidence: false,
            allow_ephemeral_receipt_log: true,
            allow_ephemeral_revocation_store: true,
            checkpoint_batch_size: 100,
            retention_config: None,
            memory_budget: MemoryBudgetConfig::defaults(),
            deadlines: HotPathDeadlineConfig::default(),
        })
    }

    fn recovery_request() -> ToolCallRequest {
        let capability = capability();
        ToolCallRequest {
            request_id: "recovery-request".to_owned(),
            capability: capability.clone(),
            tool_name: "read_finding".to_owned(),
            server_id: "srv".to_owned(),
            agent_id: capability.subject.to_hex(),
            arguments: serde_json::json!({
                "finding_id": marker().finding_id,
                FINDING_RECOVERY_CONTEXT_ARGUMENT: "recovery-carrier"
            }),
            dpop_proof: None,
            execution_nonce: None,
            governed_intent: Some(GovernedTransactionIntent {
                id: "recovery-intent".to_owned(),
                server_id: "srv".to_owned(),
                tool_name: "read_finding".to_owned(),
                purpose: "recover purchased finding".to_owned(),
                max_amount: None,
                commerce: None,
                metered_billing: None,
                runtime_attestation: None,
                call_chain: None,
                autonomy: None,
                context: Some(serde_json::json!({
                    FINDING_STATUS_PROOF_CONTEXT_KEY:
                        base64::engine::general_purpose::STANDARD.encode(b"status-proof")
                })),
                body: Default::default(),
            }),
            approval_token: None,
            approval_tokens: Vec::new(),
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            model_metadata: None,
            federated_origin_kernel_id: None,
        }
    }

    #[test]
    fn dispatch_status_recheck_denies_without_reserving_again() {
        let portable_deny = Arc::new(AtomicBool::new(false));
        let current_deny = Arc::new(AtomicBool::new(false));
        let current_checks = Arc::new(AtomicU64::new(0));
        let reservations = Arc::new(AtomicU64::new(0));
        let receipts = Arc::new(AtomicU64::new(0));
        let deny_verification = Arc::new(AtomicBool::new(false));
        let mut kernel = kernel();
        kernel.set_finding_recovery_verifier(Arc::new(TestRecoveryVerifier {
            reservations: Arc::clone(&reservations),
            receipts,
            deny_verification,
            fail_receipts: Arc::new(AtomicBool::new(false)),
        }));
        kernel.set_finding_status_proof_verifier(Arc::new(MutableStatusVerifier {
            portable_deny: Arc::clone(&portable_deny),
            current_deny: Arc::clone(&current_deny),
            current_checks: Arc::clone(&current_checks),
        }));
        let request = recovery_request();
        let grant = &request.capability.scope.grants[0];
        let admitted = kernel
            .verify_recovery_status_admission(grant, &request, 1)
            .expect("dispatch status snapshot")
            .expect("recovery marker");

        assert!(kernel
            .verify_recovery_admission(grant, &request, 1)
            .expect("initial live admission")
            .is_some());
        assert_eq!(reservations.load(Ordering::SeqCst), 1);

        portable_deny.store(true, Ordering::SeqCst);
        let error = kernel
            .verify_recovery_status_admission(grant, &request, 1)
            .expect_err("dispatch boundary must observe pending retraction");
        assert!(error.detail().contains("pending retraction"));
        assert_eq!(error.code(), FindingDenialCode::StatusDenied);
        assert_eq!(reservations.load(Ordering::SeqCst), 1);

        let expected = kernel
            .verify_recovery_context(grant, &request)
            .expect("rederive recovery binding")
            .expect("recovery marker remains present");
        current_deny.store(true, Ordering::SeqCst);
        let terminal_error = kernel
            .revalidate_completed_recovery_status(
                0,
                &request,
                Some(&expected),
                Some(&admitted.status),
                1,
            )
            .expect_err("a durable completed replay must recheck mutable status");
        assert!(terminal_error.detail().contains("pending retraction"));
        assert_eq!(terminal_error.code(), FindingDenialCode::StatusDenied);
        assert_eq!(current_checks.load(Ordering::SeqCst), 1);
        assert_eq!(reservations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn terminal_recovery_resolves_current_status_instead_of_reusing_the_admission_floor() {
        let portable_deny = Arc::new(AtomicBool::new(false));
        let current_deny = Arc::new(AtomicBool::new(false));
        let current_checks = Arc::new(AtomicU64::new(0));
        let reservations = Arc::new(AtomicU64::new(0));
        let receipts = Arc::new(AtomicU64::new(0));
        let deny_verification = Arc::new(AtomicBool::new(false));
        let mut kernel = kernel();
        kernel.set_finding_recovery_verifier(Arc::new(TestRecoveryVerifier {
            reservations: Arc::clone(&reservations),
            receipts,
            deny_verification: Arc::clone(&deny_verification),
            fail_receipts: Arc::new(AtomicBool::new(false)),
        }));
        kernel.set_finding_status_proof_verifier(Arc::new(MutableStatusVerifier {
            portable_deny: Arc::clone(&portable_deny),
            current_deny,
            current_checks: Arc::clone(&current_checks),
        }));
        let request = recovery_request();
        let grant = &request.capability.scope.grants[0];
        let admitted = kernel
            .verify_recovery_status_admission(grant, &request, 1)
            .expect("dispatch status snapshot")
            .expect("recovery marker");
        let expected = kernel
            .verify_recovery_admission(grant, &request, 1)
            .expect("initial live admission")
            .expect("recovery binding");
        assert_eq!(admitted.recovery, expected);
        let metadata = kernel
            .capture_recovery_replay_metadata(&request, 0, Some(&admitted))
            .expect("capture dispatch-frozen recovery status")
            .expect("recovery metadata");

        // Model an unrelated feed advance: the frozen portable proof is now
        // behind the floor and no longer validates under the rotated operator,
        // but the target has a fresh current-floor proof.
        portable_deny.store(true, Ordering::SeqCst);
        deny_verification.store(true, Ordering::SeqCst);
        let mut changed_request = request.clone();
        changed_request.arguments["unexpected"] = serde_json::json!(true);
        let changed_grant = &changed_request.capability.scope.grants[0];
        let changed_error = kernel
            .restore_recovery_replay_snapshot(changed_grant, &changed_request, Some(&metadata))
            .expect_err("a changed durable request must not inherit the frozen facts");
        assert!(changed_error
            .to_string()
            .contains("different request or grant"));
        let restored = kernel
            .restore_recovery_replay_snapshot(grant, &request, Some(&metadata))
            .expect("restore authenticated raw-outcome snapshot")
            .expect("recovery snapshot");
        kernel
            .revalidate_completed_recovery_status(
                0,
                &request,
                Some(&restored.recovery),
                Some(&restored.status),
                2,
            )
            .expect("current-floor status keeps the recovery live");

        assert_eq!(current_checks.load(Ordering::SeqCst), 1);
        assert_eq!(reservations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn recovery_profile_is_first_class_no_charge() {
        assert!(recovery_marked_grant(&grant(Vec::new()))
            .expect("valid recovery")
            .is_some());
        let mut priced = grant(Vec::new());
        priced.max_total_cost = Some(MonetaryAmount {
            units: 1,
            currency: "USD".to_owned(),
        });
        assert!(recovery_marked_grant(&priced).is_err());
        assert!(
            recovery_marked_grant(&grant(vec![Constraint::RequireFindingPurchase(Box::new(
                FindingPurchaseMarkerV1 {
                    finding_id: "b".repeat(64),
                    listing_id: "listing-1".to_owned(),
                    settlement: FindingSettlementSelector::LocalReversibleHold,
                }
            ),)]))
            .is_err()
        );
        assert!(recovery_marked_grant(&grant(vec![Constraint::Custom(
            "recovery_of_receipt_id".to_owned(),
            "receipt-original".to_owned(),
        )]))
        .is_err());

        let mut legacy = grant(Vec::new());
        legacy.constraints = vec![
            Constraint::Custom(
                "recovery_of_receipt_id".to_owned(),
                "receipt-original".to_owned(),
            ),
            Constraint::Custom(
                "recovery_of_capability_id".to_owned(),
                "capability-original".to_owned(),
            ),
        ];
        assert!(recovery_marked_grant(&legacy).is_err());

        let mut widened = grant(Vec::new());
        widened.operations.push(Operation::Read);
        assert!(recovery_marked_grant(&widened).is_err());
    }

    #[test]
    fn recovery_receipt_block_keeps_original_lineage() {
        let verified = VerifiedFindingRecovery {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            payload_sha256: "d".repeat(64),
            expected_status_feed_id: "feed-1".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "c".repeat(64),
            original_subject_key_hex: "e".repeat(64),
        };
        let block = crate::kernel::delivery_contract::finding_recovery_block(&verified);
        block.validate().expect("valid recovery block");
        assert_eq!(block.recovery_id, verified.recovery_id);
        assert_eq!(
            block.original_delivery_receipt_id,
            verified.original_delivery_receipt_id
        );
        assert_eq!(block.purchase_key, verified.purchase_key);
    }

    #[test]
    fn recovery_receipt_metadata_keeps_typed_original_lineage() {
        let verified = VerifiedFindingRecovery {
            recovery_id: "a".repeat(64),
            finding_id: "b".repeat(64),
            listing_id: "listing-1".to_owned(),
            payload_sha256: "d".repeat(64),
            expected_status_feed_id: "feed-1".to_owned(),
            original_capability_id: "capability-original".to_owned(),
            original_delivery_receipt_id: "receipt-original".to_owned(),
            purchase_key: "c".repeat(64),
            original_subject_key_hex: "e".repeat(64),
        };
        let metadata = crate::kernel::delivery_contract::attach_finding_recovery_metadata(
            Some(serde_json::json!({"existing": true})),
            Some(&verified),
        )
        .expect("recovery metadata");
        assert_eq!(metadata["existing"], serde_json::json!(true));
        let block: chio_core::receipt::metadata::FindingRecovery = serde_json::from_value(
            metadata[chio_core::receipt::metadata::FINDING_RECOVERY_METADATA_KEY].clone(),
        )
        .expect("typed recovery block");
        assert_eq!(block.recovery_id, verified.recovery_id);
        assert_eq!(
            block.original_delivery_receipt_id,
            verified.original_delivery_receipt_id
        );
    }

    #[test]
    fn ordinary_recovery_refuses_non_atomic_terminalization() {
        let receipts = Arc::new(AtomicU64::new(0));
        let mut kernel = kernel();
        kernel.set_finding_recovery_verifier(Arc::new(TestRecoveryVerifier {
            reservations: Arc::new(AtomicU64::new(0)),
            receipts: Arc::clone(&receipts),
            deny_verification: Arc::new(AtomicBool::new(false)),
            fail_receipts: Arc::new(AtomicBool::new(false)),
        }));
        let mut request = recovery_request();
        let output = serde_json::json!({"payload": "recovered"});
        let output_bytes = chio_core::canonical::canonical_json_bytes(&output)
            .expect("recovery output is canonical");
        request.capability.scope.grants[0].constraints[0] =
            Constraint::OutputDigestSha256(chio_core::crypto::sha256_hex(&output_bytes));
        let verified = VerifiedFindingRecovery {
            recovery_id: marker().recovery_id,
            finding_id: marker().finding_id,
            listing_id: marker().listing_id,
            payload_sha256: chio_core::crypto::sha256_hex(&output_bytes),
            expected_status_feed_id: "feed-1".to_owned(),
            original_capability_id: marker().original_capability_id,
            original_delivery_receipt_id: marker().original_delivery_receipt_id,
            purchase_key: marker().purchase_key,
            original_subject_key_hex: request.capability.subject.to_hex(),
        };
        let error = kernel
            .finalize_ordinary_recovery_response(
                crate::kernel::evaluation::evaluation_helpers::OrdinaryRecoveryFinalization {
                    request: &request,
                    output: crate::runtime::ToolServerOutput::Value(output),
                    elapsed: std::time::Duration::ZERO,
                    timestamp: 1,
                    matched_grant_index: 0,
                    cost: crate::kernel::responses::FinalizeToolOutputCostContext {
                        charge_result: None,
                        reported_cost: None,
                        payment_authorization: None,
                        cap: &request.capability,
                    },
                    metadata: None,
                    guard_evidence: &[],
                    payee_binding: None,
                    recovery: Some(&verified),
                },
            )
            .expect_err("ordinary recovery must require a durable terminal projection");
        assert!(error.to_string().contains("atomic durable admission"));
        assert_eq!(receipts.load(Ordering::SeqCst), 0);
        assert!(kernel.receipt_log().is_empty());
    }

    #[test]
    fn recovery_capability_rejects_additional_authority_surfaces() {
        assert!(validate_recovery_capability_profile(&capability()).is_ok());

        let mut additional_grant = capability();
        additional_grant.scope.grants.push(grant(Vec::new()));
        assert!(validate_recovery_capability_profile(&additional_grant).is_err());

        let mut ordinary = capability();
        ordinary.scope.grants.iter_mut().for_each(|grant| {
            grant.constraints = vec![Constraint::OutputDigestSha256("d".repeat(64))]
        });
        ordinary.scope.grants.push(ordinary.scope.grants[0].clone());
        assert!(validate_recovery_capability_profile(&ordinary).is_ok());

        let mut resource = capability();
        resource.scope.resource_grants.push(ResourceGrant {
            uri_pattern: "*".to_owned(),
            operations: vec![Operation::Read],
        });
        assert!(validate_recovery_capability_profile(&resource).is_err());

        let mut prompt = capability();
        prompt.scope.prompt_grants.push(PromptGrant {
            prompt_name: "*".to_owned(),
            operations: vec![Operation::Get],
        });
        assert!(validate_recovery_capability_profile(&prompt).is_err());
    }
}
