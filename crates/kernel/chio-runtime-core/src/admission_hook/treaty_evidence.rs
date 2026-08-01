use std::collections::BTreeSet;

use crate::treaty::{validate_bilateral_invocation, validate_cross_kernel_continuation};
use crate::*;

use super::dsse::verify_treaty_dsse_evidence;
use super::store_artifacts::{load_bilateral_invocation_artifact, load_treaty_artifact};
use super::treaty_ref::TreatyReference;

pub(super) struct VerifiedTreatyReference {
    pub(super) continuation_id: Option<String>,
    pub(super) federation_treaty_dsse: Option<serde_json::Value>,
}

pub(super) fn verify_treaty_reference_from_store<S: RuntimeAdmissionStore>(
    store: &S,
    admission_id: &str,
    treaty_ref: &TreatyReference,
    now_unix_ms: u64,
) -> Result<VerifiedTreatyReference, ChioRuntimeError> {
    let Some(bundle) = store.bundle(admission_id)? else {
        return rejected(
            "missing_admission_bundle",
            "cross-boundary request referenced an admission bundle that is not in the verifier-owned store",
        );
    };
    let Some(treaty_scope_record) =
        store.treaty_runtime_artifact("treaty_scope", &treaty_ref.treaty_scope_id)?
    else {
        return rejected(
            "chio_treaty_missing_scope",
            "cross-boundary request referenced a treaty scope that is not in the verifier-owned store",
        );
    };
    if treaty_scope_record.artifact_sha256 != treaty_ref.treaty_scope_sha256 {
        return rejected(
            "chio_treaty_scope_hash_mismatch",
            "cross-boundary request treaty scope hash does not match verifier-owned store",
        );
    }
    let treaty_scope: TreatyScope = serde_json::from_value(treaty_scope_record.raw_json)
        .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    if treaty_scope.trust_bundle_sha256 != bundle.trust_bundle_sha256 {
        return rejected(
            "chio_treaty_scope_hash_mismatch",
            "treaty scope trust bundle hash does not match the verifier-owned admission bundle",
        );
    }

    let Some(intersection_record) =
        store.treaty_runtime_artifact("ladder_intersection", &treaty_ref.ladder_intersection_id)?
    else {
        return rejected(
            "chio_treaty_missing_intersection",
            "cross-boundary request referenced a ladder intersection that is not in the verifier-owned store",
        );
    };
    if intersection_record.artifact_sha256 != treaty_ref.ladder_intersection_sha256 {
        return rejected(
            "chio_treaty_intersection_mismatch",
            "cross-boundary request ladder intersection hash does not match verifier-owned store",
        );
    }
    let ladder_intersection: LadderIntersection =
        serde_json::from_value(intersection_record.raw_json)
            .map_err(|error| ChioRuntimeError::Json(error.to_string()))?;
    let action = ladder_intersection
        .action_classes
        .iter()
        .find(|action| action.action_class_id == treaty_ref.action_class_id);
    let requires_lineage = action.is_some_and(|action| {
        action
            .evidence_required
            .iter()
            .any(|evidence| evidence == "receipt_lineage")
    });
    let requires_bilateral = action.is_some_and(|action| {
        action
            .evidence_required
            .iter()
            .any(|evidence| evidence == "bilateral_invocation")
    });

    let continuation = treaty_ref
        .continuation
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, CrossKernelContinuation>(
                store,
                "cross_kernel_continuation",
                reference,
                "chio_treaty_missing_continuation",
                "chio_treaty_continuation_hash_mismatch",
            )
        })
        .transpose()?;
    let lineage_bundle = treaty_ref
        .lineage_bundle
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, ReceiptLineageBundle>(
                store,
                "receipt_lineage_bundle",
                reference,
                "chio_treaty_missing_required_evidence",
                "chio_treaty_lineage_hash_mismatch",
            )
        })
        .transpose()?;
    let bilateral_invocation = treaty_ref
        .bilateral_invocation
        .as_ref()
        .map(|reference| {
            load_bilateral_invocation_artifact(
                store,
                reference,
                "chio_treaty_missing_bilateral_evidence",
                "chio_treaty_bilateral_hash_mismatch",
            )
        })
        .transpose()?;
    let bilateral_dsse = treaty_ref
        .bilateral_dsse
        .as_ref()
        .map(|reference| {
            load_treaty_artifact::<_, chio_federation::bilateral_dsse::DsseEnvelope>(
                store,
                "bilateral_dsse_envelope",
                reference,
                "chio_treaty_missing_bilateral_evidence",
                "chio_treaty_bilateral_hash_mismatch",
            )
        })
        .transpose()?;

    let mut present_evidence = Vec::new();
    let mut verified_evidence = Vec::new();
    let mut bilateral_invocation_sha256 = None;
    if let Some((continuation, continuation_sha256)) = continuation.as_ref() {
        verify_continuation_evidence(
            continuation,
            &treaty_scope,
            &bundle.binding,
            &treaty_ref.action_class_id,
            now_unix_ms,
        )?;
        if let Some((lineage_bundle, _lineage_bundle_sha256)) = lineage_bundle.as_ref() {
            let lineage_statement_sha256 =
                verify_lineage_bundle_evidence(lineage_bundle, continuation, continuation_sha256)?;
            present_evidence.push("receipt_lineage".to_string());
            verified_evidence.push(CrossBoundaryEvidenceRef {
                evidence_class: "receipt_lineage".to_string(),
                artifact_sha256: lineage_statement_sha256,
                verified: true,
            });
        }
        if let Some((invocation, _invocation_sha256)) = bilateral_invocation.as_ref() {
            let consistency_model = action
                .map(|action| action.consistency_model.as_str())
                .unwrap_or("totally-ordered");
            let treaty_evidence = TreatyEvidenceReview {
                treaty_scope: &treaty_scope,
                bundle: &bundle,
                request: &bundle.binding,
                action_class_id: &treaty_ref.action_class_id,
                ladder_intersection_sha256: &treaty_ref.ladder_intersection_sha256,
                consistency_model,
                continuation_sha256,
            };
            let invocation_binding_sha256 = verify_bilateral_invocation_evidence(
                invocation,
                &treaty_evidence,
                lineage_bundle.as_ref().map(|(bundle, _)| bundle),
            )?;
            present_evidence.push("bilateral_invocation".to_string());
            bilateral_invocation_sha256 = Some(invocation_binding_sha256);
        }
        if let Some((envelope, envelope_sha256)) = bilateral_dsse.as_ref() {
            let treaty_evidence = TreatyEvidenceReview {
                treaty_scope: &treaty_scope,
                bundle: &bundle,
                request: &bundle.binding,
                action_class_id: &treaty_ref.action_class_id,
                ladder_intersection_sha256: &treaty_ref.ladder_intersection_sha256,
                consistency_model: action
                    .map(|action| action.consistency_model.as_str())
                    .unwrap_or("totally-ordered"),
                continuation_sha256,
            };
            verify_treaty_dsse_evidence(
                envelope,
                &treaty_evidence,
                lineage_bundle.as_ref(),
                bilateral_invocation
                    .as_ref()
                    .map(|(invocation, _)| invocation),
            )?;
            if let Some(invocation_sha256) = bilateral_invocation_sha256.as_ref() {
                verified_evidence.push(CrossBoundaryEvidenceRef {
                    evidence_class: "bilateral_invocation".to_string(),
                    artifact_sha256: invocation_sha256.clone(),
                    verified: true,
                });
            }
            present_evidence.push("bilateral_dsse".to_string());
            verified_evidence.push(CrossBoundaryEvidenceRef {
                evidence_class: "bilateral_dsse".to_string(),
                artifact_sha256: envelope_sha256.clone(),
                verified: true,
            });
        }
    } else if requires_lineage
        || requires_bilateral
        || treaty_ref.lineage_bundle.is_some()
        || treaty_ref.bilateral_invocation.is_some()
        || treaty_ref.bilateral_dsse.is_some()
    {
        return rejected(
            "chio_treaty_missing_continuation",
            "cross-boundary request did not reference a stored continuation",
        );
    }

    let report = evaluate_cross_boundary_admission(CrossBoundaryAdmissionInput {
        treaty_scope: &treaty_scope,
        ladder_intersection: &ladder_intersection,
        expected_ladder_intersection_sha256: Some(treaty_ref.ladder_intersection_sha256.clone()),
        action_class_id: &treaty_ref.action_class_id,
        present_evidence,
        verified_evidence,
        now_unix_ms,
    })?;
    if report.accepted {
        let federation_treaty_dsse = bilateral_dsse
            .as_ref()
            .map(|(envelope, _)| federation_treaty_dsse_metadata(envelope, &report))
            .transpose()?;
        Ok(VerifiedTreatyReference {
            continuation_id: continuation
                .as_ref()
                .map(|(continuation, _)| continuation.continuation_id.clone()),
            federation_treaty_dsse,
        })
    } else {
        rejected(
            static_treaty_failure_code(report.failure_code.as_deref()),
            "cross-boundary treaty admission rejected",
        )
    }
}

fn federation_treaty_dsse_metadata(
    envelope: &chio_federation::bilateral_dsse::DsseEnvelope,
    report: &CrossBoundaryAdmissionReport,
) -> Result<serde_json::Value, ChioRuntimeError> {
    let (statement, _) = envelope
        .decode_statement()
        .map_err(|_| ChioRuntimeError::Rejected {
            code: "chio_treaty_unverified_required_evidence",
            detail: "bilateral DSSE evidence could not be decoded".to_string(),
        })?;
    let predicate = statement.predicate;
    let capability_lease_ref =
        predicate
            .capability_lease_ref
            .ok_or_else(|| ChioRuntimeError::Rejected {
                code: "chio_treaty_unverified_required_evidence",
                detail: "bilateral DSSE evidence is missing a capability lease ref".to_string(),
            })?;
    let policy_evaluation_summary =
        predicate
            .policy_evaluation_summary
            .ok_or_else(|| ChioRuntimeError::Rejected {
                code: "chio_treaty_unverified_required_evidence",
                detail: "bilateral DSSE evidence is missing a policy summary".to_string(),
            })?;
    let mut treaty_binding_ref =
        predicate
            .treaty_binding_ref
            .ok_or_else(|| ChioRuntimeError::Rejected {
                code: "chio_treaty_unverified_required_evidence",
                detail: "bilateral DSSE evidence is missing treaty binding refs".to_string(),
            })?;
    treaty_binding_ref.admission_report_sha256 = canonical_sha256(report)?;
    serde_json::to_value(serde_json::json!({
        "capability_lease_ref": capability_lease_ref,
        "policy_evaluation_summary": policy_evaluation_summary,
        "governance_receipt_ref": predicate.governance_receipt_ref,
        "consistency_anchor": predicate.consistency_anchor,
        "consistency_model": predicate.consistency_model,
        "cross_org_visibility": predicate.cross_org_visibility,
        "treaty_binding_ref": treaty_binding_ref
    }))
    .map_err(|error| ChioRuntimeError::Json(error.to_string()))
}

fn verify_continuation_evidence(
    continuation: &CrossKernelContinuation,
    treaty_scope: &TreatyScope,
    request: &RuntimeRequestBinding,
    action_class_id: &str,
    now_unix_ms: u64,
) -> Result<(), ChioRuntimeError> {
    validate_cross_kernel_continuation(continuation)?;
    if now_unix_ms < continuation.issued_at_unix_ms
        || now_unix_ms >= continuation.expires_at_unix_ms
    {
        return rejected(
            "chio_treaty_continuation_stale",
            "cross-kernel continuation is outside its validity window",
        );
    }
    let audience = format!("{}.{}", request.server_id, request.tool_name);
    if continuation.capability_id != request.capability_id
        || continuation.action_class_id != action_class_id
        || continuation.target_kernel_id != request.host_kernel_id
        || request.origin_kernel_id.as_deref() != Some(continuation.source_kernel_id.as_str())
        || continuation.audience_tool != audience
        || !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|participant| participant == &continuation.source_kernel_id)
        || !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|participant| participant == &continuation.target_kernel_id)
    {
        return rejected(
            "chio_treaty_continuation_mismatch",
            "cross-kernel continuation does not bind the requested treaty dispatch",
        );
    }
    Ok(())
}

fn verify_lineage_bundle_evidence(
    bundle: &ReceiptLineageBundle,
    continuation: &CrossKernelContinuation,
    continuation_sha256: &str,
) -> Result<String, ChioRuntimeError> {
    verify_receipt_lineage_bundle(bundle)?;
    for statement in &bundle.statements {
        if statement.continuation_sha256 == continuation_sha256
            && statement.source_kernel_id == continuation.source_kernel_id
            && statement.target_kernel_id == continuation.target_kernel_id
            && statement.parent_receipt_sha256 == continuation.parent_receipt_sha256
        {
            return receipt_lineage_statement_sha256(statement);
        }
    }
    rejected(
        "chio_treaty_lineage_mismatch",
        "receipt lineage bundle does not bind the referenced continuation",
    )
}

pub(super) struct TreatyEvidenceReview<'a> {
    pub(super) treaty_scope: &'a TreatyScope,
    pub(super) bundle: &'a RuntimeAdmissionBundle,
    pub(super) request: &'a RuntimeRequestBinding,
    pub(super) action_class_id: &'a str,
    pub(super) ladder_intersection_sha256: &'a str,
    pub(super) consistency_model: &'a str,
    pub(super) continuation_sha256: &'a str,
}

fn verify_bilateral_invocation_evidence(
    invocation: &BilateralInvocation,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&ReceiptLineageBundle>,
) -> Result<String, ChioRuntimeError> {
    validate_bilateral_invocation(invocation)?;
    let invocation_consistency_model =
        bilateral_dsse_consistency_model(&invocation.consistency_model)?;
    let expected_consistency_model = bilateral_dsse_consistency_model(review.consistency_model)?;
    if review.treaty_scope.participant_kernel_ids.len() != 2
        || invocation.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chio_treaty_bilateral_mismatch",
            "bilateral invocation requires exactly two treaty participants and signers",
        );
    }
    if invocation.treaty_id != review.treaty_scope.treaty_id
        || invocation.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || invocation.continuation_sha256 != review.continuation_sha256
        || invocation.action_class_id != review.action_class_id
        || invocation_consistency_model != expected_consistency_model
        || invocation.capability_id != review.request.capability_id
        || invocation.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chio_treaty_bilateral_mismatch",
            "bilateral invocation does not bind the requested treaty dispatch",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = invocation.signer_kernel_ids.iter().collect();
    if participants != signers {
        return rejected(
            "chio_treaty_bilateral_mismatch",
            "bilateral invocation signer set does not match treaty participants",
        );
    }
    let invocation_sha256 = bilateral_invocation_binding_sha256(invocation)?;
    if let Some(bundle) = lineage_bundle {
        if invocation.local_receipt_sha256 != bundle.root_receipt_sha256
            || invocation.remote_receipt_sha256 != bundle.leaf_receipt_sha256
            || !bundle.statements.iter().any(|statement| {
                statement.bilateral_invocation_sha256 == invocation_sha256
                    && receipt_lineage_statement_sha256(statement)
                        .is_ok_and(|hash| hash == invocation.lineage_statement_sha256)
            })
        {
            return rejected(
                "chio_treaty_bilateral_mismatch",
                "bilateral invocation does not bind the receipt lineage bundle",
            );
        }
    }
    Ok(invocation_sha256)
}
fn static_treaty_failure_code(code: Option<&str>) -> &'static str {
    match code {
        Some("chio_treaty_stale") => "chio_treaty_stale",
        Some("chio_treaty_intersection_mismatch") => "chio_treaty_intersection_mismatch",
        Some("chio_treaty_missing_intersection_binding") => {
            "chio_treaty_missing_intersection_binding"
        }
        Some("chio_treaty_action_class_not_allowed") => "chio_treaty_action_class_not_allowed",
        Some("chio_treaty_missing_required_evidence") => "chio_treaty_missing_required_evidence",
        Some("chio_treaty_unverified_required_evidence") => {
            "chio_treaty_unverified_required_evidence"
        }
        _ => "chio_treaty_unverified_required_evidence",
    }
}
