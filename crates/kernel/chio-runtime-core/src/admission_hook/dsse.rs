use std::collections::BTreeSet;

use crate::*;

use super::treaty_evidence::TreatyEvidenceReview;

pub(super) fn verify_treaty_dsse_evidence(
    envelope: &chio_federation::bilateral_dsse::DsseEnvelope,
    review: &TreatyEvidenceReview<'_>,
    lineage_bundle: Option<&(ReceiptLineageBundle, String)>,
    invocation: Option<&BilateralInvocation>,
) -> Result<(), ChioRuntimeError> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence could not be decoded",
        );
    };
    if statement.predicate_type
        != chio_federation::bilateral_dsse::PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
    {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is not a strict Chio predicate",
        );
    }
    let Some(policy_summary) = statement.predicate.policy_evaluation_summary.as_ref() else {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is missing policy evaluation summary",
        );
    };
    chio_federation::bilateral_dsse::validate_policy_evaluation_summary(policy_summary).map_err(
        |_| ChioRuntimeError::Rejected {
            code: "chio_treaty_unverified_required_evidence",
            detail: "bilateral DSSE policy evaluation summary is invalid".to_string(),
        },
    )?;
    if policy_summary.server_a_verdict.verdict != "allow" {
        return rejected(
            "chio_treaty_policy_denied",
            "bilateral DSSE policy evaluation summary is not allow",
        );
    }
    let Some(treaty) = statement.predicate.treaty_binding_ref.as_ref() else {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE evidence is missing treaty binding refs",
        );
    };
    let expected_consistency_model = bilateral_dsse_consistency_model(review.consistency_model)?;
    if treaty.treaty_id != review.treaty_scope.treaty_id
        || treaty.treaty_scope_sha256 != treaty_scope_sha256(review.treaty_scope)?
        || treaty.ladder_intersection_sha256 != review.ladder_intersection_sha256
        || treaty.continuation_sha256 != review.continuation_sha256
        || treaty.action_class_id != review.action_class_id
        || treaty.consistency_model != expected_consistency_model
        || treaty.request_sha256 != review.request.tool_args_sha256
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE treaty binding does not match the requested dispatch",
        );
    }
    if statement
        .predicate
        .tool_args_hash
        .as_ref()
        .map(|hash| hash.value.as_str())
        != Some(treaty.request_sha256.as_str())
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE tool argument hash does not match the treaty request binding",
        );
    }
    if treaty.lease_refs != review.bundle.lease_id.iter().cloned().collect::<Vec<_>>() {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE lease refs do not match the verifier-owned admission bundle",
        );
    }
    if treaty.governance_refs
        != review
            .bundle
            .governance_receipt_id
            .iter()
            .cloned()
            .collect::<Vec<_>>()
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE governance refs do not match the verifier-owned admission bundle",
        );
    }
    let participants: BTreeSet<_> = review.treaty_scope.participant_kernel_ids.iter().collect();
    let signers: BTreeSet<_> = treaty.signer_kernel_ids.iter().collect();
    if review.treaty_scope.participant_kernel_ids.len() != 2 || treaty.signer_kernel_ids.len() != 2
    {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE evidence requires exactly two treaty participants and signers",
        );
    }
    if participants != signers {
        return rejected(
            "chio_treaty_dsse_binding_mismatch",
            "bilateral DSSE signer set does not match treaty participants",
        );
    }
    let signer_a_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[0])?;
    let signer_b_public_key =
        treaty_participant_public_key(review.treaty_scope, &treaty.signer_kernel_ids[1])?;
    if signer_a_public_key == signer_b_public_key {
        return rejected(
            "chio_treaty_unverified_required_evidence",
            "bilateral DSSE signer public keys are not independent",
        );
    }
    chio_federation::bilateral_dsse::verify_chio_bilateral_dsse_envelope(
        envelope,
        signer_a_public_key,
        signer_b_public_key,
    )
    .map_err(|_| ChioRuntimeError::Rejected {
        code: "chio_treaty_unverified_required_evidence",
        detail: "bilateral DSSE signature verification failed".to_string(),
    })?;
    if let Some((bundle, bundle_sha256)) = lineage_bundle {
        if treaty.lineage_bundle_sha256 != bundle_sha256.as_str()
            || treaty.local_receipt_sha256 != bundle.root_receipt_sha256
            || treaty.remote_receipt_sha256 != bundle.leaf_receipt_sha256
        {
            return rejected(
                "chio_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match lineage bundle",
            );
        }
    }
    if let Some(invocation) = invocation {
        let invocation_consistency_model =
            bilateral_dsse_consistency_model(&invocation.consistency_model)?;
        if treaty.consistency_model != invocation_consistency_model
            || treaty.outcome_sha256 != invocation.outcome_sha256
            || treaty.local_receipt_sha256 != invocation.local_receipt_sha256
            || treaty.remote_receipt_sha256 != invocation.remote_receipt_sha256
            || treaty.signer_kernel_ids != invocation.signer_kernel_ids
        {
            return rejected(
                "chio_treaty_dsse_binding_mismatch",
                "bilateral DSSE treaty binding does not match bilateral invocation",
            );
        }
    }
    Ok(())
}

fn treaty_participant_public_key<'a>(
    treaty_scope: &'a TreatyScope,
    kernel_id: &str,
) -> Result<&'a PublicKey, ChioRuntimeError> {
    let Some(index) = treaty_scope
        .participant_kernel_ids
        .iter()
        .position(|participant| participant == kernel_id)
    else {
        return rejected(
            "chio_treaty_missing_participant",
            "treaty participant public key is missing",
        );
    };
    treaty_scope
        .participant_public_keys
        .get(index)
        .ok_or_else(|| ChioRuntimeError::Rejected {
            code: "chio_treaty_missing_participant",
            detail: "treaty participant public key is missing".to_string(),
        })
}
