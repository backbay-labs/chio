use super::error::map_bilateral_error;
use super::support::{is_sha256_hex, validate_hash_record};
use super::*;

// ---------------------------------------------------------------------------
// Partial local verifier (subset of spec §7 step list)
// ---------------------------------------------------------------------------

pub fn verify_treaty_bound_chio_bilateral_invocation(
    envelope: &DsseEnvelope,
    review: &TreatyBoundBilateralDsseReview<'_>,
) -> Result<DsseStatement, VerifierError> {
    if envelope.payload_type != PAYLOAD_TYPE_IN_TOTO {
        return Err(VerifierError::DsseMalformed(format!(
            "payloadType {:?} is not application/vnd.in-toto+json",
            envelope.payload_type
        )));
    }
    if envelope.signatures.len() != 2 {
        return Err(VerifierError::DsseMalformed(format!(
            "strict treaty DSSE expected exactly 2 signatures, got {}",
            envelope.signatures.len()
        )));
    }
    require_unique_review_signature_keyids(envelope)?;

    validate_treaty_binding_ref_for_review(review.expected_treaty_binding, "expected", true)?;

    let (statement, statement_bytes) = envelope.decode_statement().map_err(map_bilateral_error)?;
    let canonical_statement_bytes = statement.canonical_bytes().map_err(map_bilateral_error)?;
    if canonical_statement_bytes != statement_bytes {
        return Err(VerifierError::StatementMalformed(
            "strict treaty DSSE payload is not canonical JSON".to_string(),
        ));
    }
    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "_type {:?} is not {:?}",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(VerifierError::PredicateTypeUnrecognised(format!(
            "predicateType {:?} is not strict Chio {:?}",
            statement.predicate_type, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
        )));
    }
    if statement.subject.len() != 1 {
        return Err(VerifierError::StatementSchemaInvalid(format!(
            "strict treaty DSSE must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }
    let pred = &statement.predicate;
    let Some(treaty_binding) = pred.treaty_binding_ref.as_ref() else {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing treaty_binding_ref".to_string(),
        ));
    };
    validate_treaty_binding_ref_for_review(treaty_binding, "predicate", true)?;
    if !treaty_binding_refs_equal(treaty_binding, review.expected_treaty_binding) {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE treaty_binding_ref does not match expected buyer review binding"
                .to_string(),
        ));
    }
    validate_predicate_operational_refs_match_treaty(pred, treaty_binding)?;
    if pred.tool_server_a.kernel_id != review.expected_treaty_binding.signer_kernel_ids[0]
        || pred.tool_server_b.kernel_id != review.expected_treaty_binding.signer_kernel_ids[1]
    {
        return Err(VerifierError::PeerUnpinnedOrKeyidMismatch(
            "strict treaty DSSE predicate signer kernels do not match treaty binding".to_string(),
        ));
    }
    if pred.consistency_model != review.expected_treaty_binding.consistency_model {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE consistency model does not match treaty binding".to_string(),
        ));
    }
    if !is_sha256_hex(review.expected_subject_sha256) {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE expected subject digest is not a lowercase SHA-256".to_string(),
        ));
    }
    let subject = &statement.subject[0];
    if subject.name != review.expected_subject_name {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "strict treaty DSSE subject name {} != expected {}",
            subject.name, review.expected_subject_name
        )));
    }
    if subject.digest.sha256 != review.expected_subject_sha256 {
        return Err(VerifierError::SubjectDigestMismatch(format!(
            "strict treaty DSSE subject digest {} != expected {}",
            subject.digest.sha256, review.expected_subject_sha256
        )));
    }
    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing capability_lease_ref".to_string(),
        )
    })?;
    if lease_ref != review.expected_capability_lease_ref {
        return Err(VerifierError::CapabilityLeaseExpiredOrUnknown(
            "strict treaty DSSE capability_lease_ref does not match package lease".to_string(),
        ));
    }
    let governance_ref = pred.governance_receipt_ref.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing governance_receipt_ref".to_string(),
        )
    })?;
    if governance_ref != review.expected_governance_receipt_ref {
        return Err(VerifierError::GovernanceReceiptRequiredMissing(
            "strict treaty DSSE governance_receipt_ref does not match package governance receipt"
                .to_string(),
        ));
    }
    if review.expected_consistency_anchor.trim().is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE expected consistency anchor is empty".to_string(),
        ));
    }
    if pred.consistency_anchor.as_deref() != Some(review.expected_consistency_anchor) {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE consistency_anchor does not match runtime step evidence"
                .to_string(),
        ));
    }
    if matches!(
        pred.consistency_model.as_str(),
        "totally-ordered" | "quorum-required"
    ) && pred.consistency_anchor.as_deref().is_none_or(str::is_empty)
    {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE ordered consistency requires consistency_anchor".to_string(),
        ));
    }
    let summary = pred.policy_evaluation_summary.as_ref().ok_or_else(|| {
        VerifierError::PolicyVerdictDisagreement(
            "strict treaty DSSE missing policy_evaluation_summary".to_string(),
        )
    })?;
    require_policy_evaluation_allow_admission(summary).map_err(map_bilateral_error)?;

    let signer_a_id = &review.expected_treaty_binding.signer_kernel_ids[0];
    let signer_b_id = &review.expected_treaty_binding.signer_kernel_ids[1];
    let signer_a_public_key = review.signer_public_keys.get(signer_a_id).ok_or_else(|| {
        VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "strict treaty DSSE missing public key for signer {signer_a_id:?}"
        ))
    })?;
    let signer_b_public_key = review.signer_public_keys.get(signer_b_id).ok_or_else(|| {
        VerifierError::PeerUnpinnedOrKeyidMismatch(format!(
            "strict treaty DSSE missing public key for signer {signer_b_id:?}"
        ))
    })?;
    if signer_a_public_key == signer_b_public_key {
        return Err(VerifierError::DsseMalformed(
            "strict treaty DSSE signer keys must represent independent Org A and Org B passports"
                .to_string(),
        ));
    }
    verify_chio_bilateral_dsse_envelope(envelope, signer_a_public_key, signer_b_public_key)
        .map_err(map_bilateral_error)?;

    Ok(statement)
}

fn require_unique_review_signature_keyids(envelope: &DsseEnvelope) -> Result<(), VerifierError> {
    let mut seen = HashSet::new();
    for signature in &envelope.signatures {
        if signature.keyid.is_empty() {
            return Err(VerifierError::DsseMalformed(
                "strict treaty DSSE signature keyid must be non-empty".to_string(),
            ));
        }
        if !seen.insert(signature.keyid.as_str()) {
            return Err(VerifierError::DsseMalformed(format!(
                "strict treaty DSSE duplicate signature keyid {}",
                signature.keyid
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_treaty_binding_ref_for_review(
    treaty: &TreatyBindingRef,
    label: &str,
    require_operational_refs: bool,
) -> Result<(), VerifierError> {
    if treaty.treaty_id.is_empty()
        || treaty.action_class_id.is_empty()
        || treaty.consistency_model.is_empty()
    {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref treaty_id, action_class_id, and consistency_model must be non-empty"
        )));
    }
    for (field, value) in [
        ("treaty_scope_sha256", &treaty.treaty_scope_sha256),
        (
            "ladder_intersection_sha256",
            &treaty.ladder_intersection_sha256,
        ),
        ("admission_report_sha256", &treaty.admission_report_sha256),
        ("continuation_sha256", &treaty.continuation_sha256),
        ("lineage_bundle_sha256", &treaty.lineage_bundle_sha256),
        ("request_sha256", &treaty.request_sha256),
        ("outcome_sha256", &treaty.outcome_sha256),
        ("local_receipt_sha256", &treaty.local_receipt_sha256),
        ("remote_receipt_sha256", &treaty.remote_receipt_sha256),
    ] {
        if !is_sha256_hex(value) {
            return Err(VerifierError::PredicateSchemaInvalid(format!(
                "{label} treaty_binding_ref.{field} must be 64 lowercase hex"
            )));
        }
    }
    if treaty.signer_kernel_ids.len() != 2 {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref.signer_kernel_ids must contain exactly 2 signers"
        )));
    }
    if treaty
        .signer_kernel_ids
        .iter()
        .any(|signer| signer.is_empty())
    {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref.signer_kernel_ids must be non-empty"
        )));
    }
    if treaty.signer_kernel_ids[0] == treaty.signer_kernel_ids[1] {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref.signer_kernel_ids must be distinct"
        )));
    }
    if require_operational_refs && treaty.lease_refs.is_empty() {
        return Err(VerifierError::PredicateSchemaInvalid(format!(
            "{label} treaty_binding_ref lease_refs must be non-empty"
        )));
    }
    Ok(())
}

fn treaty_binding_refs_equal(left: &TreatyBindingRef, right: &TreatyBindingRef) -> bool {
    left.treaty_id == right.treaty_id
        && left.treaty_scope_sha256 == right.treaty_scope_sha256
        && left.ladder_intersection_sha256 == right.ladder_intersection_sha256
        && left.admission_report_sha256 == right.admission_report_sha256
        && left.continuation_sha256 == right.continuation_sha256
        && left.lineage_bundle_sha256 == right.lineage_bundle_sha256
        && left.action_class_id == right.action_class_id
        && left.consistency_model == right.consistency_model
        && left.request_sha256 == right.request_sha256
        && left.outcome_sha256 == right.outcome_sha256
        && left.local_receipt_sha256 == right.local_receipt_sha256
        && left.remote_receipt_sha256 == right.remote_receipt_sha256
        && left.lease_refs == right.lease_refs
        && left.governance_refs == right.governance_refs
        && left.signer_kernel_ids == right.signer_kernel_ids
}

pub(super) fn validate_predicate_operational_refs_match_treaty(
    pred: &BilateralPredicate,
    treaty: &TreatyBindingRef,
) -> Result<(), VerifierError> {
    let tool_args_hash = pred.tool_args_hash.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing tool_args_hash".to_string(),
        )
    })?;
    if treaty.request_sha256 != tool_args_hash.value {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE request_sha256 does not match tool_args_hash".to_string(),
        ));
    }
    if treaty.signer_kernel_ids
        != [
            pred.tool_server_a.kernel_id.clone(),
            pred.tool_server_b.kernel_id.clone(),
        ]
    {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE signer_kernel_ids do not match authenticated predicate kernels"
                .to_string(),
        ));
    }
    let lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
        VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE missing capability_lease_ref".to_string(),
        )
    })?;
    if treaty.lease_refs != [lease_ref.lease_id.clone()] {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE lease_refs do not match capability_lease_ref".to_string(),
        ));
    }
    match pred.governance_receipt_ref.as_ref() {
        Some(governance_ref) => {
            if treaty.governance_refs != [governance_ref.receipt_id.clone()] {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "strict treaty DSSE governance_refs do not match governance_receipt_ref"
                        .to_string(),
                ));
            }
        }
        None => {
            if !treaty.governance_refs.is_empty() {
                return Err(VerifierError::PredicateSchemaInvalid(
                    "strict treaty DSSE governance_refs must be empty when governance_receipt_ref is absent"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

pub(super) fn resolve_governance_receipt_ref(
    store: &dyn GovernanceReceiptStore,
    governance_ref: &GovernanceReceiptRef,
) -> Result<ResolvedGovernanceReceipt, VerifierError> {
    validate_hash_record(&governance_ref.digest, "governance_receipt_ref.digest")
        .map_err(VerifierError::GovernanceReceiptRequiredMissing)?;
    let resolved = store.resolve(&governance_ref.receipt_id).ok_or_else(|| {
        VerifierError::GovernanceReceiptRequiredMissing(format!(
            "receipt_id {:?} not resolvable in GovernanceReceiptStore",
            governance_ref.receipt_id
        ))
    })?;
    if resolved.kernel_id != governance_ref.kernel_id {
        return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
            "governance receipt kernel_id mismatch: store={:?} predicate={:?}",
            resolved.kernel_id, governance_ref.kernel_id
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(resolved.canonical_json.as_bytes());
    let want = hex::encode(hasher.finalize());
    if want != governance_ref.digest.value {
        return Err(VerifierError::GovernanceReceiptRequiredMissing(format!(
            "governance receipt digest mismatch: computed={} predicate={}",
            want, governance_ref.digest.value
        )));
    }
    Ok(resolved)
}

pub(super) fn validate_treaty_receipt_refs_match_resolved_receipt(
    treaty: &TreatyBindingRef,
    receipt: &ChioReceipt,
    receipt_sha256: &str,
) -> Result<(), VerifierError> {
    if treaty.outcome_sha256 != receipt.content_hash {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE outcome_sha256 does not match resolved receipt content_hash"
                .to_string(),
        ));
    }
    if treaty.remote_receipt_sha256 != receipt_sha256 {
        return Err(VerifierError::PredicateSchemaInvalid(
            "strict treaty DSSE remote_receipt_sha256 does not match resolved receipt hash"
                .to_string(),
        ));
    }
    Ok(())
}
