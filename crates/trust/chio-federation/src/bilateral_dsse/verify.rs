use super::*;

/// Verify a DSSE signature-slice envelope. Returns the parsed Statement on
/// success so callers can drive subsequent checks (peer pinning, lease
/// resolution, anchor reconciliation) against a single decoded payload.
///
/// 1. Payload base64-decodes (`dsse.malformed`).
/// 2. Statement is parseable canonical JSON (`statement.malformed`).
/// 3. `payload_type == PAYLOAD_TYPE_IN_TOTO` (PAE preimage shape).
/// 4. `predicate_type` is `PREDICATE_TYPE_BILATERAL`.
/// 5. `signatures` carries exactly two entries. Their array order is not
///    security-relevant; signatures are matched by `keyid`.
/// 6. Each required `keyid` matches the SHA-256 of the corresponding
///    public key the verifier was given (`peer.unpinned_or_keyid_mismatch`).
/// 7. Each signature, base64-decoded, is a valid Ed25519 signature over
///    the recomputed DSSE PAE bytes (`signature.server_*_invalid`).
pub fn verify_dsse_envelope(
    envelope: &DsseEnvelope,
    org_a_public_key: &PublicKey,
    org_b_public_key: &PublicKey,
) -> Result<DsseStatement, BilateralCoSigningError> {
    if envelope.payload_type != PAYLOAD_TYPE_IN_TOTO {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: payloadType '{}' is not '{}'",
            envelope.payload_type, PAYLOAD_TYPE_IN_TOTO
        )));
    }
    if envelope.signatures.len() != 2 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: expected exactly 2 signatures, got {}",
            envelope.signatures.len()
        )));
    }

    let (statement, statement_bytes) = envelope.decode_statement()?;
    let canonical_statement_bytes = statement.canonical_bytes()?;
    if canonical_statement_bytes != statement_bytes {
        return Err(BilateralCoSigningError::CanonicalJson(
            "statement.malformed: payload is not canonical JSON".to_string(),
        ));
    }

    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.schema_invalid: _type '{}' is not '{}'",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_BILATERAL {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.type_unrecognised: '{}'",
            statement.predicate_type
        )));
    }
    validate_signature_slice_predicate(&statement.predicate)?;

    // Single-subject invariant: the bilateral envelope profile
    // binds exactly ONE subject (the receipt body). Rejecting only the
    // empty-list case is fail-OPEN: a signer could insert an arbitrary
    // second subject digest and verifiers that walked the full subject
    // list (the spec-conformant behavior for in-toto subject membership)
    // would resolve a different receipt than the producer signed.
    if statement.subject.len() != 1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }
    let expected_subject_name = receipt_subject_name(&statement.predicate.invocation_id);
    if statement.subject[0].name != expected_subject_name {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.malformed: subject name '{}' is not canonical receipt subject '{}'",
            statement.subject[0].name, expected_subject_name
        )));
    }

    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_keyid = Keyid::from_public_key(org_b_public_key);

    // Bind verified keyids to the predicate's declared
    // `passport_key_fingerprint` for both tool servers. Without this
    // check, a signer could produce a validly signed envelope whose
    // predicate names different passport fingerprints, and downstream
    // peer-pinning and verification steps would act on identities that were
    // never verified.
    if statement.predicate.tool_server_a.passport_key_fingerprint != org_a_keyid {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if statement.predicate.tool_server_b.passport_key_fingerprint != org_b_keyid {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    if org_a_keyid == org_b_keyid {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    let embedded_receipt = decode_embedded_receipt(&statement.predicate)?;
    if embedded_receipt.id != statement.predicate.invocation_id {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: invocation_id {:?} does not match embedded receipt id {:?}",
            statement.predicate.invocation_id, embedded_receipt.id
        )));
    }
    if embedded_receipt.tool_name != statement.predicate.tool_name {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: tool_name {:?} does not match embedded receipt tool_name {:?}",
            statement.predicate.tool_name, embedded_receipt.tool_name
        )));
    }
    if embedded_receipt.kernel_key != *org_b_public_key {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    let receipt_signature_valid = embedded_receipt
        .verify_signature()
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    if !receipt_signature_valid {
        return Err(BilateralCoSigningError::ReceiptMismatch);
    }
    let embedded_receipt_digest = receipt_body_digest_hex(&embedded_receipt)?;
    if statement.subject[0].digest.sha256 != embedded_receipt_digest {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "subject.digest_mismatch: subject digest {} != sha256(canonical_json(embedded_receipt.body())) {}",
            statement.subject[0].digest.sha256, embedded_receipt_digest
        )));
    }
    if let Some(treaty) = statement.predicate.treaty_binding_ref.as_ref() {
        validate_treaty_receipt_refs(treaty, &embedded_receipt)?;
    }

    let pae_bytes = pae(&envelope.payload_type, &statement_bytes);

    let sig_a = signature_for_keyid(&envelope.signatures, org_a_keyid.as_str())
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b = signature_for_keyid(&envelope.signatures, org_b_keyid.as_str())
        .ok_or(BilateralCoSigningError::OrgBSignatureInvalid)?;

    let sig_a_bytes = decode_ed25519_signature(&sig_a.sig)
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b_bytes = decode_ed25519_signature(&sig_b.sig)
        .ok_or(BilateralCoSigningError::OrgBSignatureInvalid)?;

    let sig_a_struct = Signature::from_bytes(&sig_a_bytes);
    let sig_b_struct = Signature::from_bytes(&sig_b_bytes);

    // Spec §7 step 11.
    if !org_a_public_key.verify(&pae_bytes, &sig_a_struct) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    // Spec §7 step 12.
    if !org_b_public_key.verify(&pae_bytes, &sig_b_struct) {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    Ok(statement)
}

/// Verify a strict Chio bilateral invocation DSSE envelope.
pub fn verify_chio_bilateral_dsse_envelope(
    envelope: &DsseEnvelope,
    org_a_public_key: &PublicKey,
    org_b_public_key: &PublicKey,
) -> Result<DsseStatement, BilateralCoSigningError> {
    if envelope.payload_type != PAYLOAD_TYPE_IN_TOTO {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: payloadType '{}' is not '{}'",
            envelope.payload_type, PAYLOAD_TYPE_IN_TOTO
        )));
    }
    if envelope.signatures.len() != 2 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "dsse.malformed: expected exactly 2 signatures, got {}",
            envelope.signatures.len()
        )));
    }

    let (statement, statement_bytes) = envelope.decode_statement()?;
    let canonical_statement_bytes = statement.canonical_bytes()?;
    if canonical_statement_bytes != statement_bytes {
        return Err(BilateralCoSigningError::CanonicalJson(
            "statement.malformed: payload is not canonical JSON".to_string(),
        ));
    }

    if statement.statement_type != STATEMENT_TYPE_V1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.schema_invalid: _type '{}' is not '{}'",
            statement.statement_type, STATEMENT_TYPE_V1
        )));
    }
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.type_unrecognised: signature-slice profile '{}' is not strict Chio '{}'",
            statement.predicate_type, PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION
        )));
    }
    validate_chio_predicate(&statement.predicate)?;

    if statement.subject.len() != 1 {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.malformed: bilateral envelope must carry exactly 1 subject, got {}",
            statement.subject.len()
        )));
    }
    let expected_subject_name = receipt_subject_name(&statement.predicate.invocation_id);
    if statement.subject[0].name != expected_subject_name {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "statement.malformed: subject name '{}' is not canonical receipt subject '{}'",
            statement.subject[0].name, expected_subject_name
        )));
    }

    let org_a_keyid = Keyid::from_public_key(org_a_public_key);
    let org_b_keyid = Keyid::from_public_key(org_b_public_key);
    if org_a_public_key == org_b_public_key || org_a_keyid == org_b_keyid {
        return Err(BilateralCoSigningError::CanonicalJson(
            "strict Chio requires independent Org A and Org B signer keys".to_string(),
        ));
    }
    require_unique_signature_keyids(&envelope.signatures)?;
    if statement.predicate.tool_server_a.passport_key_fingerprint != org_a_keyid {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if statement.predicate.tool_server_b.passport_key_fingerprint != org_b_keyid {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    let pae_bytes = pae(&envelope.payload_type, &statement_bytes);
    let sig_a = signature_for_keyid(&envelope.signatures, org_a_keyid.as_str())
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b = signature_for_keyid(&envelope.signatures, org_b_keyid.as_str())
        .ok_or(BilateralCoSigningError::OrgBSignatureInvalid)?;
    let sig_a_bytes = decode_ed25519_signature(&sig_a.sig)
        .ok_or(BilateralCoSigningError::OrgASignatureInvalid)?;
    let sig_b_bytes = decode_ed25519_signature(&sig_b.sig)
        .ok_or(BilateralCoSigningError::OrgBSignatureInvalid)?;
    let sig_a_struct = Signature::from_bytes(&sig_a_bytes);
    let sig_b_struct = Signature::from_bytes(&sig_b_bytes);
    if !org_a_public_key.verify(&pae_bytes, &sig_a_struct) {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if !org_b_public_key.verify(&pae_bytes, &sig_b_struct) {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }

    Ok(statement)
}

fn validate_signature_slice_predicate(
    pred: &BilateralPredicate,
) -> Result<(), BilateralCoSigningError> {
    if pred.schema.as_deref() != Some(PREDICATE_BODY_SCHEMA) {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: schema {:?} is not {:?}",
            pred.schema, PREDICATE_BODY_SCHEMA
        )));
    }
    if pred.tool_args_hash.is_some() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: tool_args_hash is not part of the signature-slice profile"
                .to_string(),
        ));
    }
    if pred.treaty_binding_ref.is_some() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref is not part of the signature-slice profile"
                .to_string(),
        ));
    }
    if pred.receipt_canonical_json.is_none() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: receipt_canonical_json is required".to_string(),
        ));
    }
    require_non_empty_schema_string("invocation_id", &pred.invocation_id)?;
    require_non_empty_schema_string("tool_name", &pred.tool_name)?;
    require_non_empty_schema_string("tool_server_a.kernel_id", &pred.tool_server_a.kernel_id)?;
    require_non_empty_schema_string("tool_server_b.kernel_id", &pred.tool_server_b.kernel_id)?;
    if pred.tool_server_a.alg != "ed25519" {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if pred.tool_server_b.alg != "ed25519" {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    if !is_sha256_hex(pred.tool_server_a.passport_key_fingerprint.as_str())
        || !is_sha256_hex(pred.tool_server_b.passport_key_fingerprint.as_str())
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: passport_key_fingerprint is not 64 lowercase hex"
                .to_string(),
        ));
    }
    match pred.co_sign.as_str() {
        "bilateral_required" | "bilateral_if_cross_org" => {}
        _ => {
            return Err(BilateralCoSigningError::CanonicalJson(format!(
                "predicate.schema_invalid: co_sign {:?} is not supported",
                pred.co_sign
            )))
        }
    }
    if pred.consistency_model != DEFAULT_CONSISTENCY_MODEL {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: consistency_model {:?} is not supported by the signature-slice profile",
            pred.consistency_model
        )));
    }
    if !VALID_CROSS_ORG_VISIBILITY.contains(&pred.cross_org_visibility.as_str()) {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: cross_org_visibility {:?} is unsupported",
            pred.cross_org_visibility
        )));
    }
    if let Some(treaty) = pred.treaty_binding_ref.as_ref() {
        validate_treaty_binding_ref(treaty)?;
        let capability_lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
            BilateralCoSigningError::CanonicalJson(
                "predicate.schema_invalid: treaty_binding_ref requires capability_lease_ref"
                    .to_string(),
            )
        })?;
        validate_treaty_operational_refs(
            treaty,
            capability_lease_ref,
            pred.governance_receipt_ref.as_ref(),
            &pred.tool_server_a.kernel_id,
            &pred.tool_server_b.kernel_id,
        )?;
        if pred.tool_args_hash.as_ref().map(|hash| hash.value.as_str())
            != Some(treaty.request_sha256.as_str())
        {
            return Err(BilateralCoSigningError::CanonicalJson(
                "predicate.schema_invalid: treaty_binding_ref.request_sha256 must match tool_args_hash"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_treaty_binding_ref(treaty: &TreatyBindingRef) -> Result<(), BilateralCoSigningError> {
    require_non_empty_schema_string("treaty_binding_ref.treaty_id", &treaty.treaty_id)?;
    require_non_empty_schema_string(
        "treaty_binding_ref.action_class_id",
        &treaty.action_class_id,
    )?;
    require_non_empty_schema_string(
        "treaty_binding_ref.consistency_model",
        &treaty.consistency_model,
    )?;
    for (field, value) in [
        (
            "treaty_binding_ref.treaty_scope_sha256",
            &treaty.treaty_scope_sha256,
        ),
        (
            "treaty_binding_ref.ladder_intersection_sha256",
            &treaty.ladder_intersection_sha256,
        ),
        (
            "treaty_binding_ref.admission_report_sha256",
            &treaty.admission_report_sha256,
        ),
        (
            "treaty_binding_ref.continuation_sha256",
            &treaty.continuation_sha256,
        ),
        (
            "treaty_binding_ref.lineage_bundle_sha256",
            &treaty.lineage_bundle_sha256,
        ),
        ("treaty_binding_ref.request_sha256", &treaty.request_sha256),
        ("treaty_binding_ref.outcome_sha256", &treaty.outcome_sha256),
        (
            "treaty_binding_ref.local_receipt_sha256",
            &treaty.local_receipt_sha256,
        ),
        (
            "treaty_binding_ref.remote_receipt_sha256",
            &treaty.remote_receipt_sha256,
        ),
    ] {
        if !is_sha256_hex(value) {
            return Err(BilateralCoSigningError::CanonicalJson(format!(
                "predicate.schema_invalid: {field} must be 64 lowercase hex"
            )));
        }
    }
    if treaty.signer_kernel_ids.len() != 2
        || treaty.signer_kernel_ids[0] == treaty.signer_kernel_ids[1]
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref.signer_kernel_ids must contain two independent kernels"
                .to_string(),
        ));
    }
    if treaty.lease_refs.is_empty() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref lease_refs must be non-empty".to_string(),
        ));
    }
    if treaty
        .lease_refs
        .iter()
        .any(|value| value.trim().is_empty())
        || treaty
            .governance_refs
            .iter()
            .any(|value| value.trim().is_empty())
        || treaty
            .signer_kernel_ids
            .iter()
            .any(|value| value.trim().is_empty())
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref contains an empty ref".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_treaty_operational_refs(
    treaty: &TreatyBindingRef,
    capability_lease_ref: &CapabilityLeaseRef,
    governance_receipt_ref: Option<&GovernanceReceiptRef>,
    signer_a_kernel_id: &str,
    signer_b_kernel_id: &str,
) -> Result<(), BilateralCoSigningError> {
    if treaty.lease_refs != [capability_lease_ref.lease_id.clone()] {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref.lease_refs must match capability_lease_ref"
                .to_string(),
        ));
    }
    match governance_receipt_ref {
        Some(governance_receipt_ref) => {
            if treaty.governance_refs != [governance_receipt_ref.receipt_id.clone()] {
                return Err(BilateralCoSigningError::CanonicalJson(
                    "predicate.schema_invalid: treaty_binding_ref.governance_refs must match governance_receipt_ref"
                        .to_string(),
                ));
            }
        }
        None => {
            if !treaty.governance_refs.is_empty() {
                return Err(BilateralCoSigningError::CanonicalJson(
                    "predicate.schema_invalid: treaty_binding_ref.governance_refs must be empty when governance_receipt_ref is absent"
                        .to_string(),
                ));
            }
        }
    }
    if treaty.signer_kernel_ids
        != [
            signer_a_kernel_id.to_string(),
            signer_b_kernel_id.to_string(),
        ]
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref.signer_kernel_ids must match signer kernels"
                .to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_treaty_receipt_refs(
    treaty: &TreatyBindingRef,
    receipt: &ChioReceipt,
) -> Result<(), BilateralCoSigningError> {
    if treaty.outcome_sha256 != receipt.content_hash {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref.outcome_sha256 must match receipt content_hash"
                .to_string(),
        ));
    }
    let receipt_sha256 = receipt_canonical_digest_hex(receipt)?;
    if treaty.remote_receipt_sha256 != receipt_sha256 {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: treaty_binding_ref.remote_receipt_sha256 must match canonical receipt hash"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_chio_predicate(pred: &BilateralPredicate) -> Result<(), BilateralCoSigningError> {
    if pred.schema.is_some() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: schema must be absent from strict Chio predicates"
                .to_string(),
        ));
    }
    if pred.receipt_canonical_json.is_some() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: receipt_canonical_json must be absent from strict Chio predicates"
                .to_string(),
        ));
    }
    require_non_empty_schema_string("invocation_id", &pred.invocation_id)?;
    require_non_empty_schema_string("tool_name", &pred.tool_name)?;
    require_non_empty_schema_string("tool_server_a.kernel_id", &pred.tool_server_a.kernel_id)?;
    require_non_empty_schema_string("tool_server_b.kernel_id", &pred.tool_server_b.kernel_id)?;
    if pred.tool_server_a.alg != "ed25519" {
        return Err(BilateralCoSigningError::OrgASignatureInvalid);
    }
    if pred.tool_server_b.alg != "ed25519" {
        return Err(BilateralCoSigningError::OrgBSignatureInvalid);
    }
    if !is_sha256_hex(pred.tool_server_a.passport_key_fingerprint.as_str())
        || !is_sha256_hex(pred.tool_server_b.passport_key_fingerprint.as_str())
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: passport_key_fingerprint is not 64 lowercase hex"
                .to_string(),
        ));
    }
    let tool_args_hash = pred.tool_args_hash.as_ref().ok_or_else(|| {
        BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: tool_args_hash is required".to_string(),
        )
    })?;
    validate_hash_record(tool_args_hash, "tool_args_hash")?;
    if pred.capability_lease_ref.is_none() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: capability_lease_ref is required".to_string(),
        ));
    }
    if pred.policy_evaluation_summary.is_none() {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: policy_evaluation_summary is required".to_string(),
        ));
    }
    validate_policy_evaluation_summary(pred.policy_evaluation_summary.as_ref().ok_or_else(
        || {
            BilateralCoSigningError::CanonicalJson(
                "predicate.schema_invalid: policy_evaluation_summary is required".to_string(),
            )
        },
    )?)?;
    match pred.co_sign.as_str() {
        "bilateral_required" | "bilateral_if_cross_org" => {}
        _ => {
            return Err(BilateralCoSigningError::CanonicalJson(format!(
                "predicate.schema_invalid: co_sign {:?} is not supported",
                pred.co_sign
            )))
        }
    }
    if !VALID_CROSS_ORG_VISIBILITY.contains(&pred.cross_org_visibility.as_str()) {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: cross_org_visibility {:?} is unsupported",
            pred.cross_org_visibility
        )));
    }
    if let Some(treaty) = pred.treaty_binding_ref.as_ref() {
        validate_treaty_binding_ref(treaty)?;
        let capability_lease_ref = pred.capability_lease_ref.as_ref().ok_or_else(|| {
            BilateralCoSigningError::CanonicalJson(
                "predicate.schema_invalid: treaty_binding_ref requires capability_lease_ref"
                    .to_string(),
            )
        })?;
        validate_treaty_operational_refs(
            treaty,
            capability_lease_ref,
            pred.governance_receipt_ref.as_ref(),
            &pred.tool_server_a.kernel_id,
            &pred.tool_server_b.kernel_id,
        )?;
        if tool_args_hash.value != treaty.request_sha256 {
            return Err(BilateralCoSigningError::CanonicalJson(
                "predicate.schema_invalid: treaty_binding_ref.request_sha256 must match tool_args_hash"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

fn require_non_empty_schema_string(
    field: &str,
    value: &str,
) -> Result<(), BilateralCoSigningError> {
    if value.is_empty() {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: {field} must be non-empty"
        )));
    }
    Ok(())
}

fn decode_embedded_receipt(
    pred: &BilateralPredicate,
) -> Result<ChioReceipt, BilateralCoSigningError> {
    let receipt_canonical_json = pred.receipt_canonical_json.as_ref().ok_or_else(|| {
        BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: receipt_canonical_json is required".to_string(),
        )
    })?;
    let receipt: ChioReceipt = serde_json::from_str(receipt_canonical_json)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(format!("receipt json: {e}")))?;
    let canonical = canonical_json_bytes(&receipt)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let canonical_json = String::from_utf8(canonical)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    if &canonical_json != receipt_canonical_json {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: receipt_canonical_json is not canonical".to_string(),
        ));
    }
    Ok(receipt)
}

fn validate_hash_record(record: &HashRecord, field: &str) -> Result<(), BilateralCoSigningError> {
    if record.alg != "sha256" {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: {field}.alg must be sha256"
        )));
    }
    if !is_sha256_hex(&record.value) {
        return Err(BilateralCoSigningError::CanonicalJson(format!(
            "predicate.schema_invalid: {field}.value must be 64 lowercase hex"
        )));
    }
    Ok(())
}

pub(super) fn receipt_body_digest_hex(
    receipt: &ChioReceipt,
) -> Result<String, BilateralCoSigningError> {
    let body = receipt.body();
    let body_canonical = canonical_json_bytes(&body)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&body_canonical);
    Ok(hex::encode(hasher.finalize()))
}

pub(super) fn receipt_canonical_digest_hex(
    receipt: &ChioReceipt,
) -> Result<String, BilateralCoSigningError> {
    let canonical = canonical_json_bytes(receipt)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn decode_ed25519_signature(b64: &str) -> Option<[u8; 64]> {
    let bytes = BASE64_STANDARD.decode(b64.as_bytes()).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn signature_for_keyid<'a>(
    signatures: &'a [DsseSignature],
    keyid: &str,
) -> Option<&'a DsseSignature> {
    signatures.iter().find(|signature| signature.keyid == keyid)
}

fn require_unique_signature_keyids(
    signatures: &[DsseSignature],
) -> Result<(), BilateralCoSigningError> {
    let mut seen = BTreeSet::new();
    for signature in signatures {
        if !seen.insert(signature.keyid.as_str()) {
            return Err(BilateralCoSigningError::CanonicalJson(format!(
                "dsse.malformed: duplicate signature keyid {}",
                signature.keyid
            )));
        }
    }
    Ok(())
}
