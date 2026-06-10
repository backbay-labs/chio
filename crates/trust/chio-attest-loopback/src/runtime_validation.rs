use super::*;

pub(super) fn empty_disclosure_proof() -> SelectiveDisclosureProof {
    SelectiveDisclosureProof {
        schema: String::new(),
        projection_version: String::new(),
        subject_sha256_hex: String::new(),
        ciphersuite: String::new(),
        issuer_fingerprint: String::new(),
        issuer_public_key_hex: String::new(),
        message_count: 0,
        disclosed_indices: Vec::new(),
        disclosed: Vec::new(),
        proof_nonce_hex: String::new(),
        proof_bytes_hex: String::new(),
    }
}

pub(super) fn ensure_disclosure_subject_matches_workflow(
    package: &ChioProofPackage,
) -> Result<(), ChioPackageError> {
    let projection = project_workflow_receipt_body(&package.workflow_receipt.body())
        .map_err(|error| ChioPackageError::SelectiveDisclosure(error.to_string()))?;
    if package.selective_disclosure_proof.subject_sha256_hex != projection.subject_sha256_hex {
        return Err(ChioPackageError::SelectiveDisclosure(format!(
            "proof subject {} does not match workflow body {}",
            package.selective_disclosure_proof.subject_sha256_hex, projection.subject_sha256_hex
        )));
    }
    Ok(())
}

pub(super) fn validate_runtime_receipt_for_vendor(
    receipt: &ChioReceipt,
    vendor: &VendorFixture,
    vendor_key: &Keypair,
) -> Result<(), ChioPackageError> {
    if receipt.tool_server.as_str() != vendor.server_id {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} server {} does not match {}",
            receipt.id, receipt.tool_server, vendor.server_id
        )));
    }
    if receipt.tool_name.as_str() != vendor.tool_name {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} tool {} does not match {}",
            receipt.id, receipt.tool_name, vendor.tool_name
        )));
    }
    if receipt.capability_id.as_str() != vendor.lease_id {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} capability {} does not match {}",
            receipt.id, receipt.capability_id, vendor.lease_id
        )));
    }
    if !matches!(&receipt.decision, Some(Decision::Allow)) {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} was not an allow receipt",
            receipt.id
        )));
    }
    validate_runtime_receipt_action_payload(receipt, vendor)?;
    validate_runtime_receipt_metadata(receipt, vendor)?;
    let expected_public_key = vendor_key.public_key();
    if receipt.kernel_key != expected_public_key {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} key does not match {}",
            receipt.id, vendor.kernel_id
        )));
    }
    let verified = receipt
        .verify_signature()
        .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
    if !verified {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} signature is invalid",
            receipt.id
        )));
    }
    Ok(())
}

fn validate_runtime_receipt_action_payload(
    receipt: &ChioReceipt,
    vendor: &VendorFixture,
) -> Result<(), ChioPackageError> {
    let action_hash_valid = receipt
        .action
        .verify_hash()
        .map_err(|error| ChioPackageError::Inconsistent(error.to_string()))?;
    if !action_hash_valid {
        return Err(ChioPackageError::Inconsistent(format!(
            "runtime receipt {} action parameter hash is invalid",
            receipt.id
        )));
    }
    validate_json_string_field(
        &receipt.action.parameters,
        "workflowId",
        WORKFLOW_ID,
        "runtime receipt action payload",
    )?;
    validate_json_string_field(
        &receipt.action.parameters,
        "caseRef",
        CASE_REF,
        "runtime receipt action payload",
    )?;
    validate_json_string_field(
        &receipt.action.parameters,
        "tool",
        vendor.tool_name,
        "runtime receipt action payload",
    )
}

fn validate_runtime_receipt_metadata(
    receipt: &ChioReceipt,
    vendor: &VendorFixture,
) -> Result<(), ChioPackageError> {
    let metadata = receipt.metadata.as_ref().ok_or_else(|| {
        ChioPackageError::Inconsistent(format!(
            "runtime receipt {} is missing loopback metadata",
            receipt.id
        ))
    })?;
    validate_json_string_field(
        metadata,
        "workflow_id",
        WORKFLOW_ID,
        "runtime receipt metadata",
    )?;
    validate_json_string_field(
        metadata,
        "vendor_id",
        vendor.vendor_id,
        "runtime receipt metadata",
    )
}

fn validate_json_string_field(
    value: &serde_json::Value,
    field: &'static str,
    expected: &str,
    context: &str,
) -> Result<(), ChioPackageError> {
    match value.get(field).and_then(serde_json::Value::as_str) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(ChioPackageError::Inconsistent(format!(
            "{context} field {field} value {actual} does not match {expected}"
        ))),
        None => Err(ChioPackageError::Inconsistent(format!(
            "{context} field {field} is missing"
        ))),
    }
}

pub(super) struct RuntimeIssuedMaterialValidation<'a> {
    pub(super) index: usize,
    pub(super) vendor: &'a VendorFixture,
    pub(super) receipt: &'a ChioReceipt,
    pub(super) envelope: &'a DsseEnvelope,
    pub(super) step: &'a StepRecord,
    pub(super) expected_parent_sha256: Option<&'a str>,
    pub(super) lease: &'a SignedCapabilityLease,
    pub(super) governance_receipt: Option<&'a SignedGovernanceReceipt>,
}

pub(super) fn validate_runtime_artifact_for_issued_material(
    validation: RuntimeIssuedMaterialValidation<'_>,
) -> Result<(), ChioPackageError> {
    let RuntimeIssuedMaterialValidation {
        index,
        vendor,
        receipt,
        envelope,
        step,
        expected_parent_sha256,
        lease,
        governance_receipt,
    } = validation;

    if step.step_index != index {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step index {} does not match position {}",
            step.step_index, index
        )));
    }
    if step.tool_receipt_id.as_deref() != Some(receipt.id.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} does not reference receipt {}",
            index, receipt.id
        )));
    }
    if step.server_id.as_str() != receipt.tool_server.as_str()
        || step.server_id.as_str() != vendor.server_id
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} server does not match receipt and fixture",
            index
        )));
    }
    if step.tool_name.as_str() != receipt.tool_name.as_str()
        || step.tool_name.as_str() != vendor.tool_name
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} tool does not match receipt and fixture",
            index
        )));
    }
    if step.output_hash.as_deref() != Some(receipt.content_hash.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} output hash does not match receipt",
            index
        )));
    }
    if step.destructive.unwrap_or(false) != vendor.destructive {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} destructive flag does not match fixture",
            index
        )));
    }
    let envelope_sha256 = canonical_sha256(envelope)?;
    if step.bilateral_dsse_sha256.as_deref() != Some(envelope_sha256.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE hash does not match envelope",
            index
        )));
    }
    if step.parent_receipt_sha256.as_deref() != expected_parent_sha256 {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} parent hash does not match previous step",
            index
        )));
    }
    let expected_anchor = format!("chio:consistency:{WORKFLOW_ID}:{index}");
    if step.consistency_anchor.as_deref() != Some(expected_anchor.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} consistency anchor must be {}",
            index, expected_anchor
        )));
    }

    let (statement, _) = envelope
        .decode_statement()
        .map_err(|error| ChioPackageError::Federation(error.to_string()))?;
    if statement.predicate_type != PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION {
        return Err(ChioPackageError::Federation(format!(
            "runtime step {} DSSE predicate type {} is not strict Chio",
            index, statement.predicate_type
        )));
    }
    let predicate = &statement.predicate;
    if predicate.invocation_id.as_str() != receipt.id.as_str() {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE invocation does not match receipt",
            index
        )));
    }
    if predicate.tool_name.as_str() != receipt.tool_name.as_str() {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE tool does not match receipt",
            index
        )));
    }
    if predicate.tool_server_b.kernel_id.as_str() != vendor.kernel_id {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE peer kernel does not match fixture",
            index
        )));
    }
    if predicate
        .tool_args_hash
        .as_ref()
        .map(|hash| hash.value.as_str())
        != Some(receipt.action.parameter_hash.as_str())
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE args hash does not match receipt",
            index
        )));
    }
    if predicate.consistency_anchor.as_deref() != Some(expected_anchor.as_str()) {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE consistency anchor must be {}",
            index, expected_anchor
        )));
    }
    let lease_ref = predicate.capability_lease_ref.as_ref().ok_or_else(|| {
        ChioPackageError::Workflow(format!("runtime step {} DSSE has no lease ref", index))
    })?;
    if lease_ref.lease_id.as_str() != lease.body.lease_id.as_str()
        || lease_ref.issuer.as_str() != lease.body.issuer.as_str()
        || lease_ref.expires_at_unix_ms != lease.body.expires_at_unix_ms
        || lease_ref
            .scope_digest
            .as_ref()
            .map(|hash| hash.value.as_str())
            != Some(lease.body.scope_digest.as_str())
    {
        return Err(ChioPackageError::Workflow(format!(
            "runtime step {} DSSE lease ref does not match issued lease",
            index
        )));
    }

    match (
        governance_receipt,
        predicate.governance_receipt_ref.as_ref(),
    ) {
        (Some(receipt), Some(predicate_ref)) => {
            if step.governance_receipt_id.as_deref() != Some(receipt.body.receipt_id.as_str())
                || predicate_ref.receipt_id.as_str() != receipt.body.receipt_id.as_str()
            {
                return Err(ChioPackageError::Workflow(format!(
                    "runtime step {} governance ref does not match issued receipt",
                    index
                )));
            }
        }
        (None, None) if step.governance_receipt_id.is_none() => {}
        _ => {
            return Err(ChioPackageError::Workflow(format!(
                "runtime step {} governance material does not match issued receipt",
                index
            )));
        }
    }

    Ok(())
}
