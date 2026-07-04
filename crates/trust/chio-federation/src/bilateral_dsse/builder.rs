use super::*;

/// DSSE Pre-Authentication Encoding (DSSE v1 spec, secure-systems-lab/dsse).
///
/// The output bytes are what each kernel's Ed25519 signature covers per spec
/// §6 lines 338-343. The encoding is deterministic and does NOT include any
/// kernel-derived nonce: two kernels signing the same `(payload_type,
/// payload_bytes)` produce signatures over identical preimages.
///
/// Format: `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` where SP is a
/// single ASCII space (0x20) and LEN values are decimal ASCII.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_len = payload_type.len().to_string();
    let payload_len = payload.len().to_string();
    let mut out = Vec::with_capacity(
        PAE_PREFIX.len()
            + 1
            + type_len.len()
            + 1
            + payload_type.len()
            + 1
            + payload_len.len()
            + 1
            + payload.len(),
    );
    out.extend_from_slice(PAE_PREFIX.as_bytes());
    out.push(b' ');
    out.extend_from_slice(type_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_len.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Canonical subject name for the signed Chio receipt body.
#[must_use]
pub fn receipt_subject_name(receipt_id: &str) -> String {
    format!("{RECEIPT_SUBJECT_NAME_PREFIX}{receipt_id}")
}

/// Build a `BilateralPredicate` from a receipt and the two participating
/// kernels' identities. Used by both the local sign path and the
/// in-process verifier under test.
pub fn build_predicate(
    receipt: &ChioReceipt,
    org_a: KernelIdentity,
    org_b: KernelIdentity,
    tool_name: &str,
    timestamp_unix_ms: u64,
) -> Result<BilateralPredicate, BilateralCoSigningError> {
    if receipt.tool_name != tool_name {
        return Err(BilateralCoSigningError::ReceiptMismatch);
    }
    let receipt_canonical = canonical_json_bytes(receipt)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let receipt_canonical_json = String::from_utf8(receipt_canonical)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    Ok(BilateralPredicate {
        schema: Some(PREDICATE_BODY_SCHEMA.to_string()),
        invocation_id: receipt.id.clone(),
        tool_server_a: org_a,
        tool_server_b: org_b,
        tool_name: tool_name.to_string(),
        co_sign: DEFAULT_COSIGN_MODE.to_string(),
        consistency_model: DEFAULT_CONSISTENCY_MODEL.to_string(),
        cross_org_visibility: DEFAULT_CROSS_ORG_VISIBILITY.to_string(),
        timestamp_unix_ms,
        tool_args_hash: None,
        receipt_canonical_json: Some(receipt_canonical_json),
        capability_lease_ref: None,
        policy_evaluation_summary: None,
        governance_receipt_ref: None,
        consistency_anchor: None,
        treaty_binding_ref: None,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BilateralPredicateExtensions {
    /// Spec §5 `capability_lease_ref`; required by §7 step 14.
    pub capability_lease_ref: Option<CapabilityLeaseRef>,
    /// Spec §5 `policy_evaluation_summary`; required by §7 step 13.
    pub policy_evaluation_summary: Option<PolicyEvaluationSummary>,
    /// Spec §5 `governance_receipt_ref`; required by §7 step 15 when
    /// the action-class is `receipt-backed`.
    pub governance_receipt_ref: Option<GovernanceReceiptRef>,
    /// Spec §5 `consistency_anchor`; required by §7 step 16 for
    /// non-`crdt-commutative` consistency models.
    pub consistency_anchor: Option<String>,
    /// Override `consistency_model`. None = `DEFAULT_CONSISTENCY_MODEL`
    /// (`crdt-commutative`).
    pub consistency_model: Option<String>,
    /// Override `cross_org_visibility`. None =
    /// `DEFAULT_CROSS_ORG_VISIBILITY` (`federated`).
    pub cross_org_visibility: Option<String>,
    /// Treaty-bound runtime evidence. Required by treaty-mode verifiers,
    /// optional for non-treaty strict Chio DSSE.
    pub treaty_binding_ref: Option<TreatyBindingRef>,
}

pub fn build_predicate_full(
    receipt: &ChioReceipt,
    org_a: KernelIdentity,
    org_b: KernelIdentity,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
) -> Result<BilateralPredicate, BilateralCoSigningError> {
    let mut predicate = build_predicate(receipt, org_a, org_b, tool_name, timestamp_unix_ms)?;
    if let Some(model) = extensions.consistency_model {
        predicate.consistency_model = model;
    }
    if let Some(vis) = extensions.cross_org_visibility {
        predicate.cross_org_visibility = vis;
    }
    predicate.capability_lease_ref = extensions.capability_lease_ref;
    predicate.policy_evaluation_summary = extensions.policy_evaluation_summary;
    predicate.governance_receipt_ref = extensions.governance_receipt_ref;
    predicate.consistency_anchor = extensions.consistency_anchor;
    predicate.treaty_binding_ref = extensions.treaty_binding_ref;
    Ok(predicate)
}

pub fn build_chio_bilateral_invocation_predicate(
    receipt: &ChioReceipt,
    org_a: KernelIdentity,
    org_b: KernelIdentity,
    tool_name: &str,
    timestamp_unix_ms: u64,
    extensions: BilateralPredicateExtensions,
) -> Result<BilateralPredicate, BilateralCoSigningError> {
    if receipt.tool_name != tool_name {
        return Err(BilateralCoSigningError::ReceiptMismatch);
    }
    if !receipt
        .action
        .verify_hash()
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?
    {
        return Err(BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: receipt action parameter_hash does not match parameters"
                .to_string(),
        ));
    }
    let capability_lease_ref = extensions.capability_lease_ref.ok_or_else(|| {
        BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: capability_lease_ref is required".to_string(),
        )
    })?;
    let policy_evaluation_summary = extensions.policy_evaluation_summary.ok_or_else(|| {
        BilateralCoSigningError::CanonicalJson(
            "predicate.schema_invalid: policy_evaluation_summary is required".to_string(),
        )
    })?;
    let governance_receipt_ref = extensions.governance_receipt_ref;
    if let Some(treaty) = extensions.treaty_binding_ref.as_ref() {
        validate_treaty_operational_refs(
            treaty,
            &capability_lease_ref,
            governance_receipt_ref.as_ref(),
            &org_a.kernel_id,
            &org_b.kernel_id,
        )?;
        validate_treaty_receipt_refs(treaty, receipt)?;
    }
    Ok(BilateralPredicate {
        schema: None,
        invocation_id: receipt.id.clone(),
        tool_server_a: org_a,
        tool_server_b: org_b,
        tool_name: tool_name.to_string(),
        co_sign: DEFAULT_COSIGN_MODE.to_string(),
        consistency_model: extensions
            .consistency_model
            .unwrap_or_else(|| DEFAULT_CONSISTENCY_MODEL.to_string()),
        cross_org_visibility: extensions
            .cross_org_visibility
            .unwrap_or_else(|| DEFAULT_CROSS_ORG_VISIBILITY.to_string()),
        timestamp_unix_ms,
        tool_args_hash: Some(HashRecord {
            alg: "sha256".to_string(),
            value: receipt.action.parameter_hash.clone(),
        }),
        receipt_canonical_json: None,
        capability_lease_ref: Some(capability_lease_ref),
        policy_evaluation_summary: Some(policy_evaluation_summary),
        governance_receipt_ref,
        consistency_anchor: extensions.consistency_anchor,
        treaty_binding_ref: extensions.treaty_binding_ref,
    })
}

/// Build the in-toto Statement carrying the bilateral predicate.
///
/// The subject digest binds the receipt BODY (`ChioReceiptBody`), not
/// the full signed wrapper. Hashing the full `ChioReceipt` (including
/// the envelope's `signature` field) would make the verifier's
/// "resolve the receipt from a store and re-derive the subject" path
/// produce a different digest than the producer signed, breaking
/// cross-impl resolution. Hashing the body lets verifiers re-derive
/// the subject from any source that exposes the body (the receipt
/// store's signed wrapper, a receipt log, or a peer's re-emission).
pub fn build_statement(
    receipt: &ChioReceipt,
    predicate: BilateralPredicate,
) -> Result<DsseStatement, BilateralCoSigningError> {
    let body = receipt.body();
    let body_canonical = canonical_json_bytes(&body)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&body_canonical);
    let digest_hex = hex::encode(hasher.finalize());
    Ok(DsseStatement {
        statement_type: STATEMENT_TYPE_V1.to_string(),
        subject: vec![StatementSubject {
            name: receipt_subject_name(&receipt.id),
            digest: SubjectDigest { sha256: digest_hex },
        }],
        predicate_type: PREDICATE_TYPE_BILATERAL.to_string(),
        predicate,
    })
}

pub fn build_chio_bilateral_invocation_statement(
    receipt: &ChioReceipt,
    predicate: BilateralPredicate,
) -> Result<DsseStatement, BilateralCoSigningError> {
    let body = receipt.body();
    let body_canonical = canonical_json_bytes(&body)
        .map_err(|e| BilateralCoSigningError::CanonicalJson(e.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(&body_canonical);
    let digest_hex = hex::encode(hasher.finalize());
    Ok(DsseStatement {
        statement_type: STATEMENT_TYPE_V1.to_string(),
        subject: vec![StatementSubject {
            name: receipt_subject_name(&receipt.id),
            digest: SubjectDigest { sha256: digest_hex },
        }],
        predicate_type: PREDICATE_TYPE_CHIO_BILATERAL_INVOCATION.to_string(),
        predicate,
    })
}
