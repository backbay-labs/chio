use crate::treaty::{
    validate_bilateral_invocation, validate_cross_kernel_continuation,
    validate_receipt_lineage_bundle, validate_receipt_lineage_statement,
};
use crate::*;

const BUYER_REVIEW_REQUIRED_ROLES: &[&str] = &[
    "buyer_attestation_packet",
    "receipt_lineage_statement",
    "receipt_lineage_bundle",
    "cross_kernel_continuation",
    "cross_boundary_admission_report",
    "bilateral_invocation",
    "bilateral_dsse_envelope",
    "workflow_receipt",
    "proof_package",
    "verifier_report",
    "proof_regeneration_report",
    "runtime_run_report",
    "runtime_evidence_manifest",
    "proof_regeneration_input",
];

pub fn verify_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    continuation: &CrossKernelContinuation,
    admission: &CrossBoundaryAdmissionReport,
    bilateral: &BilateralInvocation,
) -> Result<BuyerAttestationVerificationReport, ChiodosRuntimeError> {
    validate_buyer_attestation_packet(packet)?;
    validate_receipt_lineage_statement(lineage)?;
    validate_cross_kernel_continuation(continuation)?;
    validate_cross_boundary_admission_report(admission)?;
    validate_bilateral_invocation(bilateral)?;
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(bilateral)?;
    let mut checks = vec!["chiodos_buyer.packet_valid".to_string()];
    if packet.settlement_claimed {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_settlement_claimed",
            checks,
        ));
    }
    if lineage.evidence_class != "verified" {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_lineage_not_verified",
            checks,
        ));
    }
    if packet.buyer_id != continuation.source_kernel_id
        || lineage.source_kernel_id != continuation.source_kernel_id
        || lineage.target_kernel_id != continuation.target_kernel_id
        || bilateral.signer_kernel_ids.len() != 2
        || bilateral.signer_kernel_ids.first() != Some(&continuation.source_kernel_id)
        || bilateral.signer_kernel_ids.get(1) != Some(&continuation.target_kernel_id)
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_identity_mismatch",
            checks,
        ));
    }
    if packet.capability_id != continuation.capability_id
        || bilateral.capability_id != continuation.capability_id
        || continuation.action_class_id != admission.action_class_id
        || bilateral.action_class_id != continuation.action_class_id
        || bilateral.treaty_id != admission.treaty_id
        || bilateral.consistency_model != admission.consistency_model
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_hash_mismatch",
            checks,
        ));
    }
    if receipt_lineage_statement_sha256(lineage)? != packet.receipt_lineage_statement_sha256
        || canonical_sha256(continuation)? != packet.continuation_sha256
        || canonical_sha256(admission)? != packet.cross_boundary_admission_report_sha256
        || bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || lineage.continuation_sha256 != packet.continuation_sha256
        || lineage.bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || bilateral.continuation_sha256 != packet.continuation_sha256
        || bilateral.lineage_statement_sha256 != packet.receipt_lineage_statement_sha256
        || bilateral.ladder_intersection_sha256 != packet.ladder_intersection_sha256
        || bilateral.local_receipt_sha256 != lineage.parent_receipt_sha256
        || bilateral.remote_receipt_sha256 != lineage.child_receipt_sha256
        || admission.treaty_scope_sha256 != packet.treaty_scope_sha256
        || admission.ladder_intersection_sha256 != packet.ladder_intersection_sha256
        || verified_evidence_missing_or_mismatch(
            admission,
            "receipt_lineage",
            &packet.receipt_lineage_statement_sha256,
        )
        || verified_evidence_missing_or_mismatch(
            admission,
            "bilateral_invocation",
            &packet.bilateral_invocation_sha256,
        )
        || !admission.accepted
    {
        return Ok(buyer_packet_rejection_report(
            packet,
            "chiodos_buyer_packet_hash_mismatch",
            checks,
        ));
    }
    checks.push("chiodos_buyer.lineage_verified".to_string());
    checks.push("chiodos_buyer.verification_state_hash_only".to_string());
    Ok(BuyerAttestationVerificationReport {
        schema: CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "hash_only".to_string(),
        accepted: true,
        failure_code: None,
        checks,
    })
}

fn verified_evidence_missing_or_mismatch(
    admission: &CrossBoundaryAdmissionReport,
    evidence_class: &str,
    artifact_sha256: &str,
) -> bool {
    let mut refs = admission
        .verified_evidence
        .iter()
        .filter(|evidence| evidence.evidence_class == evidence_class);
    let Some(evidence) = refs.next() else {
        return true;
    };
    refs.next().is_some() || evidence.artifact_sha256 != artifact_sha256 || !evidence.verified
}

pub fn verify_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
) -> Result<BuyerAttestationReviewReport, ChiodosRuntimeError> {
    verify_buyer_attestation_review_package_internal(package, sources, None)
}

pub fn verify_buyer_attestation_review_package_with_trust(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    trust_context: &BuyerAttestationReviewTrustContext<'_>,
) -> Result<BuyerAttestationReviewReport, ChiodosRuntimeError> {
    verify_buyer_attestation_review_package_internal(package, sources, Some(trust_context))
}

struct BuyerReviewHydratedArtifacts {
    packet: BuyerAttestationPacket,
    lineage: ReceiptLineageStatement,
    lineage_bundle: ReceiptLineageBundle,
    continuation: CrossKernelContinuation,
    admission: CrossBoundaryAdmissionReport,
    bilateral: BilateralInvocation,
    bilateral_dsse: chio_federation::DsseEnvelope,
    proof_package: serde_json::Value,
    workflow_receipt: serde_json::Value,
    verifier_report: serde_json::Value,
    proof_regeneration_report: RuntimeProofRegenerationReport,
    runtime_run_report: RuntimeWorkflowRunReport,
    runtime_evidence_manifest: RuntimeEvidenceManifest,
    proof_regeneration_input: RuntimeProofRegenerationInput,
}

impl BuyerReviewHydratedArtifacts {
    fn from_bound_sources(
        source_bytes_by_role: &BTreeMap<String, Vec<u8>>,
    ) -> Result<Self, ChiodosRuntimeError> {
        Ok(Self {
            packet: parse_review_json(source_bytes_by_role, "buyer_attestation_packet")?,
            lineage: parse_review_json(source_bytes_by_role, "receipt_lineage_statement")?,
            lineage_bundle: parse_review_json(source_bytes_by_role, "receipt_lineage_bundle")?,
            continuation: parse_review_json(source_bytes_by_role, "cross_kernel_continuation")?,
            admission: parse_review_json(source_bytes_by_role, "cross_boundary_admission_report")?,
            bilateral: parse_review_json(source_bytes_by_role, "bilateral_invocation")?,
            bilateral_dsse: parse_review_json(source_bytes_by_role, "bilateral_dsse_envelope")?,
            proof_package: parse_review_json(source_bytes_by_role, "proof_package")?,
            workflow_receipt: parse_review_json(source_bytes_by_role, "workflow_receipt")?,
            verifier_report: parse_review_json(source_bytes_by_role, "verifier_report")?,
            proof_regeneration_report: parse_review_json(
                source_bytes_by_role,
                "proof_regeneration_report",
            )?,
            runtime_run_report: parse_review_json(source_bytes_by_role, "runtime_run_report")?,
            runtime_evidence_manifest: parse_review_json(
                source_bytes_by_role,
                "runtime_evidence_manifest",
            )?,
            proof_regeneration_input: parse_review_json(
                source_bytes_by_role,
                "proof_regeneration_input",
            )?,
        })
    }
}

fn verify_buyer_attestation_review_package_internal(
    package: &BuyerAttestationReviewPackage,
    sources: &[BuyerAttestationReviewSource],
    trust_context: Option<&BuyerAttestationReviewTrustContext<'_>>,
) -> Result<BuyerAttestationReviewReport, ChiodosRuntimeError> {
    validate_buyer_attestation_review_package(package)?;
    let mut checks = vec![buyer_review_check(
        "chiodos_buyer_review.package_valid",
        true,
        "info",
        "buyer_attestation_review_package",
        None,
        None,
        "buyer review package structure is valid",
    )];
    let refs_by_role = review_refs_by_role(package)?;
    let mut source_bytes_by_role = BTreeMap::new();
    let mut source_paths = BTreeSet::new();
    for source in sources {
        validate_non_empty(&source.role, "buyer_review_artifact_empty_role")?;
        validate_relative_evidence_path(
            &source.relative_path,
            "buyer_review_artifact_unsafe_path",
        )?;
        if !source_paths.insert(source.relative_path.clone()) {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_duplicate_artifact_path",
                checks,
            ));
        }
        let Some(artifact_ref) = refs_by_role.get(&source.role) else {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_missing_artifact_role",
                checks,
            ));
        };
        if artifact_ref.relative_path != source.relative_path {
            checks.push(buyer_review_check(
                "chiodos_buyer_review.artifact_path_bound",
                false,
                "error",
                &source.role,
                Some(artifact_ref.relative_path.clone()),
                Some(source.relative_path.clone()),
                "artifact bytes were supplied from a path outside the package manifest binding",
            ));
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_artifact_path_mismatch",
                checks,
            ));
        }
        let observed = sha256_hex(&source.bytes);
        if observed != artifact_ref.artifact_sha256
            || source.bytes.len() as u64 != artifact_ref.byte_count
        {
            checks.push(buyer_review_check(
                "chiodos_buyer_review.artifact_hash_bound",
                false,
                "error",
                &source.role,
                Some(artifact_ref.artifact_sha256.clone()),
                Some(observed),
                "artifact bytes did not match the package manifest",
            ));
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_artifact_hash_mismatch",
                checks,
            ));
        }
        if source_bytes_by_role
            .insert(source.role.clone(), source.bytes.clone())
            .is_some()
        {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_duplicate_artifact_role",
                checks,
            ));
        }
    }
    for role in BUYER_REVIEW_REQUIRED_ROLES {
        let Some(artifact_ref) = refs_by_role.get(*role) else {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_missing_artifact_role",
                checks,
            ));
        };
        let Some(bytes) = source_bytes_by_role.get(*role) else {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_missing_artifact_role",
                checks,
            ));
        };
        if bytes.len() as u64 != artifact_ref.byte_count {
            checks.push(buyer_review_check(
                "chiodos_buyer_review.artifact_hash_bound",
                false,
                "error",
                role,
                Some(artifact_ref.artifact_sha256.clone()),
                Some(sha256_hex(bytes)),
                "artifact bytes did not match the package manifest",
            ));
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_artifact_hash_mismatch",
                checks,
            ));
        }
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.artifacts_hydrated",
        true,
        "info",
        "artifact_manifest",
        None,
        None,
        "all required artifact roles resolved by hash and byte count",
    ));

    let BuyerReviewHydratedArtifacts {
        packet,
        lineage,
        lineage_bundle,
        continuation,
        admission,
        bilateral,
        bilateral_dsse,
        proof_package,
        workflow_receipt,
        verifier_report,
        proof_regeneration_report,
        runtime_run_report,
        runtime_evidence_manifest,
        proof_regeneration_input,
    } = BuyerReviewHydratedArtifacts::from_bound_sources(&source_bytes_by_role)?;
    if packet.packet_id != package.packet_id || packet.buyer_id != package.buyer_id {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_packet_hash_mismatch",
            checks,
        ));
    }
    if !verify_receipt_lineage_bundle(&lineage_bundle)? {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_lineage_bundle_incomplete",
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.lineage_bundle_closed",
        true,
        "info",
        "receipt_lineage_bundle",
        None,
        None,
        "receipt lineage bundle closed over verified edges",
    ));
    if let Err(code) =
        verify_buyer_review_lineage_binding(&packet, &lineage, &lineage_bundle, &bilateral)
    {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.lineage_bundle_bound",
        true,
        "info",
        "receipt_lineage_bundle",
        None,
        None,
        "receipt lineage bundle root, leaf, and statement hash matched the buyer packet",
    ));
    let packet_report =
        verify_buyer_attestation_packet(&packet, &lineage, &continuation, &admission, &bilateral)?;
    if !packet_report.accepted {
        return Ok(buyer_review_rejection_report(
            package,
            packet_report
                .failure_code
                .as_deref()
                .unwrap_or("chiodos_buyer_packet_hash_mismatch"),
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.packet_semantics_verified",
        true,
        "info",
        "buyer_attestation_packet",
        None,
        None,
        "buyer packet bindings matched hydrated treaty evidence",
    ));
    let workflow_sha256 = canonical_sha256(&workflow_receipt)?;
    let proof_sha256 = canonical_sha256(&proof_package)?;
    let verifier_sha256 = canonical_sha256(&verifier_report)?;
    if workflow_sha256 != packet.workflow_receipt_sha256
        || proof_sha256 != packet.proof_package_sha256
        || verifier_sha256 != packet.verifier_report_sha256
    {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_packet_hash_mismatch",
            checks,
        ));
    }
    let bilateral_dsse_sha256 = canonical_sha256(&bilateral_dsse)?;
    if bilateral_dsse_sha256 != packet.bilateral_dsse_sha256 {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_packet_hash_mismatch",
            checks,
        ));
    }
    if let Err(code) = verify_buyer_review_proof_package(
        &proof_package,
        &workflow_receipt,
        &workflow_sha256,
        &bilateral_dsse_sha256,
    ) {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.proof_package_hydrated",
        true,
        "info",
        "proof_package",
        None,
        None,
        "proof package carried the hydrated workflow receipt and bilateral DSSE envelope",
    ));
    let Some(trust_context) = trust_context else {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_strict_dsse_signer_mismatch",
            checks,
        ));
    };
    if package.generated_at_unix_ms != runtime_evidence_manifest.generated_at_unix_ms {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_package_manifest_timestamp_mismatch",
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.package_manifest_timestamp_bound",
        true,
        "info",
        "runtime_evidence_manifest",
        None,
        None,
        "buyer review package timestamp matched the runtime evidence manifest",
    ));
    let Some((context_issued_at, context_expires_at)) =
        buyer_review_verification_context_window(trust_context.verification_context)
    else {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_package_stale",
            checks,
        ));
    };
    if package.generated_at_unix_ms < context_issued_at
        || package.generated_at_unix_ms >= context_expires_at
    {
        return Ok(buyer_review_rejection_report(
            package,
            "chiodos_buyer_review_package_stale",
            checks,
        ));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.package_fresh",
        true,
        "info",
        "buyer_attestation_review_package",
        None,
        None,
        &format!(
            "buyer review package generated at {} inside verification context window {}..{}",
            package.generated_at_unix_ms, context_issued_at, context_expires_at
        ),
    ));
    let trust_bundle_sha256 = canonical_sha256(trust_context.verifier_trust_bundle)
        .map_err(|_| ChiodosRuntimeError::Canonical("verifier trust bundle".to_string()))?;
    let verification_context_sha256 = canonical_sha256(trust_context.verification_context)
        .map_err(|_| ChiodosRuntimeError::Canonical("verification context".to_string()))?;
    let runtime_step = match verify_buyer_review_runtime_reports(BuyerReviewRuntimeReportContext {
        runtime_run_report: &runtime_run_report,
        proof_regeneration_report: &proof_regeneration_report,
        packet: &packet,
        bilateral: &bilateral,
        proof_package: &proof_package,
        workflow_receipt: &workflow_receipt,
        runtime_evidence_manifest: &runtime_evidence_manifest,
        proof_regeneration_input: &proof_regeneration_input,
        proof_sha256: &proof_sha256,
        verifier_sha256: &verifier_sha256,
        workflow_sha256: &workflow_sha256,
        bilateral_dsse_sha256: &bilateral_dsse_sha256,
        trust_bundle_sha256: &trust_bundle_sha256,
        verification_context_sha256: &verification_context_sha256,
        artifact_refs: &package.artifacts,
    }) {
        Ok(step) => step,
        Err(code) => return Ok(buyer_review_rejection_report(package, code, checks)),
    };
    checks.push(buyer_review_check(
        "chiodos_buyer_review.runtime_reports_bound",
        true,
        "info",
        "runtime_run_report",
        None,
        None,
        "runtime run and proof regeneration reports bound the hydrated proof artifacts",
    ));
    let signer_public_keys = match buyer_review_signer_public_keys_from_trust_bundle(
        trust_context.verifier_trust_bundle,
        &verifier_report,
        &proof_package,
        &bilateral.signer_kernel_ids,
    ) {
        Ok(Some(keys)) => keys,
        Ok(None) => {
            return Ok(buyer_review_rejection_report(
                package,
                "chiodos_buyer_review_strict_dsse_signer_mismatch",
                checks,
            ))
        }
        Err(code) => return Ok(buyer_review_rejection_report(package, code, checks)),
    };
    let strict_dsse_context = BuyerReviewStrictDsseContext {
        packet: &packet,
        lineage_bundle: &lineage_bundle,
        admission: &admission,
        bilateral: &bilateral,
        proof_package: &proof_package,
        runtime_step: &runtime_step,
        signer_public_keys: &signer_public_keys,
        generated_at_unix_ms: package.generated_at_unix_ms,
    };
    if let Err(code) = verify_buyer_review_strict_dsse(&bilateral_dsse, &strict_dsse_context) {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.strict_dsse_treaty_bound",
        true,
        "info",
        "bilateral_dsse_envelope",
        None,
        None,
        "strict Chiodos DSSE predicate carried treaty runtime bindings",
    ));
    if let Err(code) = verify_buyer_review_existing_verifier(
        &verifier_report,
        &BuyerReviewExistingVerifierContext {
            proof_package: &proof_package,
            verifier_trust_bundle: trust_context.verifier_trust_bundle,
            verification_context: trust_context.verification_context,
            proof_sha256: &proof_sha256,
            trust_bundle_sha256: &trust_bundle_sha256,
            verification_context_sha256: &verification_context_sha256,
            verifier_sha256: &verifier_sha256,
        },
    ) {
        return Ok(buyer_review_rejection_report(package, code, checks));
    }
    checks.push(buyer_review_check(
        "chiodos_buyer_review.proof_verifier_accepted",
        true,
        "info",
        "verifier_report",
        None,
        None,
        "verifier report accepted the regenerated proof package",
    ));
    Ok(BuyerAttestationReviewReport {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA.to_string(),
        package_id: package.package_id.clone(),
        packet_id: package.packet_id.clone(),
        accepted: true,
        failure_code: None,
        checks,
    })
}

fn buyer_review_verification_context_window(context: &serde_json::Value) -> Option<(u64, u64)> {
    let issued_at = context.get("issuedAtUnixMs")?.as_u64()?;
    let expires_at = context.get("expiresAtUnixMs")?.as_u64()?;
    (expires_at > issued_at).then_some((issued_at, expires_at))
}

fn verify_buyer_review_lineage_binding(
    packet: &BuyerAttestationPacket,
    lineage: &ReceiptLineageStatement,
    lineage_bundle: &ReceiptLineageBundle,
    bilateral: &BilateralInvocation,
) -> Result<(), &'static str> {
    let lineage_sha256 =
        canonical_sha256(lineage).map_err(|_| "chiodos_buyer_review_packet_hash_mismatch")?;
    if lineage_sha256 != packet.receipt_lineage_statement_sha256 {
        return Err("chiodos_buyer_review_packet_hash_mismatch");
    }
    let bilateral_invocation_sha256 = bilateral_invocation_binding_sha256(bilateral)
        .map_err(|_| "chiodos_treaty_bilateral_mismatch")?;
    if bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
        || lineage.bilateral_invocation_sha256 != packet.bilateral_invocation_sha256
    {
        return Err("chiodos_treaty_bilateral_mismatch");
    }
    let mut bundle_contains_packet_statement = false;
    for statement in &lineage_bundle.statements {
        let statement_sha256 =
            canonical_sha256(statement).map_err(|_| "chiodos_lineage_bundle_incomplete")?;
        if statement_sha256 == packet.receipt_lineage_statement_sha256 {
            bundle_contains_packet_statement = true;
            break;
        }
    }
    if !bundle_contains_packet_statement {
        return Err("chiodos_lineage_bundle_incomplete");
    }
    if lineage_bundle.root_receipt_sha256 != bilateral.local_receipt_sha256
        || lineage_bundle.leaf_receipt_sha256 != bilateral.remote_receipt_sha256
    {
        return Err("chiodos_treaty_bilateral_mismatch");
    }
    Ok(())
}

fn verify_buyer_review_proof_package(
    proof_package: &serde_json::Value,
    workflow_receipt: &serde_json::Value,
    workflow_sha256: &str,
    bilateral_dsse_sha256: &str,
) -> Result<(), &'static str> {
    if proof_package
        .get("schema")
        .and_then(serde_json::Value::as_str)
        != Some("chio.chiodos.proof-package.v1")
    {
        return Err("chiodos_buyer_review_proof_package_incomplete");
    }
    for field in [
        "toolReceipts",
        "bilateralEnvelopes",
        "capabilityLeases",
        "leaseScopeBindings",
        "peerLadderBindings",
        "vendorKeys",
    ] {
        let Some(values) = proof_package
            .get(field)
            .and_then(serde_json::Value::as_array)
        else {
            return Err("chiodos_buyer_review_proof_package_incomplete");
        };
        if values.is_empty() {
            return Err("chiodos_buyer_review_proof_package_incomplete");
        }
    }
    if !proof_package
        .get("selectiveDisclosureProof")
        .is_some_and(serde_json::Value::is_object)
        || !proof_package
            .get("workflowIntersection")
            .is_some_and(serde_json::Value::is_object)
    {
        return Err("chiodos_buyer_review_proof_package_incomplete");
    }
    let Some(embedded_workflow_receipt) = proof_package.get("workflowReceipt") else {
        return Err("chiodos_buyer_review_proof_package_incomplete");
    };
    if embedded_workflow_receipt != workflow_receipt {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    let embedded_workflow_sha256 = canonical_sha256(embedded_workflow_receipt)
        .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
    if embedded_workflow_sha256 != workflow_sha256 {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    if proof_package.get("treatyBilateralEnvelopes").is_some() {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    let bilateral_envelopes = proof_package
        .get("bilateralEnvelopes")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    let mut contains_hydrated_envelope = false;
    for envelope in bilateral_envelopes {
        let envelope_sha256 = canonical_sha256(envelope)
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if envelope_sha256 == bilateral_dsse_sha256 {
            contains_hydrated_envelope = true;
            break;
        }
    }
    if !contains_hydrated_envelope {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    Ok(())
}

fn verify_buyer_review_existing_verifier(
    verifier_report: &serde_json::Value,
    context: &BuyerReviewExistingVerifierContext<'_>,
) -> Result<(), &'static str> {
    if verifier_report
        .get("packageSha256")
        .and_then(serde_json::Value::as_str)
        != Some(context.proof_sha256)
        || verifier_report
            .get("trustBundleSha256")
            .and_then(serde_json::Value::as_str)
            != Some(context.trust_bundle_sha256)
        || verifier_report
            .get("contextSha256")
            .and_then(serde_json::Value::as_str)
            != Some(context.verification_context_sha256)
        || verifier_report
            .get("accepted")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
    {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    let proof_package_json = serde_json::to_string(context.proof_package)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let verifier_trust_bundle_json = serde_json::to_string(context.verifier_trust_bundle)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let verification_context_json = serde_json::to_string(context.verification_context)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let typed_package = chio_chiodos::proof_package_from_json(&proof_package_json)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let typed_trust_bundle =
        chio_chiodos::verifier_trust_bundle_from_json(&verifier_trust_bundle_json)
            .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let typed_context = chio_chiodos::verification_context_from_json(&verification_context_json)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    let expected_report =
        chio_chiodos::verify_package_report(&typed_package, &typed_trust_bundle, &typed_context);
    if !expected_report.accepted {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    if expected_report.package_sha256 != context.proof_sha256
        || expected_report.trust_bundle_sha256.as_deref() != Some(context.trust_bundle_sha256)
        || expected_report.context_sha256.as_deref() != Some(context.verification_context_sha256)
    {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    let expected_sha256 = canonical_sha256(&expected_report)
        .map_err(|_| "chiodos_buyer_review_verifier_report_rejected")?;
    if expected_sha256 != context.verifier_sha256 {
        return Err("chiodos_buyer_review_verifier_report_rejected");
    }
    Ok(())
}

struct BuyerReviewExistingVerifierContext<'a> {
    proof_package: &'a serde_json::Value,
    verifier_trust_bundle: &'a serde_json::Value,
    verification_context: &'a serde_json::Value,
    proof_sha256: &'a str,
    trust_bundle_sha256: &'a str,
    verification_context_sha256: &'a str,
    verifier_sha256: &'a str,
}

struct BuyerReviewRuntimeReportContext<'a> {
    runtime_run_report: &'a RuntimeWorkflowRunReport,
    proof_regeneration_report: &'a RuntimeProofRegenerationReport,
    packet: &'a BuyerAttestationPacket,
    bilateral: &'a BilateralInvocation,
    proof_package: &'a serde_json::Value,
    workflow_receipt: &'a serde_json::Value,
    runtime_evidence_manifest: &'a RuntimeEvidenceManifest,
    proof_regeneration_input: &'a RuntimeProofRegenerationInput,
    proof_sha256: &'a str,
    verifier_sha256: &'a str,
    workflow_sha256: &'a str,
    bilateral_dsse_sha256: &'a str,
    trust_bundle_sha256: &'a str,
    verification_context_sha256: &'a str,
    artifact_refs: &'a [BuyerAttestationReviewArtifactRef],
}

fn verify_buyer_review_runtime_reports(
    context: BuyerReviewRuntimeReportContext<'_>,
) -> Result<RuntimeStepEvidence, &'static str> {
    let BuyerReviewRuntimeReportContext {
        runtime_run_report,
        proof_regeneration_report,
        packet,
        bilateral,
        proof_package,
        workflow_receipt,
        runtime_evidence_manifest,
        proof_regeneration_input,
        proof_sha256,
        verifier_sha256,
        workflow_sha256,
        bilateral_dsse_sha256,
        trust_bundle_sha256,
        verification_context_sha256,
        artifact_refs,
    } = context;
    if validate_runtime_workflow_run_report(runtime_run_report).is_err()
        || validate_runtime_proof_regeneration_report(proof_regeneration_report).is_err()
        || validate_runtime_evidence_manifest(runtime_evidence_manifest).is_err()
        || validate_runtime_proof_regeneration_input(proof_regeneration_input).is_err()
        || !runtime_run_report.accepted
        || !proof_regeneration_report.accepted
        || runtime_run_report.generated_at_unix_ms != runtime_evidence_manifest.generated_at_unix_ms
        || proof_regeneration_report.generated_at_unix_ms
            != runtime_evidence_manifest.generated_at_unix_ms
    {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    let proof_regeneration_sha256 = canonical_sha256(proof_regeneration_report)
        .map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
    let runtime_run_sha256 = canonical_sha256(runtime_run_report)
        .map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
    let manifest_sha256 = canonical_sha256(runtime_evidence_manifest)
        .map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
    if runtime_run_report
        .proof_regeneration_report_sha256
        .as_deref()
        != Some(proof_regeneration_sha256.as_str())
        || runtime_run_report.run_id != proof_regeneration_report.run_id
        || runtime_evidence_manifest.run_id != runtime_run_report.run_id
        || runtime_evidence_manifest.workflow_run_report_sha256 != runtime_run_sha256
        || runtime_evidence_manifest.proof_regeneration_report_sha256 != proof_regeneration_sha256
        || proof_regeneration_input.run_id != runtime_run_report.run_id
        || proof_regeneration_input.evidence_manifest_sha256 != manifest_sha256
        || proof_regeneration_input.workflow_run_report_sha256 != runtime_run_sha256
        || proof_regeneration_input.source_records != proof_regeneration_report.source_records
        || runtime_run_report.admission_report_sha256
            != packet.cross_boundary_admission_report_sha256
        || proof_regeneration_input.admission_report_sha256
            != packet.cross_boundary_admission_report_sha256
        || proof_regeneration_input.trust_bundle_sha256 != trust_bundle_sha256
        || proof_regeneration_input.verification_context_sha256 != verification_context_sha256
        || proof_regeneration_report.proof_package_sha256.as_deref() != Some(proof_sha256)
        || proof_regeneration_report.verifier_report_sha256.as_deref() != Some(verifier_sha256)
        || proof_regeneration_report.workflow_receipt_sha256.as_deref() != Some(workflow_sha256)
    {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    verify_runtime_evidence_manifest_artifacts(runtime_evidence_manifest, artifact_refs)?;
    let Some(step) = runtime_run_report
        .step_evidence
        .iter()
        .find(|step| step.bilateral_dsse_sha256 == bilateral_dsse_sha256)
    else {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    };
    if step.lease_id.is_none() || step.governance_receipt_id.is_none() {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    if step.admission_report_sha256 != packet.cross_boundary_admission_report_sha256
        || step.tool_receipt_sha256 != bilateral.remote_receipt_sha256
        || step.parent_receipt_sha256.as_deref() != Some(bilateral.local_receipt_sha256.as_str())
        || step.output_sha256 != bilateral.outcome_sha256
    {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    if !workflow_receipt_contains_step_hash(workflow_receipt, &step.workflow_step_sha256)? {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    if !proof_package_contains_signed_receipt(proof_package, &step.tool_receipt_sha256)? {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    if let Some(parent_receipt_sha256) = step.parent_receipt_sha256.as_deref() {
        if !proof_package_contains_parent_lineage_anchor(
            proof_package,
            workflow_receipt,
            &step.workflow_step_sha256,
            parent_receipt_sha256,
        )? {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
    }
    if !proof_package_array_contains_field(
        proof_package,
        "capabilityLeases",
        "leaseId",
        step.lease_id
            .as_deref()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?,
    ) || !proof_package_array_contains_field(
        proof_package,
        "governanceReceipts",
        "receiptId",
        step.governance_receipt_id
            .as_deref()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?,
    ) {
        return Err("chiodos_buyer_review_proof_package_mismatch");
    }
    let source_record_matches = proof_regeneration_report
        .source_records
        .iter()
        .any(|record| {
            record.step_index == step.step_index
                && record.admission_report_sha256 == step.admission_report_sha256
                && record.tool_receipt_sha256 == step.tool_receipt_sha256
                && record.bilateral_dsse_sha256 == step.bilateral_dsse_sha256
                && record.workflow_step_sha256 == step.workflow_step_sha256
        });
    if !source_record_matches {
        return Err("chiodos_buyer_review_runtime_report_mismatch");
    }
    Ok(step.clone())
}

fn verify_runtime_evidence_manifest_artifacts(
    manifest: &RuntimeEvidenceManifest,
    artifact_refs: &[BuyerAttestationReviewArtifactRef],
) -> Result<(), &'static str> {
    for role in [
        "bilateral_dsse_envelope",
        "workflow_receipt",
        "proof_package",
        "verifier_report",
        "proof_regeneration_report",
        "runtime_run_report",
    ] {
        let Some(artifact) = artifact_refs.iter().find(|artifact| artifact.role == role) else {
            return Err("chiodos_buyer_review_runtime_report_mismatch");
        };
        let Some(entry) = manifest.entries.iter().find(|entry| entry.role == role) else {
            return Err("chiodos_buyer_review_runtime_report_mismatch");
        };
        if entry.path != artifact.relative_path
            || entry.sha256 != artifact.artifact_sha256
            || entry.byte_count != artifact.byte_count
        {
            return Err("chiodos_buyer_review_runtime_report_mismatch");
        }
    }
    Ok(())
}

fn receipt_wire_value_matches_parsed_receipt(
    wire_value: &serde_json::Value,
    receipt: &ChioReceipt,
) -> Result<bool, &'static str> {
    let typed_value =
        serde_json::to_value(receipt).map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
    let mut normalized_wire_value = wire_value.clone();
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "trust_level",
        |value| value.as_str() == Some("mediated"),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "algorithm",
        |value| value.as_str() == Some("ed25519") || value.is_null(),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "evidence",
        |value| value.as_array().is_some_and(Vec::is_empty),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "metadata",
        |value| value.is_null(),
    );
    remove_default_receipt_wire_field(
        &mut normalized_wire_value,
        &typed_value,
        "tenant_id",
        |value| value.is_null(),
    );
    Ok(normalized_wire_value == typed_value)
}

fn remove_default_receipt_wire_field<F>(
    wire_value: &mut serde_json::Value,
    typed_value: &serde_json::Value,
    field: &str,
    is_default: F,
) where
    F: Fn(&serde_json::Value) -> bool,
{
    if typed_value.get(field).is_some() {
        return;
    }
    let Some(wire_object) = wire_value.as_object_mut() else {
        return;
    };
    if wire_object.get(field).is_some_and(is_default) {
        wire_object.remove(field);
    }
}

fn proof_package_contains_signed_receipt(
    proof_package: &serde_json::Value,
    expected_sha256: &str,
) -> Result<bool, &'static str> {
    proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?
        .iter()
        .map(|value| {
            let actual_sha256 = canonical_sha256(value)
                .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
            if actual_sha256 != expected_sha256 {
                return Ok(false);
            }
            let receipt: ChioReceipt = serde_json::from_value(value.clone())
                .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
            if !receipt_wire_value_matches_parsed_receipt(value, &receipt)? {
                return Err("chiodos_buyer_review_proof_package_mismatch");
            }
            let signature_valid = receipt
                .verify_signature()
                .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
            if !signature_valid {
                return Err("chiodos_buyer_review_proof_package_mismatch");
            }
            Ok(true)
        })
        .try_fold(false, |found, current| {
            current.map(|current| found || current)
        })
}

fn proof_package_array_contains_field(
    proof_package: &serde_json::Value,
    array_field: &str,
    field: &str,
    expected: &str,
) -> bool {
    proof_package
        .get(array_field)
        .and_then(serde_json::Value::as_array)
        .is_some_and(|values| {
            values.iter().any(|value| {
                value
                    .get(field)
                    .or_else(|| value.get("body").and_then(|body| body.get(field)))
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|actual| actual == expected)
            })
        })
}

fn workflow_receipt_contains_step_hash(
    workflow_receipt: &serde_json::Value,
    expected_sha256: &str,
) -> Result<bool, &'static str> {
    Ok(workflow_step_by_hash(workflow_receipt, expected_sha256)?.is_some())
}

fn workflow_step_by_hash<'a>(
    workflow_receipt: &'a serde_json::Value,
    expected_sha256: &str,
) -> Result<Option<&'a serde_json::Value>, &'static str> {
    let Some(steps) = workflow_receipt
        .get("steps")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(workflow_receipt
            .get("workflowStepSha256")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|hash| hash == expected_sha256)
            .then_some(workflow_receipt));
    };
    for step in steps {
        let hash =
            canonical_sha256(step).map_err(|_| "chiodos_buyer_review_runtime_report_mismatch")?;
        if hash == expected_sha256 {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

fn proof_package_contains_parent_lineage_anchor(
    proof_package: &serde_json::Value,
    workflow_receipt: &serde_json::Value,
    child_workflow_step_sha256: &str,
    parent_sha256: &str,
) -> Result<bool, &'static str> {
    if proof_package_contains_signed_receipt(proof_package, parent_sha256)? {
        return Ok(true);
    }
    let Some(child_step) = workflow_step_by_hash(workflow_receipt, child_workflow_step_sha256)?
    else {
        return Ok(false);
    };
    if child_step
        .get("parent_receipt_sha256")
        .and_then(serde_json::Value::as_str)
        != Some(parent_sha256)
    {
        return Ok(false);
    }
    workflow_receipt_contains_step_hash(workflow_receipt, parent_sha256)
}

fn proof_package_receipt_subject(
    proof_package: &serde_json::Value,
    receipt_sha256: &str,
) -> Result<(String, String), &'static str> {
    let receipts = proof_package
        .get("toolReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    for receipt_value in receipts {
        let Ok(actual_sha256) = canonical_sha256(receipt_value) else {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        };
        if actual_sha256 != receipt_sha256 {
            continue;
        }
        let receipt: ChioReceipt = serde_json::from_value(receipt_value.clone())
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if !receipt_wire_value_matches_parsed_receipt(receipt_value, &receipt)? {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
        let signature_valid = receipt
            .verify_signature()
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if !signature_valid {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
        let subject_sha256 = canonical_sha256(&receipt.body())
            .map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        return Ok((
            chio_federation::receipt_subject_name(&receipt.id),
            subject_sha256,
        ));
    }
    Err("chiodos_buyer_review_proof_package_mismatch")
}

fn proof_package_capability_lease_ref(
    proof_package: &serde_json::Value,
    lease_id: &str,
) -> Result<chio_federation::CapabilityLeaseRef, &'static str> {
    let leases = proof_package
        .get("capabilityLeases")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    for lease in leases {
        let body = lease.get("body").unwrap_or(lease);
        if body.get("leaseId").and_then(serde_json::Value::as_str) != Some(lease_id) {
            continue;
        }
        let issuer = body
            .get("issuer")
            .and_then(serde_json::Value::as_str)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        let expires_at_unix_ms = body
            .get("expiresAtUnixMs")
            .and_then(serde_json::Value::as_u64)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        let scope_digest = body
            .get("scopeDigest")
            .and_then(serde_json::Value::as_str)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        return Ok(chio_federation::CapabilityLeaseRef {
            lease_id: lease_id.to_string(),
            issuer: issuer.to_string(),
            expires_at_unix_ms,
            scope_digest: Some(chio_federation::HashRecord {
                alg: "sha256".to_string(),
                value: scope_digest.to_string(),
            }),
        });
    }
    Err("chiodos_buyer_review_proof_package_mismatch")
}

fn proof_package_governance_receipt_ref(
    proof_package: &serde_json::Value,
    receipt_id: &str,
) -> Result<chio_federation::GovernanceReceiptRef, &'static str> {
    let receipts = proof_package
        .get("governanceReceipts")
        .and_then(serde_json::Value::as_array)
        .ok_or("chiodos_buyer_review_proof_package_incomplete")?;
    for receipt in receipts {
        let body = receipt.get("body").unwrap_or(receipt);
        if body.get("receiptId").and_then(serde_json::Value::as_str) != Some(receipt_id) {
            continue;
        }
        let kernel_id = body
            .get("authorizingKernel")
            .or_else(|| body.get("kernelId"))
            .and_then(serde_json::Value::as_str)
            .ok_or("chiodos_buyer_review_proof_package_mismatch")?;
        let digest =
            canonical_sha256(receipt).map_err(|_| "chiodos_buyer_review_proof_package_mismatch")?;
        if receipt
            .get("digest")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|claimed| claimed != digest)
        {
            return Err("chiodos_buyer_review_proof_package_mismatch");
        }
        return Ok(chio_federation::GovernanceReceiptRef {
            receipt_id: receipt_id.to_string(),
            kernel_id: kernel_id.to_string(),
            digest: chio_federation::HashRecord {
                alg: "sha256".to_string(),
                value: digest,
            },
        });
    }
    Err("chiodos_buyer_review_proof_package_mismatch")
}

pub fn verify_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<bool, ChiodosRuntimeError> {
    validate_receipt_lineage_bundle(bundle)?;
    if bundle.statements.is_empty() {
        return rejected(
            "chiodos_lineage_bundle_incomplete",
            "receipt lineage bundle must contain at least one statement",
        );
    }
    let mut seen_statement_ids = BTreeSet::new();
    let mut seen_receipts = BTreeSet::new();
    let mut current = bundle.root_receipt_sha256.clone();
    seen_receipts.insert(current.clone());
    for statement in &bundle.statements {
        validate_receipt_lineage_statement(statement)?;
        if statement.evidence_class != "verified" {
            return rejected(
                "chiodos_lineage_bundle_unverified_edge",
                "receipt lineage bundle requires verified lineage edges",
            );
        }
        if !seen_statement_ids.insert(statement.statement_id.clone()) {
            return rejected(
                "chiodos_lineage_bundle_cycle",
                "receipt lineage bundle contains duplicate statement id",
            );
        }
        if statement.parent_receipt_sha256 != current {
            return rejected(
                "chiodos_lineage_bundle_incomplete",
                "receipt lineage bundle has a parent-child gap",
            );
        }
        if !seen_receipts.insert(statement.child_receipt_sha256.clone()) {
            return rejected(
                "chiodos_lineage_bundle_cycle",
                "receipt lineage bundle reuses a child receipt",
            );
        }
        current = statement.child_receipt_sha256.clone();
    }
    if current != bundle.leaf_receipt_sha256 {
        return rejected(
            "chiodos_lineage_bundle_incomplete",
            "receipt lineage bundle does not reach the declared leaf receipt",
        );
    }
    Ok(true)
}

struct BuyerReviewStrictDsseContext<'a> {
    packet: &'a BuyerAttestationPacket,
    lineage_bundle: &'a ReceiptLineageBundle,
    admission: &'a CrossBoundaryAdmissionReport,
    bilateral: &'a BilateralInvocation,
    proof_package: &'a serde_json::Value,
    runtime_step: &'a RuntimeStepEvidence,
    signer_public_keys: &'a BTreeMap<String, PublicKey>,
    generated_at_unix_ms: u64,
}

fn verify_buyer_review_strict_dsse(
    envelope: &chio_federation::DsseEnvelope,
    context: &BuyerReviewStrictDsseContext<'_>,
) -> Result<(), &'static str> {
    let Ok((statement, _)) = envelope.decode_statement() else {
        return Err("chiodos_buyer_review_non_strict_dsse");
    };
    if statement.predicate_type != chio_federation::PREDICATE_TYPE_CHIODOS_BILATERAL {
        return Err("chiodos_buyer_review_non_strict_dsse");
    }
    if statement.predicate.timestamp_unix_ms != context.generated_at_unix_ms {
        return Err("chiodos_buyer_review_runtime_timestamp_mismatch");
    }
    let lineage_bundle_sha256 = match canonical_sha256(context.lineage_bundle) {
        Ok(hash) => hash,
        Err(_) => return Err("chiodos_buyer_review_lineage_hash_mismatch"),
    };
    let expected_treaty_binding = chio_federation::TreatyBindingRef {
        treaty_id: context.admission.treaty_id.clone(),
        treaty_scope_sha256: context.packet.treaty_scope_sha256.clone(),
        ladder_intersection_sha256: context.packet.ladder_intersection_sha256.clone(),
        admission_report_sha256: context
            .packet
            .cross_boundary_admission_report_sha256
            .clone(),
        continuation_sha256: context.packet.continuation_sha256.clone(),
        lineage_bundle_sha256,
        action_class_id: context.admission.action_class_id.clone(),
        consistency_model: context.admission.consistency_model.clone(),
        request_sha256: context.bilateral.request_sha256.clone(),
        outcome_sha256: context.bilateral.outcome_sha256.clone(),
        local_receipt_sha256: context.bilateral.local_receipt_sha256.clone(),
        remote_receipt_sha256: context.bilateral.remote_receipt_sha256.clone(),
        lease_refs: vec![context
            .runtime_step
            .lease_id
            .clone()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?],
        governance_refs: vec![context
            .runtime_step
            .governance_receipt_id
            .clone()
            .ok_or("chiodos_buyer_review_runtime_report_mismatch")?],
        signer_kernel_ids: context.bilateral.signer_kernel_ids.clone(),
    };
    let (expected_subject_name, expected_subject_sha256) = proof_package_receipt_subject(
        context.proof_package,
        &context.runtime_step.tool_receipt_sha256,
    )?;
    let lease_id = context
        .runtime_step
        .lease_id
        .as_deref()
        .ok_or("chiodos_buyer_review_runtime_report_mismatch")?;
    let expected_capability_lease_ref =
        proof_package_capability_lease_ref(context.proof_package, lease_id)?;
    let governance_receipt_id = context
        .runtime_step
        .governance_receipt_id
        .as_deref()
        .ok_or("chiodos_buyer_review_runtime_report_mismatch")?;
    let expected_governance_receipt_ref =
        proof_package_governance_receipt_ref(context.proof_package, governance_receipt_id)?;
    let review = chio_federation::TreatyBoundBilateralDsseReview {
        expected_treaty_binding: &expected_treaty_binding,
        expected_subject_name: &expected_subject_name,
        expected_subject_sha256: &expected_subject_sha256,
        expected_capability_lease_ref: &expected_capability_lease_ref,
        expected_governance_receipt_ref: &expected_governance_receipt_ref,
        expected_consistency_anchor: &context.runtime_step.consistency_anchor,
        signer_public_keys: context.signer_public_keys,
    };
    chio_federation::verify_treaty_bound_chiodos_bilateral_invocation(envelope, &review)
        .map(|_| ())
        .map_err(|error| buyer_review_strict_dsse_error_code(&error))
}

fn buyer_review_signer_public_keys_from_trust_bundle(
    verifier_trust_bundle: &serde_json::Value,
    verifier_report: &serde_json::Value,
    proof_package: &serde_json::Value,
    signer_kernel_ids: &[String],
) -> Result<Option<BTreeMap<String, PublicKey>>, &'static str> {
    let trust_bundle_sha256 = canonical_sha256(verifier_trust_bundle)
        .map_err(|_| "chiodos_buyer_review_strict_dsse_signer_mismatch")?;
    if verifier_report
        .get("trustBundleSha256")
        .and_then(serde_json::Value::as_str)
        != Some(trust_bundle_sha256.as_str())
    {
        return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
    }
    let Some(trusted_peers) = verifier_trust_bundle
        .get("peers")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let Some(proof_bindings) = proof_package
        .get("peerLadderBindings")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let expected_signers: BTreeSet<&str> = signer_kernel_ids.iter().map(String::as_str).collect();
    let mut signer_public_keys = BTreeMap::new();
    for binding in trusted_peers {
        let Some(kernel_id) = binding.get("kernelId").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !expected_signers.contains(kernel_id) {
            continue;
        }
        let Some(public_key_hex) = binding.get("publicKey").and_then(serde_json::Value::as_str)
        else {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        };
        let public_key = PublicKey::from_hex(public_key_hex)
            .map_err(|_| "chiodos_buyer_review_strict_dsse_signature_invalid")?;
        if signer_public_keys
            .insert(kernel_id.to_string(), public_key)
            .is_some()
        {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        }
    }
    for binding in proof_bindings {
        let Some(kernel_id) = binding.get("kernelId").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if !expected_signers.contains(kernel_id) {
            continue;
        }
        let Some(public_key_hex) = binding.get("publicKey").and_then(serde_json::Value::as_str)
        else {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        };
        let Some(trusted_key) = signer_public_keys.get(kernel_id) else {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        };
        if trusted_key.to_hex() != public_key_hex {
            return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
        }
    }
    if signer_public_keys.is_empty() {
        return Ok(None);
    }
    if signer_kernel_ids
        .iter()
        .any(|kernel_id| !signer_public_keys.contains_key(kernel_id))
    {
        return Err("chiodos_buyer_review_strict_dsse_signer_mismatch");
    }
    Ok(Some(signer_public_keys))
}

fn buyer_review_strict_dsse_error_code(error: &chio_federation::VerifierError) -> &'static str {
    match error {
        chio_federation::VerifierError::PredicateTypeUnrecognised(_)
        | chio_federation::VerifierError::StatementMalformed(_)
        | chio_federation::VerifierError::StatementSchemaInvalid(_) => {
            "chiodos_buyer_review_non_strict_dsse"
        }
        chio_federation::VerifierError::PredicateSchemaInvalid(message) => {
            if message.contains("missing treaty_binding_ref") {
                "chiodos_buyer_review_missing_treaty_dsse_binding"
            } else if message.contains("signer_kernel_ids") || message.contains("signer kernels") {
                "chiodos_buyer_review_strict_dsse_signer_mismatch"
            } else {
                "chiodos_buyer_review_strict_dsse_binding_mismatch"
            }
        }
        chio_federation::VerifierError::PeerUnpinnedOrKeyidMismatch(_) => {
            "chiodos_buyer_review_strict_dsse_signer_mismatch"
        }
        chio_federation::VerifierError::SignatureServerAInvalid(_)
        | chio_federation::VerifierError::SignatureServerBInvalid(_) => {
            "chiodos_buyer_review_strict_dsse_signature_invalid"
        }
        chio_federation::VerifierError::DsseMalformed(message) => {
            if message.contains("duplicate signature")
                || message.contains("signature keyid")
                || message.contains("signer keys")
                || message.contains("independent Org")
                || message.contains("expected exactly 2 signatures")
            {
                "chiodos_buyer_review_strict_dsse_signature_invalid"
            } else {
                "chiodos_buyer_review_non_strict_dsse"
            }
        }
        _ => "chiodos_buyer_review_strict_dsse_binding_mismatch",
    }
}

fn validate_buyer_attestation_review_package(
    package: &BuyerAttestationReviewPackage,
) -> Result<(), ChiodosRuntimeError> {
    if package.schema != CHIODOS_BUYER_ATTESTATION_REVIEW_PACKAGE_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_review_package_schema",
            "buyer attestation review package declared an unsupported schema",
        );
    }
    validate_non_empty(&package.package_id, "buyer_review_package_empty_id")?;
    validate_non_empty(&package.packet_id, "buyer_review_package_empty_packet")?;
    validate_non_empty(&package.buyer_id, "buyer_review_package_empty_buyer")?;
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for artifact in &package.artifacts {
        validate_non_empty(&artifact.role, "buyer_review_artifact_empty_role")?;
        validate_non_empty(
            &artifact.relative_path,
            "buyer_review_artifact_empty_relative_path",
        )?;
        validate_relative_evidence_path(
            &artifact.relative_path,
            "buyer_review_artifact_unsafe_path",
        )?;
        ensure_sha256_hash(
            &artifact.artifact_sha256,
            "buyer_review_artifact_invalid_hash",
        )?;
        if artifact.byte_count == 0 {
            return rejected(
                "buyer_review_artifact_empty_bytes",
                "buyer review artifact byte count must be nonzero",
            );
        }
        if !roles.insert(artifact.role.clone()) {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            );
        }
        if !paths.insert(artifact.relative_path.clone()) {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_path",
                "buyer review package contains duplicate artifact path",
            );
        }
    }
    Ok(())
}

pub(crate) fn validate_buyer_attestation_review_report(
    report: &BuyerAttestationReviewReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_review_report_schema",
            "buyer attestation review report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.package_id, "buyer_review_report_empty_package")?;
    validate_non_empty(&report.packet_id, "buyer_review_report_empty_packet")?;
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "buyer_review_report_missing_failure_code",
            "rejected buyer attestation review report must include failure code",
        );
    }
    Ok(())
}

fn review_refs_by_role(
    package: &BuyerAttestationReviewPackage,
) -> Result<BTreeMap<String, BuyerAttestationReviewArtifactRef>, ChiodosRuntimeError> {
    let mut refs = BTreeMap::new();
    for artifact in &package.artifacts {
        if refs
            .insert(artifact.role.clone(), artifact.clone())
            .is_some()
        {
            return rejected(
                "chiodos_buyer_review_duplicate_artifact_role",
                "buyer review package contains duplicate artifact role",
            );
        }
    }
    Ok(refs)
}

fn parse_review_json<T: serde::de::DeserializeOwned>(
    sources_by_role: &BTreeMap<String, Vec<u8>>,
    role: &str,
) -> Result<T, ChiodosRuntimeError> {
    let bytes = sources_by_role
        .get(role)
        .ok_or_else(|| ChiodosRuntimeError::Rejected {
            code: "chiodos_buyer_review_missing_artifact_role",
            detail: format!("buyer review package is missing artifact role {role}"),
        })?;
    serde_json::from_slice(bytes).map_err(|error| ChiodosRuntimeError::Json(error.to_string()))
}

fn buyer_review_check(
    code: &str,
    passed: bool,
    severity: &str,
    artifact_role: &str,
    expected_sha256: Option<String>,
    observed_sha256: Option<String>,
    message: &str,
) -> BuyerAttestationReviewCheck {
    BuyerAttestationReviewCheck {
        code: code.to_string(),
        passed,
        severity: severity.to_string(),
        artifact_role: artifact_role.to_string(),
        expected_sha256,
        observed_sha256,
        message: message.to_string(),
    }
}

fn buyer_review_rejection_report(
    package: &BuyerAttestationReviewPackage,
    failure_code: &str,
    checks: Vec<BuyerAttestationReviewCheck>,
) -> BuyerAttestationReviewReport {
    BuyerAttestationReviewReport {
        schema: CHIODOS_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA.to_string(),
        package_id: package.package_id.clone(),
        packet_id: package.packet_id.clone(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}

fn validate_buyer_attestation_packet(
    packet: &BuyerAttestationPacket,
) -> Result<(), ChiodosRuntimeError> {
    if packet.schema != CHIODOS_BUYER_ATTESTATION_PACKET_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_packet_schema",
            "buyer attestation packet declared an unsupported schema",
        );
    }
    validate_non_empty(&packet.packet_id, "buyer_packet_empty_id")?;
    validate_non_empty(&packet.buyer_id, "buyer_packet_empty_buyer")?;
    validate_non_empty(&packet.capability_id, "buyer_packet_empty_capability")?;
    ensure_sha256_hash(
        &packet.treaty_scope_sha256,
        "buyer_packet_invalid_treaty_hash",
    )?;
    ensure_sha256_hash(
        &packet.ladder_intersection_sha256,
        "buyer_packet_invalid_intersection_hash",
    )?;
    ensure_sha256_hash(
        &packet.cross_boundary_admission_report_sha256,
        "buyer_packet_invalid_admission_hash",
    )?;
    ensure_sha256_hash(
        &packet.continuation_sha256,
        "buyer_packet_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &packet.receipt_lineage_statement_sha256,
        "buyer_packet_invalid_lineage_hash",
    )?;
    ensure_sha256_hash(
        &packet.bilateral_invocation_sha256,
        "buyer_packet_invalid_bilateral_hash",
    )?;
    ensure_sha256_hash(
        &packet.bilateral_dsse_sha256,
        "buyer_packet_invalid_bilateral_dsse_hash",
    )?;
    ensure_sha256_hash(
        &packet.workflow_receipt_sha256,
        "buyer_packet_invalid_workflow_hash",
    )?;
    ensure_sha256_hash(
        &packet.proof_package_sha256,
        "buyer_packet_invalid_package_hash",
    )?;
    ensure_sha256_hash(
        &packet.verifier_report_sha256,
        "buyer_packet_invalid_verifier_hash",
    )
}

pub(crate) fn validate_buyer_attestation_verification_report(
    report: &BuyerAttestationVerificationReport,
) -> Result<(), ChiodosRuntimeError> {
    if report.schema != CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA {
        return rejected(
            "unsupported_buyer_attestation_verification_report_schema",
            "buyer attestation verification report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.packet_id, "buyer_verification_empty_packet")?;
    match (report.accepted, report.verification_state.as_str()) {
        (true, "hash_only") | (false, "rejected") => {}
        _ => {
            return rejected(
                "buyer_verification_invalid_state",
                "buyer attestation packet verification state must describe hash-only or rejected review",
            )
        }
    }
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "buyer_verification_missing_failure_code",
            "rejected buyer attestation verification report must include failure code",
        );
    }
    Ok(())
}

fn buyer_packet_rejection_report(
    packet: &BuyerAttestationPacket,
    failure_code: &'static str,
    checks: Vec<String>,
) -> BuyerAttestationVerificationReport {
    BuyerAttestationVerificationReport {
        schema: CHIODOS_BUYER_ATTESTATION_VERIFICATION_REPORT_SCHEMA.to_string(),
        packet_id: packet.packet_id.clone(),
        verification_state: "rejected".to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        checks,
    }
}
