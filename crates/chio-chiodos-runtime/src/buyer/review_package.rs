use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::crypto::sha256_hex;

use crate::buyer::helpers::{
    buyer_review_check, buyer_review_rejection_report, buyer_review_verification_context_window,
    review_refs_by_role, validate_buyer_attestation_review_package,
};
use crate::buyer::packet::verify_buyer_attestation_packet_with_resolved_dsse;
use crate::buyer::proof_package::{
    verify_buyer_review_existing_verifier, verify_buyer_review_lineage_binding,
    verify_buyer_review_proof_package, verify_receipt_lineage_bundle,
    BuyerReviewExistingVerifierContext,
};
use crate::buyer::review_hydration::{BuyerReviewHydratedArtifacts, BUYER_REVIEW_REQUIRED_ROLES};
use crate::buyer::runtime_report::{
    verify_buyer_review_runtime_reports, BuyerReviewRuntimeReportContext,
};
use crate::buyer::strict_dsse::{
    buyer_review_signer_public_keys_from_trust_bundle, verify_buyer_review_strict_dsse,
    BuyerReviewStrictDsseContext,
};
use crate::hash::canonical_sha256;
use crate::schema::CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA;
use crate::types::{
    BuyerAttestationReviewPackage, BuyerAttestationReviewReport, BuyerAttestationReviewSource,
    BuyerAttestationReviewTrustContext,
};
use crate::validation::{validate_non_empty, validate_relative_evidence_path};
use crate::ChiodosRuntimeError;

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
    let bilateral_dsse_sha256 = canonical_sha256(&bilateral_dsse)?;
    let packet_report = verify_buyer_attestation_packet_with_resolved_dsse(
        &packet,
        &lineage,
        &continuation,
        &admission,
        &bilateral,
        Some(&bilateral_dsse_sha256),
    )?;
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
        schema: CHIO_ATTEST_BUYER_ATTESTATION_REVIEW_REPORT_SCHEMA.to_string(),
        package_id: package.package_id.clone(),
        packet_id: package.packet_id.clone(),
        accepted: true,
        failure_code: None,
        checks,
    })
}
