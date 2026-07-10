const CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND: &str = "claim.disclosure.crypto_context_bound";

#[cfg(test)]
pub(crate) fn crypto_context_verified_report_bytes(
    context_bytes: &[u8],
    report_bytes: &[u8],
    fixture_id: &str,
) -> Result<Vec<u8>, String> {
    let _ = (context_bytes, report_bytes);
    Err(format!(
        "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: missing BBS proof material"
    ))
}

pub fn crypto_context_verified_report_bytes_with_bbs(
    context_bytes: &[u8],
    report_bytes: &[u8],
    proof_bytes: &[u8],
    privacy_profile_bytes: &[u8],
    fixture_id: &str,
) -> Result<Vec<u8>, String> {
    let context: chio_selective_disclosure::CryptoVerificationContext =
        serde_json::from_slice(context_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-invalid: {fixture_id}: {error}")
        })?;
    let report: chio_disclosure_lineage::DisclosureCryptoContextReport =
        serde_json::from_slice(report_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-report-invalid: {fixture_id}: {error}")
        })?;
    let proof: chio_selective_disclosure::SelectiveDisclosureProof =
        serde_json::from_slice(proof_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-proof-invalid: {fixture_id}: {error}")
        })?;
    let privacy_profile: chio_selective_disclosure::DisclosureVerifierPrivacyProfile =
        serde_json::from_slice(privacy_profile_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-profile-invalid: {fixture_id}: {error}")
        })?;
    if report.schema != chio_disclosure_lineage::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1 {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: unsupported schema"
        ));
    }
    let trust = crate::disclosure_lineage_verifier_trust_from_env().map_err(|error| {
        format!("proof-room.fixture.crypto-context-report-invalid: {fixture_id}: {error}")
    })?;
    chio_disclosure_lineage::verify_crypto_context_report_signature_with_trust(
        &report,
        trust.trusted_crypto_context_report_signer_keys(),
    )
    .map_err(|error| {
        format!("proof-room.fixture.crypto-context-report-invalid: {fixture_id}: {error}")
    })?;
    if report.verdict != chio_disclosure_lineage::DisclosureContextVerdict::Verified {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: verdict not verified"
        ));
    }
    if report.context_id != context.context_id {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: context id mismatch"
        ));
    }
    if report.artifact_ref != context.artifact_ref {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: artifact ref mismatch"
        ));
    }
    if !report.cryptographic_proof_verified {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: cryptographic proof not verified"
        ));
    }
    if !report.rejected_checks.is_empty() {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: verified report has rejected checks"
        ));
    }
    if !report
        .verified_claims
        .iter()
        .any(|claim| claim == CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND)
    {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: missing crypto context claim"
        ));
    }
    let recomputed =
        recompute_crypto_context_report(&context, &proof, &privacy_profile, fixture_id)?;
    if recomputed.verdict != chio_selective_disclosure::DisclosureContextVerdict::Verified {
        let rejected_codes = recomputed
            .rejected_checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if rejected_codes == "disclosure_context_nonce_replayed" {
            return Err(format!(
                "proof-room.negative.disclosure-context-nonce-replayed: {fixture_id}"
            ));
        }
        return Err(format!(
            "proof-room.fixture.crypto-context-invalid: {fixture_id}: {rejected_codes}"
        ));
    }
    if report.projection_manifest_ref != recomputed.projection_manifest_ref {
        return Err(format!(
            "proof-room.negative.disclosure-crypto-report-projection-manifest-ref-mismatch: {fixture_id}"
        ));
    }
    ensure_same_string_set(
        fixture_id,
        "verified claims",
        &report.verified_claims,
        &recomputed.verified_claims,
    )?;
    ensure_same_string_set(
        fixture_id,
        "disclosed fields",
        &report.disclosed_fields,
        &recomputed.disclosed_fields,
    )?;
    Ok(report_bytes.to_vec())
}

pub fn crypto_context_rejected_report_bytes_with_bbs(
    context_bytes: &[u8],
    proof_bytes: &[u8],
    privacy_profile_bytes: &[u8],
    fixture_id: &str,
) -> Result<Vec<u8>, String> {
    let context: chio_selective_disclosure::CryptoVerificationContext =
        serde_json::from_slice(context_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-invalid: {fixture_id}: {error}")
        })?;
    let proof: chio_selective_disclosure::SelectiveDisclosureProof =
        serde_json::from_slice(proof_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-proof-invalid: {fixture_id}: {error}")
        })?;
    let privacy_profile: chio_selective_disclosure::DisclosureVerifierPrivacyProfile =
        serde_json::from_slice(privacy_profile_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-profile-invalid: {fixture_id}: {error}")
        })?;
    let report = recompute_crypto_context_report(&context, &proof, &privacy_profile, fixture_id)?;
    if report.verdict != chio_selective_disclosure::DisclosureContextVerdict::Rejected {
        return Err(format!(
            "proof-room.fixture.crypto-context-invalid: {fixture_id}: context unexpectedly verified"
        ));
    }
    serde_json::to_vec(&report).map_err(|error| {
        format!("proof-room.fixture.crypto-context-report-encode: {fixture_id}: {error}")
    })
}

fn recompute_crypto_context_report(
    context: &chio_selective_disclosure::CryptoVerificationContext,
    proof: &chio_selective_disclosure::SelectiveDisclosureProof,
    privacy_profile: &chio_selective_disclosure::DisclosureVerifierPrivacyProfile,
    fixture_id: &str,
) -> Result<chio_selective_disclosure::DisclosureCryptoContextReport, String> {
    let public_key_bytes = hex::decode(&proof.issuer_public_key_hex).map_err(|error| {
        format!("proof-room.fixture.crypto-context-proof-invalid: {fixture_id}: {error}")
    })?;
    if chio_core_types::sha256_hex(&public_key_bytes) != proof.issuer_fingerprint {
        return Err(format!(
            "proof-room.fixture.crypto-context-proof-invalid: {fixture_id}: issuer fingerprint mismatch"
        ));
    }
    let mut registry = chio_selective_disclosure::InMemoryIssuerRegistry::default();
    registry.insert(
        proof.issuer_fingerprint.clone(),
        proof.issuer_public_key_hex.clone(),
    );
    let mut proof_context = context.clone();
    proof_context.artifact_ref = proof.subject_sha256_hex.clone();
    chio_selective_disclosure::verify_selective_disclosure_with_context(
        proof,
        &registry,
        &proof_context,
        privacy_profile,
    )
    .map_err(|error| {
        format!("proof-room.fixture.crypto-context-proof-invalid: {fixture_id}: {error}")
    })
}

fn ensure_same_string_set(
    fixture_id: &str,
    label: &str,
    actual: &[String],
    expected: &[String],
) -> Result<(), String> {
    let actual = actual
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = expected
        .iter()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: {label} did not match recomputed BBS verification"
        ));
    }
    Ok(())
}
