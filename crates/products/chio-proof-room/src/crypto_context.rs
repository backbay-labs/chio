const CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND: &str = "claim.disclosure.crypto_context_bound";
const CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1: &str = "chio.crypto.verification-context.v1";

pub(crate) fn crypto_context_verified_report_bytes(
    context_bytes: &[u8],
    report_bytes: &[u8],
    fixture_id: &str,
) -> Result<Vec<u8>, String> {
    match crypto_context_rejection_report_bytes(context_bytes, fixture_id) {
        Ok(rejection_report_bytes) => {
            return Err(format!(
                "proof-room.fixture.crypto-context-invalid: {fixture_id}: {}",
                crypto_context_rejection_summary(&rejection_report_bytes)
            ));
        }
        Err(error) if error.contains("no rejected context checks") => {}
        Err(error) => return Err(error),
    }

    let context: serde_json::Value = serde_json::from_slice(context_bytes).map_err(|error| {
        format!("proof-room.fixture.crypto-context-invalid: {fixture_id}: {error}")
    })?;
    let context_id = required_context_string(&context, "context_id", fixture_id)?;
    let artifact_ref = required_context_string(&context, "artifact_ref", fixture_id)?;
    let report: chio_disclosure_lineage::DisclosureCryptoContextReport =
        serde_json::from_slice(report_bytes).map_err(|error| {
            format!("proof-room.fixture.crypto-context-report-invalid: {fixture_id}: {error}")
        })?;
    if report.schema != chio_disclosure_lineage::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1 {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: unsupported schema"
        ));
    }
    if report.verdict != chio_disclosure_lineage::DisclosureContextVerdict::Verified {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: verdict not verified"
        ));
    }
    if report.context_id != context_id {
        return Err(format!(
            "proof-room.fixture.crypto-context-report-invalid: {fixture_id}: context id mismatch"
        ));
    }
    if report.artifact_ref != artifact_ref {
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
    Ok(report_bytes.to_vec())
}

pub fn crypto_context_rejection_report_bytes(
    context_bytes: &[u8],
    fixture_id: &str,
) -> Result<Vec<u8>, String> {
    let context: serde_json::Value = serde_json::from_slice(context_bytes).map_err(|error| {
        format!("proof-room.fixture.crypto-context-invalid: {fixture_id}: {error}")
    })?;
    if context.get("schema").and_then(serde_json::Value::as_str)
        != Some(CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1)
    {
        return Err(format!(
            "proof-room.fixture.crypto-context-invalid: {fixture_id}: unsupported schema"
        ));
    }
    let context_id = required_context_string(&context, "context_id", fixture_id)?;
    let artifact_ref = required_context_string(&context, "artifact_ref", fixture_id)?;
    let rejected_checks = crypto_context_rejected_checks(&context);
    if rejected_checks.is_empty() {
        return Err(format!(
            "proof-room.fixture.crypto-context-invalid: {fixture_id}: no rejected context checks"
        ));
    }
    let report = chio_disclosure_lineage::DisclosureCryptoContextReport {
        schema: chio_disclosure_lineage::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1.to_string(),
        id: format!("disclosure-crypto-context-report-{context_id}"),
        context_id,
        artifact_ref,
        verdict: chio_disclosure_lineage::DisclosureContextVerdict::Rejected,
        evidence_class: "verifier_context".to_string(),
        cryptographic_proof_verified: true,
        verified_claims: Vec::new(),
        rejected_checks,
        disclosed_fields: Vec::new(),
    };
    serde_json::to_vec(&report).map_err(|error| {
        format!("proof-room.fixture.crypto-context-report-encode: {fixture_id}: {error}")
    })
}

fn crypto_context_rejection_summary(report_bytes: &[u8]) -> String {
    let Ok(report) = serde_json::from_slice::<serde_json::Value>(report_bytes) else {
        return "invalid rejection report".to_string();
    };
    report
        .get("rejected_checks")
        .and_then(serde_json::Value::as_array)
        .and_then(|checks| checks.first())
        .and_then(|check| {
            let code = check.get("code").and_then(serde_json::Value::as_str)?;
            let message = check
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            Some(if message.is_empty() {
                code.to_string()
            } else {
                format!("{code}: {message}")
            })
        })
        .unwrap_or_else(|| "rejected without checks".to_string())
}

fn required_context_string(
    value: &serde_json::Value,
    field: &str,
    fixture_id: &str,
) -> Result<String, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|field_value| !field_value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            format!("proof-room.fixture.crypto-context-invalid: {fixture_id}: missing {field}")
        })
}

fn crypto_context_rejected_checks(
    context: &serde_json::Value,
) -> Vec<chio_disclosure_lineage::DisclosureContextCheck> {
    let mut checks = Vec::new();
    if context.get("algorithm").and_then(serde_json::Value::as_str) != Some("bbs-bls12381-sha256") {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_algorithm_forbidden",
            "proof algorithm is not allowed by the verifier profile",
        ));
    }
    if context
        .get("key_state")
        .and_then(|key_state| key_state.get("status"))
        .and_then(serde_json::Value::as_str)
        != Some("active")
    {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_key_not_active",
            "issuer key state is not active",
        ));
    }
    if context.get("revocation_snapshot").is_none() {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_revocation_snapshot_missing",
            "revocation snapshot evidence is missing",
        ));
    }
    if context
        .get("nonce_replay_status")
        .and_then(serde_json::Value::as_str)
        == Some("replayed")
    {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_nonce_replayed",
            "presentation nonce has already been observed",
        ));
    }
    if context.get("holder_binding_ref").is_none()
        || context
            .get("holder_binding_status")
            .and_then(serde_json::Value::as_str)
            != Some("bound")
    {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_holder_binding_missing",
            "holder binding evidence is missing",
        ));
    }
    if context
        .get("transparency_state")
        .and_then(serde_json::Value::as_str)
        != Some("anchored")
    {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_transparency_state_insufficient",
            "transparency state does not satisfy the verifier profile",
        ));
    }
    if context.get("audience").and_then(serde_json::Value::as_str)
        != Some("https://auditor.example/chio")
    {
        checks.push(chio_disclosure_lineage::DisclosureContextCheck::new(
            "disclosure_context_audience_mismatch",
            "verifier audience does not match the presentation audience",
        ));
    }
    checks
}
