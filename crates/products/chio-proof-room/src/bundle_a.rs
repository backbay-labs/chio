use super::*;

pub(crate) fn verify_proof_room_bundle_inner(manifest_path: &Path) -> Result<(), String> {
    verify_proof_room_bundle_inner_with_options(manifest_path, true, true, true)
}

pub(crate) fn verify_proof_room_bundle_inner_with_options(
    manifest_path: &Path,
    verify_manifest_negative_cases: bool,
    verify_manifest_signature: bool,
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    let bundle_root = manifest_path
        .parent()
        .ok_or_else(|| "proof-room.bundle.path-invalid: manifest has no parent".to_string())?;
    validate_bundle_tree_file_types(bundle_root)?;

    let manifest_bytes =
        fs::read(manifest_path).map_err(|error| format!("missing or unreadable: {error}"))?;
    let manifest_value: serde_json::Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid Proof Room manifest JSON: {error}"))?;
    validate_proof_room_schema(&manifest_value, PROOF_ROOM_BUNDLE_SCHEMA_JSON, "manifest")?;
    let manifest: ProofRoomBundleManifest = serde_json::from_value(manifest_value)
        .map_err(|error| format!("invalid Proof Room manifest JSON: {error}"))?;
    if manifest.schema != PROOF_ROOM_BUNDLE_SCHEMA {
        return Err(format!(
            "proof-room.bundle.schema-mismatch: expected {PROOF_ROOM_BUNDLE_SCHEMA}"
        ));
    }
    if manifest.hash_algorithm != "sha256" {
        return Err("proof-room.hash.unsupported: expected sha256".to_string());
    }
    let requires_first_run_claims = manifest.fixture_id == "single-call-authority";

    if verify_manifest_signature {
        verify_bundle_signature(bundle_root, &manifest, &manifest_bytes)?;
    }
    let transaction_passport = verify_manifest_ref(
        bundle_root,
        &manifest.transaction_passport_ref,
        "transaction_passport_ref",
        Some("chio.transaction-passport.v1"),
    )?;
    let evidence_graph = verify_manifest_ref(
        bundle_root,
        &manifest.evidence_graph_ref,
        "evidence_graph_ref",
        Some("chio.transaction.evidence-graph.v1"),
    )?;
    let has_authority_claim =
        has_claim(&manifest.claims, CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND);
    let requires_authority_evidence = requires_first_run_claims || has_authority_claim;
    if requires_authority_evidence {
        verify_first_run_authority_evidence(bundle_root, &manifest.claims, &manifest.artifacts)?;
        verify_first_run_evidence_graph_binding(&evidence_graph.bytes, &manifest.artifacts)?;
    }
    let verifier_report = verify_manifest_ref(
        bundle_root,
        &manifest.verifier_report_ref,
        "verifier_report_ref",
        Some("chio.transaction.verifier-report.v1"),
    )?;
    let verifier_report_value: serde_json::Value =
        serde_json::from_slice(&verifier_report.bytes)
            .map_err(|error| format!("proof-room.report.invalid-json: {error}"))?;
    verify_source_verifier_report(
        bundle_root,
        &transaction_passport,
        &verifier_report_value,
        verify_transaction_passport_signature,
    )?;
    verify_manifest_claims(
        &manifest.claims,
        &manifest.artifacts,
        &manifest.verifier_report_ref,
        manifest.proof_room_verifier_report_ref.as_ref(),
        &verifier_report_value,
        requires_first_run_claims,
    )?;
    let has_receipt_matrix_claim = has_claim(
        &manifest.claims,
        CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND,
    );
    let trusted_receipt_kernel_keys = proof_room_trusted_receipt_kernel_keys_from_env()?;
    receipt_coverage::verify(
        bundle_root,
        &manifest.receipt_coverage,
        &manifest.artifacts,
        &trusted_receipt_kernel_keys,
        requires_first_run_claims || has_receipt_matrix_claim,
    )?;
    if verify_manifest_negative_cases {
        verify_negative_cases(
            bundle_root,
            &manifest.negative_cases,
            requires_first_run_claims,
            verify_transaction_passport_signature,
        )?;
    }
    let source_verifier_verdict = verifier_report_value
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "proof-room.report.verdict-missing".to_string())?;
    let proof_room_report_path = manifest
        .proof_room_verifier_report_ref
        .as_ref()
        .map(|reference| reference.path.as_str());
    for artifact in &manifest.artifacts {
        let label = if proof_room_report_path == Some(artifact.path.as_str())
            && artifact.schema == PROOF_ROOM_VERIFIER_REPORT_SCHEMA
        {
            "ui-report"
        } else {
            "artifact"
        };
        verify_manifest_ref(bundle_root, artifact, label, None)?;
    }
    if let Some(proof_room_report_ref) = &manifest.proof_room_verifier_report_ref {
        let proof_room_report = verify_manifest_ref(
            bundle_root,
            proof_room_report_ref,
            "proof_room_verifier_report_ref",
            Some(PROOF_ROOM_VERIFIER_REPORT_SCHEMA),
        )?;
        verify_proof_room_report(
            &proof_room_report.bytes,
            &manifest.bundle_id,
            &manifest.fixture_id,
            &manifest.verifier_report_ref,
            source_verifier_verdict,
            &manifest.claims,
        )?;
    }

    Ok(())
}

pub(crate) fn write_doctor_report(path: &Path, bundle: &Path) -> Result<(), ProofRoomError> {
    let manifest_path = bundle.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).map_err(|source| ProofRoomError::Io {
        context: "proof-room.doctor-report.manifest-read",
        source,
    })?;
    let manifest: ProofRoomBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| ProofRoomError::Json {
            context: "proof-room.doctor-report.manifest-json",
            source,
        })?;
    let report = ProofRoomDoctorReport {
        schema: "chio.proof-room.quickstart-doctor-report.v1",
        verdict: "verified",
        bundle: &bundle.to_string_lossy(),
        bundle_id: &manifest.bundle_id,
        fixture_id: &manifest.fixture_id,
        verifier_report_ref: &manifest.verifier_report_ref,
        receipt_coverage: &manifest.receipt_coverage,
        negative_cases: &manifest.negative_cases,
    };
    let bytes = serde_json::to_vec_pretty(&report).map_err(|source| ProofRoomError::Json {
        context: "proof-room.doctor-report.encode",
        source,
    })?;
    fs::write(path, bytes).map_err(|source| ProofRoomError::Io {
        context: "proof-room.doctor-report.write",
        source,
    })
}

pub(crate) fn verify_negative_cases(
    bundle_root: &Path,
    negative_cases: &[ProofRoomNegativeCase],
    require_cases: bool,
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    if negative_cases.is_empty() {
        return if require_cases {
            Err("proof-room.negative-case.missing".to_string())
        } else {
            Ok(())
        };
    }
    let mut ids = BTreeSet::new();
    for negative_case in negative_cases {
        if negative_case.id.is_empty() {
            return Err("proof-room.negative-case.id-missing".to_string());
        }
        if !ids.insert(negative_case.id.as_str()) {
            return Err(format!(
                "proof-room.negative-case.duplicate: {}",
                negative_case.id
            ));
        }
        if negative_case.path.is_empty() {
            return Err(format!(
                "proof-room.negative-case.path-missing: {}",
                negative_case.id
            ));
        }
        if negative_case.expected_failure_code.is_empty() {
            return Err(format!(
                "proof-room.negative-case.expected-failure-missing: {}",
                negative_case.id
            ));
        }
        let negative_path = resolve_proof_room_bundle_path(bundle_root, &negative_case.path)?;
        let _env_overrides = negative_case.verifier_context.apply();
        let error = match verify_negative_case_path(
            bundle_root,
            &negative_path,
            negative_case,
            verify_transaction_passport_signature,
        ) {
            Ok(()) => {
                return Err(format!(
                    "proof-room.negative-case.unexpected-success: {}",
                    negative_case.id
                ));
            }
            Err(error) => error,
        };
        if !negative_failure_code_matches(&error, &negative_case.expected_failure_code) {
            return Err(format!(
                "proof-room.negative-case.failure-mismatch: {} expected {} got {error}",
                negative_case.id, negative_case.expected_failure_code
            ));
        }
        if let Some(observed_failure_code) = negative_case.observed_failure_code.as_deref() {
            if observed_failure_code.is_empty() {
                return Err(format!(
                    "proof-room.negative-case.observed-failure-missing: {}",
                    negative_case.id
                ));
            }
            if !negative_failure_code_matches(&error, observed_failure_code) {
                return Err(format!(
                    "proof-room.negative-case.observed-failure-mismatch: {} expected {} got {error}",
                    negative_case.id, observed_failure_code
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn negative_failure_code_matches(error: &str, expected_code: &str) -> bool {
    if error.match_indices(expected_code).any(|(index, _)| {
        let before = error[..index].chars().next_back();
        let after = error[index + expected_code.len()..].chars().next();
        negative_failure_code_start_boundary(before) && negative_failure_code_end_boundary(after)
    }) {
        return true;
    }
    stable_negative_failure_code(error) == expected_code
}

pub(crate) fn stable_negative_failure_code(code: &str) -> String {
    let normalized = strip_negative_failure_context(code);
    if is_dotted_negative_failure_code(normalized) {
        return normalized.to_string();
    }
    let slug = slug_negative_failure_code(normalized);
    if slug.is_empty() {
        "proof-room.negative.unknown".to_string()
    } else {
        format!("proof-room.negative.{slug}")
    }
}

fn strip_negative_failure_context(mut code: &str) -> &str {
    code = code.trim();
    for prefix in [
        "proof-room.source-verifier.failed: ",
        "proof-room.passport.invalid: ",
        "invalid disclosure lineage artifact: ",
        "invalid agent web interop artifact: ",
        "invalid Agent Web interop artifact: ",
        "invalid public settlement artifact: ",
        "invalid enterprise export artifact: ",
        "invalid trust market artifact: ",
        "invalid runtime security artifact: ",
        "runtime security claim failed: ",
        "invalid evidence graph artifact: ",
        "minimal governed action evidence invalid: ",
        "commerce payment failed: ",
        "commerce mandate failed: ",
        "commerce event log failed: ",
        "commerce replay failed: ",
        "commerce recovery failed: ",
        "commerce fraud failed: ",
        "swarm authority invalid: ",
        "public settlement proof invalid: ",
        "invalid settlement: ",
        "invalid proof: ",
        "agent web interop invalid: ",
        "agent web claim failed: ",
        "Agent Web claim failed: ",
        "enterprise export invalid: ",
        "enterprise export claim failed: ",
        "risk comptroller claim failed: ",
        "trust market context invalid: ",
        "trust market claim failed: ",
        "trust-market claim failed: ",
        "Trust market claim failed: ",
        "Trust Market claim failed: ",
    ] {
        if let Some(stripped) = code.strip_prefix(prefix) {
            code = stripped.trim();
        }
    }
    if !is_dotted_negative_failure_code(code) {
        if let Some((base, _detail)) = code.split_once(": ") {
            code = base.trim();
        }
    }
    code
}

fn is_dotted_negative_failure_code(code: &str) -> bool {
    let base = code.split(':').next().unwrap_or(code);
    !base.is_empty()
        && base.contains('.')
        && !base.chars().any(char::is_whitespace)
        && base.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '-' | '_')
        })
}

fn slug_negative_failure_code(code: &str) -> String {
    let mut slug = String::new();
    let mut last_was_separator = false;
    for character in code.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            slug.push(character);
            last_was_separator = false;
        } else if !last_was_separator {
            slug.push('-');
            last_was_separator = true;
        }
    }
    slug.trim_matches('-').to_string()
}

pub(crate) fn negative_failure_code_start_boundary(boundary: Option<char>) -> bool {
    boundary.is_none_or(|character| character == ':' || character.is_ascii_whitespace())
}

pub(crate) fn negative_failure_code_end_boundary(boundary: Option<char>) -> bool {
    boundary.is_none_or(|character| character == ':')
}

pub(crate) fn verify_negative_case_path(
    bundle_root: &Path,
    negative_path: &Path,
    negative_case: &ProofRoomNegativeCase,
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    let bytes = fs::read(negative_path)
        .map_err(|error| format!("proof-room.negative-case.unreadable: {error}"))?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("proof-room.negative-case.invalid-json: {error}"))?;
    if value.get("mutation").is_some() {
        let descriptor: ProofRoomNegativeDescriptor = serde_json::from_value(value)
            .map_err(|error| format!("proof-room.negative-case.descriptor-invalid: {error}"))?;
        verify_proof_room_negative_descriptor(bundle_root, &descriptor, negative_case)
    } else {
        verify_negative_transaction_passport(negative_path, verify_transaction_passport_signature)
            .map(|_| ())
    }
}

pub(crate) fn verify_proof_room_negative_descriptor(
    bundle_root: &Path,
    descriptor: &ProofRoomNegativeDescriptor,
    negative_case: &ProofRoomNegativeCase,
) -> Result<(), String> {
    if !descriptor.schema.is_empty() && descriptor.schema != "chio.proof-room.negative-fixture.v1" {
        return Err(format!(
            "proof-room.negative-case.descriptor-schema-unsupported: {}",
            descriptor.schema
        ));
    }
    if descriptor.id != negative_case.id {
        return Err(format!(
            "proof-room.negative-case.descriptor-id-mismatch: {}",
            negative_case.id
        ));
    }
    if descriptor.expected_failure_code != negative_case.expected_failure_code {
        return Err(format!(
            "proof-room.negative-case.descriptor-expected-failure-mismatch: {}",
            negative_case.id
        ));
    }

    let work = create_negative_case_work_dir(&negative_case.id)?;
    let result = (|| {
        copy_dir_all(bundle_root, &work)?;
        apply_proof_room_negative_descriptor(&work, descriptor)?;
        let manifest_path = resolve_proof_room_bundle_path(&work, &descriptor.base_manifest)?;
        verify_proof_room_bundle_inner_with_options(&manifest_path, false, false, false)
    })();
    let _ = fs::remove_dir_all(&work);
    result
}

pub(crate) fn verify_negative_transaction_passport(
    path: &Path,
    verify_transaction_passport_signature: bool,
) -> Result<(), String> {
    let bundle_root = path
        .parent()
        .ok_or_else(|| "proof-room.negative-case.path-invalid".to_string())?;
    verify_transaction_passport_family_report_with_options(
        bundle_root,
        path,
        verify_transaction_passport_signature,
    )
    .map(|_| ())
}

pub(crate) fn verify_manifest_claims(
    claims: &[ProofRoomClaim],
    artifacts: &[ProofRoomArtifactRef],
    verifier_report_ref: &ProofRoomArtifactRef,
    proof_room_report_ref: Option<&ProofRoomArtifactRef>,
    source_report: &serde_json::Value,
    require_first_run_claims: bool,
) -> Result<(), String> {
    if claims.is_empty() {
        return Err("proof-room.claim.missing: manifest has no claims".to_string());
    }
    let artifact_paths = artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    for claim in claims {
        let source_verified = source_report_verifies_claim(source_report, &claim.claim_id);
        let bundle_allowed = ALLOWED_BUNDLE_CLAIMS.contains(&claim.claim_id.as_str());
        if !bundle_allowed && !source_verified {
            return Err(format!("proof-room.claim.unregistered: {}", claim.claim_id));
        }
        if source_verified && claim.result != "verified" {
            return Err(format!(
                "proof-room.claim.source-result-mismatch: {}",
                claim.claim_id
            ));
        }
        if bundle_allowed && claim.result != "verified" {
            return Err(format!(
                "proof-room.claim.result-unverified: {}",
                claim.claim_id
            ));
        }
        if claim.required_artifacts.is_empty() {
            return Err(format!(
                "proof-room.claim.required-artifacts-missing: {}",
                claim.claim_id
            ));
        }
        for artifact_path in &claim.required_artifacts {
            if !artifact_paths.contains(artifact_path.as_str()) {
                return Err(format!(
                    "proof-room.claim.required-artifact-missing: {} -> {}",
                    claim.claim_id, artifact_path
                ));
            }
        }
        match claim.claim_id.as_str() {
            CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND => {
                require_claim_artifact(
                    claim,
                    &verifier_report_ref.path,
                    "proof-room.report.claim-source-missing",
                )?;
                if let Some(proof_room_report_ref) = proof_room_report_ref {
                    require_claim_artifact(
                        claim,
                        &proof_room_report_ref.path,
                        "proof-room.ui-report.claim-source-missing",
                    )?;
                }
            }
            CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE => {
                require_claim_artifact(
                    claim,
                    "artifacts/receipts/allow-receipt.json",
                    "proof-room.first-run.allow-missing",
                )?;
                require_claim_artifact(
                    claim,
                    "artifacts/receipts/denial-receipt.json",
                    "proof-room.first-run.denial-missing",
                )?;
            }
            _ => {}
        }
    }
    if !has_claim(claims, CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND) {
        return Err(format!(
            "proof-room.claim.missing: {CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND}"
        ));
    }
    if require_first_run_claims {
        for required_claim in REQUIRED_FIRST_RUN_PROOF_ROOM_CLAIMS {
            if !has_claim(claims, required_claim) {
                if *required_claim == CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND {
                    return Err("proof-room.first-run.authority-evidence-missing".to_string());
                }
                return Err(format!("proof-room.claim.missing: {required_claim}"));
            }
        }
    }
    Ok(())
}

pub(crate) fn has_claim(claims: &[ProofRoomClaim], claim_id: &str) -> bool {
    claims.iter().any(|claim| claim.claim_id == claim_id)
}

pub(crate) fn source_report_verifies_claim(
    source_report: &serde_json::Value,
    claim_id: &str,
) -> bool {
    if source_report
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        != Some("verified")
    {
        return false;
    }
    if claim_id == CLAIM_TRANSACTION_PASSPORT_ROOT_VERIFIED {
        return source_report
            .get("schema")
            .and_then(serde_json::Value::as_str)
            == Some("chio.transaction.verifier-report.v1");
    }
    source_report
        .get("verified_claims")
        .or_else(|| source_report.get("verifiedClaims"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|claims| claims.iter().any(|claim| claim.as_str() == Some(claim_id)))
}

pub(crate) fn verify_first_run_authority_evidence(
    bundle_root: &Path,
    claims: &[ProofRoomClaim],
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let Some(authority_claim) = claims
        .iter()
        .find(|claim| claim.claim_id == CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND)
    else {
        return Err("proof-room.first-run.authority-evidence-missing".to_string());
    };

    for (artifact_path, schema) in REQUIRED_AUTHORITY_ARTIFACTS {
        require_claim_artifact(
            authority_claim,
            artifact_path,
            "proof-room.first-run.authority-evidence-missing",
        )?;
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.path == *artifact_path)
            .ok_or_else(|| "proof-room.first-run.authority-evidence-missing".to_string())?;
        let verified = verify_manifest_ref_defer_json_schema(
            bundle_root,
            artifact,
            "authority_evidence",
            Some(schema),
        )?;
        validate_authority_artifact(artifact_path, &verified.bytes)?;
        validate_json_artifact_schema(&verified.bytes, schema, "authority_evidence")?;
    }
    verify_first_run_guard_receipt_refs(bundle_root, artifacts)?;
    Ok(())
}

pub(crate) fn verify_first_run_guard_receipt_refs(
    bundle_root: &Path,
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let guard_artifact = artifact_ref(
        artifacts,
        "artifacts/authority/guard-report.json",
        "proof-room.first-run.authority-evidence-missing",
    )?;
    let guard_report = verify_manifest_ref(
        bundle_root,
        guard_artifact,
        "authority_evidence",
        Some(PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA),
    )?;
    let guard: serde_json::Value = serde_json::from_slice(&guard_report.bytes)
        .map_err(|error| format!("proof-room.first-run.guard-report-invalid: {error}"))?;
    let allow_receipt_ref = required_json_string(
        &guard,
        "allow_receipt_ref",
        "proof-room.first-run.guard-allow-receipt-ref-missing",
    )?;
    let denial_receipt_ref = required_json_string(
        &guard,
        "denial_receipt_ref",
        "proof-room.first-run.guard-denial-receipt-ref-missing",
    )?;
    let allow_receipt_id = first_run_receipt_id(
        bundle_root,
        artifacts,
        "artifacts/receipts/allow-receipt.json",
        "proof-room.first-run.allow-missing",
    )?;
    let denial_receipt_id = first_run_receipt_id(
        bundle_root,
        artifacts,
        "artifacts/receipts/denial-receipt.json",
        "proof-room.first-run.denial-missing",
    )?;
    if allow_receipt_ref != allow_receipt_id {
        return Err("proof-room.first-run.guard-allow-receipt-mismatch".to_string());
    }
    if denial_receipt_ref != denial_receipt_id {
        return Err("proof-room.first-run.guard-denial-receipt-mismatch".to_string());
    }
    Ok(())
}

pub(crate) fn first_run_receipt_id(
    bundle_root: &Path,
    artifacts: &[ProofRoomArtifactRef],
    artifact_path: &str,
    missing_code: &str,
) -> Result<String, String> {
    let receipt_artifact = artifact_ref(artifacts, artifact_path, missing_code)?;
    let receipt = verify_manifest_ref(
        bundle_root,
        receipt_artifact,
        "first_run_receipt",
        Some(PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA),
    )?;
    let value: serde_json::Value = serde_json::from_slice(&receipt.bytes).map_err(|error| {
        format!("proof-room.first-run.receipt-invalid: {artifact_path}: {error}")
    })?;
    required_json_string(
        &value,
        "receipt_id",
        "proof-room.first-run.receipt-id-missing",
    )
    .map(str::to_string)
}

pub(crate) fn artifact_ref<'a>(
    artifacts: &'a [ProofRoomArtifactRef],
    artifact_path: &str,
    missing_code: &str,
) -> Result<&'a ProofRoomArtifactRef, String> {
    artifacts
        .iter()
        .find(|artifact| artifact.path == artifact_path)
        .ok_or_else(|| format!("{missing_code}: {artifact_path}"))
}

pub(crate) fn required_json_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
    missing_code: &str,
) -> Result<&'a str, String> {
    let Some(field_value) = value.get(field).and_then(serde_json::Value::as_str) else {
        return Err(missing_code.to_string());
    };
    if field_value.is_empty() {
        return Err(missing_code.to_string());
    }
    Ok(field_value)
}

pub(crate) fn verify_first_run_evidence_graph_binding(
    evidence_graph_bytes: &[u8],
    artifacts: &[ProofRoomArtifactRef],
) -> Result<(), String> {
    let graph: serde_json::Value = serde_json::from_slice(evidence_graph_bytes)
        .map_err(|error| format!("proof-room.evidence-graph.invalid-json: {error}"))?;
    let nodes = graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "proof-room.evidence-graph.nodes-missing".to_string())?;
    for (artifact_path, _schema) in REQUIRED_AUTHORITY_ARTIFACTS {
        require_graph_bound_artifact(
            nodes,
            artifacts,
            artifact_path,
            "proof-room.evidence-graph.authority-node-missing",
        )?;
    }
    for artifact_path in REQUIRED_RECEIPT_ARTIFACTS {
        require_graph_bound_artifact(
            nodes,
            artifacts,
            artifact_path,
            "proof-room.evidence-graph.receipt-node-missing",
        )?;
    }
    Ok(())
}

pub(crate) fn require_graph_bound_artifact(
    nodes: &[serde_json::Value],
    artifacts: &[ProofRoomArtifactRef],
    artifact_path: &str,
    missing_code: &str,
) -> Result<(), String> {
    let artifact = artifacts
        .iter()
        .find(|artifact| artifact.path == artifact_path)
        .ok_or_else(|| format!("{missing_code}: {artifact_path}"))?;
    let node = nodes
        .iter()
        .find(|node| node.get("path").and_then(serde_json::Value::as_str) == Some(artifact_path))
        .ok_or_else(|| format!("{missing_code}: {artifact_path}"))?;
    let node_schema = node
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof-room.evidence-graph.node-schema-missing: {artifact_path}"))?;
    if node_schema != artifact.schema {
        return Err(format!(
            "proof-room.evidence-graph.node-schema-mismatch: {artifact_path}"
        ));
    }
    let node_sha256 = node
        .get("sha256")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("proof-room.evidence-graph.node-hash-missing: {artifact_path}"))?;
    if node_sha256 != artifact.sha256 {
        return Err(format!(
            "proof-room.evidence-graph.node-hash-mismatch: {artifact_path}"
        ));
    }
    Ok(())
}

pub(crate) fn validate_authority_artifact(path: &str, bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("proof-room.authority-evidence.invalid-json: {path}: {error}"))?;
    match path {
        "artifacts/authority/capability-proof.json" => require_json_fields(
            path,
            &value,
            &[
                "capability_id",
                "issuer",
                "subject",
                "scope",
                "policy_digest",
                "not_before",
                "expires_at",
                "signature",
            ],
        ),
        "artifacts/authority/guard-report.json" => require_json_fields(
            path,
            &value,
            &[
                "capability_id",
                "guard_id",
                "decision",
                "policy_digest",
                "allow_receipt_ref",
                "denial_receipt_ref",
                "request_digest",
                "response_digest",
                "signature",
            ],
        ),
        "artifacts/authority/trust-roots.json" => {
            require_json_fields(path, &value, &["trust_domain", "signature"])?;
            let roots = value
                .get("roots")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| {
                    format!("proof-room.authority-evidence.field-missing: {path} roots")
                })?;
            if roots.is_empty() {
                Err(format!(
                    "proof-room.authority-evidence.field-missing: {path} roots"
                ))
            } else {
                Ok(())
            }
        }
        _ => Ok(()),
    }
}

pub(crate) fn require_json_fields(
    path: &str,
    value: &serde_json::Value,
    fields: &[&str],
) -> Result<(), String> {
    for field in fields {
        let Some(value) = value.get(*field).and_then(serde_json::Value::as_str) else {
            return Err(format!(
                "proof-room.authority-evidence.field-missing: {path} {field}"
            ));
        };
        if value.is_empty() {
            return Err(format!(
                "proof-room.authority-evidence.field-missing: {path} {field}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_claim_artifact(
    claim: &ProofRoomClaim,
    artifact_path: &str,
    error_code: &str,
) -> Result<(), String> {
    if claim
        .required_artifacts
        .iter()
        .any(|required| required == artifact_path)
    {
        return Ok(());
    }
    Err(error_code.to_string())
}

pub(crate) fn verify_bundle_signature(
    bundle_root: &Path,
    manifest: &ProofRoomBundleManifest,
    manifest_bytes: &[u8],
) -> Result<(), String> {
    let signature = manifest
        .signature
        .as_ref()
        .ok_or_else(|| "proof-room.signature.missing".to_string())?;
    if signature.kind != PROOF_ROOM_SIGNATURE_KIND {
        return Err(format!(
            "proof-room.signature.kind-unsupported: {}",
            signature.kind
        ));
    }
    if signature.signature_ref.is_empty() {
        return Err("proof-room.signature.path-missing".to_string());
    }

    let signature_path = resolve_proof_room_bundle_path(bundle_root, &signature.signature_ref)?;
    let signature_bytes = fs::read(&signature_path)
        .map_err(|error| format!("proof-room.signature.unreadable: {error}"))?;
    let detached: ProofRoomDetachedDsse = serde_json::from_slice(&signature_bytes)
        .map_err(|error| format!("proof-room.signature.invalid-json: {error}"))?;

    if detached.payload_type != PROOF_ROOM_DSSE_PAYLOAD_TYPE {
        return Err("proof-room.signature.payload-type-mismatch".to_string());
    }
    if detached.payload_ref.path != "manifest.json" {
        return Err("proof-room.signature.payload-path-mismatch".to_string());
    }
    if detached.payload_ref.schema != PROOF_ROOM_BUNDLE_SCHEMA {
        return Err("proof-room.signature.payload-schema-mismatch".to_string());
    }
    let actual_manifest_sha256 = sha256_hex(manifest_bytes);
    if detached.payload_ref.sha256 != actual_manifest_sha256 {
        return Err("proof-room.signature.payload-hash-mismatch".to_string());
    }
    if detached.signatures.is_empty() {
        return Err("proof-room.signature.signatures-missing".to_string());
    }
    let declared_signer_keys = trusted_bundle_signer_keys(bundle_root, manifest)?;
    let trusted_signer_keys = proof_room_trusted_bundle_signer_keys_from_env()?;
    let signing_payload = dsse_pre_auth_encoding(&detached.payload_type, manifest_bytes);
    for entry in &detached.signatures {
        if entry.keyid.is_empty() || entry.sig.is_empty() {
            return Err("proof-room.signature.field-missing".to_string());
        }
        let public_key = PublicKey::from_hex(&entry.keyid)
            .map_err(|error| format!("proof-room.signature.key-invalid: {error}"))?;
        let key_id = public_key.to_hex();
        if !declared_signer_keys.contains(&key_id) || !trusted_signer_keys.contains(&key_id) {
            return Err(format!(
                "proof-room.signature.signer-untrusted: set {PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS_ENV} to include trusted bundle signer keys"
            ));
        }
        let signature = Signature::from_hex(&entry.sig)
            .map_err(|error| format!("proof-room.signature.signature-invalid: {error}"))?;
        if !public_key.verify(&signing_payload, &signature) {
            return Err("proof-room.signature.verification-failed".to_string());
        }
    }

    Ok(())
}

pub(crate) fn trusted_bundle_signer_keys(
    bundle_root: &Path,
    manifest: &ProofRoomBundleManifest,
) -> Result<BTreeSet<String>, String> {
    let Some(reference) = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.path == "artifacts/authority/trust-roots.json")
    else {
        return Err("proof-room.signature.trust-roots-missing".to_string());
    };
    let artifact = verify_manifest_ref(
        bundle_root,
        reference,
        "signature_trust_roots_ref",
        Some(PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA),
    )?;
    let trust_roots: ProofRoomTrustRoots = serde_json::from_slice(&artifact.bytes)
        .map_err(|error| format!("proof-room.signature.trust-roots-invalid: {error}"))?;
    if trust_roots.roots.is_empty() {
        return Err("proof-room.signature.trust-roots-missing".to_string());
    }
    let mut trusted = BTreeSet::new();
    for root in trust_roots.roots {
        if root.key_id.is_empty() || root.key_digest.is_empty() {
            return Err("proof-room.signature.trust-root-field-missing".to_string());
        }
        if root.key_digest != sha256_hex(root.key_id.as_bytes()) {
            return Err("proof-room.signature.trust-root-digest-mismatch".to_string());
        }
        let public_key = PublicKey::from_hex(&root.key_id)
            .map_err(|error| format!("proof-room.signature.trust-root-key-invalid: {error}"))?;
        trusted.insert(public_key.to_hex());
    }
    Ok(trusted)
}

pub(crate) fn dsse_pre_auth_encoding(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let payload_type = payload_type.as_bytes();
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"DSSEv1 ");
    encoded.extend_from_slice(payload_type.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload_type);
    encoded.push(b' ');
    encoded.extend_from_slice(payload.len().to_string().as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(payload);
    encoded
}

pub(crate) struct VerifiedManifestArtifact {
    pub(crate) bytes: Vec<u8>,
    pub(crate) path: PathBuf,
}

pub(crate) fn verify_manifest_ref(
    bundle_root: &Path,
    reference: &ProofRoomArtifactRef,
    label: &str,
    expected_schema: Option<&str>,
) -> Result<VerifiedManifestArtifact, String> {
    verify_manifest_ref_with_json_schema(bundle_root, reference, label, expected_schema, true)
}

pub(crate) fn verify_manifest_ref_defer_json_schema(
    bundle_root: &Path,
    reference: &ProofRoomArtifactRef,
    label: &str,
    expected_schema: Option<&str>,
) -> Result<VerifiedManifestArtifact, String> {
    verify_manifest_ref_with_json_schema(bundle_root, reference, label, expected_schema, false)
}

pub(crate) fn verify_manifest_ref_with_json_schema(
    bundle_root: &Path,
    reference: &ProofRoomArtifactRef,
    label: &str,
    expected_schema: Option<&str>,
    validate_json_schema: bool,
) -> Result<VerifiedManifestArtifact, String> {
    if let Some(expected_schema) = expected_schema {
        if reference.schema != expected_schema {
            return Err(format!(
                "proof-room.schema-mismatch: {label} expected {expected_schema}"
            ));
        }
    }
    let artifact_path = resolve_proof_room_bundle_path(bundle_root, &reference.path)?;
    let bytes = fs::read(&artifact_path).map_err(|error| {
        format!(
            "proof-room.artifact.unreadable: {}: {error}",
            reference.path
        )
    })?;
    let actual_sha256 = sha256_hex(&bytes);
    if actual_sha256 != reference.sha256 {
        let code = if label == "verifier_report_ref" {
            "proof-room.report.hash-mismatch"
        } else {
            "proof-room.artifact.hash-mismatch"
        };
        return Err(format!(
            "{code}: {label} expected {} got {actual_sha256}",
            reference.sha256
        ));
    }
    if validate_json_schema {
        validate_json_artifact_schema(&bytes, &reference.schema, label)?;
    }
    Ok(VerifiedManifestArtifact {
        bytes,
        path: artifact_path,
    })
}
