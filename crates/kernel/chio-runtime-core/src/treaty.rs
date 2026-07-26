use std::collections::{BTreeMap, BTreeSet};

use crate::validation::{validate_non_empty, validate_state_label};
use crate::*;

pub fn governance_ladder_manifest_from_json(
    json: &str,
) -> Result<GovernanceLadderManifest, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn treaty_scope_from_json(json: &str) -> Result<TreatyScope, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn ladder_intersection_from_json(json: &str) -> Result<LadderIntersection, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn receipt_lineage_statement_from_json(
    json: &str,
) -> Result<ReceiptLineageStatement, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn receipt_lineage_bundle_from_json(
    json: &str,
) -> Result<ReceiptLineageBundle, ChioRuntimeError> {
    serde_json::from_str(json).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn ladder_intersection_json(
    intersection: &LadderIntersection,
) -> Result<String, ChioRuntimeError> {
    validate_ladder_intersection(intersection)?;
    serde_json::to_string_pretty(intersection)
        .map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn cross_boundary_admission_report_json(
    report: &CrossBoundaryAdmissionReport,
) -> Result<String, ChioRuntimeError> {
    validate_cross_boundary_admission_report(report)?;
    serde_json::to_string_pretty(report).map_err(|error| ChioRuntimeError::Json(error.to_string()))
}
pub fn governance_ladder_manifest_sha256(
    manifest: &GovernanceLadderManifest,
) -> Result<String, ChioRuntimeError> {
    canonical_sha256(manifest)
}
pub fn treaty_scope_sha256(scope: &TreatyScope) -> Result<String, ChioRuntimeError> {
    canonical_sha256(scope)
}
pub fn treaty_scope_semantic_intersection_sha256(
    scope: &TreatyScope,
) -> Result<String, ChioRuntimeError> {
    canonical_sha256(&serde_json::json!({
        "treatyId": scope.treaty_id,
        "participantKernelIds": scope.participant_kernel_ids,
        "participantPublicKeys": scope.participant_public_keys,
        "ladderManifestSha256s": scope.ladder_manifest_sha256s,
        "allowedActionClasses": scope.allowed_action_classes,
        "revocationEpochSha256": scope.revocation_epoch_sha256,
        "trustBundleSha256": scope.trust_bundle_sha256
    }))
}
pub fn ladder_intersection_sha256(
    intersection: &LadderIntersection,
) -> Result<String, ChioRuntimeError> {
    canonical_sha256(intersection)
}
pub fn ladder_intersection_semantic_sha256(
    intersection: &LadderIntersection,
) -> Result<String, ChioRuntimeError> {
    canonical_sha256(&serde_json::json!({
        "treatyId": intersection.treaty_id,
        "participantKernelIds": intersection.participant_kernel_ids,
        "ladderManifestSha256s": intersection.ladder_manifest_sha256s,
        "actionClasses": intersection.action_classes
    }))
}
pub fn receipt_lineage_statement_sha256(
    statement: &ReceiptLineageStatement,
) -> Result<String, ChioRuntimeError> {
    canonical_sha256(statement)
}
pub fn bilateral_invocation_binding_sha256(
    invocation: &BilateralInvocation,
) -> Result<String, ChioRuntimeError> {
    canonical_sha256(&serde_json::json!({
        "schema": &invocation.schema,
        "invocationId": &invocation.invocation_id,
        "treatyId": &invocation.treaty_id,
        "ladderIntersectionSha256": &invocation.ladder_intersection_sha256,
        "continuationSha256": &invocation.continuation_sha256,
        "actionClassId": &invocation.action_class_id,
        "consistencyModel": &invocation.consistency_model,
        "capabilityId": &invocation.capability_id,
        "requestSha256": &invocation.request_sha256,
        "outcomeSha256": &invocation.outcome_sha256,
        "localReceiptSha256": &invocation.local_receipt_sha256,
        "remoteReceiptSha256": &invocation.remote_receipt_sha256,
        "signerKernelIds": &invocation.signer_kernel_ids
    }))
}
pub fn validate_governance_ladder_manifest(
    manifest: &GovernanceLadderManifest,
) -> Result<(), ChioRuntimeError> {
    if manifest.schema != CHIO_GOVERNANCE_LADDER_MANIFEST_SCHEMA {
        return rejected(
            "unsupported_governance_ladder_manifest_schema",
            "governance ladder manifest declared an unsupported schema",
        );
    }
    validate_non_empty(&manifest.manifest_id, "governance_ladder_manifest_empty_id")?;
    validate_non_empty(
        &manifest.kernel_id,
        "governance_ladder_manifest_empty_kernel",
    )?;
    validate_non_empty(&manifest.issuer, "governance_ladder_manifest_empty_issuer")?;
    validate_non_empty(&manifest.key_id, "governance_ladder_manifest_empty_key")?;
    if manifest.issued_at_unix_ms >= manifest.expires_at_unix_ms {
        return rejected(
            "governance_ladder_manifest_invalid_window",
            "governance ladder manifest validity window is empty",
        );
    }
    if manifest.default_unknown_mode != "deny" {
        return rejected(
            "governance_ladder_manifest_unknown_default_not_deny",
            "governance ladder manifest must deny unknown action classes",
        );
    }
    let destructive_floor_rank = ladder_mode_rank(&manifest.destructive_floor)?;
    let mut action_ids = BTreeSet::new();
    let mut aliases = BTreeSet::new();
    if manifest.action_classes.is_empty() {
        return rejected(
            "governance_ladder_manifest_missing_action_classes",
            "governance ladder manifest must define at least one action class",
        );
    }
    for action in &manifest.action_classes {
        validate_non_empty(&action.action_class_id, "governance_ladder_action_empty_id")?;
        if !action_ids.insert(action.action_class_id.as_str()) {
            return rejected(
                "chio_ladder_duplicate_action_class",
                "governance ladder manifest contains a duplicate action class",
            );
        }
        let action_rank = ladder_mode_rank(&action.mode)?;
        let consistency_model = bilateral_dsse_consistency_model(&action.consistency_model)?;
        validate_co_sign_mode(&action.co_sign)?;
        validate_co_sign_quorum(&action.co_sign, action.co_sign_quorum.as_ref())?;
        if action.destructive && action_rank < destructive_floor_rank {
            return rejected(
                "chio_ladder_destructive_below_floor",
                "destructive action class resolves below the destructive floor",
            );
        }
        if action.destructive && consistency_model == "crdt-commutative" {
            return rejected(
                "chio_ladder_destructive_crdt_not_allowed",
                "destructive action class cannot use crdt-commutative consistency",
            );
        }
        if action.destructive && action.evidence_required.is_empty() {
            return rejected(
                "governance_ladder_destructive_missing_evidence",
                "destructive action class must require evidence",
            );
        }
        let mut evidence = BTreeSet::new();
        for item in &action.evidence_required {
            validate_state_label(item, "governance_ladder_invalid_evidence_label")?;
            if !evidence.insert(item.as_str()) {
                return rejected(
                    "governance_ladder_duplicate_evidence",
                    "governance ladder action contains duplicate required evidence",
                );
            }
        }
        for alias in &action.aliases {
            validate_non_empty(alias, "governance_ladder_empty_alias")?;
            if !aliases.insert(alias.as_str()) || action_ids.contains(alias.as_str()) {
                return rejected(
                    "chio_ladder_alias_conflict",
                    "governance ladder alias conflicts with another action class",
                );
            }
        }
    }
    Ok(())
}
pub fn validate_treaty_scope(scope: &TreatyScope) -> Result<(), ChioRuntimeError> {
    if !is_supported_treaty_scope_schema(&scope.schema) {
        return rejected(
            "unsupported_treaty_scope_schema",
            "treaty scope declared an unsupported schema",
        );
    }
    validate_non_empty(&scope.treaty_id, "treaty_scope_empty_id")?;
    if scope.issued_at_unix_ms >= scope.expires_at_unix_ms {
        return rejected("chio_treaty_stale", "treaty scope validity window is empty");
    }
    if scope.participant_kernel_ids.len() < 2 {
        return rejected(
            "chio_treaty_missing_participant",
            "treaty scope must bind at least two participant kernels",
        );
    }
    if scope.participant_kernel_ids.len() != scope.ladder_manifest_sha256s.len() {
        return rejected(
            "chio_ladder_manifest_hash_mismatch",
            "treaty scope must bind one ladder manifest hash per participant",
        );
    }
    if scope.participant_kernel_ids.len() != scope.participant_public_keys.len() {
        return rejected(
            "chio_treaty_missing_participant",
            "treaty scope must bind one public key per participant",
        );
    }
    let mut participants = BTreeSet::new();
    for participant in &scope.participant_kernel_ids {
        validate_non_empty(participant, "treaty_scope_empty_participant")?;
        if !participants.insert(participant.as_str()) {
            return rejected(
                "treaty_scope_duplicate_participant",
                "treaty scope contains duplicate participant kernel",
            );
        }
    }
    let mut public_keys = BTreeSet::new();
    for public_key in &scope.participant_public_keys {
        if !public_keys.insert(public_key.to_hex()) {
            return rejected(
                "treaty_scope_duplicate_participant_key",
                "treaty scope contains duplicate participant public key",
            );
        }
    }
    let mut hashes = BTreeSet::new();
    for hash in &scope.ladder_manifest_sha256s {
        ensure_sha256_hash(hash, "chio_ladder_manifest_hash_mismatch")?;
        if !hashes.insert(hash.as_str()) {
            return rejected(
                "chio_ladder_manifest_hash_mismatch",
                "treaty scope contains duplicate ladder manifest hash",
            );
        }
    }
    for action_class in &scope.allowed_action_classes {
        validate_non_empty(action_class, "treaty_scope_empty_action_class")?;
    }
    ensure_sha256_hash(
        &scope.revocation_epoch_sha256,
        "treaty_scope_invalid_revocation_epoch_hash",
    )?;
    ensure_sha256_hash(
        &scope.trust_bundle_sha256,
        "treaty_scope_invalid_trust_bundle_hash",
    )
}
fn is_supported_treaty_scope_schema(schema: &str) -> bool {
    matches!(schema, CHIO_FEDERATION_TREATY_SCOPE_SCHEMA)
}
pub fn compute_ladder_intersection(
    treaty_scope: &TreatyScope,
    manifests: &[GovernanceLadderManifest],
    now_unix_ms: u64,
) -> Result<LadderIntersection, ChioRuntimeError> {
    validate_treaty_scope(treaty_scope)?;
    if now_unix_ms < treaty_scope.issued_at_unix_ms
        || now_unix_ms >= treaty_scope.expires_at_unix_ms
    {
        return rejected("chio_treaty_stale", "treaty scope is not fresh");
    }
    if manifests.len() != treaty_scope.participant_kernel_ids.len() {
        return rejected(
            "chio_treaty_missing_participant",
            "manifest set does not cover every treaty participant",
        );
    }
    let mut manifest_hashes = Vec::new();
    let mut by_kernel = BTreeMap::new();
    for manifest in manifests {
        validate_governance_ladder_manifest(manifest)?;
        if now_unix_ms < manifest.issued_at_unix_ms || now_unix_ms >= manifest.expires_at_unix_ms {
            return rejected(
                "chio_ladder_manifest_stale",
                "governance ladder manifest is not fresh",
            );
        }
        if !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|kernel| kernel == &manifest.kernel_id)
        {
            return rejected(
                "chio_treaty_missing_participant",
                "governance ladder manifest kernel is outside treaty scope",
            );
        }
        let hash = governance_ladder_manifest_sha256(manifest)?;
        manifest_hashes.push(hash);
        if by_kernel
            .insert(manifest.kernel_id.as_str(), manifest)
            .is_some()
        {
            return rejected(
                "chio_treaty_missing_participant",
                "duplicate governance ladder manifest for participant",
            );
        }
    }
    let expected: BTreeSet<_> = treaty_scope.ladder_manifest_sha256s.iter().collect();
    let actual: BTreeSet<_> = manifest_hashes.iter().collect();
    if expected != actual {
        return rejected(
            "chio_ladder_manifest_hash_mismatch",
            "computed ladder manifest hashes do not match treaty scope",
        );
    }

    let mut action_classes = Vec::new();
    for action_class_id in &treaty_scope.allowed_action_classes {
        let mut participant_modes = BTreeMap::new();
        let mut mode_rank = 0;
        let mut mode = "observation".to_string();
        let mut destructive = false;
        let mut consistency_model: Option<String> = None;
        let mut co_sign = "none".to_string();
        let mut co_sign_quorum: Option<GovernanceLadderQuorum> = None;
        let mut evidence_required = BTreeSet::new();
        for participant in &treaty_scope.participant_kernel_ids {
            let Some(manifest) = by_kernel.get(participant.as_str()) else {
                return rejected(
                    "chio_treaty_missing_participant",
                    "treaty participant is missing a governance ladder manifest",
                );
            };
            let Some(action) = find_ladder_action(manifest, action_class_id) else {
                return rejected(
                    "chio_treaty_action_class_not_allowed",
                    "governance ladder manifest does not allow action class",
                );
            };
            let action_consistency_model =
                bilateral_dsse_consistency_model(&action.consistency_model)?;
            let rank = ladder_mode_rank(&action.mode)?;
            if rank > mode_rank {
                mode_rank = rank;
                mode = action.mode.clone();
            }
            destructive |= action.destructive;
            if let Some(existing) = consistency_model.as_ref() {
                if existing != action_consistency_model {
                    return rejected(
                        "chio_ladder_consistency_mismatch",
                        "governance ladder consistency models do not intersect",
                    );
                }
            } else {
                consistency_model = Some(action_consistency_model.to_owned());
            }
            if co_sign_requirement_rank(&action.co_sign)? > co_sign_requirement_rank(&co_sign)? {
                co_sign = ladder_co_sign_mode(&action.co_sign)?.to_string();
            }
            merge_quorum(&mut co_sign_quorum, action.co_sign_quorum.as_ref())?;
            for item in &action.evidence_required {
                evidence_required.insert(item.clone());
            }
            participant_modes.insert(participant.clone(), action.mode.clone());
        }
        if destructive && mode_rank < ladder_mode_rank("receipt_backed")? {
            return rejected(
                "chio_ladder_destructive_below_floor",
                "intersected destructive action resolves below receipt backed mode",
            );
        }
        if destructive && consistency_model.as_deref() == Some("crdt-commutative") {
            return rejected(
                "chio_ladder_destructive_crdt_not_allowed",
                "intersected destructive action cannot use crdt_commutative consistency",
            );
        }
        action_classes.push(LadderIntersectionActionClass {
            action_class_id: action_class_id.clone(),
            mode,
            destructive,
            consistency_model: consistency_model.unwrap_or_else(|| "totally-ordered".to_string()),
            co_sign,
            co_sign_quorum,
            evidence_required: evidence_required.into_iter().collect(),
            participant_modes,
        });
    }
    if action_classes.is_empty() {
        return rejected(
            "chio_treaty_action_class_not_allowed",
            "treaty scope does not allow any action classes",
        );
    }
    let expires_at_unix_ms = manifests
        .iter()
        .map(|manifest| manifest.expires_at_unix_ms)
        .chain(std::iter::once(treaty_scope.expires_at_unix_ms))
        .min()
        .unwrap_or(treaty_scope.expires_at_unix_ms);
    Ok(LadderIntersection {
        schema: CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA.to_string(),
        intersection_id: format!("{}:{}", treaty_scope.treaty_id, now_unix_ms),
        treaty_id: treaty_scope.treaty_id.clone(),
        participant_kernel_ids: treaty_scope.participant_kernel_ids.clone(),
        ladder_manifest_sha256s: treaty_scope.ladder_manifest_sha256s.clone(),
        generated_at_unix_ms: now_unix_ms,
        expires_at_unix_ms,
        action_classes,
    })
}
pub fn validate_ladder_intersection(
    intersection: &LadderIntersection,
) -> Result<(), ChioRuntimeError> {
    if !is_supported_ladder_intersection_schema(&intersection.schema) {
        return rejected(
            "unsupported_ladder_intersection_schema",
            "ladder intersection declared an unsupported schema",
        );
    }
    validate_non_empty(
        &intersection.intersection_id,
        "ladder_intersection_empty_id",
    )?;
    validate_non_empty(&intersection.treaty_id, "ladder_intersection_empty_treaty")?;
    if intersection.generated_at_unix_ms >= intersection.expires_at_unix_ms {
        return rejected(
            "chio_treaty_stale",
            "ladder intersection validity window is empty",
        );
    }
    if intersection.action_classes.is_empty() {
        return rejected(
            "chio_treaty_action_class_not_allowed",
            "ladder intersection contains no action classes",
        );
    }
    for hash in &intersection.ladder_manifest_sha256s {
        ensure_sha256_hash(hash, "chio_ladder_manifest_hash_mismatch")?;
    }
    for action in &intersection.action_classes {
        validate_non_empty(
            &action.action_class_id,
            "ladder_intersection_empty_action_class",
        )?;
        ladder_mode_rank(&action.mode)?;
        let consistency_model = bilateral_dsse_consistency_model(&action.consistency_model)?;
        validate_co_sign_mode(&action.co_sign)?;
        validate_co_sign_quorum(&action.co_sign, action.co_sign_quorum.as_ref())?;
        if action.destructive
            && ladder_mode_rank(&action.mode)? < ladder_mode_rank("receipt_backed")?
        {
            return rejected(
                "chio_ladder_destructive_below_floor",
                "ladder intersection destructive action resolves below receipt backed mode",
            );
        }
        if action.destructive && consistency_model == "crdt-commutative" {
            return rejected(
                "chio_ladder_destructive_crdt_not_allowed",
                "ladder intersection destructive action cannot use crdt-commutative consistency",
            );
        }
    }
    Ok(())
}
fn is_supported_ladder_intersection_schema(schema: &str) -> bool {
    matches!(schema, CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA)
}
pub fn evaluate_cross_boundary_admission(
    input: CrossBoundaryAdmissionInput<'_>,
) -> Result<CrossBoundaryAdmissionReport, ChioRuntimeError> {
    validate_treaty_scope(input.treaty_scope)?;
    validate_ladder_intersection(input.ladder_intersection)?;
    let treaty_scope_sha256 = treaty_scope_sha256(input.treaty_scope)?;
    let ladder_intersection_sha256 = ladder_intersection_sha256(input.ladder_intersection)?;
    let mut checks = vec![
        "chio_treaty.scope_valid".to_string(),
        "chio_treaty.intersection_valid".to_string(),
    ];
    if input.now_unix_ms < input.treaty_scope.issued_at_unix_ms
        || input.now_unix_ms < input.ladder_intersection.generated_at_unix_ms
        || input.now_unix_ms >= input.treaty_scope.expires_at_unix_ms
        || input.now_unix_ms >= input.ladder_intersection.expires_at_unix_ms
    {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_treaty_stale",
            checks,
        ));
    }
    if input.treaty_scope.treaty_id != input.ladder_intersection.treaty_id
        || input.treaty_scope.ladder_manifest_sha256s
            != input.ladder_intersection.ladder_manifest_sha256s
        || input.treaty_scope.participant_kernel_ids
            != input.ladder_intersection.participant_kernel_ids
    {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_treaty_intersection_mismatch",
            checks,
        ));
    }
    let Some(expected_ladder_intersection_sha256) =
        input.expected_ladder_intersection_sha256.clone()
    else {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_treaty_missing_intersection_binding",
            checks,
        ));
    };
    if expected_ladder_intersection_sha256 != ladder_intersection_sha256 {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_treaty_intersection_mismatch",
            checks,
        ));
    }
    if !input
        .treaty_scope
        .allowed_action_classes
        .iter()
        .any(|action| action == input.action_class_id)
    {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_treaty_action_class_not_allowed",
            checks,
        ));
    }
    let Some(action) = input
        .ladder_intersection
        .action_classes
        .iter()
        .find(|action| action.action_class_id == input.action_class_id)
    else {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_treaty_action_class_not_allowed",
            checks,
        ));
    };
    let present: BTreeSet<_> = input.present_evidence.iter().map(String::as_str).collect();
    let verified: BTreeMap<_, _> = input
        .verified_evidence
        .iter()
        .map(|evidence| (evidence.evidence_class.as_str(), evidence))
        .collect();
    let required_evidence = required_evidence_for_action(action);
    let missing_required = required_evidence
        .iter()
        .any(|required| !present.contains(required.as_str()));
    if missing_required {
        return Ok(CrossBoundaryAdmissionReport {
            schema: CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
            treaty_id: input.treaty_scope.treaty_id.clone(),
            action_class_id: input.action_class_id.to_string(),
            accepted: false,
            failure_code: Some("chio_treaty_missing_required_evidence".to_string()),
            mode: action.mode.clone(),
            consistency_model: action.consistency_model.clone(),
            co_sign: action.co_sign.clone(),
            co_sign_quorum: action.co_sign_quorum.clone(),
            required_evidence,
            present_evidence: input.present_evidence,
            verified_evidence: input.verified_evidence,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
            checks,
        });
    }
    let missing_verified = required_evidence.iter().any(|required| {
        verified
            .get(required.as_str())
            .is_none_or(|evidence| !evidence.verified)
    });
    if missing_verified {
        return Ok(CrossBoundaryAdmissionReport {
            schema: CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
            treaty_id: input.treaty_scope.treaty_id.clone(),
            action_class_id: input.action_class_id.to_string(),
            accepted: false,
            failure_code: Some("chio_treaty_unverified_required_evidence".to_string()),
            mode: action.mode.clone(),
            consistency_model: action.consistency_model.clone(),
            co_sign: action.co_sign.clone(),
            co_sign_quorum: action.co_sign_quorum.clone(),
            required_evidence,
            present_evidence: input.present_evidence,
            verified_evidence: input.verified_evidence,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
            checks,
        });
    }
    checks.push("chio_treaty.required_evidence_present".to_string());
    checks.push("chio_treaty.required_evidence_verified".to_string());
    Ok(CrossBoundaryAdmissionReport {
        schema: CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: input.treaty_scope.treaty_id.clone(),
        action_class_id: input.action_class_id.to_string(),
        accepted: true,
        failure_code: None,
        mode: action.mode.clone(),
        consistency_model: action.consistency_model.clone(),
        co_sign: action.co_sign.clone(),
        co_sign_quorum: action.co_sign_quorum.clone(),
        required_evidence,
        present_evidence: input.present_evidence,
        verified_evidence: input.verified_evidence,
        treaty_scope_sha256,
        ladder_intersection_sha256,
        expected_ladder_intersection_sha256: Some(expected_ladder_intersection_sha256),
        checks,
    })
}
fn required_evidence_for_action(action: &LadderIntersectionActionClass) -> Vec<String> {
    let mut required = action.evidence_required.clone();
    let co_sign = ladder_co_sign_mode(&action.co_sign).ok();
    if co_sign == Some("bilateral_required")
        && !required
            .iter()
            .any(|evidence| evidence == "bilateral_invocation")
    {
        required.push("bilateral_invocation".to_string());
    }
    if co_sign == Some("n_of_m")
        && !required
            .iter()
            .any(|evidence| evidence == "quorum_signature")
    {
        required.push("quorum_signature".to_string());
    }
    required
}
pub fn validate_cross_boundary_admission_report(
    report: &CrossBoundaryAdmissionReport,
) -> Result<(), ChioRuntimeError> {
    if !is_supported_cross_boundary_admission_report_schema(&report.schema) {
        return rejected(
            "unsupported_cross_boundary_admission_report_schema",
            "cross-boundary admission report declared an unsupported schema",
        );
    }
    validate_non_empty(&report.treaty_id, "cross_boundary_admission_empty_treaty")?;
    validate_non_empty(
        &report.action_class_id,
        "cross_boundary_admission_empty_action_class",
    )?;
    ladder_mode_rank(&report.mode)?;
    validate_consistency_model(&report.consistency_model)?;
    validate_co_sign_mode(&report.co_sign)?;
    validate_co_sign_quorum(&report.co_sign, report.co_sign_quorum.as_ref())?;
    ensure_sha256_hash(
        &report.treaty_scope_sha256,
        "cross_boundary_admission_invalid_treaty_hash",
    )?;
    ensure_sha256_hash(
        &report.ladder_intersection_sha256,
        "cross_boundary_admission_invalid_intersection_hash",
    )?;
    if !report.accepted && report.failure_code.is_none() {
        return rejected(
            "cross_boundary_admission_missing_failure_code",
            "rejected cross-boundary admission report must include failure code",
        );
    }
    if report.accepted && report.failure_code.is_some() {
        return rejected(
            "cross_boundary_admission_unexpected_failure_code",
            "accepted cross-boundary admission report cannot include failure code",
        );
    }
    let present: BTreeSet<_> = report.present_evidence.iter().map(String::as_str).collect();
    let mut verified = BTreeMap::new();
    for evidence in &report.verified_evidence {
        validate_state_label(
            &evidence.evidence_class,
            "cross_boundary_admission_invalid_evidence_class",
        )?;
        ensure_sha256_hash(
            &evidence.artifact_sha256,
            "cross_boundary_admission_invalid_evidence_hash",
        )?;
        verified.insert(evidence.evidence_class.as_str(), evidence.verified);
    }
    for evidence_class in &report.present_evidence {
        validate_state_label(
            evidence_class,
            "cross_boundary_admission_invalid_evidence_class",
        )?;
    }
    if report.accepted {
        for required in &report.required_evidence {
            validate_state_label(required, "cross_boundary_admission_invalid_evidence_class")?;
            if !present.contains(required.as_str()) {
                return rejected(
                    "chio_treaty_missing_required_evidence",
                    "accepted cross-boundary admission report is missing required evidence",
                );
            }
            if verified
                .get(required.as_str())
                .copied()
                .is_none_or(|is_verified| !is_verified)
            {
                return rejected(
                    "chio_treaty_unverified_required_evidence",
                    "accepted cross-boundary admission report has unverified required evidence",
                );
            }
        }
    }
    Ok(())
}
fn is_supported_cross_boundary_admission_report_schema(schema: &str) -> bool {
    matches!(
        schema,
        CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA
    )
}
fn ladder_mode_rank(mode: &str) -> Result<u8, ChioRuntimeError> {
    match mode {
        "observation" => Ok(0),
        "guarded" => Ok(1),
        "receipt_backed" => Ok(2),
        "partition_contingency" => Ok(3),
        "maintenance" | "quorum_required" => Ok(4),
        _ => rejected(
            "chio_ladder_invalid_mode",
            "governance ladder mode is not supported",
        ),
    }
}
pub fn bilateral_dsse_consistency_model(model: &str) -> Result<&'static str, ChioRuntimeError> {
    match model {
        "crdt_commutative" | "crdt-commutative" => Ok("crdt-commutative"),
        "totally_ordered" | "totally-ordered" => Ok("totally-ordered"),
        "single_kernel" | "single-kernel" => Ok("single-kernel"),
        "quorum_required" | "quorum-required" => Ok("quorum-required"),
        _ => rejected(
            "chio_ladder_invalid_consistency_model",
            "governance ladder consistency model is not supported",
        ),
    }
}
fn validate_consistency_model(model: &str) -> Result<(), ChioRuntimeError> {
    bilateral_dsse_consistency_model(model).map(|_| ())
}
pub fn ladder_co_sign_mode(mode: &str) -> Result<&'static str, ChioRuntimeError> {
    match mode {
        "none" => Ok("none"),
        "bilateral_if_cross_org" => Ok("bilateral_if_cross_org"),
        "bilateral_required" => Ok("bilateral_required"),
        "n_of_m" | "quorum_required" => Ok("n_of_m"),
        _ => rejected(
            "chio_ladder_invalid_cosign_mode",
            "governance ladder co-sign mode is not supported",
        ),
    }
}
fn validate_co_sign_mode(mode: &str) -> Result<(), ChioRuntimeError> {
    ladder_co_sign_mode(mode).map(|_| ())
}
fn co_sign_requirement_rank(mode: &str) -> Result<u8, ChioRuntimeError> {
    match ladder_co_sign_mode(mode)? {
        "none" => Ok(0),
        "bilateral_if_cross_org" => Ok(1),
        "bilateral_required" => Ok(2),
        _ => Ok(3),
    }
}
fn validate_co_sign_quorum(
    mode: &str,
    quorum: Option<&GovernanceLadderQuorum>,
) -> Result<(), ChioRuntimeError> {
    match (ladder_co_sign_mode(mode)?, quorum) {
        ("n_of_m", Some(quorum)) => {
            if quorum.n < 2 || quorum.m < 2 || quorum.n > quorum.m {
                return rejected(
                    "chio_ladder_quorum_misdeclared",
                    "n_of_m quorum requires 2 <= n <= m",
                );
            }
            if !matches!(quorum.scope.as_str(), "treaty" | "kernel" | "operator") {
                return rejected(
                    "chio_ladder_quorum_misdeclared",
                    "n_of_m quorum scope is unsupported",
                );
            }
            Ok(())
        }
        ("n_of_m", None) => rejected(
            "chio_ladder_quorum_misdeclared",
            "n_of_m co-sign mode requires quorum metadata",
        ),
        (_, Some(_)) => rejected(
            "chio_ladder_quorum_misdeclared",
            "quorum metadata is only valid for n_of_m co-sign mode",
        ),
        (_, None) => Ok(()),
    }
}
fn merge_quorum(
    current: &mut Option<GovernanceLadderQuorum>,
    candidate: Option<&GovernanceLadderQuorum>,
) -> Result<(), ChioRuntimeError> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    match current {
        Some(existing) => {
            if existing.m != candidate.m || existing.scope != candidate.scope {
                return rejected(
                    "chio_ladder_quorum_misdeclared",
                    "participant quorum counts or scopes do not intersect",
                );
            }
            existing.n = existing.n.max(candidate.n);
        }
        None => *current = Some(candidate.clone()),
    }
    Ok(())
}
fn find_ladder_action<'a>(
    manifest: &'a GovernanceLadderManifest,
    action_class_id: &str,
) -> Option<&'a GovernanceLadderActionClass> {
    manifest.action_classes.iter().find(|action| {
        action.action_class_id == action_class_id
            || action.aliases.iter().any(|alias| alias == action_class_id)
    })
}
fn cross_boundary_rejection_report(
    input: CrossBoundaryAdmissionInput<'_>,
    treaty_scope_sha256: String,
    ladder_intersection_sha256: String,
    failure_code: &'static str,
    checks: Vec<String>,
) -> CrossBoundaryAdmissionReport {
    CrossBoundaryAdmissionReport {
        schema: CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA.to_string(),
        treaty_id: input.treaty_scope.treaty_id.clone(),
        action_class_id: input.action_class_id.to_string(),
        accepted: false,
        failure_code: Some(failure_code.to_string()),
        mode: "observation".to_string(),
        consistency_model: "totally-ordered".to_string(),
        co_sign: "none".to_string(),
        co_sign_quorum: None,
        required_evidence: Vec::new(),
        present_evidence: input.present_evidence,
        verified_evidence: input.verified_evidence,
        treaty_scope_sha256,
        ladder_intersection_sha256,
        expected_ladder_intersection_sha256: input.expected_ladder_intersection_sha256,
        checks,
    }
}
pub(crate) fn validate_receipt_lineage_statement(
    statement: &ReceiptLineageStatement,
) -> Result<(), ChioRuntimeError> {
    if !matches!(
        statement.schema.as_str(),
        CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA
    ) {
        return rejected(
            "unsupported_receipt_lineage_statement_schema",
            "receipt lineage statement declared an unsupported schema",
        );
    }
    validate_non_empty(&statement.statement_id, "receipt_lineage_empty_id")?;
    ensure_sha256_hash(
        &statement.parent_receipt_sha256,
        "receipt_lineage_invalid_parent_hash",
    )?;
    ensure_sha256_hash(
        &statement.child_receipt_sha256,
        "receipt_lineage_invalid_child_hash",
    )?;
    ensure_sha256_hash(
        &statement.continuation_sha256,
        "receipt_lineage_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &statement.bilateral_invocation_sha256,
        "receipt_lineage_invalid_bilateral_hash",
    )?;
    match statement.evidence_class.as_str() {
        "verified" | "observed" | "asserted" | "unverifiable" | "rejected" => {}
        _ => {
            return rejected(
                "receipt_lineage_invalid_evidence_class",
                "receipt lineage statement evidence class is unsupported",
            );
        }
    }
    validate_non_empty(
        &statement.source_kernel_id,
        "receipt_lineage_empty_source_kernel",
    )?;
    validate_non_empty(
        &statement.target_kernel_id,
        "receipt_lineage_empty_target_kernel",
    )
}
pub(crate) fn validate_cross_kernel_continuation(
    continuation: &CrossKernelContinuation,
) -> Result<(), ChioRuntimeError> {
    if !matches!(
        continuation.schema.as_str(),
        CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA
    ) {
        return rejected(
            "unsupported_cross_kernel_continuation_schema",
            "cross-kernel continuation declared an unsupported schema",
        );
    }
    validate_non_empty(&continuation.continuation_id, "continuation_empty_id")?;
    validate_non_empty(
        &continuation.source_kernel_id,
        "continuation_empty_source_kernel",
    )?;
    validate_non_empty(
        &continuation.target_kernel_id,
        "continuation_empty_target_kernel",
    )?;
    ensure_sha256_hash(
        &continuation.parent_receipt_sha256,
        "continuation_invalid_parent_hash",
    )?;
    ensure_sha256_hash(
        &continuation.parent_session_anchor_sha256,
        "continuation_invalid_session_anchor_hash",
    )?;
    validate_non_empty(&continuation.capability_id, "continuation_empty_capability")?;
    validate_non_empty(
        &continuation.action_class_id,
        "continuation_empty_action_class",
    )?;
    validate_non_empty(&continuation.audience_tool, "continuation_empty_audience")?;
    validate_non_empty(&continuation.nonce, "continuation_empty_nonce")?;
    if continuation.issued_at_unix_ms >= continuation.expires_at_unix_ms {
        return rejected(
            "continuation_invalid_window",
            "cross-kernel continuation validity window is empty",
        );
    }
    Ok(())
}
pub(crate) fn validate_bilateral_invocation(
    invocation: &BilateralInvocation,
) -> Result<(), ChioRuntimeError> {
    if !matches!(
        invocation.schema.as_str(),
        CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA
    ) {
        return rejected(
            "unsupported_bilateral_invocation_schema",
            "bilateral invocation declared an unsupported schema",
        );
    }
    validate_non_empty(&invocation.invocation_id, "bilateral_invocation_empty_id")?;
    validate_non_empty(&invocation.treaty_id, "bilateral_invocation_empty_treaty")?;
    ensure_sha256_hash(
        &invocation.ladder_intersection_sha256,
        "bilateral_invocation_invalid_intersection_hash",
    )?;
    ensure_sha256_hash(
        &invocation.continuation_sha256,
        "bilateral_invocation_invalid_continuation_hash",
    )?;
    ensure_sha256_hash(
        &invocation.lineage_statement_sha256,
        "bilateral_invocation_invalid_lineage_hash",
    )?;
    validate_non_empty(
        &invocation.action_class_id,
        "bilateral_invocation_empty_action_class",
    )?;
    validate_consistency_model(&invocation.consistency_model)?;
    validate_non_empty(
        &invocation.capability_id,
        "bilateral_invocation_empty_capability",
    )?;
    ensure_sha256_hash(
        &invocation.request_sha256,
        "bilateral_invocation_invalid_request_hash",
    )?;
    ensure_sha256_hash(
        &invocation.outcome_sha256,
        "bilateral_invocation_invalid_outcome_hash",
    )?;
    ensure_sha256_hash(
        &invocation.local_receipt_sha256,
        "bilateral_invocation_invalid_local_receipt_hash",
    )?;
    ensure_sha256_hash(
        &invocation.remote_receipt_sha256,
        "bilateral_invocation_invalid_remote_receipt_hash",
    )?;
    if invocation.signer_kernel_ids.len() != 2 {
        return rejected(
            "bilateral_invocation_signer_count_mismatch",
            "bilateral invocation must include exactly two kernel signers",
        );
    }
    let mut signers = BTreeSet::new();
    for signer in &invocation.signer_kernel_ids {
        validate_non_empty(signer, "bilateral_invocation_empty_signer")?;
        if !signers.insert(signer) {
            return rejected(
                "bilateral_invocation_duplicate_signer",
                "bilateral invocation signer kernels must be distinct",
            );
        }
    }
    Ok(())
}
pub(crate) fn validate_receipt_lineage_bundle(
    bundle: &ReceiptLineageBundle,
) -> Result<(), ChioRuntimeError> {
    if !matches!(
        bundle.schema.as_str(),
        CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA
    ) {
        return rejected(
            "unsupported_receipt_lineage_bundle_schema",
            "receipt lineage bundle declared an unsupported schema",
        );
    }
    validate_non_empty(&bundle.bundle_id, "receipt_lineage_bundle_empty_id")?;
    ensure_sha256_hash(
        &bundle.root_receipt_sha256,
        "receipt_lineage_bundle_invalid_root_hash",
    )?;
    ensure_sha256_hash(
        &bundle.leaf_receipt_sha256,
        "receipt_lineage_bundle_invalid_leaf_hash",
    )
}
