use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::crypto::{canonical_json_bytes, sha256_hex};
use chio_core_types::PublicKey;
use serde::{Deserialize, Serialize};

pub const CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA: &str =
    "chio.federation.governance-ladder-manifest.v1";
pub const CHIO_FEDERATION_TREATY_SCOPE_SCHEMA: &str = "chio.federation.treaty-scope.v1";
pub const CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA: &str =
    "chio.federation.ladder-intersection.v1";
pub const CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA: &str =
    "chio.federation.cross-boundary-admission-report.v1";

#[derive(Debug, thiserror::Error)]
pub enum FederationTreatyError {
    #[error("federation treaty rejected: {code}: {detail}")]
    Rejected { code: &'static str, detail: String },
    #[error("federation treaty JSON failed: {0}")]
    Json(String),
    #[error("federation treaty canonical JSON failed: {0}")]
    Canonical(String),
}

impl FederationTreatyError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Rejected { code, .. } => code,
            Self::Json(_) => "federation_treaty_json",
            Self::Canonical(_) => "federation_treaty_canonical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderActionClass {
    pub action_class_id: String,
    pub mode: String,
    pub destructive: bool,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub evidence_required: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderQuorum {
    pub n: u16,
    pub m: u16,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernanceLadderManifest {
    pub schema: String,
    pub manifest_id: String,
    pub kernel_id: String,
    pub issuer: String,
    pub key_id: String,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub destructive_floor: String,
    pub default_unknown_mode: String,
    pub action_classes: Vec<GovernanceLadderActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TreatyScope {
    pub schema: String,
    pub treaty_id: String,
    pub participant_kernel_ids: Vec<String>,
    pub participant_public_keys: Vec<PublicKey>,
    pub ladder_manifest_sha256s: Vec<String>,
    pub allowed_action_classes: Vec<String>,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revocation_epoch_sha256: String,
    pub trust_bundle_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderIntersectionActionClass {
    pub action_class_id: String,
    pub mode: String,
    pub destructive: bool,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub evidence_required: Vec<String>,
    pub participant_modes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LadderIntersection {
    pub schema: String,
    pub intersection_id: String,
    pub treaty_id: String,
    pub participant_kernel_ids: Vec<String>,
    pub ladder_manifest_sha256s: Vec<String>,
    pub generated_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub action_classes: Vec<LadderIntersectionActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryAdmissionReport {
    pub schema: String,
    pub treaty_id: String,
    pub action_class_id: String,
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    pub mode: String,
    pub consistency_model: String,
    pub co_sign: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub co_sign_quorum: Option<GovernanceLadderQuorum>,
    pub required_evidence: Vec<String>,
    pub present_evidence: Vec<String>,
    #[serde(default)]
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub treaty_scope_sha256: String,
    pub ladder_intersection_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_ladder_intersection_sha256: Option<String>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CrossBoundaryEvidenceRef {
    pub evidence_class: String,
    pub artifact_sha256: String,
    pub verified: bool,
}

pub struct CrossBoundaryAdmissionInput<'a> {
    pub treaty_scope: &'a TreatyScope,
    pub ladder_intersection: &'a LadderIntersection,
    pub expected_ladder_intersection_sha256: Option<String>,
    pub action_class_id: &'a str,
    pub present_evidence: Vec<String>,
    pub verified_evidence: Vec<CrossBoundaryEvidenceRef>,
    pub now_unix_ms: u64,
}

pub fn governance_ladder_manifest_from_json(
    json: &str,
) -> Result<GovernanceLadderManifest, FederationTreatyError> {
    serde_json::from_str(json).map_err(|error| FederationTreatyError::Json(error.to_string()))
}

pub fn treaty_scope_from_json(json: &str) -> Result<TreatyScope, FederationTreatyError> {
    serde_json::from_str(json).map_err(|error| FederationTreatyError::Json(error.to_string()))
}

pub fn ladder_intersection_from_json(
    json: &str,
) -> Result<LadderIntersection, FederationTreatyError> {
    serde_json::from_str(json).map_err(|error| FederationTreatyError::Json(error.to_string()))
}

pub fn ladder_intersection_json(
    intersection: &LadderIntersection,
) -> Result<String, FederationTreatyError> {
    validate_ladder_intersection(intersection)?;
    serde_json::to_string_pretty(intersection)
        .map_err(|error| FederationTreatyError::Json(error.to_string()))
}

pub fn cross_boundary_admission_report_json(
    report: &CrossBoundaryAdmissionReport,
) -> Result<String, FederationTreatyError> {
    validate_cross_boundary_admission_report(report)?;
    serde_json::to_string_pretty(report)
        .map_err(|error| FederationTreatyError::Json(error.to_string()))
}

pub fn governance_ladder_manifest_sha256(
    manifest: &GovernanceLadderManifest,
) -> Result<String, FederationTreatyError> {
    validate_governance_ladder_manifest(manifest)?;
    canonical_sha256(manifest)
}

pub fn treaty_scope_sha256(scope: &TreatyScope) -> Result<String, FederationTreatyError> {
    canonical_sha256(scope)
}

pub fn ladder_intersection_sha256(
    intersection: &LadderIntersection,
) -> Result<String, FederationTreatyError> {
    canonical_sha256(intersection)
}

pub fn compute_ladder_intersection(
    treaty_scope: &TreatyScope,
    manifests: &[GovernanceLadderManifest],
    now_unix_ms: u64,
) -> Result<LadderIntersection, FederationTreatyError> {
    validate_treaty_scope(treaty_scope)?;
    if now_unix_ms < treaty_scope.issued_at_unix_ms
        || now_unix_ms >= treaty_scope.expires_at_unix_ms
    {
        return rejected("chio_federation_treaty_stale", "treaty scope is not fresh");
    }
    if manifests.len() != treaty_scope.participant_kernel_ids.len() {
        return rejected(
            "chio_federation_treaty_missing_participant",
            "manifest set does not cover every treaty participant",
        );
    }
    let mut manifest_hashes = Vec::new();
    let mut by_kernel = BTreeMap::new();
    for manifest in manifests {
        validate_governance_ladder_manifest(manifest)?;
        if now_unix_ms < manifest.issued_at_unix_ms || now_unix_ms >= manifest.expires_at_unix_ms {
            return rejected(
                "chio_federation_ladder_manifest_stale",
                "governance ladder manifest is not fresh",
            );
        }
        if !treaty_scope
            .participant_kernel_ids
            .iter()
            .any(|kernel| kernel == &manifest.kernel_id)
        {
            return rejected(
                "chio_federation_treaty_missing_participant",
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
                "chio_federation_treaty_missing_participant",
                "duplicate governance ladder manifest for participant",
            );
        }
    }
    let expected: BTreeSet<_> = treaty_scope.ladder_manifest_sha256s.iter().collect();
    let actual: BTreeSet<_> = manifest_hashes.iter().collect();
    if expected != actual {
        return rejected(
            "chio_federation_ladder_manifest_hash_mismatch",
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
                    "chio_federation_treaty_missing_participant",
                    "treaty participant is missing a governance ladder manifest",
                );
            };
            let Some(action) = find_ladder_action(manifest, action_class_id) else {
                return rejected(
                    "chio_federation_treaty_action_class_not_allowed",
                    "governance ladder manifest does not allow action class",
                );
            };
            let rank = ladder_mode_rank(&action.mode)?;
            if rank > mode_rank {
                mode_rank = rank;
                mode.clone_from(&action.mode);
            }
            destructive |= action.destructive;
            if let Some(existing) = consistency_model.as_ref() {
                if existing != &action.consistency_model {
                    return rejected(
                        "chio_federation_ladder_consistency_mismatch",
                        "governance ladder consistency models do not intersect",
                    );
                }
            } else {
                consistency_model = Some(action.consistency_model.clone());
            }
            if co_sign_requirement_rank(&action.co_sign)? > co_sign_requirement_rank(&co_sign)? {
                co_sign.clone_from(&action.co_sign);
            }
            merge_quorum(&mut co_sign_quorum, action.co_sign_quorum.as_ref())?;
            for item in &action.evidence_required {
                evidence_required.insert(item.clone());
            }
            participant_modes.insert(participant.clone(), action.mode.clone());
        }
        if destructive && mode_rank < ladder_mode_rank("receipt_backed")? {
            return rejected(
                "chio_federation_ladder_destructive_below_floor",
                "intersected destructive action resolves below receipt backed mode",
            );
        }
        if destructive && consistency_model.as_deref() == Some("crdt-commutative") {
            return rejected(
                "chio_federation_ladder_destructive_crdt_not_allowed",
                "intersected destructive action cannot use crdt-commutative consistency",
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
            "chio_federation_treaty_action_class_not_allowed",
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

pub fn evaluate_cross_boundary_admission(
    input: CrossBoundaryAdmissionInput<'_>,
) -> Result<CrossBoundaryAdmissionReport, FederationTreatyError> {
    validate_treaty_scope(input.treaty_scope)?;
    validate_ladder_intersection(input.ladder_intersection)?;
    let treaty_scope_sha256 = treaty_scope_sha256(input.treaty_scope)?;
    let ladder_intersection_sha256 = ladder_intersection_sha256(input.ladder_intersection)?;
    let mut checks = vec![
        "chio_federation.treaty.scope_valid".to_string(),
        "chio_federation.treaty.intersection_valid".to_string(),
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
            "chio_federation_treaty_stale",
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
            "chio_federation_treaty_intersection_mismatch",
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
            "chio_federation_treaty_missing_intersection_binding",
            checks,
        ));
    };
    if expected_ladder_intersection_sha256 != ladder_intersection_sha256 {
        return Ok(cross_boundary_rejection_report(
            input,
            treaty_scope_sha256,
            ladder_intersection_sha256,
            "chio_federation_treaty_intersection_mismatch",
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
            "chio_federation_treaty_action_class_not_allowed",
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
            "chio_federation_treaty_action_class_not_allowed",
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
            failure_code: Some("chio_federation_treaty_missing_required_evidence".to_string()),
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
            failure_code: Some("chio_federation_treaty_unverified_required_evidence".to_string()),
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
    checks.push("chio_federation.treaty.required_evidence_present".to_string());
    checks.push("chio_federation.treaty.required_evidence_verified".to_string());
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

pub fn validate_governance_ladder_manifest(
    manifest: &GovernanceLadderManifest,
) -> Result<(), FederationTreatyError> {
    if !matches!(
        manifest.schema.as_str(),
        CHIO_FEDERATION_GOVERNANCE_LADDER_MANIFEST_SCHEMA
    ) {
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
        if aliases.contains(action.action_class_id.as_str()) {
            return rejected(
                "chio_federation_ladder_alias_conflict",
                "governance ladder action class conflicts with a prior alias",
            );
        }
        if !action_ids.insert(action.action_class_id.as_str()) {
            return rejected(
                "chio_federation_ladder_duplicate_action_class",
                "governance ladder manifest contains a duplicate action class",
            );
        }
        let action_rank = ladder_mode_rank(&action.mode)?;
        validate_consistency_model(&action.consistency_model)?;
        validate_co_sign_mode(&action.co_sign)?;
        validate_co_sign_quorum(&action.co_sign, action.co_sign_quorum.as_ref())?;
        if action.destructive && action_rank < destructive_floor_rank {
            return rejected(
                "chio_federation_ladder_destructive_below_floor",
                "destructive action class resolves below the destructive floor",
            );
        }
        if action.destructive && action.consistency_model == "crdt-commutative" {
            return rejected(
                "chio_federation_ladder_destructive_crdt_not_allowed",
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
                    "chio_federation_ladder_alias_conflict",
                    "governance ladder alias conflicts with another action class",
                );
            }
        }
    }
    Ok(())
}

pub fn validate_treaty_scope(scope: &TreatyScope) -> Result<(), FederationTreatyError> {
    if !matches!(scope.schema.as_str(), CHIO_FEDERATION_TREATY_SCOPE_SCHEMA) {
        return rejected(
            "unsupported_treaty_scope_schema",
            "treaty scope declared an unsupported schema",
        );
    }
    validate_non_empty(&scope.treaty_id, "treaty_scope_empty_id")?;
    if scope.issued_at_unix_ms >= scope.expires_at_unix_ms {
        return rejected(
            "chio_federation_treaty_stale",
            "treaty scope validity window is empty",
        );
    }
    if scope.participant_kernel_ids.len() < 2 {
        return rejected(
            "chio_federation_treaty_missing_participant",
            "treaty scope must bind at least two participant kernels",
        );
    }
    if scope.participant_kernel_ids.len() != scope.ladder_manifest_sha256s.len() {
        return rejected(
            "chio_federation_ladder_manifest_hash_mismatch",
            "treaty scope must bind one ladder manifest hash per participant",
        );
    }
    if scope.participant_kernel_ids.len() != scope.participant_public_keys.len() {
        return rejected(
            "chio_federation_treaty_missing_participant",
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
        ensure_sha256_hash(hash, "chio_federation_ladder_manifest_hash_mismatch")?;
        if !hashes.insert(hash.as_str()) {
            return rejected(
                "chio_federation_ladder_manifest_hash_mismatch",
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

pub fn validate_ladder_intersection(
    intersection: &LadderIntersection,
) -> Result<(), FederationTreatyError> {
    if !matches!(
        intersection.schema.as_str(),
        CHIO_FEDERATION_LADDER_INTERSECTION_SCHEMA
    ) {
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
            "chio_federation_treaty_stale",
            "ladder intersection validity window is empty",
        );
    }
    if intersection.action_classes.is_empty() {
        return rejected(
            "chio_federation_treaty_action_class_not_allowed",
            "ladder intersection contains no action classes",
        );
    }
    for hash in &intersection.ladder_manifest_sha256s {
        ensure_sha256_hash(hash, "chio_federation_ladder_manifest_hash_mismatch")?;
    }
    for action in &intersection.action_classes {
        validate_non_empty(
            &action.action_class_id,
            "ladder_intersection_empty_action_class",
        )?;
        ladder_mode_rank(&action.mode)?;
        validate_consistency_model(&action.consistency_model)?;
        validate_co_sign_mode(&action.co_sign)?;
        validate_co_sign_quorum(&action.co_sign, action.co_sign_quorum.as_ref())?;
        if action.destructive
            && ladder_mode_rank(&action.mode)? < ladder_mode_rank("receipt_backed")?
        {
            return rejected(
                "chio_federation_ladder_destructive_below_floor",
                "ladder intersection destructive action resolves below receipt backed mode",
            );
        }
        if action.destructive && action.consistency_model == "crdt-commutative" {
            return rejected(
                "chio_federation_ladder_destructive_crdt_not_allowed",
                "ladder intersection destructive action cannot use crdt-commutative consistency",
            );
        }
    }
    Ok(())
}

pub fn validate_cross_boundary_admission_report(
    report: &CrossBoundaryAdmissionReport,
) -> Result<(), FederationTreatyError> {
    if !matches!(
        report.schema.as_str(),
        CHIO_FEDERATION_CROSS_BOUNDARY_ADMISSION_REPORT_SCHEMA
    ) {
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
                    "chio_federation_treaty_missing_required_evidence",
                    "accepted cross-boundary admission report is missing required evidence",
                );
            }
            if verified
                .get(required.as_str())
                .copied()
                .is_none_or(|is_verified| !is_verified)
            {
                return rejected(
                    "chio_federation_treaty_unverified_required_evidence",
                    "accepted cross-boundary admission report has unverified required evidence",
                );
            }
        }
    }
    Ok(())
}

fn required_evidence_for_action(action: &LadderIntersectionActionClass) -> Vec<String> {
    let mut required = action.evidence_required.clone();
    if action.co_sign == "bilateral_required"
        && !required
            .iter()
            .any(|evidence| evidence == "bilateral_invocation")
    {
        required.push("bilateral_invocation".to_string());
    }
    if action.co_sign == "n_of_m"
        && !required
            .iter()
            .any(|evidence| evidence == "quorum_signature")
    {
        required.push("quorum_signature".to_string());
    }
    required
}

fn ladder_mode_rank(mode: &str) -> Result<u8, FederationTreatyError> {
    match mode {
        "observation" => Ok(0),
        "guarded" => Ok(1),
        "receipt_backed" => Ok(2),
        "partition_contingency" => Ok(3),
        "maintenance" => Ok(4),
        _ => rejected(
            "chio_federation_ladder_invalid_mode",
            "governance ladder mode is not supported",
        ),
    }
}

fn validate_consistency_model(model: &str) -> Result<(), FederationTreatyError> {
    match model {
        "crdt-commutative" | "totally-ordered" | "single-kernel" | "quorum-required" => Ok(()),
        _ => rejected(
            "chio_federation_ladder_invalid_consistency_model",
            "governance ladder consistency model is not supported",
        ),
    }
}

fn validate_co_sign_mode(mode: &str) -> Result<(), FederationTreatyError> {
    match mode {
        "none" | "bilateral_if_cross_org" | "bilateral_required" | "n_of_m" => Ok(()),
        _ => rejected(
            "chio_federation_ladder_invalid_cosign_mode",
            "governance ladder co-sign mode is not supported",
        ),
    }
}

fn validate_co_sign_quorum(
    mode: &str,
    quorum: Option<&GovernanceLadderQuorum>,
) -> Result<(), FederationTreatyError> {
    match (mode, quorum) {
        ("n_of_m", Some(quorum)) => {
            if quorum.n < 2 || quorum.m < 2 || quorum.n > quorum.m {
                return rejected(
                    "chio_federation_ladder_quorum_misdeclared",
                    "n_of_m quorum requires 2 <= n <= m",
                );
            }
            if !matches!(quorum.scope.as_str(), "treaty" | "kernel" | "operator") {
                return rejected(
                    "chio_federation_ladder_quorum_misdeclared",
                    "n_of_m quorum scope is unsupported",
                );
            }
            Ok(())
        }
        ("n_of_m", None) => rejected(
            "chio_federation_ladder_quorum_misdeclared",
            "n_of_m co-sign mode requires quorum metadata",
        ),
        (_, Some(_)) => rejected(
            "chio_federation_ladder_quorum_misdeclared",
            "quorum metadata is only valid for n_of_m co-sign mode",
        ),
        (_, None) => Ok(()),
    }
}

fn merge_quorum(
    current: &mut Option<GovernanceLadderQuorum>,
    candidate: Option<&GovernanceLadderQuorum>,
) -> Result<(), FederationTreatyError> {
    let Some(candidate) = candidate else {
        return Ok(());
    };
    match current {
        Some(existing) => {
            if existing.m != candidate.m || existing.scope != candidate.scope {
                return rejected(
                    "chio_federation_ladder_quorum_misdeclared",
                    "participant quorum counts or scopes do not intersect",
                );
            }
            existing.n = existing.n.max(candidate.n);
        }
        None => *current = Some(candidate.clone()),
    }
    Ok(())
}

fn co_sign_requirement_rank(mode: &str) -> Result<u8, FederationTreatyError> {
    match mode {
        "none" => Ok(0),
        "bilateral_if_cross_org" => Ok(1),
        "bilateral_required" => Ok(2),
        "n_of_m" => Ok(3),
        _ => rejected(
            "chio_federation_ladder_invalid_cosign_mode",
            "governance ladder co-sign mode is not supported",
        ),
    }
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

fn validate_non_empty(value: &str, code: &'static str) -> Result<(), FederationTreatyError> {
    if value.trim().is_empty() {
        return rejected(code, "federation treaty field must not be empty");
    }
    Ok(())
}

fn validate_state_label(value: &str, code: &'static str) -> Result<(), FederationTreatyError> {
    if value.trim().is_empty()
        || value.trim() != value
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(FederationTreatyError::Rejected {
            code,
            detail: format!("federation treaty label {value:?} is invalid"),
        });
    }
    Ok(())
}

fn ensure_sha256_hash(hash: &str, code: &'static str) -> Result<(), FederationTreatyError> {
    if hash.len() == 64 && hash.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Ok(());
    }
    Err(FederationTreatyError::Rejected {
        code,
        detail: format!("federation treaty hash {hash} is not sha256 hex"),
    })
}

fn rejected<T>(code: &'static str, detail: &str) -> Result<T, FederationTreatyError> {
    Err(FederationTreatyError::Rejected {
        code,
        detail: detail.to_string(),
    })
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, FederationTreatyError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| FederationTreatyError::Canonical(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
