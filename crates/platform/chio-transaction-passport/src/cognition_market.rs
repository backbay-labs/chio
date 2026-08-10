//! Qualified cognition-market proof-bundle verification.
//!
//! The signed finding-verifier report is the authority artifact. Replay
//! recipes and portable status proofs remain unsigned, content-addressed
//! attachments in the evidence graph's advisory role. This verifier checks
//! their exact canonical bytes and semantics independently before accepting
//! any `claim.finding.*` ClaimSet row.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chio_core_types::crypto::PublicKey;
use chio_core_types::{canonical_json_bytes, canonical_json_bytes_from_str};
use chio_finding::{
    verify_signed_verifier_report, verify_status_proof_input, FindingAuthorityKeyPolicy,
    FindingFacetKind, FindingFacetOutcome, FindingReplayRecipeInput, FindingStatusFreshnessPolicy,
    FindingStatusNonInclusionProofInput, FindingStatusOperatorAuthorization,
    FindingStatusProofInput, SignedFindingStatusEpoch, SignedFindingVerifierReport,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_STATUS_PROOF_INPUT_SCHEMA_V1,
    FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    verify_passport_root_and_claim_set_artifacts_with_transparency_anchors, TransactionPassport,
    TransactionPassportError, TransactionTrustAnchors, TransactionVerifierReport,
};

pub const COGNITION_MARKET_CLAIMS: [&str; 4] = [
    "claim.finding.delivery_digest_bound",
    "claim.finding.evidence_bound",
    "claim.finding.status_fresh",
    "claim.finding.bond_backed",
];

const FINDING_VERIFIER_MODULE: &str = "chio-finding-verifier";

/// Exact verified status material that must cross a durable trust boundary
/// before a cognition-market claim can be granted.
pub struct CognitionMarketStatusObservation<'a> {
    pub signed_epoch: &'a SignedFindingStatusEpoch,
    pub signed_epoch_bytes: &'a [u8],
    pub proof: &'a FindingStatusNonInclusionProofInput,
    pub proof_bytes: &'a [u8],
    pub operator_authorization_sha256: &'a str,
    pub recorded_at: u64,
}

/// Deployment-owned durable status memory.
///
/// Implementations must atomically enforce a monotonic epoch floor for the
/// feed and stable operator identity, reject same-epoch conflicts, retain
/// sticky pending or retracted state, and accept only an exact current-floor
/// non-inclusion proof for the named Finding.
pub trait CognitionMarketStatusTrustStore: Send + Sync {
    fn admit_verified_non_inclusion(
        &self,
        observation: &CognitionMarketStatusObservation<'_>,
    ) -> Result<(), String>;
}

/// Deployment-owned roots used to recheck the proof bundle. Neither the
/// report nor the status proof may self-authorize these keys or time bounds.
#[derive(Clone)]
pub struct CognitionMarketProofTrust {
    pub trusted_passport_signer_keys: Vec<PublicKey>,
    pub trusted_checkpoint_signer_keys: Vec<PublicKey>,
    pub finding_verifier_authority: PublicKey,
    pub finding_verifier_signer: FindingAuthorityKeyPolicy,
    pub trusted_verifier_profile_envelope_sha256: String,
    pub trusted_verifier_profile_required_facets: Vec<FindingFacetKind>,
    pub trusted_trust_root_snapshot_sha256: String,
    pub status: Option<CognitionMarketStatusTrust>,
}

/// Deployment-owned trust needed only by `claim.finding.status_fresh`.
#[derive(Clone)]
pub struct CognitionMarketStatusTrust {
    pub status_operator_authorization: FindingStatusOperatorAuthorization,
    pub status_freshness: FindingStatusFreshnessPolicy,
    pub status_store: Arc<dyn CognitionMarketStatusTrustStore>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClaimSet {
    schema: String,
    id: String,
    issued_at: String,
    claims: Vec<Claim>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    claim_id: String,
    status: String,
    #[serde(default)]
    required_evidence: Vec<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
    failure_reason: Option<String>,
    verifier_module: String,
}

struct GraphNode<'a> {
    id: &'a str,
    schema: &'a str,
    path: &'a str,
    role: &'a str,
}

/// Verify the cognition-market ClaimSet, signed report, and both unsigned
/// attachments from exact persisted artifact bytes.
pub fn verify_cognition_market_passport_artifacts(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trust: &CognitionMarketProofTrust,
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    verify_cognition_market_passport_artifacts_with_external_claims(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        trust,
        &[],
    )
}

/// Verify cognition-market artifacts while carrying claims already verified
/// by other authoritative family verifiers into the combined root gate.
#[allow(clippy::too_many_arguments)]
pub fn verify_cognition_market_passport_artifacts_with_external_claims(
    passport: &TransactionPassport,
    passport_path: String,
    evidence_graph_bytes: &[u8],
    verifier_policy_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    trust: &CognitionMarketProofTrust,
    externally_verified_claims: &[String],
) -> Result<TransactionVerifierReport, TransactionPassportError> {
    // Validate the signed root and the complete graph shape before interpreting
    // cognition-market roles. This also rejects unsupported registered schemas,
    // dangling/cyclic edges, and advisory authority edges.
    crate::minimal::verify_minimal_passport_artifacts_with_anchor_inputs(
        passport,
        passport_path.clone(),
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        &trust.trusted_checkpoint_signer_keys,
    )?;

    let graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(
                "evidence graph missing nodes".to_string(),
            )
        })?;
    validate_every_graph_artifact(nodes, artifacts)?;

    let claim_set = parse_cognition_claim_set(passport, artifacts)?;
    let selected_claims = selected_cognition_claims(&claim_set)?;
    if selected_claims.is_empty() {
        return Err(claim_failed(
            "ClaimSet has no verified cognition-market claim",
        ));
    }

    let report_node = unique_node(nodes, "report", FINDING_VERIFIER_REPORT_SCHEMA_V1)?;
    let recipe_node = selected_claims
        .contains(COGNITION_MARKET_CLAIMS[1])
        .then(|| {
            unique_node(
                nodes,
                "advisory-observation",
                FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
            )
        })
        .transpose()?;
    let status_node = selected_claims
        .contains(COGNITION_MARKET_CLAIMS[2])
        .then(|| {
            unique_node(
                nodes,
                "advisory-observation",
                FINDING_STATUS_PROOF_INPUT_SCHEMA_V1,
            )
        })
        .transpose()?;
    let attachment_nodes = recipe_node
        .iter()
        .chain(status_node.iter())
        .collect::<Vec<_>>();
    require_digest_bound_attachment_edges(&graph, &report_node, &attachment_nodes)?;

    let report_bytes = artifact_bytes(artifacts, report_node.path)?;
    require_exact_canonical_json(report_node.path, report_bytes)?;
    let report: SignedFindingVerifierReport =
        serde_json::from_slice(report_bytes).map_err(|error| {
            invalid_artifact(
                report_node.path,
                format!("invalid signed verifier report: {error}"),
            )
        })?;
    trust
        .finding_verifier_signer
        .validate("finding_verifier_signer")
        .map_err(|error| {
            claim_failed(format!(
                "trusted verifier signer policy is invalid: {error}"
            ))
        })?;
    if trust.finding_verifier_signer.key != trust.finding_verifier_authority {
        return Err(claim_failed(
            "trusted verifier signer policy and authority key disagree",
        ));
    }
    verify_signed_verifier_report(&report, &trust.finding_verifier_authority)
        .map_err(|error| invalid_artifact(report_node.path, error.to_string()))?;
    if report.body.verifier_key_epoch != trust.finding_verifier_signer.key_epoch {
        return Err(claim_failed(
            "signed verifier report key epoch does not match the deployment-pinned signer policy",
        ));
    }
    if report.body.evaluation_time < trust.finding_verifier_signer.valid_from
        || report.body.evaluation_time >= trust.finding_verifier_signer.valid_until
    {
        return Err(claim_failed(
            "signed verifier report evaluation time is outside the deployment-pinned signer lifecycle",
        ));
    }
    if report.body.verifier_profile_envelope_sha256
        != trust.trusted_verifier_profile_envelope_sha256
    {
        return Err(claim_failed(
            "signed verifier report does not bind the deployment-pinned verifier profile",
        ));
    }
    if report.body.trust_root_snapshot_sha256 != trust.trusted_trust_root_snapshot_sha256 {
        return Err(claim_failed(
            "signed verifier report does not bind the deployment-pinned trust-root snapshot",
        ));
    }

    if let Some(recipe_node) = &recipe_node {
        let recipe_bytes = artifact_bytes(artifacts, recipe_node.path)?;
        let recipe = parse_recipe(recipe_node.path, recipe_bytes)?;
        let recipe_digest = crate::sha256_hex(recipe_bytes);
        if report.body.replay_recipe_input_sha256.as_deref() != Some(recipe_digest.as_str()) {
            return Err(claim_failed(
                "signed verifier report does not bind the exact replay-recipe attachment",
            ));
        }
        // Recompute through the typed artifact too. This catches any future
        // parser drift even though strict canonical raw bytes already pin the
        // node.
        if recipe
            .canonical_sha256()
            .map_err(|error| invalid_artifact(recipe_node.path, error.to_string()))?
            != recipe_digest
        {
            return Err(claim_failed("replay-recipe typed digest drift"));
        }
        if recipe.verifier_profile_envelope_sha256 != report.body.verifier_profile_envelope_sha256 {
            return Err(claim_failed(
                "replay recipe and signed report bind different verifier profiles",
            ));
        }
    }

    let verified_status = if let Some(status_node) = &status_node {
        let status_trust = trust.status.as_ref().ok_or_else(|| {
            claim_failed("status-fresh claim has no deployment-pinned status trust")
        })?;
        let status_bytes = artifact_bytes(artifacts, status_node.path)?;
        let status = chio_finding::parse_status_proof_input(status_bytes)
            .map_err(|error| invalid_artifact(status_node.path, error.to_string()))?;
        let status_digest = crate::sha256_hex(status_bytes);
        if report.body.status_proof_input_sha256.as_deref() != Some(status_digest.as_str()) {
            return Err(claim_failed(
                "signed verifier report does not bind the exact status-proof attachment",
            ));
        }
        if status.finding_id() != report.body.finding_id {
            return Err(claim_failed(
                "status-proof attachment does not name the report Finding",
            ));
        }
        if !matches!(status, FindingStatusProofInput::NonInclusion(_)) {
            return Err(claim_failed(
                "qualified status-fresh claim requires a non-inclusion proof",
            ));
        }
        if status_trust.status_freshness.now != report.body.evaluation_time {
            return Err(claim_failed(
                "status freshness clock does not match the signed report evaluation time",
            ));
        }
        let signed_epoch = verify_status_proof_input(
            &status,
            &status_trust.status_operator_authorization,
            status_trust.status_freshness,
        )
        .map_err(|error| invalid_artifact(status_node.path, error.to_string()))?;
        Some((status_node.path, status_bytes, status, signed_epoch))
    } else {
        None
    };

    require_report_facets(
        &report,
        &selected_claims,
        &trust.trusted_verifier_profile_required_facets,
    )?;
    validate_selected_cognition_claim_rows(
        &claim_set,
        &selected_claims,
        report_node.path,
        recipe_node.as_ref().map(|node| node.path),
        status_node.as_ref().map(|node| node.path),
    )?;

    // The generic verifier performs the final passport signature, graph/root,
    // policy, and ClaimSet digest checks. Cognition-specific semantics above
    // are what make these four external claims eligible for acceptance.
    // Generic transaction-integrity claims remain independently verified by
    // that root verifier and must survive this family projection.
    let mut report = verify_passport_root_and_claim_set_artifacts_with_transparency_anchors(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        TransactionTrustAnchors {
            passport_root_signers: &trust.trusted_passport_signer_keys,
            checkpoint_signers: &trust.trusted_checkpoint_signer_keys,
        },
        externally_verified_claims,
    )?;
    report
        .verified_claims
        .retain(|claim| selected_cognition_report_claim(&selected_claims, claim));
    report
        .claim_results
        .retain(|claim| selected_cognition_report_claim(&selected_claims, &claim.claim_id));

    // Advance durable status memory only after every passport, graph, report,
    // and ClaimSet check succeeds, but before any claim leaves this verifier.
    if let Some((status_path, status_bytes, status, signed_epoch)) = verified_status {
        let status_trust = trust.status.as_ref().ok_or_else(|| {
            claim_failed("status-fresh claim has no deployment-pinned status trust")
        })?;
        let FindingStatusProofInput::NonInclusion(non_inclusion) = &status else {
            return Err(claim_failed(
                "qualified status-fresh claim requires a non-inclusion proof",
            ));
        };
        let signed_epoch_bytes = canonical_json_bytes(&signed_epoch)
            .map_err(|error| invalid_artifact(status_path, error.to_string()))?;
        let authorization_bytes = canonical_json_bytes(&status_trust.status_operator_authorization)
            .map_err(|error| invalid_artifact(status_path, error.to_string()))?;
        let operator_authorization_sha256 = crate::sha256_hex(&authorization_bytes);
        status_trust
            .status_store
            .admit_verified_non_inclusion(&CognitionMarketStatusObservation {
                signed_epoch: &signed_epoch,
                signed_epoch_bytes: &signed_epoch_bytes,
                proof: non_inclusion,
                proof_bytes: status_bytes,
                operator_authorization_sha256: &operator_authorization_sha256,
                recorded_at: status_trust.status_freshness.now,
            })
            .map_err(|error| {
                claim_failed(format!(
                    "durable finding status trust rejected proof: {error}"
                ))
            })?;
    }
    Ok(report)
}

fn selected_cognition_report_claim(
    selected_claims: &BTreeSet<&'static str>,
    claim_id: &str,
) -> bool {
    selected_claims.contains(claim_id) || claim_id.starts_with("claim.transaction.")
}

fn validate_every_graph_artifact(
    nodes: &[Value],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<(), TransactionPassportError> {
    for value in nodes {
        let node = graph_node(value)?;
        let bytes = artifact_bytes(artifacts, node.path)?;
        let actual = crate::sha256_hex(bytes);
        if node.id != actual {
            return Err(
                TransactionPassportError::EvidenceGraphArtifactDigestMismatch {
                    path: node.path.to_string(),
                    expected: node.id.to_string(),
                    actual,
                },
            );
        }
    }
    Ok(())
}

fn unique_node<'a>(
    nodes: &'a [Value],
    role: &str,
    schema: &str,
) -> Result<GraphNode<'a>, TransactionPassportError> {
    let mut found = None;
    for value in nodes {
        let node = graph_node(value)?;
        if node.role == role && node.schema == schema {
            if found.is_some() {
                return Err(claim_failed(format!(
                    "duplicate {role} node for schema {schema}"
                )));
            }
            found = Some(node);
        }
    }
    found.ok_or_else(|| {
        TransactionPassportError::MissingCognitionMarketArtifact(format!(
            "role={role}, schema={schema}"
        ))
    })
}

fn graph_node(value: &Value) -> Result<GraphNode<'_>, TransactionPassportError> {
    let string = |field: &str| {
        value
            .get(field)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
                    "evidence graph node missing {field}"
                ))
            })
    };
    Ok(GraphNode {
        id: string("id")?,
        schema: string("schema")?,
        path: string("path")?,
        role: string("role")?,
    })
}

fn require_digest_bound_attachment_edges(
    graph: &Value,
    report: &GraphNode<'_>,
    attachments: &[&GraphNode<'_>],
) -> Result<(), TransactionPassportError> {
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(
                "evidence graph missing edges".to_string(),
            )
        })?;
    for attachment in attachments {
        let present = edges.iter().any(|edge| {
            edge.get("from").and_then(Value::as_str) == Some(report.id)
                && edge.get("to").and_then(Value::as_str) == Some(attachment.id)
                && edge.get("predicate").and_then(Value::as_str) == Some("binds")
                && edge.get("evidence_class").and_then(Value::as_str)
                    == Some("digest-bound-reference")
        });
        if !present {
            return Err(claim_failed(format!(
                "signed report has no digest-bound edge to {}",
                attachment.path
            )));
        }
    }
    Ok(())
}

fn require_report_facets(
    report: &SignedFindingVerifierReport,
    selected_claims: &BTreeSet<&'static str>,
    profile_required_facets: &[FindingFacetKind],
) -> Result<(), TransactionPassportError> {
    if let Some(failed) = report
        .body
        .facets
        .iter()
        .find(|facet| facet.outcome == FindingFacetOutcome::Failed)
    {
        return Err(claim_failed(format!(
            "signed verifier report contains failed facet {:?}",
            failed.facet
        )));
    }
    for facet in profile_required_facets {
        if report.body.facet_outcome(*facet) != Some(FindingFacetOutcome::Verified) {
            return Err(claim_failed(format!(
                "deployment-pinned verifier profile requires verified facet {facet:?}"
            )));
        }
    }
    if selected_claims.contains(COGNITION_MARKET_CLAIMS[0])
        && report.body.finding_delivery_receipt_id.is_none()
    {
        return Err(claim_failed(
            "delivery-digest-bound claim requires a verified Finding delivery receipt",
        ));
    }
    for (claim, required) in [
        (
            COGNITION_MARKET_CLAIMS[0],
            &[
                FindingFacetKind::ArtifactIntegrity,
                FindingFacetKind::ReceiptAuthenticity,
                FindingFacetKind::CheckpointMembership,
                FindingFacetKind::GuaranteeConsistency,
            ][..],
        ),
        (
            COGNITION_MARKET_CLAIMS[1],
            &[
                FindingFacetKind::ReceiptAuthenticity,
                FindingFacetKind::CheckpointMembership,
                FindingFacetKind::RecipeBinding,
            ][..],
        ),
        (
            COGNITION_MARKET_CLAIMS[2],
            &[FindingFacetKind::StatusLiveness][..],
        ),
        (
            COGNITION_MARKET_CLAIMS[3],
            &[FindingFacetKind::BondBacking][..],
        ),
    ] {
        if !selected_claims.contains(claim) {
            continue;
        }
        for facet in required {
            if report.body.facet_outcome(*facet) != Some(FindingFacetOutcome::Verified) {
                return Err(claim_failed(format!(
                    "{claim} requires verified facet {facet:?}"
                )));
            }
        }
    }
    Ok(())
}

fn parse_cognition_claim_set(
    passport: &TransactionPassport,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<ClaimSet, TransactionPassportError> {
    let bytes = artifact_bytes(artifacts, &passport.claim_set_path)?;
    let claim_set: ClaimSet = serde_json::from_slice(bytes).map_err(|error| {
        invalid_artifact(
            &passport.claim_set_path,
            format!("invalid ClaimSet: {error}"),
        )
    })?;
    if claim_set.schema != "chio.transaction.claim-set.v1"
        || claim_set.id.is_empty()
        || claim_set.issued_at.is_empty()
    {
        return Err(claim_failed("invalid cognition-market ClaimSet header"));
    }
    for claim in &claim_set.claims {
        if claim.claim_id.starts_with("claim.finding.")
            && !COGNITION_MARKET_CLAIMS.contains(&claim.claim_id.as_str())
        {
            return Err(claim_failed(format!(
                "ClaimSet contains unqualified Finding claim {}",
                claim.claim_id
            )));
        }
    }
    Ok(claim_set)
}

fn selected_cognition_claims(
    claim_set: &ClaimSet,
) -> Result<BTreeSet<&'static str>, TransactionPassportError> {
    let mut selected = BTreeSet::new();
    for claim_id in COGNITION_MARKET_CLAIMS {
        let mut matching = claim_set
            .claims
            .iter()
            .filter(|candidate| candidate.claim_id == claim_id);
        let first = matching.next();
        if matching.next().is_some() {
            return Err(claim_failed(format!(
                "ClaimSet contains duplicate rows for {claim_id}"
            )));
        }
        if first.is_some_and(|claim| claim.status == "verified") {
            selected.insert(claim_id);
        }
    }
    Ok(selected)
}

fn validate_selected_cognition_claim_rows(
    claim_set: &ClaimSet,
    selected_claims: &BTreeSet<&'static str>,
    report_path: &str,
    recipe_path: Option<&str>,
    status_path: Option<&str>,
) -> Result<(), TransactionPassportError> {
    for claim_id in selected_claims {
        let mut matching = claim_set
            .claims
            .iter()
            .filter(|candidate| candidate.claim_id == **claim_id);
        let claim = matching
            .next()
            .ok_or_else(|| claim_failed(format!("ClaimSet missing {claim_id}")))?;
        if matching.next().is_some()
            || claim.status != "verified"
            || claim.verifier_module != FINDING_VERIFIER_MODULE
            || claim.failure_reason.is_some()
        {
            return Err(claim_failed(format!(
                "ClaimSet has invalid verified row for {claim_id}"
            )));
        }
        let expected_paths = match *claim_id {
            claim if claim == COGNITION_MARKET_CLAIMS[0] => vec![report_path.to_string()],
            claim if claim == COGNITION_MARKET_CLAIMS[1] => vec![
                report_path.to_string(),
                recipe_path
                    .ok_or_else(|| claim_failed("evidence-bound claim is missing its recipe"))?
                    .to_string(),
            ],
            claim if claim == COGNITION_MARKET_CLAIMS[2] => vec![
                report_path.to_string(),
                status_path
                    .ok_or_else(|| claim_failed("status-fresh claim is missing its proof"))?
                    .to_string(),
            ],
            claim if claim == COGNITION_MARKET_CLAIMS[3] => vec![report_path.to_string()],
            _ => {
                return Err(claim_failed(format!(
                    "unsupported cognition-market claim {claim_id}"
                )))
            }
        };
        if claim.required_evidence != expected_paths || claim.evidence_refs != expected_paths {
            return Err(claim_failed(format!(
                "ClaimSet evidence pins do not match {claim_id}"
            )));
        }
    }
    Ok(())
}

fn parse_recipe(
    path: &str,
    bytes: &[u8],
) -> Result<FindingReplayRecipeInput, TransactionPassportError> {
    require_exact_canonical_json(path, bytes)?;
    let recipe: FindingReplayRecipeInput = serde_json::from_slice(bytes)
        .map_err(|error| invalid_artifact(path, format!("invalid replay recipe: {error}")))?;
    recipe
        .validate()
        .map_err(|error| invalid_artifact(path, error.to_string()))?;
    Ok(recipe)
}

fn require_exact_canonical_json(path: &str, bytes: &[u8]) -> Result<(), TransactionPassportError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| invalid_artifact(path, format!("not UTF-8: {error}")))?;
    let canonical = canonical_json_bytes_from_str(text)
        .map_err(|error| invalid_artifact(path, format!("not strict canonical JSON: {error}")))?;
    if canonical != bytes {
        return Err(invalid_artifact(path, "bytes are not canonical JSON"));
    }
    Ok(())
}

fn artifact_bytes<'a>(
    artifacts: &'a BTreeMap<String, Vec<u8>>,
    path: &str,
) -> Result<&'a [u8], TransactionPassportError> {
    artifacts
        .get(path)
        .map(Vec::as_slice)
        .ok_or_else(|| TransactionPassportError::MissingCognitionMarketArtifact(path.to_string()))
}

fn invalid_artifact(path: &str, message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::InvalidCognitionMarketArtifact {
        path: path.to_string(),
        message: message.into(),
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::CognitionMarketClaimFailed(message.into())
}
