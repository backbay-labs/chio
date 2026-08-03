//! Qualified cognition-market proof-bundle verification.
//!
//! The signed finding-verifier report is the authority artifact. Replay
//! recipes and portable status proofs remain unsigned, content-addressed
//! attachments in the evidence graph's advisory role. This verifier checks
//! their exact canonical bytes and semantics independently before accepting
//! any `claim.finding.*` ClaimSet row.

use std::collections::BTreeMap;

use chio_core_types::canonical_json_bytes_from_str;
use chio_core_types::crypto::PublicKey;
use chio_finding::{
    verify_signed_verifier_report, verify_status_proof_input, FindingFacetKind,
    FindingFacetOutcome, FindingReplayRecipeInput, FindingStatusFreshnessPolicy,
    FindingStatusOperatorAuthorization, FindingStatusProofInput, SignedFindingVerifierReport,
    FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1, FINDING_STATUS_PROOF_INPUT_SCHEMA_V1,
    FINDING_VERIFIER_REPORT_SCHEMA_V1,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    verify_minimal_passport_artifacts, verify_passport_root_and_claim_set_artifacts,
    TransactionPassport, TransactionPassportError, TransactionVerifierReport,
};

pub const COGNITION_MARKET_CLAIMS: [&str; 4] = [
    "claim.finding.delivery_digest_bound",
    "claim.finding.evidence_bound",
    "claim.finding.status_fresh",
    "claim.finding.bond_backed",
];

const FINDING_VERIFIER_MODULE: &str = "chio-finding-verifier";

/// Deployment-owned roots used to recheck the proof bundle. Neither the
/// report nor the status proof may self-authorize these keys or time bounds.
#[derive(Clone)]
pub struct CognitionMarketProofTrust {
    pub trusted_passport_signer_keys: Vec<PublicKey>,
    pub finding_verifier_authority: PublicKey,
    pub trusted_verifier_profile_envelope_sha256: String,
    pub status_operator_authorization: FindingStatusOperatorAuthorization,
    pub status_freshness: FindingStatusFreshnessPolicy,
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
    // Validate the signed root and the complete graph shape before interpreting
    // cognition-market roles. This also rejects unsupported registered schemas,
    // dangling/cyclic edges, and advisory authority edges.
    verify_minimal_passport_artifacts(
        passport,
        passport_path.clone(),
        evidence_graph_bytes,
        verifier_policy_bytes,
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

    let report_node = unique_node(nodes, "report", FINDING_VERIFIER_REPORT_SCHEMA_V1)?;
    let recipe_node = unique_node(
        nodes,
        "advisory-observation",
        FINDING_REPLAY_RECIPE_INPUT_SCHEMA_V1,
    )?;
    let status_node = unique_node(
        nodes,
        "advisory-observation",
        FINDING_STATUS_PROOF_INPUT_SCHEMA_V1,
    )?;
    require_digest_bound_attachment_edges(&graph, &report_node, [&recipe_node, &status_node])?;

    let report_bytes = artifact_bytes(artifacts, report_node.path)?;
    require_exact_canonical_json(report_node.path, report_bytes)?;
    let report: SignedFindingVerifierReport =
        serde_json::from_slice(report_bytes).map_err(|error| {
            invalid_artifact(
                report_node.path,
                format!("invalid signed verifier report: {error}"),
            )
        })?;
    verify_signed_verifier_report(&report, &trust.finding_verifier_authority)
        .map_err(|error| invalid_artifact(report_node.path, error.to_string()))?;
    if report.body.verifier_profile_envelope_sha256
        != trust.trusted_verifier_profile_envelope_sha256
    {
        return Err(claim_failed(
            "signed verifier report does not bind the deployment-pinned verifier profile",
        ));
    }

    let recipe_bytes = artifact_bytes(artifacts, recipe_node.path)?;
    let recipe = parse_recipe(recipe_node.path, recipe_bytes)?;
    let recipe_digest = crate::sha256_hex(recipe_bytes);
    if report.body.replay_recipe_input_sha256.as_deref() != Some(recipe_digest.as_str()) {
        return Err(claim_failed(
            "signed verifier report does not bind the exact replay-recipe attachment",
        ));
    }
    // Recompute through the typed artifact too. This catches any future parser
    // drift even though strict canonical raw bytes already pin the node.
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
    if trust.status_freshness.now != report.body.evaluation_time {
        return Err(claim_failed(
            "status freshness clock does not match the signed report evaluation time",
        ));
    }
    verify_status_proof_input(
        &status,
        &trust.status_operator_authorization,
        trust.status_freshness,
    )
    .map_err(|error| invalid_artifact(status_node.path, error.to_string()))?;

    require_report_facets(&report)?;
    validate_cognition_claim_set(
        passport,
        artifacts,
        report_node.path,
        recipe_node.path,
        status_node.path,
    )?;

    // The generic verifier performs the final passport signature, graph/root,
    // policy, and ClaimSet digest checks. Cognition-specific semantics above
    // are what make these four external claims eligible for acceptance.
    // Generic transaction-integrity claims remain independently verified by
    // that root verifier and must survive this family projection.
    let mut report = verify_passport_root_and_claim_set_artifacts(
        passport,
        passport_path,
        evidence_graph_bytes,
        verifier_policy_bytes,
        artifacts,
        &trust.trusted_passport_signer_keys,
    )?;
    report
        .verified_claims
        .retain(|claim| cognition_report_claim(claim));
    report
        .claim_results
        .retain(|claim| cognition_report_claim(&claim.claim_id));
    Ok(report)
}

fn cognition_report_claim(claim_id: &str) -> bool {
    COGNITION_MARKET_CLAIMS.contains(&claim_id) || claim_id.starts_with("claim.transaction.")
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
    attachments: [&GraphNode<'_>; 2],
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
) -> Result<(), TransactionPassportError> {
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

fn validate_cognition_claim_set(
    passport: &TransactionPassport,
    artifacts: &BTreeMap<String, Vec<u8>>,
    report_path: &str,
    recipe_path: &str,
    status_path: &str,
) -> Result<(), TransactionPassportError> {
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
    let expected: BTreeMap<&str, Vec<&str>> = BTreeMap::from([
        (COGNITION_MARKET_CLAIMS[0], vec![report_path]),
        (COGNITION_MARKET_CLAIMS[1], vec![report_path, recipe_path]),
        (COGNITION_MARKET_CLAIMS[2], vec![report_path, status_path]),
        (COGNITION_MARKET_CLAIMS[3], vec![report_path]),
    ]);
    for claim in &claim_set.claims {
        if claim.claim_id.starts_with("claim.finding.")
            && !expected.contains_key(claim.claim_id.as_str())
        {
            return Err(claim_failed(format!(
                "ClaimSet contains unqualified Finding claim {}",
                claim.claim_id
            )));
        }
    }
    for (claim_id, required_paths) in &expected {
        let mut matching = claim_set
            .claims
            .iter()
            .filter(|candidate| candidate.claim_id == *claim_id);
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
        let expected_paths = required_paths
            .iter()
            .map(|path| (*path).to_string())
            .collect::<Vec<_>>();
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
