use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use chio_core_types::crypto::{PublicKey, Signature};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize};

use super::error::TransactionPassportError;
use super::ids::TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID;
use super::validation::{require_non_empty, validate_bundle_relative_path, validate_sha256_hex};

const DID_CHIO_PREFIX: &str = "did:chio:";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TransactionEvidenceGraph {
    schema: String,
    id: String,
    issued_at: String,
    nodes: Vec<EvidenceNode>,
    edges: Vec<EvidenceEdge>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceNode {
    id: String,
    schema: String,
    path: String,
    sha256: String,
    role: EvidenceNodeRole,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EvidenceNodeRole {
    Root,
    Receipt,
    Capability,
    GuardDecision,
    Policy,
    Request,
    Response,
    TrustRoot,
    VerifierPolicy,
    Report,
    ExecutionLease,
    ToolServerAck,
    RevocationFreshnessProof,
    SandboxAttestation,
    AdvisoryObservation,
    RiskComptrollerReport,
    DataGovernanceReport,
    EvidenceExportBundle,
    TelemetryProjection,
    ApprovalCase,
    ControlEvidenceMap,
    AgentWebProofEnvelope,
    ExternalProjectionManifest,
    ExternalSubject,
    ProviderDiscoverySnapshot,
    ProviderSelectionReport,
    TrustScorecardSnapshot,
    ReputationImportReport,
    SlaCommitment,
    SlaPerformanceReport,
    CollateralPositionReport,
    GuaranteeDecision,
    AdjudicationJurisdictionReceipt,
    DisclosureCapsule,
    DisclosureLeakageLedger,
    SignedLineageSubgraph,
    DisclosureCryptoContextReport,
}

impl<'de> Deserialize<'de> for EvidenceNodeRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let role = match value.as_str() {
            "root" => Self::Root,
            "receipt" => Self::Receipt,
            "capability" => Self::Capability,
            "guard-decision" => Self::GuardDecision,
            "policy" => Self::Policy,
            "request" => Self::Request,
            "response" => Self::Response,
            "trust-root" => Self::TrustRoot,
            "verifier-policy" => Self::VerifierPolicy,
            "report" => Self::Report,
            "execution-lease" => Self::ExecutionLease,
            "tool-server-ack" => Self::ToolServerAck,
            "revocation-freshness-proof" => Self::RevocationFreshnessProof,
            "sandbox-attestation" => Self::SandboxAttestation,
            "advisory-observation" => Self::AdvisoryObservation,
            "risk-comptroller-report" => Self::RiskComptrollerReport,
            "data-governance-report" => Self::DataGovernanceReport,
            "evidence-export-bundle" => Self::EvidenceExportBundle,
            "telemetry-projection" => Self::TelemetryProjection,
            "approval-case" => Self::ApprovalCase,
            "control-evidence-map" => Self::ControlEvidenceMap,
            "agent-web-proof-envelope" => Self::AgentWebProofEnvelope,
            "external-projection-manifest" => Self::ExternalProjectionManifest,
            "external-subject" => Self::ExternalSubject,
            "provider-discovery-snapshot" => Self::ProviderDiscoverySnapshot,
            "provider-selection-report" => Self::ProviderSelectionReport,
            "trust-scorecard-snapshot" => Self::TrustScorecardSnapshot,
            "reputation-import-report" => Self::ReputationImportReport,
            "sla-commitment" => Self::SlaCommitment,
            "sla-performance-report" => Self::SlaPerformanceReport,
            "collateral-position-report" => Self::CollateralPositionReport,
            "guarantee-decision" => Self::GuaranteeDecision,
            "adjudication-jurisdiction-receipt" => Self::AdjudicationJurisdictionReceipt,
            "disclosure-capsule" => Self::DisclosureCapsule,
            "disclosure-leakage-ledger" => Self::DisclosureLeakageLedger,
            "signed-lineage-subgraph" => Self::SignedLineageSubgraph,
            "disclosure-crypto-context-report" => Self::DisclosureCryptoContextReport,
            _ => {
                return Err(serde::de::Error::unknown_variant(
                    &value,
                    &[
                        "root",
                        "receipt",
                        "capability",
                        "guard-decision",
                        "policy",
                        "request",
                        "response",
                        "trust-root",
                        "verifier-policy",
                        "report",
                        "execution-lease",
                        "tool-server-ack",
                        "revocation-freshness-proof",
                        "sandbox-attestation",
                        "advisory-observation",
                        "risk-comptroller-report",
                        "data-governance-report",
                        "evidence-export-bundle",
                        "telemetry-projection",
                        "approval-case",
                        "control-evidence-map",
                        "agent-web-proof-envelope",
                        "external-projection-manifest",
                        "external-subject",
                        "provider-discovery-snapshot",
                        "provider-selection-report",
                        "trust-scorecard-snapshot",
                        "reputation-import-report",
                        "sla-commitment",
                        "sla-performance-report",
                        "collateral-position-report",
                        "guarantee-decision",
                        "adjudication-jurisdiction-receipt",
                        "disclosure-capsule",
                        "disclosure-leakage-ledger",
                        "signed-lineage-subgraph",
                        "disclosure-crypto-context-report",
                    ],
                ))
            }
        };
        Ok(role)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEdge {
    from: String,
    to: String,
    predicate: EvidenceEdgePredicate,
    #[serde(default)]
    evidence_class: Option<EvidenceClass>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum EvidenceEdgePredicate {
    Authorizes,
    Attenuates,
    Executes,
    Derives,
    Binds,
    Settles,
    Discloses,
    Redacts,
    Reconciles,
    ProjectsTo,
    Leases,
    Acknowledges,
    Freshens,
    Attests,
    Denies,
    Simulates,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum EvidenceClass {
    NativeExternalProof,
    ChioSidecarProof,
    DigestBoundReference,
    AdvisoryObservation,
    Unsupported,
}

pub(super) fn validate_evidence_graph(
    graph: &TransactionEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    if graph.schema != TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedEvidenceGraphSchema(
            graph.schema.clone(),
        ));
    }
    require_non_empty(&graph.id, "evidence graph id").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    require_non_empty(&graph.issued_at, "evidence graph issued_at").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    if graph.nodes.is_empty() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "evidence graph must contain at least one node".to_string(),
        ));
    }
    for node in &graph.nodes {
        validate_evidence_node(node)?;
    }
    for edge in &graph.edges {
        validate_evidence_edge(edge)?;
    }
    validate_graph_references(
        graph.nodes.iter().map(|node| node.id.as_str()),
        graph
            .edges
            .iter()
            .map(|edge| (edge.from.as_str(), edge.to.as_str())),
    )?;
    Ok(())
}

pub(super) fn validate_minimal_governed_action_evidence(
    graph: &TransactionEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    for (role, label) in [
        (EvidenceNodeRole::Receipt, "receipt"),
        (EvidenceNodeRole::Capability, "capability"),
        (EvidenceNodeRole::GuardDecision, "guard decision"),
        (EvidenceNodeRole::Policy, "policy"),
        (EvidenceNodeRole::Request, "request digest"),
        (EvidenceNodeRole::Response, "response digest"),
        (EvidenceNodeRole::TrustRoot, "trust root"),
        (EvidenceNodeRole::VerifierPolicy, "verifier policy"),
    ] {
        node_for_role(graph, role).ok_or_else(|| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
                "minimal governed action evidence missing: {label}"
            ))
        })?;
    }

    for (from, to, predicate, label) in [
        (
            EvidenceNodeRole::Capability,
            EvidenceNodeRole::Receipt,
            EvidenceEdgePredicate::Authorizes,
            "capability authorizes receipt",
        ),
        (
            EvidenceNodeRole::GuardDecision,
            EvidenceNodeRole::Receipt,
            EvidenceEdgePredicate::Authorizes,
            "guard decision authorizes receipt",
        ),
        (
            EvidenceNodeRole::Policy,
            EvidenceNodeRole::GuardDecision,
            EvidenceEdgePredicate::Binds,
            "policy binds guard decision",
        ),
        (
            EvidenceNodeRole::Request,
            EvidenceNodeRole::Receipt,
            EvidenceEdgePredicate::Binds,
            "request digest binds receipt",
        ),
        (
            EvidenceNodeRole::Response,
            EvidenceNodeRole::Receipt,
            EvidenceEdgePredicate::Binds,
            "response digest binds receipt",
        ),
        (
            EvidenceNodeRole::TrustRoot,
            EvidenceNodeRole::Capability,
            EvidenceEdgePredicate::Authorizes,
            "trust root authorizes capability",
        ),
        (
            EvidenceNodeRole::VerifierPolicy,
            EvidenceNodeRole::Receipt,
            EvidenceEdgePredicate::Binds,
            "verifier policy binds receipt",
        ),
    ] {
        if !has_role_edge(graph, from, to, predicate) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("minimal governed action evidence missing: {label}"),
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_verifier_policy_node_binding(
    graph: &TransactionEvidenceGraph,
    verifier_policy_path: &str,
    verifier_policy_sha256: &str,
) -> Result<(), TransactionPassportError> {
    let node = node_for_role(graph, EvidenceNodeRole::VerifierPolicy).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(
            "minimal governed action evidence missing: verifier policy".to_string(),
        )
    })?;
    if !path_matches_or_contains_suffix(&node.path, verifier_policy_path) {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "verifier policy evidence graph path mismatch".to_string(),
        ));
    }
    if node.sha256 != verifier_policy_sha256 {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "verifier policy evidence graph digest mismatch".to_string(),
        ));
    }
    Ok(())
}

fn path_matches_or_contains_suffix(path: &str, expected_suffix: &str) -> bool {
    let path_components = normal_path_components(path);
    let suffix_components = normal_path_components(expected_suffix);
    !suffix_components.is_empty() && path_components.ends_with(&suffix_components)
}

fn normal_path_components(path: &str) -> Vec<&str> {
    Path::new(path)
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => value.to_str(),
            _ => None,
        })
        .collect()
}

pub(super) fn validate_evidence_graph_artifact_bytes(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<(), TransactionPassportError> {
    for node in &graph.nodes {
        let bytes = artifacts.get(&node.path).ok_or_else(|| {
            TransactionPassportError::MissingEvidenceGraphArtifact(node.path.clone())
        })?;
        let actual_digest = super::sha256_hex(bytes);
        if actual_digest != node.sha256 {
            return Err(
                TransactionPassportError::EvidenceGraphArtifactDigestMismatch {
                    path: node.path.clone(),
                    expected: node.sha256.clone(),
                    actual: actual_digest,
                },
            );
        }
    }
    Ok(())
}

pub(super) fn validate_minimal_governed_action_artifact_bindings(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    let capability: MinimalCapabilityProof =
        parse_artifact_for_role(graph, artifacts, EvidenceNodeRole::Capability, "capability")?;
    let guard: MinimalGuardDecision = parse_artifact_for_role(
        graph,
        artifacts,
        EvidenceNodeRole::GuardDecision,
        "guard decision",
    )?;
    let receipt: MinimalReceipt =
        parse_artifact_for_role(graph, artifacts, EvidenceNodeRole::Receipt, "receipt")?;
    let trust_root: MinimalTrustRoot =
        parse_artifact_for_role(graph, artifacts, EvidenceNodeRole::TrustRoot, "trust root")?;
    let request: MinimalDigestArtifact = parse_artifact_for_role(
        graph,
        artifacts,
        EvidenceNodeRole::Request,
        "request digest",
    )?;
    let response: MinimalDigestArtifact = parse_artifact_for_role(
        graph,
        artifacts,
        EvidenceNodeRole::Response,
        "response digest",
    )?;
    let policy_digest = artifact_digest_for_role(graph, artifacts, EvidenceNodeRole::Policy)?;
    let request_artifact_digest =
        artifact_digest_for_role(graph, artifacts, EvidenceNodeRole::Request)?;
    let response_artifact_digest =
        artifact_digest_for_role(graph, artifacts, EvidenceNodeRole::Response)?;
    let request_digest_candidates =
        digest_candidates(request_artifact_digest, request.sha256.as_deref())?;
    let response_digest_candidates =
        digest_candidates(response_artifact_digest, response.sha256.as_deref())?;
    let evidence_graph_issued_at = parse_rfc3339_utc(&graph.issued_at, "evidence graph issued_at")?;
    let guard_id = first_present(
        guard.id.as_deref(),
        guard.guard_id.as_deref(),
        "guard decision id",
    )?;
    let guard_policy_digest = first_present(
        guard.policy_sha256.as_deref(),
        guard.policy_digest.as_deref(),
        "guard decision policy digest",
    )?;
    let guard_request_digest = first_present(
        guard.request_sha256.as_deref(),
        guard.request_digest.as_deref(),
        "guard decision request digest",
    )?;
    let guard_response_digest = first_present(
        guard.response_sha256.as_deref(),
        guard.response_digest.as_deref(),
        "guard decision response digest",
    )?;

    require_binding_value(&capability.capability_id, "capability_id")?;
    require_binding_value(&capability.issuer, "capability issuer")?;
    validate_capability_window(&capability, evidence_graph_issued_at)?;
    require_binding_value(guard_id, "guard decision id")?;
    require_binding_digest(guard_policy_digest, "guard decision policy digest")?;
    require_binding_digest(guard_request_digest, "guard decision request digest")?;
    require_binding_digest(guard_response_digest, "guard decision response digest")?;
    require_binding_digest(&receipt.policy_digest, "receipt policy_digest")?;
    require_binding_digest(&receipt.request_digest, "receipt request_digest")?;
    require_binding_digest(&receipt.response_digest, "receipt response_digest")?;

    if let Some(receipt_capability_id) = receipt.capability_id.as_deref() {
        require_binding_value(receipt_capability_id, "receipt capability_id")?;
        ensure_binding_equal(
            &capability.capability_id,
            receipt_capability_id,
            "capability proof does not match receipt capability",
        )?;
    }
    if let Some(guard_capability_id) = guard.capability_id.as_deref() {
        require_binding_value(guard_capability_id, "guard decision capability_id")?;
        ensure_binding_equal(
            guard_capability_id,
            &capability.capability_id,
            "guard decision does not match capability proof",
        )?;
    }
    ensure_guard_receipt_binding(&guard, &receipt, guard_id)?;
    ensure_binding_equal(
        &receipt.policy_digest,
        &policy_digest,
        "receipt policy digest mismatch",
    )?;
    ensure_binding_equal(
        guard_policy_digest,
        &policy_digest,
        "guard decision policy digest mismatch",
    )?;
    ensure_digest_candidate(
        &receipt.request_digest,
        &request_digest_candidates,
        "receipt request digest mismatch",
    )?;
    ensure_digest_candidate(
        guard_request_digest,
        &request_digest_candidates,
        "guard decision request digest mismatch",
    )?;
    ensure_digest_candidate(
        &receipt.response_digest,
        &response_digest_candidates,
        "receipt response digest mismatch",
    )?;
    ensure_digest_candidate(
        guard_response_digest,
        &response_digest_candidates,
        "guard decision response digest mismatch",
    )?;
    ensure_trust_root_authorizes_issuer(&trust_root, &capability.issuer)?;
    let trust_root_signer = trust_root_signer_identity(&trust_root, &capability.issuer)?;
    ensure_trust_root_signer_is_pinned(&trust_root_signer, trusted_root_signer_keys)?;
    verify_signed_role_artifact(
        graph,
        artifacts,
        EvidenceNodeRole::Capability,
        Some(capability.issuer.as_str()),
        capability.signature.as_deref(),
        "capability proof",
    )?;
    verify_signed_role_artifact(
        graph,
        artifacts,
        EvidenceNodeRole::TrustRoot,
        Some(trust_root_signer.as_str()),
        trust_root.signature.as_deref(),
        "trust root",
    )?;
    let guard_signer = guard
        .guard_key
        .as_deref()
        .unwrap_or(trust_root_signer.as_str());
    verify_signed_role_artifact(
        graph,
        artifacts,
        EvidenceNodeRole::GuardDecision,
        Some(guard_signer),
        guard.signature.as_deref(),
        "guard decision",
    )?;
    verify_signed_role_artifact(
        graph,
        artifacts,
        EvidenceNodeRole::Receipt,
        receipt.kernel_key.as_deref(),
        receipt.signature.as_deref(),
        "receipt",
    )?;

    Ok(())
}

#[derive(Deserialize)]
struct MinimalCapabilityProof {
    capability_id: String,
    not_before: Option<String>,
    expires_at: String,
    issuer: String,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct MinimalGuardDecision {
    id: Option<String>,
    guard_id: Option<String>,
    capability_id: Option<String>,
    policy_sha256: Option<String>,
    policy_digest: Option<String>,
    request_sha256: Option<String>,
    request_digest: Option<String>,
    response_sha256: Option<String>,
    response_digest: Option<String>,
    allow_receipt_ref: Option<String>,
    guard_key: Option<String>,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct MinimalReceipt {
    receipt_id: Option<String>,
    capability_id: Option<String>,
    guard_decision_id: Option<String>,
    policy_digest: String,
    request_digest: String,
    response_digest: String,
    kernel_key: Option<String>,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct MinimalTrustRoot {
    authority: Option<String>,
    #[serde(default)]
    roots: Vec<MinimalTrustRootEntry>,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct MinimalTrustRootEntry {
    subject: String,
    key_id: Option<String>,
    key_digest: Option<String>,
}

#[derive(Deserialize)]
struct MinimalDigestArtifact {
    sha256: Option<String>,
}

fn parse_artifact_for_role<T: DeserializeOwned>(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: EvidenceNodeRole,
    label: &'static str,
) -> Result<T, TransactionPassportError> {
    let bytes = artifact_bytes_for_role(graph, artifacts, role)?;
    serde_json::from_slice(bytes)
        .map_err(|error| minimal_governed_action_binding_error(format!("invalid {label}: {error}")))
}

fn artifact_digest_for_role(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: EvidenceNodeRole,
) -> Result<String, TransactionPassportError> {
    Ok(super::sha256_hex(artifact_bytes_for_role(
        graph, artifacts, role,
    )?))
}

fn artifact_bytes_for_role<'a>(
    graph: &TransactionEvidenceGraph,
    artifacts: &'a BTreeMap<String, Vec<u8>>,
    role: EvidenceNodeRole,
) -> Result<&'a [u8], TransactionPassportError> {
    let node = node_for_role(graph, role).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(
            "minimal governed action evidence missing".to_string(),
        )
    })?;
    artifacts
        .get(&node.path)
        .map(Vec::as_slice)
        .ok_or_else(|| TransactionPassportError::MissingEvidenceGraphArtifact(node.path.clone()))
}

fn require_binding_value(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    require_non_empty(value, field)
        .map_err(|error| minimal_governed_action_binding_error(error.to_string()))
}

fn require_binding_digest(
    value: &str,
    field: &'static str,
) -> Result<(), TransactionPassportError> {
    validate_sha256_hex(value)
        .map_err(|_| minimal_governed_action_binding_error(format!("invalid {field}: {value}")))
}

fn ensure_binding_equal(
    actual: &str,
    expected: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    if actual != expected {
        return Err(minimal_governed_action_binding_error(message));
    }
    Ok(())
}

fn first_present<'a>(
    primary: Option<&'a str>,
    secondary: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, TransactionPassportError> {
    primary
        .or(secondary)
        .ok_or_else(|| minimal_governed_action_binding_error(format!("{field} missing")))
}

fn digest_candidates(
    artifact_digest: String,
    declared_digest: Option<&str>,
) -> Result<Vec<String>, TransactionPassportError> {
    let mut candidates = vec![artifact_digest];
    if let Some(declared_digest) = declared_digest {
        require_binding_digest(declared_digest, "declared digest")?;
        if !candidates
            .iter()
            .any(|candidate| candidate == declared_digest)
        {
            candidates.push(declared_digest.to_string());
        }
    }
    Ok(candidates)
}

fn ensure_digest_candidate(
    actual: &str,
    candidates: &[String],
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    if !candidates.iter().any(|candidate| candidate == actual) {
        return Err(minimal_governed_action_binding_error(message));
    }
    Ok(())
}

fn ensure_guard_receipt_binding(
    guard: &MinimalGuardDecision,
    receipt: &MinimalReceipt,
    guard_id: &str,
) -> Result<(), TransactionPassportError> {
    if let Some(guard_decision_id) = receipt.guard_decision_id.as_deref() {
        require_binding_value(guard_decision_id, "receipt guard_decision_id")?;
        return ensure_binding_equal(
            guard_decision_id,
            guard_id,
            "receipt does not reference guard decision",
        );
    }
    if let (Some(allow_receipt_ref), Some(receipt_id)) = (
        guard.allow_receipt_ref.as_deref(),
        receipt.receipt_id.as_deref(),
    ) {
        require_binding_value(allow_receipt_ref, "guard allow_receipt_ref")?;
        require_binding_value(receipt_id, "receipt_id")?;
        return ensure_binding_equal(
            allow_receipt_ref,
            receipt_id,
            "guard report does not reference receipt",
        );
    }
    Err(minimal_governed_action_binding_error(
        "guard-to-receipt binding missing",
    ))
}

fn ensure_trust_root_authorizes_issuer(
    trust_root: &MinimalTrustRoot,
    issuer: &str,
) -> Result<(), TransactionPassportError> {
    if let Some(authority) = trust_root.authority.as_deref() {
        require_binding_value(authority, "trust root authority")?;
        if authority == issuer {
            return Ok(());
        }
    }
    if trust_root
        .roots
        .iter()
        .any(|root| root.subject.as_str() == issuer)
    {
        return Ok(());
    }
    Err(minimal_governed_action_binding_error(
        "trust root does not authorize capability issuer",
    ))
}

fn ensure_trust_root_signer_is_pinned(
    signer_identity: &str,
    trusted_root_signer_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    if trusted_root_signer_keys.is_empty() {
        return Err(minimal_governed_action_binding_error(
            "trusted transaction root keys missing",
        ));
    }
    let signer_key = minimal_self_certifying_public_key(signer_identity, "trust root")?;
    if trusted_root_signer_keys
        .iter()
        .any(|trusted_key| trusted_key == &signer_key)
    {
        Ok(())
    } else {
        Err(minimal_governed_action_binding_error(
            "trust root signer is not trusted",
        ))
    }
}

fn trust_root_signer_identity(
    trust_root: &MinimalTrustRoot,
    issuer: &str,
) -> Result<String, TransactionPassportError> {
    if let Some(authority) = trust_root.authority.as_deref() {
        require_binding_value(authority, "trust root authority")?;
        return Ok(authority.to_string());
    }
    let root = trust_root
        .roots
        .iter()
        .find(|root| root.subject == issuer)
        .ok_or_else(|| {
            minimal_governed_action_binding_error("trust root does not authorize capability issuer")
        })?;
    let key_id = root
        .key_id
        .as_deref()
        .ok_or_else(|| minimal_governed_action_binding_error("trust root signer key missing"))?;
    require_binding_value(key_id, "trust root signer key")?;
    if let Some(key_digest) = root.key_digest.as_deref() {
        require_binding_digest(key_digest, "trust root signer key digest")?;
        let actual = super::sha256_hex(key_id.as_bytes());
        if key_digest != actual {
            return Err(minimal_governed_action_binding_error(
                "trust root signer key digest mismatch",
            ));
        }
    }
    Ok(key_id.to_string())
}

fn verify_signed_role_artifact(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: EvidenceNodeRole,
    signer_identity: Option<&str>,
    signature: Option<&str>,
    label: &'static str,
) -> Result<(), TransactionPassportError> {
    let signer_identity = signer_identity
        .ok_or_else(|| minimal_governed_action_binding_error(format!("{label} signer missing")))?;
    require_binding_value(signer_identity, "artifact signer")?;
    let signature = signature.ok_or_else(|| {
        minimal_governed_action_binding_error(format!("{label} signature missing"))
    })?;
    require_binding_value(signature, "artifact signature")?;
    let public_key = minimal_self_certifying_public_key(signer_identity, label)?;
    let signature = Signature::from_hex(signature).map_err(|error| {
        minimal_governed_action_binding_error(format!("{label} signature invalid: {error}"))
    })?;
    let bytes = artifact_bytes_for_role(graph, artifacts, role)?;
    let mut artifact: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        minimal_governed_action_binding_error(format!("invalid {label}: {error}"))
    })?;
    let object = artifact.as_object_mut().ok_or_else(|| {
        minimal_governed_action_binding_error(format!("{label} artifact must be an object"))
    })?;
    object.remove("signature");
    let verified = public_key
        .verify_canonical(&artifact, &signature)
        .map_err(|error| {
            minimal_governed_action_binding_error(format!("{label} signature invalid: {error}"))
        })?;
    if verified {
        Ok(())
    } else {
        Err(minimal_governed_action_binding_error(format!(
            "{label} signature invalid"
        )))
    }
}

fn minimal_self_certifying_public_key(
    identity: &str,
    label: &'static str,
) -> Result<PublicKey, TransactionPassportError> {
    let public_key_hex = if let Some(public_key_hex) = identity.strip_prefix(DID_CHIO_PREFIX) {
        if validate_sha256_hex(public_key_hex).is_err() {
            return Err(minimal_governed_action_binding_error(format!(
                "{label} signer is not self-certifying"
            )));
        }
        public_key_hex
    } else {
        identity
    };
    PublicKey::from_hex(public_key_hex).map_err(|error| {
        minimal_governed_action_binding_error(format!("{label} signer key invalid: {error}"))
    })
}

fn validate_capability_window(
    capability: &MinimalCapabilityProof,
    evidence_graph_issued_at: DateTime<Utc>,
) -> Result<(), TransactionPassportError> {
    if let Some(not_before) = capability.not_before.as_deref() {
        require_binding_value(not_before, "capability not_before")?;
        let not_before = parse_rfc3339_utc(not_before, "capability not_before")?;
        if not_before > evidence_graph_issued_at {
            return Err(minimal_governed_action_binding_error(
                "capability proof not valid at evidence graph issuance",
            ));
        }
    }
    require_binding_value(&capability.expires_at, "capability expires_at")?;
    let expires_at = parse_rfc3339_utc(&capability.expires_at, "capability expires_at")?;
    if expires_at <= evidence_graph_issued_at {
        return Err(minimal_governed_action_binding_error(
            "capability proof expired before evidence graph issuance",
        ));
    }
    Ok(())
}

fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|_| minimal_governed_action_binding_error(format!("invalid {field}: {value}")))
}

fn minimal_governed_action_binding_error(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
        "minimal governed action evidence invalid: {}",
        message.into()
    ))
}

fn node_for_role(
    graph: &TransactionEvidenceGraph,
    role: EvidenceNodeRole,
) -> Option<&EvidenceNode> {
    graph.nodes.iter().find(|node| node.role == role)
}

fn has_role_edge(
    graph: &TransactionEvidenceGraph,
    from: EvidenceNodeRole,
    to: EvidenceNodeRole,
    predicate: EvidenceEdgePredicate,
) -> bool {
    let Some(from_node) = node_for_role(graph, from) else {
        return false;
    };
    let Some(to_node) = node_for_role(graph, to) else {
        return false;
    };
    graph.edges.iter().any(|edge| {
        edge.from == from_node.id && edge.to == to_node.id && edge.predicate == predicate
    })
}

pub(super) fn validate_graph_references<'a>(
    node_ids: impl IntoIterator<Item = &'a str>,
    edge_refs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), TransactionPassportError> {
    let mut known_node_ids = BTreeSet::new();
    for node_id in node_ids {
        if !known_node_ids.insert(node_id) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("duplicate evidence graph node id: {node_id}"),
            ));
        }
    }
    for (from, to) in edge_refs {
        if !known_node_ids.contains(from) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("unknown evidence graph edge source: {from}"),
            ));
        }
        if !known_node_ids.contains(to) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("unknown evidence graph edge target: {to}"),
            ));
        }
    }
    Ok(())
}

fn validate_evidence_node(node: &EvidenceNode) -> Result<(), TransactionPassportError> {
    require_non_empty(&node.id, "evidence graph node id").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    require_non_empty(&node.schema, "evidence graph node schema").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    validate_sha256_hex(&node.sha256).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "invalid evidence graph node digest: {}",
            node.sha256
        ))
    })?;
    validate_bundle_relative_path(&node.path).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "unsafe evidence graph node path: {}",
            node.path
        ))
    })?;
    let _ = &node.role;
    Ok(())
}

fn validate_evidence_edge(edge: &EvidenceEdge) -> Result<(), TransactionPassportError> {
    require_non_empty(&edge.from, "evidence graph edge from").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    require_non_empty(&edge.to, "evidence graph edge to").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    let _ = &edge.predicate;
    let _ = &edge.evidence_class;
    Ok(())
}
