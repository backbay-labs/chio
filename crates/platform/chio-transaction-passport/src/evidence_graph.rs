use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use chio_core_types::crypto::{PublicKey, Signature};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::Value;

use super::error::TransactionPassportError;
use super::ids::{TRANSACTION_CLAIM_SET_SCHEMA_ID, TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID};
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
    PolicyActivationReceipt,
    Request,
    Response,
    TrustRoot,
    ClaimSet,
    VerifierPolicy,
    Report,
    ExecutionLease,
    ToolServerAck,
    TrustedTimeProof,
    RevocationFreshnessProof,
    SandboxAttestation,
    RuntimeAttackSimulationReport,
    RuntimeChaosRunReport,
    AdvisoryObservation,
    CommerceOrderContext,
    CommerceEventLog,
    CommercePaymentLifecycle,
    CommerceMandateAllowanceLedger,
    CommerceProtocolPayload,
    CommerceProviderPassport,
    CommerceReputationSnapshot,
    CommerceFederationTrustBundle,
    CommerceSettlementPacket,
    CommerceOrderPassport,
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
    PublicSettlementProofBundle,
    SwarmTaskGraph,
    SwarmContinuationToken,
    SwarmDelegationWitnessChain,
    SwarmJoinReceipt,
    SwarmRoutePlanReceipt,
    SwarmTerminalGraphReceipt,
    SwarmBudgetPool,
    SwarmRevocationEpoch,
    DisclosureCapsule,
    DisclosureLeakageLedger,
    SignedLineageSubgraph,
    DisclosureCryptoContextReport,
    DisclosureVerifierPrivacyProfile,
    CryptoVerificationContext,
    SelectiveDisclosureProof,
    BbsProjectionManifest,
    TransparencyInclusionProof,
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
            "policy-activation-receipt" => Self::PolicyActivationReceipt,
            "request" => Self::Request,
            "response" => Self::Response,
            "trust-root" => Self::TrustRoot,
            "claim-set" => Self::ClaimSet,
            "verifier-policy" => Self::VerifierPolicy,
            "report" => Self::Report,
            "execution-lease" => Self::ExecutionLease,
            "tool-server-ack" => Self::ToolServerAck,
            "trusted-time-proof" => Self::TrustedTimeProof,
            "revocation-freshness-proof" => Self::RevocationFreshnessProof,
            "sandbox-attestation" => Self::SandboxAttestation,
            "runtime-attack-simulation-report" => Self::RuntimeAttackSimulationReport,
            "runtime-chaos-run-report" => Self::RuntimeChaosRunReport,
            "advisory-observation" => Self::AdvisoryObservation,
            "commerce-order-context" => Self::CommerceOrderContext,
            "commerce-event-log" => Self::CommerceEventLog,
            "commerce-payment-lifecycle" => Self::CommercePaymentLifecycle,
            "commerce-mandate-allowance-ledger" => Self::CommerceMandateAllowanceLedger,
            "commerce-protocol-payload" => Self::CommerceProtocolPayload,
            "commerce-provider-passport" => Self::CommerceProviderPassport,
            "commerce-reputation-snapshot" => Self::CommerceReputationSnapshot,
            "commerce-federation-trust-bundle" => Self::CommerceFederationTrustBundle,
            "commerce-settlement-packet" => Self::CommerceSettlementPacket,
            "commerce-order-passport" => Self::CommerceOrderPassport,
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
            "public-settlement-proof-bundle" => Self::PublicSettlementProofBundle,
            "swarm-task-graph" => Self::SwarmTaskGraph,
            "swarm-continuation-token" => Self::SwarmContinuationToken,
            "swarm-delegation-witness-chain" => Self::SwarmDelegationWitnessChain,
            "swarm-join-receipt" => Self::SwarmJoinReceipt,
            "swarm-route-plan-receipt" => Self::SwarmRoutePlanReceipt,
            "swarm-terminal-graph-receipt" => Self::SwarmTerminalGraphReceipt,
            "swarm-budget-pool" => Self::SwarmBudgetPool,
            "swarm-revocation-epoch" => Self::SwarmRevocationEpoch,
            "disclosure-capsule" => Self::DisclosureCapsule,
            "disclosure-leakage-ledger" => Self::DisclosureLeakageLedger,
            "signed-lineage-subgraph" => Self::SignedLineageSubgraph,
            "disclosure-crypto-context-report" => Self::DisclosureCryptoContextReport,
            "disclosure-verifier-privacy-profile" => Self::DisclosureVerifierPrivacyProfile,
            "crypto-verification-context" => Self::CryptoVerificationContext,
            "selective-disclosure-proof" => Self::SelectiveDisclosureProof,
            "bbs-projection-manifest" => Self::BbsProjectionManifest,
            "transparency-inclusion-proof" => Self::TransparencyInclusionProof,
            _ => {
                return Err(serde::de::Error::unknown_variant(
                    &value,
                    &[
                        "root",
                        "receipt",
                        "capability",
                        "guard-decision",
                        "policy",
                        "policy-activation-receipt",
                        "request",
                        "response",
                        "trust-root",
                        "claim-set",
                        "verifier-policy",
                        "report",
                        "execution-lease",
                        "tool-server-ack",
                        "trusted-time-proof",
                        "revocation-freshness-proof",
                        "sandbox-attestation",
                        "runtime-attack-simulation-report",
                        "runtime-chaos-run-report",
                        "advisory-observation",
                        "commerce-order-context",
                        "commerce-event-log",
                        "commerce-payment-lifecycle",
                        "commerce-mandate-allowance-ledger",
                        "commerce-protocol-payload",
                        "commerce-provider-passport",
                        "commerce-reputation-snapshot",
                        "commerce-federation-trust-bundle",
                        "commerce-settlement-packet",
                        "commerce-order-passport",
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
                        "public-settlement-proof-bundle",
                        "swarm-task-graph",
                        "swarm-continuation-token",
                        "swarm-delegation-witness-chain",
                        "swarm-join-receipt",
                        "swarm-route-plan-receipt",
                        "swarm-terminal-graph-receipt",
                        "swarm-budget-pool",
                        "swarm-revocation-epoch",
                        "disclosure-capsule",
                        "disclosure-leakage-ledger",
                        "signed-lineage-subgraph",
                        "disclosure-crypto-context-report",
                        "disclosure-verifier-privacy-profile",
                        "crypto-verification-context",
                        "selective-disclosure-proof",
                        "bbs-projection-manifest",
                        "transparency-inclusion-proof",
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
    validate_no_advisory_authority_edges(graph)?;
    validate_graph_references(
        graph.nodes.iter().map(|node| node.id.as_str()),
        graph
            .edges
            .iter()
            .map(|edge| (edge.from.as_str(), edge.to.as_str())),
    )?;
    validate_graph_acyclic(
        graph.nodes.iter().map(|node| node.id.as_str()),
        graph
            .edges
            .iter()
            .map(|edge| (edge.from.as_str(), edge.to.as_str())),
    )?;
    Ok(())
}

pub fn validate_transaction_evidence_graph(
    evidence_graph_bytes: &[u8],
) -> Result<(), TransactionPassportError> {
    let graph: Value = serde_json::from_slice(evidence_graph_bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    let schema = required_graph_string(&graph, "schema", "evidence graph schema")?;
    if schema != TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedEvidenceGraphSchema(
            schema.to_string(),
        ));
    }
    required_graph_string(&graph, "id", "evidence graph id")?;
    required_graph_string(&graph, "issued_at", "evidence graph issued_at")?;

    let nodes = required_graph_array(&graph, "nodes", "evidence graph nodes")?;
    if nodes.is_empty() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "evidence graph must contain at least one node".to_string(),
        ));
    }
    let mut node_ids = Vec::with_capacity(nodes.len());
    for node in nodes {
        let node_id = required_graph_string(node, "id", "evidence graph node id")?;
        let node_sha256 = required_graph_string(node, "sha256", "evidence graph node digest")?;
        validate_sha256_hex(node_sha256).map_err(|_| {
            TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
                "invalid evidence graph node digest: {node_sha256}"
            ))
        })?;
        if node_id != node_sha256 {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!(
                    "evidence graph node id digest mismatch: expected {node_sha256}, got {node_id}"
                ),
            ));
        }
        node_ids.push(node_id);
    }

    let edges = required_graph_array(&graph, "edges", "evidence graph edges")?;
    let mut edge_refs = Vec::with_capacity(edges.len());
    for edge in edges {
        edge_refs.push((
            required_graph_string(edge, "from", "evidence graph edge source")?,
            required_graph_string(edge, "to", "evidence graph edge target")?,
        ));
    }
    validate_no_advisory_authority_edges_in_value(&graph)?;

    validate_graph_references(node_ids.iter().copied(), edge_refs.iter().copied())?;
    validate_graph_acyclic(node_ids.iter().copied(), edge_refs.iter().copied())
}

fn required_graph_array<'a>(
    value: &'a Value,
    field: &str,
    label: &'static str,
) -> Result<&'a Vec<Value>, TransactionPassportError> {
    value.get(field).and_then(Value::as_array).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!("{label} missing"))
    })
}

fn required_graph_string<'a>(
    value: &'a Value,
    field: &str,
    label: &'static str,
) -> Result<&'a str, TransactionPassportError> {
    let text = value.get(field).and_then(Value::as_str).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!("{label} missing"))
    })?;
    require_non_empty(text, label).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    Ok(text)
}

pub(super) fn validate_minimal_governed_action_evidence(
    graph: &TransactionEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    for (role, label) in [
        (EvidenceNodeRole::Receipt, "receipt"),
        (EvidenceNodeRole::Capability, "capability"),
        (EvidenceNodeRole::GuardDecision, "guard decision"),
        (EvidenceNodeRole::Request, "request digest"),
        (EvidenceNodeRole::Response, "response digest"),
        (EvidenceNodeRole::TrustRoot, "trust root"),
        (EvidenceNodeRole::ClaimSet, "claim set"),
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
            EvidenceNodeRole::ClaimSet,
            EvidenceNodeRole::VerifierPolicy,
            EvidenceEdgePredicate::Binds,
            "claim set binds verifier policy",
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

    if governed_policy_anchor_node(graph).is_none() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "minimal governed action evidence missing: policy".to_string(),
        ));
    }
    if !has_governed_policy_anchor_edge(
        graph,
        EvidenceNodeRole::GuardDecision,
        EvidenceEdgePredicate::Binds,
    ) {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "minimal governed action evidence missing: policy binds guard decision".to_string(),
        ));
    }

    Ok(())
}

pub(super) fn validate_claim_set_node_binding(
    graph: &TransactionEvidenceGraph,
    claim_set_path: &str,
    claim_set_sha256: &str,
) -> Result<(), TransactionPassportError> {
    let node = node_for_role(graph, EvidenceNodeRole::ClaimSet).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(
            "minimal governed action evidence missing: claim set".to_string(),
        )
    })?;
    if !path_matches_or_contains_suffix(&node.path, claim_set_path) {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "claim set evidence graph path mismatch".to_string(),
        ));
    }
    if node.sha256 != claim_set_sha256 {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "claim set evidence graph digest mismatch".to_string(),
        ));
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
    let policy_digest = artifact_digest_for_governed_policy_anchor(graph, artifacts)?;
    let request_digest = declared_digest(request.sha256.as_deref(), "request digest")?;
    let response_digest = declared_digest(response.sha256.as_deref(), "response digest")?;
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
    ensure_binding_equal(
        &receipt.request_digest,
        request_digest,
        "receipt request digest mismatch",
    )?;
    ensure_binding_equal(
        guard_request_digest,
        request_digest,
        "guard decision request digest mismatch",
    )?;
    ensure_binding_equal(
        &receipt.response_digest,
        response_digest,
        "receipt response digest mismatch",
    )?;
    ensure_binding_equal(
        guard_response_digest,
        response_digest,
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
    ensure_trust_root_authorizes_signer(&trust_root, guard_signer, "guard decision")?;
    verify_signed_role_artifact(
        graph,
        artifacts,
        EvidenceNodeRole::GuardDecision,
        Some(guard_signer),
        guard.signature.as_deref(),
        "guard decision",
    )?;
    if let Some(receipt_signer) = receipt.kernel_key.as_deref() {
        ensure_trust_root_authorizes_signer(&trust_root, receipt_signer, "receipt")?;
    }
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

pub(super) fn validate_claim_set_artifact_bindings(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
    required_claims: &[String],
) -> Result<(), TransactionPassportError> {
    let claim_set: MinimalClaimSet =
        parse_artifact_for_role(graph, artifacts, EvidenceNodeRole::ClaimSet, "claim set")?;
    if claim_set.schema != TRANSACTION_CLAIM_SET_SCHEMA_ID {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "unsupported claim set schema".to_string(),
        ));
    }
    require_binding_value(&claim_set.id, "claim set id")?;
    require_binding_value(&claim_set.issued_at, "claim set issued_at")?;
    if claim_set.claims.is_empty() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "claim set must contain at least one claim".to_string(),
        ));
    }
    let mut seen = BTreeSet::new();
    for claim in &claim_set.claims {
        require_binding_value(&claim.claim_id, "claim id")?;
        require_binding_value(&claim.verifier_module, "claim verifier module")?;
        validate_required_evidence_refs(&claim.required_evidence, "required evidence")?;
        validate_required_evidence_refs(&claim.evidence_refs, "evidence ref")?;
        if !seen.insert(claim.claim_id.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("duplicate claim set claim: {}", claim.claim_id),
            ));
        }
        match claim.status.as_str() {
            "verified" | "omitted" | "unsupported" => {}
            "failed" => {
                if claim
                    .failure_reason
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty()
                {
                    return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                        "failed claim set entry missing failure reason".to_string(),
                    ));
                }
            }
            _ => {
                return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                    format!("unsupported claim set status: {}", claim.status),
                ));
            }
        }
    }
    for required_claim in required_claims {
        let Some(claim) = claim_set
            .claims
            .iter()
            .find(|claim| claim.claim_id == *required_claim)
        else {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("claim set missing required claim: {required_claim}"),
            ));
        };
        if claim.status != "verified" {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("claim set required claim was not verified: {required_claim}"),
            ));
        }
    }
    Ok(())
}

fn validate_required_evidence_refs(
    values: &[String],
    label: &'static str,
) -> Result<(), TransactionPassportError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_binding_value(value, label)?;
        if !seen.insert(value.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("duplicate claim set {label}: {value}"),
            ));
        }
    }
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

#[derive(Deserialize)]
struct MinimalClaimSet {
    schema: String,
    id: String,
    issued_at: String,
    claims: Vec<MinimalClaimSetClaim>,
}

#[derive(Deserialize)]
struct MinimalClaimSetClaim {
    claim_id: String,
    status: String,
    #[serde(default)]
    required_evidence: Vec<String>,
    #[serde(default)]
    evidence_refs: Vec<String>,
    failure_reason: Option<String>,
    verifier_module: String,
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

fn artifact_digest_for_governed_policy_anchor(
    graph: &TransactionEvidenceGraph,
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<String, TransactionPassportError> {
    let node = governed_policy_anchor_node(graph).ok_or_else(|| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(
            "minimal governed action evidence missing".to_string(),
        )
    })?;
    Ok(super::sha256_hex(artifact_bytes_for_node(node, artifacts)?))
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
    artifact_bytes_for_node(node, artifacts)
}

fn artifact_bytes_for_node<'a>(
    node: &EvidenceNode,
    artifacts: &'a BTreeMap<String, Vec<u8>>,
) -> Result<&'a [u8], TransactionPassportError> {
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

fn declared_digest<'a>(
    declared_digest: Option<&'a str>,
    field: &'static str,
) -> Result<&'a str, TransactionPassportError> {
    let declared_digest = declared_digest
        .ok_or_else(|| minimal_governed_action_binding_error(format!("{field} missing")))?;
    require_binding_digest(declared_digest, field)?;
    Ok(declared_digest)
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

fn ensure_trust_root_authorizes_signer(
    trust_root: &MinimalTrustRoot,
    signer_identity: &str,
    label: &'static str,
) -> Result<(), TransactionPassportError> {
    require_binding_value(signer_identity, "artifact signer")?;
    if trust_root.authority.as_deref() == Some(signer_identity)
        || trust_root
            .roots
            .iter()
            .any(|root| root.subject.as_str() == signer_identity)
    {
        Ok(())
    } else {
        Err(minimal_governed_action_binding_error(format!(
            "{label} signer is not authorized"
        )))
    }
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

fn governed_policy_anchor_node(graph: &TransactionEvidenceGraph) -> Option<&EvidenceNode> {
    node_for_role(graph, EvidenceNodeRole::Policy)
        .or_else(|| node_for_role(graph, EvidenceNodeRole::VerifierPolicy))
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

fn has_governed_policy_anchor_edge(
    graph: &TransactionEvidenceGraph,
    to: EvidenceNodeRole,
    predicate: EvidenceEdgePredicate,
) -> bool {
    let Some(from_node) = governed_policy_anchor_node(graph) else {
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

pub(super) fn validate_graph_acyclic<'a>(
    node_ids: impl IntoIterator<Item = &'a str>,
    edge_refs: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<(), TransactionPassportError> {
    let mut adjacency = BTreeMap::new();
    for node_id in node_ids {
        adjacency.entry(node_id).or_insert_with(Vec::new);
    }
    for (from, to) in edge_refs {
        adjacency.entry(from).or_insert_with(Vec::new).push(to);
    }

    let mut visit_state = BTreeMap::new();
    let nodes: Vec<_> = adjacency.keys().copied().collect();
    for node_id in nodes {
        visit_graph_node(node_id, &adjacency, &mut visit_state)?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GraphVisitState {
    Visiting,
    Visited,
}

fn visit_graph_node<'a>(
    node_id: &'a str,
    adjacency: &BTreeMap<&'a str, Vec<&'a str>>,
    visit_state: &mut BTreeMap<&'a str, GraphVisitState>,
) -> Result<(), TransactionPassportError> {
    match visit_state.get(node_id).copied() {
        Some(GraphVisitState::Visiting) => {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("cyclic evidence graph: {node_id}"),
            ));
        }
        Some(GraphVisitState::Visited) => return Ok(()),
        None => {}
    }

    visit_state.insert(node_id, GraphVisitState::Visiting);
    if let Some(children) = adjacency.get(node_id) {
        for child in children {
            visit_graph_node(child, adjacency, visit_state)?;
        }
    }
    visit_state.insert(node_id, GraphVisitState::Visited);
    Ok(())
}

fn validate_evidence_node(node: &EvidenceNode) -> Result<(), TransactionPassportError> {
    require_non_empty(&node.id, "evidence graph node id").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    require_non_empty(&node.schema, "evidence graph node schema").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    if evidence_node_schema_requires_registry(node.role)
        && !chio_core_types::is_supported_signed_artifact_schema(&node.schema)
    {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            format!("unsupported evidence graph node schema: {}", node.schema),
        ));
    }
    validate_sha256_hex(&node.sha256).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "invalid evidence graph node digest: {}",
            node.sha256
        ))
    })?;
    if node.id != node.sha256 {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            format!(
                "evidence graph node id digest mismatch: expected {}, got {}",
                node.sha256, node.id
            ),
        ));
    }
    validate_bundle_relative_path(&node.path).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "unsafe evidence graph node path: {}",
            node.path
        ))
    })?;
    let _ = &node.role;
    Ok(())
}

fn evidence_node_schema_requires_registry(role: EvidenceNodeRole) -> bool {
    !matches!(
        role,
        EvidenceNodeRole::AdvisoryObservation | EvidenceNodeRole::ExternalSubject
    )
}

fn validate_evidence_edge(edge: &EvidenceEdge) -> Result<(), TransactionPassportError> {
    require_non_empty(&edge.from, "evidence graph edge from").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    require_non_empty(&edge.to, "evidence graph edge to").map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    if is_authority_edge_predicate(&edge.predicate)
        && matches!(
            edge.evidence_class.as_ref(),
            Some(EvidenceClass::AdvisoryObservation)
        )
    {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "advisory evidence cannot satisfy authority edge".to_string(),
        ));
    }
    Ok(())
}

fn validate_no_advisory_authority_edges(
    graph: &TransactionEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    for edge in &graph.edges {
        if !is_authority_edge_predicate(&edge.predicate) {
            continue;
        }
        let advisory_class = matches!(
            edge.evidence_class.as_ref(),
            Some(EvidenceClass::AdvisoryObservation)
        );
        let advisory_endpoint = graph.nodes.iter().any(|node| {
            (node.id == edge.from || node.id == edge.to)
                && node.role == EvidenceNodeRole::AdvisoryObservation
        });
        if advisory_class || advisory_endpoint {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                "advisory evidence cannot satisfy authority edge".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_no_advisory_authority_edges_in_value(
    graph: &Value,
) -> Result<(), TransactionPassportError> {
    let advisory_node_ids: BTreeSet<&str> =
        required_graph_array(graph, "nodes", "evidence graph nodes")?
            .iter()
            .filter_map(|node| {
                if node.get("role").and_then(Value::as_str) == Some("advisory-observation") {
                    node.get("id").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect();
    for edge in required_graph_array(graph, "edges", "evidence graph edges")? {
        let Some(predicate) = edge.get("predicate").and_then(Value::as_str) else {
            continue;
        };
        if !is_authority_edge_predicate_value(predicate) {
            continue;
        }
        let advisory_class =
            edge.get("evidence_class").and_then(Value::as_str) == Some("advisory-observation");
        let from = edge.get("from").and_then(Value::as_str);
        let to = edge.get("to").and_then(Value::as_str);
        let advisory_endpoint = from
            .into_iter()
            .chain(to)
            .any(|node_id| advisory_node_ids.contains(node_id));
        if advisory_class || advisory_endpoint {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                "advisory evidence cannot satisfy authority edge".to_string(),
            ));
        }
    }
    Ok(())
}

fn is_authority_edge_predicate(predicate: &EvidenceEdgePredicate) -> bool {
    matches!(
        predicate,
        EvidenceEdgePredicate::Authorizes
            | EvidenceEdgePredicate::Executes
            | EvidenceEdgePredicate::Leases
            | EvidenceEdgePredicate::Attenuates
            | EvidenceEdgePredicate::Settles
    )
}

fn is_authority_edge_predicate_value(predicate: &str) -> bool {
    matches!(
        predicate,
        "authorizes" | "executes" | "leases" | "attenuates" | "settles"
    )
}
