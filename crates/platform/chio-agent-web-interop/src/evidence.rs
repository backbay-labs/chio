use serde::Deserialize;

use chio_transaction_passport::{TransactionPassportError, TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID};

use super::AgentWebInteropBundle;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentWebEvidenceGraph {
    schema: String,
    id: String,
    issued_at: String,
    pub(super) nodes: Vec<AgentWebEvidenceNode>,
    edges: Vec<AgentWebEvidenceEdge>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentWebEvidenceNode {
    pub(super) id: String,
    pub(super) schema: String,
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) role: AgentWebEvidenceRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AgentWebEvidenceRole {
    ClaimSet,
    AgentWebProofEnvelope,
    ExternalProjectionManifest,
    ExternalSubject,
    Receipt,
    VerifierPolicy,
    Report,
    CommerceOrderContext,
    CommerceEventLog,
    CommercePaymentLifecycle,
    CommerceMandateAllowanceLedger,
    CommerceProviderPassport,
    CommerceReputationSnapshot,
    CommerceFederationTrustBundle,
    CommerceSettlementPacket,
    DisclosureCapsule,
    DisclosureLeakageLedger,
    SignedLineageSubgraph,
    DisclosureCryptoContextReport,
}

impl<'de> Deserialize<'de> for AgentWebEvidenceRole {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let role = match value.as_str() {
            "claim-set" => Self::ClaimSet,
            "agent-web-proof-envelope" => Self::AgentWebProofEnvelope,
            "external-projection-manifest" => Self::ExternalProjectionManifest,
            "external-subject" => Self::ExternalSubject,
            "receipt" => Self::Receipt,
            "verifier-policy" => Self::VerifierPolicy,
            "report" => Self::Report,
            "commerce-order-context" => Self::CommerceOrderContext,
            "commerce-event-log" => Self::CommerceEventLog,
            "commerce-payment-lifecycle" => Self::CommercePaymentLifecycle,
            "commerce-mandate-allowance-ledger" => Self::CommerceMandateAllowanceLedger,
            "commerce-provider-passport" => Self::CommerceProviderPassport,
            "commerce-reputation-snapshot" => Self::CommerceReputationSnapshot,
            "commerce-federation-trust-bundle" => Self::CommerceFederationTrustBundle,
            "commerce-settlement-packet" => Self::CommerceSettlementPacket,
            "disclosure-capsule" => Self::DisclosureCapsule,
            "disclosure-leakage-ledger" => Self::DisclosureLeakageLedger,
            "signed-lineage-subgraph" => Self::SignedLineageSubgraph,
            "disclosure-crypto-context-report" => Self::DisclosureCryptoContextReport,
            _ => {
                return Err(serde::de::Error::unknown_variant(
                    &value,
                    &[
                        "agent-web-proof-envelope",
                        "claim-set",
                        "external-projection-manifest",
                        "external-subject",
                        "receipt",
                        "verifier-policy",
                        "report",
                        "commerce-order-context",
                        "commerce-event-log",
                        "commerce-payment-lifecycle",
                        "commerce-mandate-allowance-ledger",
                        "commerce-provider-passport",
                        "commerce-reputation-snapshot",
                        "commerce-federation-trust-bundle",
                        "commerce-settlement-packet",
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
struct AgentWebEvidenceEdge {
    from: String,
    to: String,
    predicate: String,
    #[serde(default)]
    evidence_class: Option<String>,
}

pub(super) fn parse_graph(bytes: &[u8]) -> Result<AgentWebEvidenceGraph, TransactionPassportError> {
    let graph: AgentWebEvidenceGraph = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(error.to_string())
    })?;
    if graph.schema != TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID {
        return Err(TransactionPassportError::UnsupportedEvidenceGraphSchema(
            graph.schema,
        ));
    }
    require_non_empty(&graph.id, "evidence graph id")?;
    require_non_empty(&graph.issued_at, "evidence graph issued_at")?;
    if graph.nodes.is_empty() {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            "evidence graph must contain at least one node".to_string(),
        ));
    }
    for node in &graph.nodes {
        validate_node(node)?;
    }
    for edge in &graph.edges {
        validate_edge(edge)?;
    }
    validate_graph_references(&graph)?;
    Ok(graph)
}

pub(super) fn find_node_by_path<'a>(
    graph: &'a AgentWebEvidenceGraph,
    role: AgentWebEvidenceRole,
    path: &str,
) -> Option<&'a AgentWebEvidenceNode> {
    graph
        .nodes
        .iter()
        .find(|node| node.role == role && node.path == path)
}

pub(super) fn find_node_by_id<'a>(
    graph: &'a AgentWebEvidenceGraph,
    role: AgentWebEvidenceRole,
    id: &str,
) -> Option<&'a AgentWebEvidenceNode> {
    graph
        .nodes
        .iter()
        .find(|node| node.role == role && graph_node_ref_matches(node, id))
}

fn graph_node_ref_matches(node: &AgentWebEvidenceNode, reference: &str) -> bool {
    node.id == reference
        || node.sha256 == reference
        || node.path == reference
        || std::path::Path::new(&node.path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            == Some(reference)
}

pub(super) fn graph_has_edge(
    graph: &AgentWebEvidenceGraph,
    from: &str,
    to: &str,
    predicate: &str,
    evidence_class: &str,
) -> bool {
    graph.edges.iter().any(|edge| {
        edge.from == from
            && edge.to == to
            && edge.predicate == predicate
            && edge.evidence_class.as_deref() == Some(evidence_class)
    })
}

pub(super) fn parse_artifact<T: for<'de> Deserialize<'de>>(
    bundle: &AgentWebInteropBundle,
    node: &AgentWebEvidenceNode,
    expected_schema: &str,
) -> Result<T, TransactionPassportError> {
    let bytes = raw_artifact_bytes(bundle, node)?;
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidAgentWebArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TransactionPassportError::InvalidAgentWebArtifact {
            path: node.path.clone(),
            message: "missing schema".to_string(),
        })?;
    if schema != expected_schema {
        return Err(TransactionPassportError::InvalidAgentWebArtifact {
            path: node.path.clone(),
            message: format!("unsupported schema: {schema}"),
        });
    }
    serde_json::from_value(value).map_err(|error| {
        TransactionPassportError::InvalidAgentWebArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })
}

pub(super) fn raw_artifact_bytes<'a>(
    bundle: &'a AgentWebInteropBundle,
    node: &AgentWebEvidenceNode,
) -> Result<&'a [u8], TransactionPassportError> {
    validate_node(node)?;
    let bytes = bundle
        .artifacts
        .get(&node.path)
        .ok_or_else(|| TransactionPassportError::MissingAgentWebArtifact(node.path.clone()))?;
    let actual_digest = chio_core_types::sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(TransactionPassportError::InvalidAgentWebArtifact {
            path: node.path.clone(),
            message: format!(
                "digest mismatch: expected {}, got {actual_digest}",
                node.sha256
            ),
        });
    }
    Ok(bytes)
}

fn validate_graph_references(
    graph: &AgentWebEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    let mut node_ids = std::collections::BTreeSet::new();
    for node in &graph.nodes {
        if !node_ids.insert(node.id.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("duplicate evidence graph node id: {}", node.id),
            ));
        }
    }
    for edge in &graph.edges {
        if !node_ids.contains(edge.from.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("unknown evidence graph edge source: {}", edge.from),
            ));
        }
        if !node_ids.contains(edge.to.as_str()) {
            return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
                format!("unknown evidence graph edge target: {}", edge.to),
            ));
        }
    }
    Ok(())
}

fn validate_node(node: &AgentWebEvidenceNode) -> Result<(), TransactionPassportError> {
    require_non_empty(&node.id, "evidence graph node id")?;
    require_non_empty(&node.schema, "evidence graph node schema")?;
    validate_bundle_relative_path(&node.path).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "unsafe evidence graph node path: {}",
            node.path
        ))
    })?;
    validate_sha256_hex(&node.sha256).map_err(|_| {
        TransactionPassportError::InvalidEvidenceGraphArtifact(format!(
            "invalid evidence graph node digest: {}",
            node.sha256
        ))
    })
}

fn validate_edge(edge: &AgentWebEvidenceEdge) -> Result<(), TransactionPassportError> {
    require_non_empty(&edge.from, "evidence graph edge from")?;
    require_non_empty(&edge.to, "evidence graph edge to")?;
    require_non_empty(&edge.predicate, "evidence graph edge predicate")?;
    let _ = &edge.evidence_class;
    Ok(())
}

pub(super) fn validate_bundle_relative_path(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.contains('\\') || has_windows_drive_prefix(value) {
        return Err(());
    }
    let path = std::path::Path::new(value);
    if path.is_absolute() {
        return Err(());
    }
    let mut saw_component = false;
    for component in path.components() {
        match component {
            std::path::Component::Normal(_) => {
                saw_component = true;
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => return Err(()),
        }
    }
    if saw_component {
        Ok(())
    } else {
        Err(())
    }
}

pub(super) fn validate_sha256_hex(value: &str) -> Result<(), ()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(())
    }
}

fn has_windows_drive_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(TransactionPassportError::AgentWebClaimFailed(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}
