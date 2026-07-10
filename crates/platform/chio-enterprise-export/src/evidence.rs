use serde::Deserialize;

use chio_transaction_passport::{TransactionPassportError, TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID};

use super::EnterpriseExportBundle;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnterpriseEvidenceGraph {
    schema: String,
    id: String,
    issued_at: String,
    pub(super) nodes: Vec<EnterpriseEvidenceNode>,
    edges: Vec<EnterpriseEvidenceEdge>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EnterpriseEvidenceNode {
    pub(super) id: String,
    pub(super) schema: String,
    pub(super) path: String,
    pub(super) sha256: String,
    pub(super) role: EnterpriseEvidenceRole,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum EnterpriseEvidenceRole {
    ClaimSet,
    RiskComptrollerReport,
    DataGovernanceReport,
    EvidenceExportBundle,
    TelemetryProjection,
    ApprovalCase,
    ControlEvidenceMap,
    AdjudicationJurisdictionReceipt,
    VerifierPolicy,
    Report,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnterpriseEvidenceEdge {
    from: String,
    to: String,
    predicate: String,
    #[serde(default)]
    evidence_class: Option<String>,
}

pub(super) fn parse_graph(
    bytes: &[u8],
) -> Result<EnterpriseEvidenceGraph, TransactionPassportError> {
    let graph: EnterpriseEvidenceGraph = serde_json::from_slice(bytes).map_err(|error| {
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

pub(super) fn find_node(
    graph: &EnterpriseEvidenceGraph,
    role: EnterpriseEvidenceRole,
) -> Option<&EnterpriseEvidenceNode> {
    graph.nodes.iter().find(|node| node.role == role)
}

pub(super) fn find_nodes(
    graph: &EnterpriseEvidenceGraph,
    role: EnterpriseEvidenceRole,
) -> impl Iterator<Item = &EnterpriseEvidenceNode> {
    graph.nodes.iter().filter(move |node| node.role == role)
}

pub(super) fn require_node(
    graph: &EnterpriseEvidenceGraph,
    role: EnterpriseEvidenceRole,
) -> Result<&EnterpriseEvidenceNode, TransactionPassportError> {
    find_node(graph, role).ok_or_else(|| {
        TransactionPassportError::EnterpriseExportClaimFailed(
            "missing enterprise evidence".to_string(),
        )
    })
}

pub(super) fn parse_artifact<T: for<'de> Deserialize<'de>>(
    bundle: &EnterpriseExportBundle,
    node: &EnterpriseEvidenceNode,
    expected_schema: &str,
) -> Result<T, TransactionPassportError> {
    let value = parse_artifact_value(bundle, node, expected_schema)?;
    parse_artifact_from_value(node, value)
}

pub(super) fn parse_signed_risk_comptroller_report(
    bundle: &EnterpriseExportBundle,
    node: &EnterpriseEvidenceNode,
    trusted_authority_keys: &[chio_core_types::PublicKey],
) -> Result<chio_risk_comptroller::RiskComptrollerReport, TransactionPassportError> {
    let value = parse_artifact_value(bundle, node, "chio.risk.comptroller-report.v1")?;
    chio_risk_comptroller::validate_risk_report_signature(&value, trusted_authority_keys)?;
    parse_artifact_from_value(node, value)
}

fn parse_artifact_value(
    bundle: &EnterpriseExportBundle,
    node: &EnterpriseEvidenceNode,
    expected_schema: &str,
) -> Result<serde_json::Value, TransactionPassportError> {
    validate_node(node)?;
    let bytes = bundle
        .artifacts
        .get(&node.path)
        .ok_or_else(|| TransactionPassportError::MissingEnterpriseArtifact(node.path.clone()))?;
    let actual_digest = chio_core_types::sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(TransactionPassportError::InvalidEnterpriseArtifact {
            path: node.path.clone(),
            message: format!(
                "digest mismatch: expected {}, got {actual_digest}",
                node.sha256
            ),
        });
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidEnterpriseArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TransactionPassportError::InvalidEnterpriseArtifact {
            path: node.path.clone(),
            message: "missing schema".to_string(),
        })?;
    if schema != expected_schema {
        return Err(TransactionPassportError::InvalidEnterpriseArtifact {
            path: node.path.clone(),
            message: format!("unsupported schema: {schema}"),
        });
    }
    Ok(value)
}

fn parse_artifact_from_value<T: for<'de> Deserialize<'de>>(
    node: &EnterpriseEvidenceNode,
    value: serde_json::Value,
) -> Result<T, TransactionPassportError> {
    serde_json::from_value(value).map_err(|error| {
        TransactionPassportError::InvalidEnterpriseArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })
}

fn validate_graph_references(
    graph: &EnterpriseEvidenceGraph,
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

fn validate_node(node: &EnterpriseEvidenceNode) -> Result<(), TransactionPassportError> {
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

fn validate_edge(edge: &EnterpriseEvidenceEdge) -> Result<(), TransactionPassportError> {
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
        Err(TransactionPassportError::EnterpriseExportClaimFailed(
            format!("{field} must not be empty"),
        ))
    } else {
        Ok(())
    }
}
