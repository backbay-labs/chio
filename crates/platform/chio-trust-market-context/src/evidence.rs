use serde::Deserialize;

use chio_core_types::{PublicKey, Signature};
use chio_risk_comptroller::RiskEvidenceRefKind;
use chio_transaction_passport::{TransactionPassportError, TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID};

use super::TrustMarketBundle;

const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";
const COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
const RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
const RISK_COLLATERAL_POSITION_REPORT_SCHEMA: &str = "chio.risk.collateral-position-report.v1";
const RISK_GUARANTEE_DECISION_SCHEMA: &str = "chio.risk.guarantee-decision.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustMarketEvidenceGraph {
    schema: String,
    id: String,
    issued_at: String,
    pub(super) nodes: Vec<TrustMarketEvidenceNode>,
    edges: Vec<TrustMarketEvidenceEdge>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustMarketEvidenceNode {
    id: String,
    schema: String,
    pub(super) path: String,
    sha256: String,
    pub(super) role: TrustMarketEvidenceRole,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TrustMarketEvidenceRole {
    ClaimSet,
    Receipt,
    ProviderDiscoverySnapshot,
    ProviderSelectionReport,
    TrustScorecardSnapshot,
    ReputationImportReport,
    SlaCommitment,
    SlaPerformanceReport,
    RiskComptrollerReport,
    CollateralPositionReport,
    GuaranteeDecision,
    AdjudicationJurisdictionReceipt,
    VerifierPolicy,
    Report,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustMarketEvidenceEdge {
    from: String,
    to: String,
    predicate: String,
    #[serde(default)]
    evidence_class: Option<String>,
}

pub(super) fn parse_graph(
    bytes: &[u8],
) -> Result<TrustMarketEvidenceGraph, TransactionPassportError> {
    let graph: TrustMarketEvidenceGraph = serde_json::from_slice(bytes).map_err(|error| {
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

pub(super) fn require_node(
    graph: &TrustMarketEvidenceGraph,
    role: TrustMarketEvidenceRole,
) -> Result<&TrustMarketEvidenceNode, TransactionPassportError> {
    graph
        .nodes
        .iter()
        .find(|node| node.role == role)
        .ok_or_else(|| {
            TransactionPassportError::TrustMarketClaimFailed(
                "missing trust-market evidence".to_string(),
            )
        })
}

pub(super) fn bundle_contains_verified_receipt_node_id(
    bundle: &TrustMarketBundle,
    graph: &TrustMarketEvidenceGraph,
    receipt_ref: &str,
    trusted_authority_keys: &[PublicKey],
) -> bool {
    let Some(node) = graph.nodes.iter().find(|node| {
        risk_evidence_ref_matches_node(node, receipt_ref)
            && node.role == TrustMarketEvidenceRole::Receipt
            && node.schema == CHIO_RECEIPT_SCHEMA
    }) else {
        return false;
    };
    let Some(bytes) = bundle.artifacts.get(&node.path) else {
        return false;
    };
    if chio_core_types::sha256_hex(bytes) != node.sha256 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(CHIO_RECEIPT_SCHEMA) {
        return false;
    }
    let receipt_id = value
        .get("receipt_id")
        .or_else(|| value.get("id"))
        .and_then(serde_json::Value::as_str);
    let node_file_stem = std::path::Path::new(&node.path)
        .file_stem()
        .and_then(|stem| stem.to_str());
    if receipt_id != Some(receipt_ref)
        && receipt_id != Some(node.id.as_str())
        && receipt_id != node_file_stem
    {
        return false;
    }
    if value
        .get("terminal_status")
        .and_then(serde_json::Value::as_str)
        != Some("allowed_executed")
    {
        return false;
    }
    validate_artifact_signature(node, &value, trusted_authority_keys).is_ok()
}

pub(super) fn bundle_contains_risk_evidence_kind(
    bundle: &TrustMarketBundle,
    graph: &TrustMarketEvidenceGraph,
    evidence_ref: &str,
    kind: RiskEvidenceRefKind,
    trusted_authority_keys: &[PublicKey],
) -> bool {
    let Some(node) = graph.nodes.iter().find(|node| {
        risk_evidence_ref_matches_node(node, evidence_ref)
            && risk_evidence_schema_matches_kind(&node.schema, kind)
    }) else {
        return false;
    };
    let Some(bytes) = bundle.artifacts.get(&node.path) else {
        return false;
    };
    if chio_core_types::sha256_hex(bytes) != node.sha256 {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return false;
    };
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(node.schema.as_str()) {
        return false;
    }
    validate_artifact_signature(node, &value, trusted_authority_keys).is_ok()
}

fn risk_evidence_ref_matches_node(node: &TrustMarketEvidenceNode, evidence_ref: &str) -> bool {
    node.id == evidence_ref
        || node.sha256 == evidence_ref
        || node.path == evidence_ref
        || std::path::Path::new(&node.path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            == Some(evidence_ref)
}

fn risk_evidence_schema_matches_kind(schema: &str, kind: RiskEvidenceRefKind) -> bool {
    match kind {
        RiskEvidenceRefKind::AuthorityReceipt => matches!(
            schema,
            RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA
                | RISK_GUARANTEE_DECISION_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::SupportingEvidence => matches!(
            schema,
            COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA
                | RISK_COLLATERAL_POSITION_REPORT_SCHEMA
                | RISK_GUARANTEE_DECISION_SCHEMA
        ),
        RiskEvidenceRefKind::ReserveLedgerReceipt => {
            matches!(schema, RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA)
        }
        RiskEvidenceRefKind::Settlement => matches!(schema, CHIO_RECEIPT_SCHEMA),
        RiskEvidenceRefKind::Jurisdiction => matches!(
            schema,
            RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
    }
}

pub(super) fn parse_signed_artifact<T: for<'de> Deserialize<'de>>(
    bundle: &TrustMarketBundle,
    node: &TrustMarketEvidenceNode,
    expected_schema: &str,
    trusted_authority_keys: &[PublicKey],
) -> Result<T, TransactionPassportError> {
    let value = parse_artifact_value(bundle, node, expected_schema)?;
    validate_artifact_signature(node, &value, trusted_authority_keys)?;
    parse_artifact_from_value(node, value)
}

fn parse_artifact_value(
    bundle: &TrustMarketBundle,
    node: &TrustMarketEvidenceNode,
    expected_schema: &str,
) -> Result<serde_json::Value, TransactionPassportError> {
    validate_node(node)?;
    let bytes = bundle
        .artifacts
        .get(&node.path)
        .ok_or_else(|| TransactionPassportError::MissingTrustMarketArtifact(node.path.clone()))?;
    let actual_digest = chio_core_types::sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(TransactionPassportError::InvalidTrustMarketArtifact {
            path: node.path.clone(),
            message: format!(
                "digest mismatch: expected {}, got {actual_digest}",
                node.sha256
            ),
        });
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidTrustMarketArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TransactionPassportError::InvalidTrustMarketArtifact {
            path: node.path.clone(),
            message: "missing schema".to_string(),
        })?;
    if schema != expected_schema {
        return Err(TransactionPassportError::InvalidTrustMarketArtifact {
            path: node.path.clone(),
            message: format!("unsupported schema: {schema}"),
        });
    }
    Ok(value)
}

fn parse_artifact_from_value<T: for<'de> Deserialize<'de>>(
    node: &TrustMarketEvidenceNode,
    value: serde_json::Value,
) -> Result<T, TransactionPassportError> {
    serde_json::from_value(value).map_err(|error| {
        TransactionPassportError::InvalidTrustMarketArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })
}

fn validate_artifact_signature(
    node: &TrustMarketEvidenceNode,
    value: &serde_json::Value,
    trusted_authority_keys: &[PublicKey],
) -> Result<(), TransactionPassportError> {
    let signature = value
        .get("signature")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid_signature(node, "signature field missing"))?;
    let Some(rest) = signature.strip_prefix("sig-ed25519:") else {
        return Err(invalid_signature(node, "unsupported signature format"));
    };
    let mut parts = rest.splitn(2, ':');
    let Some(key_hex) = parts.next().filter(|value| !value.is_empty()) else {
        return Err(invalid_signature(node, "signing key missing"));
    };
    let Some(signature_hex) = parts.next().filter(|value| !value.is_empty()) else {
        return Err(invalid_signature(node, "signature bytes missing"));
    };
    let trusted_key = trusted_authority_keys
        .iter()
        .find(|key| key.to_hex() == key_hex)
        .ok_or_else(|| invalid_signature(node, "signing key is not trusted"))?;
    let signature = Signature::from_hex(signature_hex)
        .map_err(|error| invalid_signature(node, format!("signature decode failed: {error}")))?;
    let mut signed_value = value.clone();
    let Some(object) = signed_value.as_object_mut() else {
        return Err(invalid_signature(node, "artifact must be an object"));
    };
    object.remove("signature");
    let verified = trusted_key
        .verify_canonical(&signed_value, &signature)
        .map_err(|error| invalid_signature(node, format!("signature check failed: {error}")))?;
    if verified {
        Ok(())
    } else {
        Err(invalid_signature(node, "signature check failed"))
    }
}

fn invalid_signature(
    node: &TrustMarketEvidenceNode,
    message: impl Into<String>,
) -> TransactionPassportError {
    TransactionPassportError::InvalidTrustMarketArtifact {
        path: node.path.clone(),
        message: format!(
            "trust-market artifact signature invalid: {}",
            message.into()
        ),
    }
}

fn validate_graph_references(
    graph: &TrustMarketEvidenceGraph,
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

fn validate_node(node: &TrustMarketEvidenceNode) -> Result<(), TransactionPassportError> {
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

fn validate_edge(edge: &TrustMarketEvidenceEdge) -> Result<(), TransactionPassportError> {
    require_non_empty(&edge.from, "evidence graph edge from")?;
    require_non_empty(&edge.to, "evidence graph edge to")?;
    require_non_empty(&edge.predicate, "evidence graph edge predicate")?;
    let _ = &edge.evidence_class;
    Ok(())
}

fn validate_bundle_relative_path(value: &str) -> Result<(), ()> {
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

fn validate_sha256_hex(value: &str) -> Result<(), ()> {
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
        Err(TransactionPassportError::TrustMarketClaimFailed(format!(
            "{field} must not be empty"
        )))
    } else {
        Ok(())
    }
}
