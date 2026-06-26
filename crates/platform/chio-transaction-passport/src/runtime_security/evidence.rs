use serde::Deserialize;

use super::super::error::TransactionPassportError;
use super::super::evidence_graph::{
    validate_graph_acyclic, validate_graph_references, EvidenceClass, EvidenceEdgePredicate,
};
use super::super::ids::TRANSACTION_EVIDENCE_GRAPH_SCHEMA_ID;
use super::super::validation::{validate_bundle_relative_path, validate_sha256_hex};
use super::RuntimeSecurityBundle;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeEvidenceGraph {
    schema: String,
    id: String,
    issued_at: String,
    pub(super) nodes: Vec<RuntimeEvidenceNode>,
    edges: Vec<RuntimeEvidenceEdge>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeEvidenceNode {
    id: String,
    schema: String,
    pub(super) path: String,
    sha256: String,
    pub(super) role: RuntimeEvidenceRole,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(super) enum RuntimeEvidenceRole {
    Receipt,
    Request,
    TrustRoot,
    PolicyActivationReceipt,
    ExecutionLease,
    ToolServerAck,
    TrustedTimeProof,
    RevocationFreshnessProof,
    SandboxAttestation,
    RuntimeAttackSimulationReport,
    RuntimeChaosRunReport,
    #[serde(rename = "swarm-task-graph")]
    SwarmTaskGraph,
    #[serde(rename = "swarm-budget-pool")]
    SwarmBudgetPool,
    #[serde(rename = "swarm-join-receipt")]
    SwarmJoinReceipt,
    #[serde(rename = "swarm-route-plan-receipt")]
    SwarmRoutePlanReceipt,
    AdvisoryObservation,
    ClaimSet,
    VerifierPolicy,
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeEvidenceEdge {
    from: String,
    to: String,
    predicate: EvidenceEdgePredicate,
    #[serde(default)]
    evidence_class: Option<EvidenceClass>,
}

pub(super) fn parse_graph(bytes: &[u8]) -> Result<RuntimeEvidenceGraph, TransactionPassportError> {
    let graph: RuntimeEvidenceGraph = serde_json::from_slice(bytes).map_err(|error| {
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
    Ok(graph)
}

pub(super) fn ensure_no_advisory_authorization(
    graph: &RuntimeEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    for edge in &graph.edges {
        let authorizes_runtime = matches!(
            edge.predicate,
            EvidenceEdgePredicate::Authorizes
                | EvidenceEdgePredicate::Executes
                | EvidenceEdgePredicate::Leases
                | EvidenceEdgePredicate::Attenuates
                | EvidenceEdgePredicate::Settles
        );
        if authorizes_runtime {
            let advisory_class = edge.evidence_class == Some(EvidenceClass::AdvisoryObservation);
            let advisory_endpoint = graph.nodes.iter().any(|node| {
                (node.id == edge.from || node.id == edge.to)
                    && node.role == RuntimeEvidenceRole::AdvisoryObservation
            });
            if advisory_class || advisory_endpoint {
                return Err(TransactionPassportError::AdvisoryEvidenceCannotAuthorize);
            }
        }
        require_non_empty(&edge.from, "evidence graph edge from")?;
        require_non_empty(&edge.to, "evidence graph edge to")?;
    }
    Ok(())
}

pub(super) fn nodes_by_role(
    graph: &RuntimeEvidenceGraph,
    role: RuntimeEvidenceRole,
) -> impl Iterator<Item = &RuntimeEvidenceNode> {
    graph.nodes.iter().filter(move |node| node.role == role)
}

pub(super) fn leased_receipt_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    lease_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::Receipt
            && graph.edges.iter().any(|edge| {
                edge.from == lease_node.id
                    && edge.to == node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Leases)
            })
    })
}

pub(super) fn bound_request_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    lease_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::Request
            && graph.edges.iter().any(|edge| {
                edge.from == node.id
                    && edge.to == lease_node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Binds)
            })
    })
}

pub(super) fn bound_route_plan_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    lease_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::SwarmRoutePlanReceipt
            && graph.edges.iter().any(|edge| {
                edge.from == node.id
                    && edge.to == lease_node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Binds)
            })
    })
}

pub(super) fn bound_task_graph_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    lease_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::SwarmTaskGraph
            && graph.edges.iter().any(|edge| {
                edge.from == node.id
                    && edge.to == lease_node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Binds)
            })
    })
}

pub(super) fn bound_budget_pool_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    lease_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::SwarmBudgetPool
            && graph.edges.iter().any(|edge| {
                edge.from == node.id
                    && edge.to == lease_node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Binds)
            })
    })
}

pub(super) fn bound_join_receipt_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    lease_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::SwarmJoinReceipt
            && graph.edges.iter().any(|edge| {
                edge.from == node.id
                    && edge.to == lease_node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Binds)
            })
    })
}

pub(super) fn bound_trusted_time_nodes<'a>(
    graph: &'a RuntimeEvidenceGraph,
    ack_node: &'a RuntimeEvidenceNode,
) -> impl Iterator<Item = &'a RuntimeEvidenceNode> + 'a {
    graph.nodes.iter().filter(move |node| {
        node.role == RuntimeEvidenceRole::TrustedTimeProof
            && graph.edges.iter().any(|edge| {
                edge.from == node.id
                    && edge.to == ack_node.id
                    && matches!(edge.predicate, EvidenceEdgePredicate::Binds)
            })
    })
}

pub(super) fn trust_root_authorizes_lease(
    graph: &RuntimeEvidenceGraph,
    trust_root_node: &RuntimeEvidenceNode,
    lease_node: &RuntimeEvidenceNode,
) -> bool {
    graph.edges.iter().any(|edge| {
        edge.from == trust_root_node.id
            && edge.to == lease_node.id
            && matches!(edge.predicate, EvidenceEdgePredicate::Authorizes)
    })
}

pub(super) fn node_sha256(node: &RuntimeEvidenceNode) -> &str {
    &node.sha256
}

pub(super) fn parse_artifact<T: for<'de> Deserialize<'de>>(
    bundle: &RuntimeSecurityBundle,
    node: &RuntimeEvidenceNode,
    expected_schema: &str,
) -> Result<T, TransactionPassportError> {
    validate_node(node)?;
    let bytes = bundle
        .artifacts
        .get(&node.path)
        .ok_or_else(|| TransactionPassportError::MissingRuntimeArtifact(node.path.clone()))?;
    let actual_digest = super::super::sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(TransactionPassportError::InvalidRuntimeArtifact {
            path: node.path.clone(),
            message: format!(
                "digest mismatch: expected {}, got {actual_digest}",
                node.sha256
            ),
        });
    }
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        TransactionPassportError::InvalidRuntimeArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| TransactionPassportError::InvalidRuntimeArtifact {
            path: node.path.clone(),
            message: "missing schema".to_string(),
        })?;
    if schema != expected_schema {
        return Err(TransactionPassportError::InvalidRuntimeArtifact {
            path: node.path.clone(),
            message: format!("unsupported schema: {schema}"),
        });
    }
    serde_json::from_value(value).map_err(|error| {
        TransactionPassportError::InvalidRuntimeArtifact {
            path: node.path.clone(),
            message: error.to_string(),
        }
    })
}

fn validate_node(node: &RuntimeEvidenceNode) -> Result<(), TransactionPassportError> {
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
    })?;
    if node.id != node.sha256 {
        return Err(TransactionPassportError::InvalidEvidenceGraphArtifact(
            format!(
                "evidence graph node id digest mismatch: expected {}, got {}",
                node.sha256, node.id
            ),
        ));
    }
    Ok(())
}

fn validate_edge(edge: &RuntimeEvidenceEdge) -> Result<(), TransactionPassportError> {
    require_non_empty(&edge.from, "evidence graph edge from")?;
    require_non_empty(&edge.to, "evidence graph edge to")?;
    let _ = &edge.predicate;
    let _ = &edge.evidence_class;
    Ok(())
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), TransactionPassportError> {
    if value.is_empty() {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            format!("{field} must not be empty"),
        ))
    } else {
        Ok(())
    }
}
