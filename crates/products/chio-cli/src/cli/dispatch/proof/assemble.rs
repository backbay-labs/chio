use super::*;
use std::{collections::BTreeMap, fs, io::Write, path::Path};

const TRANSACTION_PASSPORT_SCHEMA: &str = "chio.transaction-passport.v1";
const TRANSACTION_EVIDENCE_GRAPH_SCHEMA: &str = "chio.transaction.evidence-graph.v1";
const TRANSACTION_VERIFIER_POLICY_SCHEMA: &str = "chio.transaction.verifier-policy.v1";
const RESERVED_ASSEMBLE_ROOTS: &[&str] = &[
    "transaction-passport.json",
    "evidence-graph.json",
    "verifier-policy.json",
];

#[derive(serde::Serialize)]
struct ProofAssembleReport {
    schema: &'static str,
    passport_id: String,
    artifact_dir: String,
    verifier_policy: String,
    out: String,
    passport_path: String,
    evidence_graph_path: String,
    verifier_policy_path: String,
}

#[derive(serde::Serialize)]
struct AssembledEvidenceGraph {
    schema: &'static str,
    id: String,
    issued_at: String,
    nodes: Vec<AssembledEvidenceNode>,
    edges: Vec<AssembledEvidenceEdge>,
}

#[derive(Clone, serde::Serialize)]
struct AssembledEvidenceNode {
    id: String,
    schema: String,
    path: String,
    sha256: String,
    role: String,
    #[serde(skip_serializing)]
    runtime_binding: RuntimeArtifactBinding,
}

#[derive(Clone, Default)]
struct RuntimeArtifactBinding {
    lease_id: Option<String>,
    revocation_freshness_ref: Option<String>,
    sandbox_attestation_ref: Option<String>,
    revocation_proof_id: Option<String>,
    sandbox_attestation_id: Option<String>,
    ack_lease_id: Option<String>,
    receipt_execution_lease_ref: Option<String>,
}

#[derive(serde::Serialize)]
struct AssembledEvidenceEdge {
    from: String,
    to: String,
    predicate: &'static str,
    evidence_class: &'static str,
}

pub(super) fn assemble_transaction_passport(
    artifact_dir: &Path,
    verifier_policy: &Path,
    passport_id: &str,
    issued_at: &str,
    out: &Path,
    json_output: bool,
) -> Result<(), CliError> {
    if passport_id.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "proof assemble requires a non-empty passport id".to_string(),
        ));
    }
    if issued_at.trim().is_empty() {
        return Err(CliError::cli_other_error(
            "proof assemble requires a non-empty issued-at timestamp".to_string(),
        ));
    }
    ensure_regular_file(verifier_policy, "verifier policy")?;
    ensure_no_reserved_roots(artifact_dir)?;
    let source_nodes = assemble_evidence_nodes(artifact_dir)?;
    ensure_required_receipt(&source_nodes)?;

    fixture::copy_dir_contents(artifact_dir, out)?;
    let verifier_policy_out = out.join("verifier-policy.json");
    fs::copy(verifier_policy, &verifier_policy_out)?;

    let nodes = assemble_evidence_nodes(out)?;
    let graph = AssembledEvidenceGraph {
        schema: TRANSACTION_EVIDENCE_GRAPH_SCHEMA,
        id: format!("evidence-graph-{passport_id}"),
        issued_at: issued_at.to_string(),
        edges: assemble_evidence_edges(&nodes),
        nodes,
    };
    let evidence_graph_path = out.join("evidence-graph.json");
    write_json_line_file(&evidence_graph_path, &graph)?;
    let evidence_graph_bytes = fs::read(&evidence_graph_path)?;
    let verifier_policy_bytes = fs::read(&verifier_policy_out)?;

    let passport = serde_json::json!({
        "schema": TRANSACTION_PASSPORT_SCHEMA,
        "id": passport_id,
        "issued_at": issued_at,
        "evidence_graph_sha256": chio_core::sha256_hex(&evidence_graph_bytes),
        "evidence_graph_path": "evidence-graph.json",
        "verifier_policy_sha256": chio_core::sha256_hex(&verifier_policy_bytes),
        "verifier_policy_path": "verifier-policy.json"
    });
    let passport_path = out.join("transaction-passport.json");
    write_json_line_file(&passport_path, &passport)?;

    let report = ProofAssembleReport {
        schema: "chio.proof.assemble-report.v1",
        passport_id: passport_id.to_string(),
        artifact_dir: artifact_dir.to_string_lossy().into_owned(),
        verifier_policy: verifier_policy.to_string_lossy().into_owned(),
        out: out.to_string_lossy().into_owned(),
        passport_path: passport_path.to_string_lossy().into_owned(),
        evidence_graph_path: evidence_graph_path.to_string_lossy().into_owned(),
        verifier_policy_path: verifier_policy_out.to_string_lossy().into_owned(),
    };
    write_assemble_report(&report, json_output)
}

fn write_assemble_report(report: &ProofAssembleReport, json_output: bool) -> Result<(), CliError> {
    let mut stdout = std::io::stdout();
    if json_output {
        serde_json::to_writer(&mut stdout, report)?;
        stdout.write_all(b"\n")?;
    } else {
        writeln!(stdout, "assembled proof roots at {}", report.out)?;
        writeln!(stdout, "passport: {}", report.passport_path)?;
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<(), CliError> {
    let file_type = fs::symlink_metadata(path)?.file_type();
    if file_type.is_file() {
        Ok(())
    } else {
        Err(CliError::cli_io_error(format!(
            "proof assemble {label} is not a regular file: {}",
            path.display()
        )))
    }
}

fn ensure_no_reserved_roots(artifact_dir: &Path) -> Result<(), CliError> {
    for name in RESERVED_ASSEMBLE_ROOTS {
        let path = artifact_dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(CliError::cli_other_error(format!(
                    "proof assemble input contains reserved root {name}: {}",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(CliError::from(error)),
        }
    }
    Ok(())
}

fn ensure_required_receipt(nodes: &[AssembledEvidenceNode]) -> Result<(), CliError> {
    if nodes.iter().any(|node| node.role == "receipt") {
        Ok(())
    } else {
        Err(CliError::cli_other_error(
            "proof assemble requires at least one receipt artifact".to_string(),
        ))
    }
}

fn assemble_evidence_nodes(root: &Path) -> Result<Vec<AssembledEvidenceNode>, CliError> {
    let mut entries = Vec::new();
    collect_json_entries(root, root, &mut entries)?;
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
        .into_iter()
        .map(|(path, bytes)| evidence_node_for_entry(&path, &bytes))
        .collect()
}

fn collect_json_entries(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), CliError> {
    let mut children = fs::read_dir(current)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|child| child.file_name());
    for child in children {
        let path = child.path();
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_dir() {
            collect_json_entries(root, &path, entries)?;
        } else if file_type.is_file() {
            let relative = relative_artifact_path(root, &path)?;
            if relative == "transaction-passport.json" || relative == "evidence-graph.json" {
                continue;
            }
            if relative.ends_with(".json") {
                entries.push((relative, fs::read(path)?));
            }
        } else {
            return Err(CliError::cli_other_error(format!(
                "unsupported proof assemble artifact type: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn relative_artifact_path(root: &Path, path: &Path) -> Result<String, CliError> {
    let relative = path.strip_prefix(root).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof assemble artifact {} is outside {}: {error}",
            path.display(),
            root.display()
        ))
    })?;
    let relative = relative.to_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof assemble artifact path is not UTF-8: {}",
            path.display()
        ))
    })?;
    Ok(relative.replace(std::path::MAIN_SEPARATOR, "/"))
}

fn evidence_node_for_entry(path: &str, bytes: &[u8]) -> Result<AssembledEvidenceNode, CliError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let schema = value
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .filter(|schema| !schema.is_empty())
        .ok_or_else(|| {
            CliError::cli_other_error(format!("proof assemble artifact missing schema: {path}"))
        })?;
    let role = evidence_role_for_schema(path, schema);
    Ok(AssembledEvidenceNode {
        id: evidence_node_id(path),
        schema: schema.to_string(),
        path: path.to_string(),
        sha256: chio_core::sha256_hex(bytes),
        role,
        runtime_binding: runtime_binding_for_artifact(&value),
    })
}

fn evidence_node_id(path: &str) -> String {
    path.trim_end_matches(".json")
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn evidence_role_for_schema(path: &str, schema: &str) -> String {
    if path == "verifier-policy.json" || schema == TRANSACTION_VERIFIER_POLICY_SCHEMA {
        return "verifier-policy".to_string();
    }
    match schema {
        "chio.capability.proof.v1" => "capability".to_string(),
        "chio.guard.decision.v1" => "guard-decision".to_string(),
        "chio.policy.bundle.v1" => "policy".to_string(),
        "chio.receipt.v1" => "receipt".to_string(),
        "chio.runtime.terminal-receipt.v1" => "receipt".to_string(),
        "chio.request.digest.v1" => "request".to_string(),
        "chio.response.digest.v1" => "response".to_string(),
        "chio.trust.root.v1" => "trust-root".to_string(),
        "chio.runtime.execution-lease.v1" => "execution-lease".to_string(),
        "chio.runtime.revocation-freshness-proof.v1" => {
            "revocation-freshness-proof".to_string()
        }
        "chio.runtime.sandbox-attestation.v1" => "sandbox-attestation".to_string(),
        "chio.runtime.tool-server-ack.v1" => "tool-server-ack".to_string(),
        "chio.runtime.advisory-observation.v1" => "advisory-observation".to_string(),
        "chio.enterprise.data-governance-report.v1" => "data-governance-report".to_string(),
        "chio.enterprise.evidence-export-bundle.v1" => "evidence-export-bundle".to_string(),
        "chio.enterprise.telemetry-projection.v1" => "telemetry-projection".to_string(),
        "chio.enterprise.approval-case.v1" => "approval-case".to_string(),
        "chio.enterprise.control-evidence-map.v1" => "control-evidence-map".to_string(),
        _ => schema
            .trim_start_matches("chio.")
            .trim_end_matches(".v1")
            .replace('.', "-"),
    }
}

fn runtime_binding_for_artifact(value: &serde_json::Value) -> RuntimeArtifactBinding {
    RuntimeArtifactBinding {
        lease_id: string_field(value, "lease_id"),
        revocation_freshness_ref: string_field(value, "revocation_freshness_ref"),
        sandbox_attestation_ref: string_field(value, "sandbox_attestation_ref"),
        revocation_proof_id: string_field(value, "proof_id"),
        sandbox_attestation_id: string_field(value, "attestation_id"),
        ack_lease_id: string_field(value, "lease_id"),
        receipt_execution_lease_ref: string_field(value, "execution_lease_ref"),
    }
}

fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn assemble_evidence_edges(nodes: &[AssembledEvidenceNode]) -> Vec<AssembledEvidenceEdge> {
    let mut edges = assemble_minimal_edges(nodes);
    edges.extend(assemble_runtime_edges(nodes));
    edges
}

fn assemble_minimal_edges(nodes: &[AssembledEvidenceNode]) -> Vec<AssembledEvidenceEdge> {
    let by_role = nodes
        .iter()
        .map(|node| (node.role.as_str(), node.id.as_str()))
        .collect::<BTreeMap<_, _>>();
    [
        ("capability", "receipt", "authorizes"),
        ("guard-decision", "receipt", "authorizes"),
        ("policy", "guard-decision", "binds"),
        ("request", "receipt", "binds"),
        ("response", "receipt", "binds"),
        ("trust-root", "capability", "authorizes"),
        ("verifier-policy", "receipt", "binds"),
    ]
    .into_iter()
    .filter_map(|(from_role, to_role, predicate)| {
        let from = by_role.get(from_role)?;
        let to = by_role.get(to_role)?;
        Some(AssembledEvidenceEdge {
            from: (*from).to_string(),
            to: (*to).to_string(),
            predicate,
            evidence_class: "digest-bound-reference",
        })
    })
    .collect()
}

fn assemble_runtime_edges(nodes: &[AssembledEvidenceNode]) -> Vec<AssembledEvidenceEdge> {
    let Some(verifier_policy) = nodes.iter().find(|node| node.role == "verifier-policy") else {
        return Vec::new();
    };
    let mut edges = Vec::new();
    for lease in nodes.iter().filter(|node| node.role == "execution-lease") {
        let Some(lease_id) = lease.runtime_binding.lease_id.as_deref() else {
            continue;
        };
        edges.push(AssembledEvidenceEdge {
            from: verifier_policy.id.clone(),
            to: lease.id.clone(),
            predicate: "authorizes",
            evidence_class: "chio-sidecar-proof",
        });
        if let Some(revocation) = nodes.iter().find(|node| {
            node.role == "revocation-freshness-proof"
                && node.runtime_binding.revocation_proof_id.as_deref()
                    == lease.runtime_binding.revocation_freshness_ref.as_deref()
        }) {
            edges.push(AssembledEvidenceEdge {
                from: revocation.id.clone(),
                to: lease.id.clone(),
                predicate: "freshens",
                evidence_class: "native-external-proof",
            });
        }
        if let Some(sandbox) = nodes.iter().find(|node| {
            node.role == "sandbox-attestation"
                && node.runtime_binding.sandbox_attestation_id.as_deref()
                    == lease.runtime_binding.sandbox_attestation_ref.as_deref()
        }) {
            edges.push(AssembledEvidenceEdge {
                from: sandbox.id.clone(),
                to: lease.id.clone(),
                predicate: "attests",
                evidence_class: "native-external-proof",
            });
        }
        for receipt in nodes.iter().filter(|node| {
            node.role == "receipt"
                && node.runtime_binding.receipt_execution_lease_ref.as_deref() == Some(lease_id)
        }) {
            edges.push(AssembledEvidenceEdge {
                from: lease.id.clone(),
                to: receipt.id.clone(),
                predicate: "leases",
                evidence_class: "native-external-proof",
            });
            if let Some(ack) = nodes.iter().find(|node| {
                node.role == "tool-server-ack"
                    && node.runtime_binding.ack_lease_id.as_deref() == Some(lease_id)
            }) {
                edges.push(AssembledEvidenceEdge {
                    from: ack.id.clone(),
                    to: receipt.id.clone(),
                    predicate: "acknowledges",
                    evidence_class: "native-external-proof",
                });
            }
        }
    }
    edges
}
