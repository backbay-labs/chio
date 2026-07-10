use super::*;

pub(crate) fn risk_evidence_schema_matches_kind(
    schema: &str,
    kind: chio_risk_comptroller::RiskEvidenceRefKind,
) -> bool {
    use chio_risk_comptroller::RiskEvidenceRefKind;

    match kind {
        RiskEvidenceRefKind::AuthorityReceipt => matches!(
            schema,
            ENTERPRISE_APPROVAL_CASE_SCHEMA | RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::SupportingEvidence => matches!(
            schema,
            ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA
                | ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
                | ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA
                | ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA
                | COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA
        ),
        RiskEvidenceRefKind::ReserveLedgerReceipt => matches!(
            schema,
            ENTERPRISE_APPROVAL_CASE_SCHEMA | RISK_GUARANTEE_DECISION_SCHEMA | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::Settlement => matches!(
            schema,
            ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA
                | WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA
                | WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
        RiskEvidenceRefKind::Jurisdiction => matches!(
            schema,
            RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA
                | ENTERPRISE_APPROVAL_CASE_SCHEMA
                | CHIO_RECEIPT_SCHEMA
        ),
    }
}

pub(crate) fn embedded_risk_evidence_ref_matches(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    evidence_ref: &str,
    kind: chio_risk_comptroller::RiskEvidenceRefKind,
) -> bool {
    nodes.iter().any(|node| {
        if !embedded_graph_ref_matches_node(node, evidence_ref) {
            return false;
        }
        risk_evidence_schema_matches_kind(&node.schema, kind)
            && embedded_artifact_node_bytes(node, artifacts, &node.schema, "risk evidence").is_ok()
    })
}

fn embedded_graph_ref_matches_node(
    node: &ProofRoomEmbeddedEvidenceNode,
    evidence_ref: &str,
) -> bool {
    node.id == evidence_ref
        || node.sha256 == evidence_ref
        || node.path == evidence_ref
        || std::path::Path::new(&node.path)
            .file_stem()
            .and_then(|stem| stem.to_str())
            == Some(evidence_ref)
}

pub(crate) fn is_enterprise_risk_context_role(role: &str) -> bool {
    matches!(
        role,
        "data-governance-report"
            | "evidence-export-bundle"
            | "telemetry-projection"
            | "approval-case"
            | "control-evidence-map"
    )
}

pub(crate) fn is_trust_market_risk_context_role(role: &str) -> bool {
    matches!(
        role,
        "provider-discovery-snapshot"
            | "provider-selection-report"
            | "trust-scorecard-snapshot"
            | "reputation-import-report"
            | "sla-commitment"
            | "sla-performance-report"
            | "collateral-position-report"
            | "guarantee-decision"
            | "adjudication-jurisdiction-receipt"
    )
}

pub(crate) fn embedded_risk_comptroller_report_value(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<serde_json::Value, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "risk evidence graph")?;
    let bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "risk-comptroller-report",
        "chio.risk.comptroller-report.v1",
        "risk comptroller",
    )?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("risk comptroller report JSON invalid: {error}"))
}

pub(crate) fn embedded_single_role_artifact_bytes(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let node = select_single_embedded_artifact_node(nodes, role, label)?;
    embedded_artifact_node_bytes(node, artifacts, expected_schema, label)
}

pub(crate) fn select_single_embedded_artifact_node<'a>(
    nodes: &'a [ProofRoomEmbeddedEvidenceNode],
    role: &str,
    label: &str,
) -> Result<&'a ProofRoomEmbeddedEvidenceNode, String> {
    let matches = embedded_artifact_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(format!("missing {label} artifact role: {role}")),
        _ => Err(format!("multiple {label} artifact roles: {role}")),
    }
}

pub(crate) fn embedded_artifact_nodes_by_role<'a>(
    nodes: &'a [ProofRoomEmbeddedEvidenceNode],
    role: &str,
) -> Vec<&'a ProofRoomEmbeddedEvidenceNode> {
    nodes.iter().filter(|node| node.role == role).collect()
}

fn select_single_embedded_artifact_node_by_path<'a>(
    nodes: &'a [ProofRoomEmbeddedEvidenceNode],
    path: &str,
    label: &str,
) -> Result<&'a ProofRoomEmbeddedEvidenceNode, String> {
    let matches: Vec<&ProofRoomEmbeddedEvidenceNode> =
        nodes.iter().filter(|node| node.path == path).collect();
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(format!("missing {label} artifact path: {path}")),
        _ => Err(format!("multiple {label} artifact paths: {path}")),
    }
}

fn embedded_artifact_bytes_by_path(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    path: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    let node = select_single_embedded_artifact_node_by_path(nodes, path, label)?;
    embedded_artifact_node_bytes(node, artifacts, expected_schema, label)
}

pub(crate) fn embedded_artifact_node_bytes(
    node: &ProofRoomEmbeddedEvidenceNode,
    artifacts: &BTreeMap<String, Vec<u8>>,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<u8>, String> {
    if node.schema != expected_schema {
        return Err(format!(
            "unsupported {label} artifact schema for {}: {}",
            node.path, node.schema,
        ));
    }
    let bytes = artifacts
        .get(&node.path)
        .ok_or_else(|| format!("missing {label} artifact: {}", node.path))?;
    let actual_digest = sha256_hex(bytes);
    if actual_digest != node.sha256 {
        return Err(format!(
            "{label} artifact digest mismatch for {}: expected {}, got {}",
            node.path, node.sha256, actual_digest,
        ));
    }
    Ok(bytes.clone())
}

pub(crate) fn embedded_required_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<T, String> {
    let node = select_single_embedded_artifact_node(nodes, role, label)?;
    embedded_json_artifact(node, artifacts, expected_schema, label)
}

pub(crate) fn embedded_optional_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Option<T>, String> {
    let matches = embedded_artifact_nodes_by_role(nodes, role);
    match matches.as_slice() {
        [node] => embedded_json_artifact(node, artifacts, expected_schema, label).map(Some),
        [] => Ok(None),
        _ => Err(format!("multiple {label} artifact roles: {role}")),
    }
}

pub(crate) fn embedded_json_artifacts<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
    label: &str,
) -> Result<Vec<T>, String> {
    let mut decoded = Vec::new();
    for node in embedded_artifact_nodes_by_role(nodes, role) {
        decoded.push(embedded_json_artifact(
            node,
            artifacts,
            expected_schema,
            label,
        )?);
    }
    if decoded.is_empty() {
        return Err(format!("missing {label} artifact role: {role}"));
    }
    Ok(decoded)
}

pub(crate) fn embedded_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    node: &ProofRoomEmbeddedEvidenceNode,
    artifacts: &BTreeMap<String, Vec<u8>>,
    expected_schema: &str,
    label: &str,
) -> Result<T, String> {
    let bytes = embedded_artifact_node_bytes(node, artifacts, expected_schema, label)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{label} artifact JSON invalid for {}: {error}", node.path))
}

pub(crate) fn embedded_commerce_order_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
    verified_trust_market_context: Option<&chio_commerce_order::CommerceVerifiedTrustMarketContext>,
) -> Result<chio_commerce_order::CommerceOrderVerificationBundle, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "commerce evidence graph")?;
    let order_context: chio_commerce_order::CommerceOrderContext = embedded_commerce_json_artifact(
        &graph.nodes,
        artifacts,
        "commerce-order-context",
        chio_commerce_order::COMMERCE_ORDER_CONTEXT_SCHEMA_ID,
    )?;
    let event_log_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.event_log_path,
        chio_commerce_order::COMMERCE_EVENT_LOG_SCHEMA_ID,
        "commerce",
    )?;
    let event_authority_receipts =
        embedded_commerce_event_authority_receipts(&graph.nodes, artifacts, &event_log_bytes)?;
    let payment_lifecycle_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.payment_lifecycle_path,
        chio_commerce_order::COMMERCE_PAYMENT_LIFECYCLE_SCHEMA_ID,
        "commerce",
    )?;
    let mandate_ledger_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.mandate_ledger_path,
        chio_commerce_order::COMMERCE_MANDATE_ALLOWANCE_LEDGER_SCHEMA_ID,
        "commerce",
    )?;
    let mandate_protocol_payloads = embedded_commerce_mandate_protocol_payloads(
        &graph.nodes,
        artifacts,
        &mandate_ledger_bytes,
    )?;
    let provider_passport_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.provider_passport_path,
        chio_commerce_order::COMMERCE_PROVIDER_PASSPORT_SCHEMA_ID,
        "commerce",
    )?;
    let reputation_snapshot_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.reputation_snapshot_path,
        chio_commerce_order::COMMERCE_REPUTATION_SNAPSHOT_SCHEMA_ID,
        "commerce",
    )?;
    let federation_trust_bundle_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.federation_trust_bundle_path,
        chio_commerce_order::COMMERCE_FEDERATION_TRUST_BUNDLE_SCHEMA_ID,
        "commerce",
    )?;
    let settlement_packet_bytes = embedded_artifact_bytes_by_path(
        &graph.nodes,
        artifacts,
        &order_context.settlement_packet_path,
        chio_commerce_order::COMMERCE_SETTLEMENT_PACKET_SCHEMA_ID,
        "commerce",
    )?;
    let risk_comptroller_report_bytes = if let Some(requirement) = order_context
        .coverage_requirement
        .as_ref()
        .filter(|requirement| requirement.required)
    {
        Some(embedded_artifact_bytes_by_path(
            &graph.nodes,
            artifacts,
            &requirement.risk_comptroller_report_path,
            "chio.risk.comptroller-report.v1",
            "commerce",
        )?)
    } else {
        None
    };

    Ok(chio_commerce_order::CommerceOrderVerificationBundle {
        order_context,
        event_log_bytes,
        event_authority_receipts,
        payment_lifecycle_bytes,
        mandate_ledger_bytes,
        provider_passport_bytes,
        reputation_snapshot_bytes,
        federation_trust_bundle_bytes,
        settlement_packet_bytes,
        mandate_protocol_payloads,
        risk_comptroller_report_bytes,
        verified_trust_market_context: verified_trust_market_context.cloned(),
        trusted_event_authority_receipt_kernel_keys:
            crate::commerce_trusted_event_authority_receipt_kernel_keys_from_env()?,
        trusted_payment_signer_keys: crate::commerce_trusted_payment_signer_keys_from_env()?,
        trusted_provider_trust_signer_keys: crate::commerce_trusted_provider_keys_from_env()?,
        trusted_risk_comptroller_signer_keys:
            crate::enterprise_trusted_risk_comptroller_signer_keys_from_env()?,
    })
}

fn embedded_commerce_event_authority_receipts(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    event_log_bytes: &[u8],
) -> Result<Vec<chio_commerce_order::CommerceEventAuthorityReceiptArtifact>, String> {
    commerce_event_authority_receipt_refs(event_log_bytes)?
        .into_iter()
        .map(|receipt_ref| {
            let node = select_single_embedded_artifact_node_by_id(
                nodes,
                &receipt_ref,
                CHIO_RECEIPT_SCHEMA,
                "commerce authority receipt",
            )?;
            let receipt_bytes = embedded_artifact_node_bytes(
                node,
                artifacts,
                CHIO_RECEIPT_SCHEMA,
                "commerce authority receipt",
            )?;
            Ok(chio_commerce_order::CommerceEventAuthorityReceiptArtifact {
                receipt_ref,
                receipt_bytes,
            })
        })
        .collect()
}

fn commerce_event_authority_receipt_refs(event_log_bytes: &[u8]) -> Result<Vec<String>, String> {
    let event_log: serde_json::Value = serde_json::from_slice(event_log_bytes)
        .map_err(|error| format!("commerce event log JSON invalid: {error}"))?;
    let events = event_log
        .get("events")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "commerce event log events must be an array".to_string())?;
    events
        .iter()
        .map(|event| {
            event
                .get("authority_receipt_ref")
                .and_then(serde_json::Value::as_str)
                .filter(|receipt_ref| !receipt_ref.is_empty())
                .map(str::to_string)
                .ok_or_else(|| "commerce event missing authority receipt ref".to_string())
        })
        .collect()
}

fn select_single_embedded_artifact_node_by_id<'a>(
    nodes: &'a [ProofRoomEmbeddedEvidenceNode],
    id: &str,
    expected_schema: &str,
    label: &str,
) -> Result<&'a ProofRoomEmbeddedEvidenceNode, String> {
    let matches: Vec<&ProofRoomEmbeddedEvidenceNode> = nodes
        .iter()
        .filter(|node| embedded_graph_ref_matches_node(node, id) && node.schema == expected_schema)
        .collect();
    match matches.as_slice() {
        [node] => Ok(node),
        [] => Err(format!("missing {label} artifact id: {id}")),
        _ => Err(format!("multiple {label} artifact ids: {id}")),
    }
}

#[derive(serde::Deserialize)]
struct EmbeddedCommerceMandateProtocolPayloadRefs {
    protocol_projections: Vec<EmbeddedCommerceMandateProtocolPayloadRef>,
}

#[derive(serde::Deserialize)]
struct EmbeddedCommerceMandateProtocolPayloadRef {
    protocol: String,
    purpose: String,
    payload_path: String,
}

fn embedded_commerce_mandate_protocol_payloads(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    mandate_ledger_bytes: &[u8],
) -> Result<Vec<chio_commerce_order::CommerceMandateProtocolPayload>, String> {
    let refs: EmbeddedCommerceMandateProtocolPayloadRefs =
        serde_json::from_slice(mandate_ledger_bytes)
            .map_err(|error| format!("commerce mandate payload refs invalid: {error}"))?;
    let mut payloads = Vec::with_capacity(refs.protocol_projections.len());
    for projection in refs.protocol_projections {
        let payload_bytes = embedded_artifact_bytes_by_path(
            nodes,
            artifacts,
            &projection.payload_path,
            chio_commerce_order::COMMERCE_PROTOCOL_PAYLOAD_SCHEMA_ID,
            "commerce mandate protocol payload",
        )?;
        payloads.push(chio_commerce_order::CommerceMandateProtocolPayload {
            protocol: projection.protocol,
            purpose: projection.purpose,
            payload_bytes,
        });
    }
    Ok(payloads)
}

pub(crate) fn embedded_commerce_json_artifact<T: for<'de> serde::Deserialize<'de>>(
    nodes: &[ProofRoomEmbeddedEvidenceNode],
    artifacts: &BTreeMap<String, Vec<u8>>,
    role: &str,
    expected_schema: &str,
) -> Result<T, String> {
    let bytes =
        embedded_single_role_artifact_bytes(nodes, artifacts, role, expected_schema, "commerce")?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("commerce artifact JSON invalid for {role}: {error}"))
}

pub(crate) fn embedded_disclosure_lineage_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_disclosure_lineage::DisclosureLineageBundle, String> {
    let graph =
        parse_embedded_evidence_graph(evidence_graph_bytes, "disclosure lineage evidence graph")?;
    let capsule: chio_disclosure_lineage::DisclosureCapsule = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "disclosure-capsule",
        chio_disclosure_lineage::DISCLOSURE_CAPSULE_SCHEMA_V1,
        "disclosure lineage",
    )?;
    let lineage: chio_disclosure_lineage::SignedLineageSubgraph = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "signed-lineage-subgraph",
        chio_disclosure_lineage::LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
        "disclosure lineage",
    )?;
    let privacy_profile: chio_disclosure_lineage::DisclosureVerifierPrivacyProfile =
        embedded_required_json_artifact(
            &graph.nodes,
            artifacts,
            "disclosure-verifier-privacy-profile",
            chio_disclosure_lineage::DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
            "disclosure lineage",
        )?;
    let leakage_ledger: chio_disclosure_lineage::DisclosureLeakageLedger =
        embedded_required_json_artifact(
            &graph.nodes,
            artifacts,
            "disclosure-leakage-ledger",
            chio_disclosure_lineage::DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
            "disclosure lineage",
        )?;
    let crypto_context_report: Option<chio_disclosure_lineage::DisclosureCryptoContextReport> =
        embedded_optional_json_artifact(
            &graph.nodes,
            artifacts,
            "disclosure-crypto-context-report",
            chio_disclosure_lineage::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
            "disclosure lineage",
        )?;
    if crypto_context_report.as_ref().is_some_and(|report| {
        report
            .verified_claims
            .iter()
            .any(|claim| claim == "claim.disclosure.crypto_context_bound")
    }) {
        let context_bytes = embedded_single_role_artifact_bytes(
            &graph.nodes,
            artifacts,
            "crypto-verification-context",
            chio_selective_disclosure::CRYPTO_VERIFICATION_CONTEXT_SCHEMA_V1,
            "disclosure crypto context",
        )
        .map_err(|error| format!("missing BBS proof material: {error}"))?;
        let report_bytes = embedded_single_role_artifact_bytes(
            &graph.nodes,
            artifacts,
            "disclosure-crypto-context-report",
            chio_disclosure_lineage::DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1,
            "disclosure crypto context",
        )
        .map_err(|error| format!("missing BBS proof material: {error}"))?;
        let proof_bytes = embedded_single_role_artifact_bytes(
            &graph.nodes,
            artifacts,
            "selective-disclosure-proof",
            chio_selective_disclosure::SELECTIVE_DISCLOSURE_PROOF_SCHEMA_V1,
            "disclosure crypto context",
        )
        .map_err(|error| format!("missing BBS proof material: {error}"))?;
        let projection_manifest_bytes = embedded_single_role_artifact_bytes(
            &graph.nodes,
            artifacts,
            "bbs-projection-manifest",
            chio_selective_disclosure::BBS_PROJECTION_MANIFEST_SCHEMA_V2,
            "disclosure crypto context",
        )
        .map_err(|error| format!("missing BBS proof material: {error}"))?;
        verify_embedded_disclosure_projection_manifest(
            &capsule,
            &proof_bytes,
            &projection_manifest_bytes,
        )?;
        let privacy_profile_bytes = embedded_single_role_artifact_bytes(
            &graph.nodes,
            artifacts,
            "disclosure-verifier-privacy-profile",
            chio_disclosure_lineage::DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
            "disclosure crypto context",
        )
        .map_err(|error| format!("missing BBS proof material: {error}"))?;
        crate::crypto_context::crypto_context_verified_report_bytes_with_bbs(
            &context_bytes,
            &report_bytes,
            &proof_bytes,
            &privacy_profile_bytes,
            "source-disclosure-lineage",
        )
        .map_err(|error| format!("disclosure crypto context invalid: {error}"))?;
    }

    Ok(chio_disclosure_lineage::DisclosureLineageBundle {
        capsule,
        privacy_profile,
        lineage,
        leakage_ledger,
        crypto_context_report,
    })
}

fn verify_embedded_disclosure_projection_manifest(
    capsule: &chio_disclosure_lineage::DisclosureCapsule,
    proof_bytes: &[u8],
    projection_manifest_bytes: &[u8],
) -> Result<(), String> {
    type SelectiveDisclosureProof = chio_selective_disclosure::SelectiveDisclosureProof;

    let proof =
        serde_json::from_slice::<SelectiveDisclosureProof>(proof_bytes).map_err(|error| {
            format!(
            "proof-room.fixture.crypto-context-proof-invalid: source-disclosure-lineage: {error}"
        )
        })?;
    let projection_manifest: chio_selective_disclosure::BbsProjectionManifest =
        serde_json::from_slice(projection_manifest_bytes).map_err(|error| {
            format!(
                "proof-room.fixture.projection-manifest-invalid: source-disclosure-lineage: {error}"
            )
        })?;
    let declared = projection_manifest
        .hidden_predicates
        .iter()
        .map(|predicate| predicate.predicate_id.as_str())
        .collect::<BTreeSet<_>>();
    for predicate in &capsule.hidden_predicates {
        if !declared.contains(predicate.predicate_id.as_str()) {
            return Err(format!(
                "proof-room.negative.disclosure-hidden-predicate-missing-from-projection-manifest: source-disclosure-lineage: {}",
                predicate.predicate_id
            ));
        }
    }
    chio_selective_disclosure::verify_bbs_projection_manifest(&proof, &projection_manifest).map_err(
        |error| {
            format!(
                "proof-room.fixture.projection-manifest-invalid: source-disclosure-lineage: {error}"
            )
        },
    )
}

pub(crate) fn embedded_runtime_artifacts(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "runtime evidence graph")?;
    let mut runtime_artifacts = BTreeMap::new();
    for node in graph
        .nodes
        .iter()
        .filter(|node| is_runtime_artifact_role(&node.role))
    {
        let bytes = artifacts
            .get(&node.path)
            .ok_or_else(|| format!("missing runtime artifact: {}", node.path))?;
        runtime_artifacts.insert(node.path.clone(), bytes.clone());
    }
    if runtime_artifacts.is_empty() {
        return Err("missing runtime evidence artifacts".to_string());
    }
    Ok(runtime_artifacts)
}

pub(crate) fn is_runtime_artifact_role(role: &str) -> bool {
    matches!(
        role,
        "claim-set"
            | "receipt"
            | "request"
            | "execution-lease"
            | "trust-root"
            | "tool-server-ack"
            | "trusted-time-proof"
            | "revocation-freshness-proof"
            | "sandbox-attestation"
            | "swarm-task-graph"
            | "swarm-budget-pool"
            | "swarm-join-receipt"
            | "swarm-route-plan-receipt"
            | "runtime-attack-simulation-report"
            | "runtime-chaos-run-report"
    )
}

pub(crate) fn embedded_swarm_authority_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_swarm_authority::SwarmAuthorityBundle, String> {
    let graph = parse_embedded_evidence_graph(evidence_graph_bytes, "swarm evidence graph")?;
    let task_graph: chio_swarm_authority::SwarmTaskGraph = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "swarm-task-graph",
        chio_swarm_authority::CHIO_SWARM_TASK_GRAPH_SCHEMA,
        "swarm",
    )?;
    let budget_pool: chio_swarm_authority::SwarmBudgetPool = embedded_required_json_artifact(
        &graph.nodes,
        artifacts,
        "swarm-budget-pool",
        chio_swarm_authority::CHIO_SWARM_BUDGET_POOL_SCHEMA,
        "swarm",
    )?;
    let revocation_epoch: chio_swarm_authority::SwarmRevocationEpoch =
        embedded_required_json_artifact(
            &graph.nodes,
            artifacts,
            "swarm-revocation-epoch",
            chio_swarm_authority::CHIO_SWARM_REVOCATION_EPOCH_SCHEMA,
            "swarm",
        )?;
    let continuation_tokens: Vec<chio_swarm_authority::SwarmContinuationToken> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-continuation-token",
            chio_swarm_authority::CHIO_SWARM_CONTINUATION_TOKEN_SCHEMA,
            "swarm",
        )?;
    let witness_chains: Vec<chio_swarm_authority::SwarmDelegationWitnessChain> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-delegation-witness-chain",
            chio_swarm_authority::CHIO_SWARM_DELEGATION_WITNESS_CHAIN_SCHEMA,
            "swarm",
        )?;
    let join_receipts: Vec<chio_swarm_authority::SwarmJoinReceipt> = embedded_json_artifacts(
        &graph.nodes,
        artifacts,
        "swarm-join-receipt",
        chio_swarm_authority::CHIO_SWARM_JOIN_RECEIPT_SCHEMA,
        "swarm",
    )?;
    let route_plan_receipts: Vec<chio_swarm_authority::SwarmRoutePlanReceipt> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-route-plan-receipt",
            chio_swarm_authority::CHIO_SWARM_ROUTE_PLAN_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let terminal_receipts: Vec<chio_swarm_authority::SwarmTerminalGraphReceipt> =
        embedded_json_artifacts(
            &graph.nodes,
            artifacts,
            "swarm-terminal-graph-receipt",
            chio_swarm_authority::CHIO_SWARM_TERMINAL_GRAPH_RECEIPT_SCHEMA,
            "swarm",
        )?;
    let now_unix_ms = proof_room_swarm_verification_time()?;

    Ok(chio_swarm_authority::SwarmAuthorityBundle {
        now_unix_ms,
        task_graph,
        continuation_tokens,
        witness_chains,
        join_receipts,
        route_plan_receipts,
        budget_pool,
        revocation_epoch,
        terminal_receipts,
    })
}

fn proof_room_swarm_verification_time() -> Result<u64, String> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| {
            format!("proof room swarm verifier system clock before Unix epoch: {error}")
        })?;
    u64::try_from(duration.as_millis())
        .map_err(|_| "proof room swarm verifier system clock milliseconds overflow".to_string())
}

pub(crate) fn embedded_public_settlement_proof_bundle(
    evidence_graph_bytes: &[u8],
    artifacts: &BTreeMap<String, Vec<u8>>,
) -> Result<chio_web3::settlement_proof::PublicSettlementProofBundle, String> {
    let graph =
        parse_embedded_evidence_graph(evidence_graph_bytes, "public settlement evidence graph")?;
    let bytes = embedded_single_role_artifact_bytes(
        &graph.nodes,
        artifacts,
        "public-settlement-proof-bundle",
        chio_web3::settlement_proof::CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA,
        "public settlement",
    )?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("public settlement proof bundle JSON invalid: {error}"))
}

pub(crate) fn embedded_fixture_file(
    fixture_root: &str,
    asset_path: &str,
    fixture_id: &str,
) -> Result<&'static [u8], (StatusCode, String)> {
    validate_fixture_asset_path(asset_path)?;
    let embedded_path = format!("{fixture_root}/{asset_path}");
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .find(|file| file.path == embedded_path)
        .map(|file| file.contents)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.asset-not-found: {fixture_id}/{asset_path}"),
            )
        })
}

pub(crate) fn embedded_fixture_artifact_map(fixture_root: &str) -> BTreeMap<String, Vec<u8>> {
    let prefix = format!("{fixture_root}/");
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .filter_map(|file| {
            let relative_path = file.path.strip_prefix(&prefix)?;
            Some((relative_path.to_string(), file.contents.to_vec()))
        })
        .collect()
}

pub(crate) fn embedded_fixture_has_files(fixture_root: &str) -> bool {
    let prefix = format!("{fixture_root}/");
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .any(|file| file.path.starts_with(&prefix))
}

pub(crate) fn available_fixture_descriptor(
    fixture_id: &str,
    installed_fixture_root: Option<&Path>,
) -> Result<ProofRoomAvailableFixture, (StatusCode, String)> {
    validate_fixture_id(fixture_id)?;
    parse_available_proof_fixtures_with_root(installed_fixture_root)
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .into_iter()
        .find(|fixture| fixture.id == fixture_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("proof-room.fixture.unknown: {fixture_id}"),
            )
        })
}

pub(crate) fn available_fixture_embedded_root(
    fixture: &ProofRoomAvailableFixture,
) -> Result<String, (StatusCode, String)> {
    fixture
        .path
        .strip_prefix("fixtures/proof-room/")
        .filter(|relative_path| validate_fixture_asset_path(relative_path).is_ok())
        .map(str::to_string)
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("proof-room.fixture.catalog-path-invalid: {}", fixture.path),
            )
        })
}

pub(crate) fn validate_fixture_id(fixture_id: &str) -> Result<(), (StatusCode, String)> {
    if fixture_id.is_empty()
        || fixture_id.contains('/')
        || fixture_id.contains('\\')
        || fixture_id == "."
        || fixture_id == ".."
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.id-invalid: {fixture_id}"),
        ));
    }
    Ok(())
}

pub(crate) fn validate_fixture_asset_path(asset_path: &str) -> Result<&str, (StatusCode, String)> {
    if asset_path.is_empty() || asset_path.starts_with('/') || asset_path.contains('\\') {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {asset_path}"),
        ));
    }
    if asset_path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("proof-room.fixture.asset-path-invalid: {asset_path}"),
        ));
    }
    Ok(asset_path)
}

pub(crate) fn fixture_asset_content_type(asset_path: &str) -> &'static str {
    if asset_path.ends_with(".json") {
        "application/json"
    } else if asset_path.ends_with(".md") {
        "text/markdown; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

pub(crate) fn build_proof_room_fixture_catalog(
    bundle: &Path,
    installed_fixture_root: Option<&Path>,
) -> Result<ProofRoomFixtureCatalog, String> {
    let manifest_path = bundle.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("proof-room.catalog.manifest: {error}"))?;
    let manifest: ProofRoomBundleManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("proof-room.catalog.manifest-json: {error}"))?;
    let load_report_path = manifest
        .proof_room_verifier_report_ref
        .as_ref()
        .map(|reference| reference.path.clone())
        .unwrap_or_else(|| "ui/proof-room-static/load-report.json".to_string());
    let resolved_load_report_path = resolve_proof_room_bundle_path(bundle, &load_report_path)?;
    let load_report_bytes = fs::read(&resolved_load_report_path)
        .map_err(|error| format!("proof-room.catalog.load-report: {error}"))?;
    let load_report: ProofRoomCatalogLoadReport = serde_json::from_slice(&load_report_bytes)
        .map_err(|error| format!("proof-room.catalog.load-report-json: {error}"))?;
    let negative_cases = manifest
        .negative_cases
        .into_iter()
        .map(|negative_case| ProofRoomFixtureCatalogNegativeCase {
            id: negative_case.id,
            path: negative_case.path,
            expected_failure_code: negative_case.expected_failure_code,
            observed_failure_code: negative_case.observed_failure_code,
        })
        .collect();

    Ok(ProofRoomFixtureCatalog {
        schema: "chio.proof-room.fixture-catalog.v1",
        fixtures: vec![ProofRoomFixtureCatalogEntry {
            fixture_id: manifest.fixture_id,
            bundle_id: manifest.bundle_id,
            verdict: load_report.verdict,
            manifest_path: "manifest.json",
            load_report_path,
            negative_cases,
        }],
        available_fixtures: available_proof_fixtures_with_reports(installed_fixture_root)?,
    })
}

pub(crate) fn available_proof_fixtures_with_reports(
    installed_fixture_root: Option<&Path>,
) -> Result<Vec<ProofRoomAvailableFixture>, String> {
    let fixtures = parse_available_proof_fixtures_with_root(installed_fixture_root)?
        .into_iter()
        .filter(|fixture| {
            installed_fixture_root.is_some() || available_fixture_embedded_assets_exist(fixture)
        })
        .collect::<Vec<_>>();
    let mut negative_cases =
        available_fixture_negative_cases_by_fixture(&fixtures, installed_fixture_root)?;
    fixtures
        .into_iter()
        .map(|mut fixture| {
            if fixture.kind == "transaction-passport" {
                fixture.negative_cases = negative_cases.remove(&fixture.id).unwrap_or_default();
            } else if fixture.kind == "proof-room" {
                fixture.negative_cases =
                    available_proof_room_fixture_negative_cases(&fixture, installed_fixture_root)?;
            }
            fixture.verifier_report = Some(proof_room_available_fixture_report_for_fixture(
                &fixture,
                installed_fixture_root,
            ));
            Ok(fixture)
        })
        .collect()
}

pub(crate) fn available_proof_room_fixture_negative_cases(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> Result<Vec<ProofRoomFixtureCatalogNegativeCase>, String> {
    let source = ProofRoomFixtureSource::new(fixture, installed_fixture_root)
        .map_err(|(_status, error)| error)?;
    let manifest_bytes = match source.file("proof-room-bundle/manifest.json", &fixture.id) {
        Ok(bytes) => bytes,
        Err((StatusCode::NOT_FOUND, _error)) => return Ok(Vec::new()),
        Err((_status, error)) => return Err(error),
    };
    let manifest: ProofRoomBundleManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|error| {
            format!(
                "proof-room.fixture.manifest-invalid: {}: {error}",
                fixture.id
            )
        })?;

    manifest
        .negative_cases
        .into_iter()
        .map(|negative_case| {
            let path = format!("proof-room-bundle/{}", negative_case.path);
            validate_fixture_asset_path(&path).map_err(|(_status, error)| error)?;
            Ok(ProofRoomFixtureCatalogNegativeCase {
                id: negative_case.id,
                path,
                expected_failure_code: negative_case.expected_failure_code,
                observed_failure_code: negative_case.observed_failure_code,
            })
        })
        .collect()
}

pub(crate) fn available_fixture_embedded_assets_exist(fixture: &ProofRoomAvailableFixture) -> bool {
    available_fixture_embedded_root(fixture)
        .map(|fixture_root| embedded_fixture_has_files(&fixture_root))
        .unwrap_or(false)
}

pub(crate) fn available_fixture_negative_cases_by_fixture(
    fixtures: &[ProofRoomAvailableFixture],
    installed_fixture_root: Option<&Path>,
) -> Result<BTreeMap<String, Vec<ProofRoomFixtureCatalogNegativeCase>>, String> {
    let positives = fixtures
        .iter()
        .filter(|fixture| fixture.kind == "transaction-passport")
        .collect::<Vec<_>>();
    let mut negative_cases = BTreeMap::new();

    for negative_fixture in fixtures
        .iter()
        .filter(|fixture| fixture.kind == "negative-transaction-passport")
    {
        let Some(descriptor) =
            available_fixture_negative_descriptor(negative_fixture, installed_fixture_root)?
        else {
            continue;
        };
        let Some(base_fixture_path) = descriptor.base_fixture.as_deref() else {
            continue;
        };
        let Some(base_fixture) = positives
            .iter()
            .find(|fixture| descriptor_base_matches_fixture(base_fixture_path, fixture))
        else {
            continue;
        };
        negative_cases
            .entry(base_fixture.id.clone())
            .or_insert_with(Vec::new)
            .push(available_fixture_catalog_negative_case(
                negative_fixture,
                &descriptor,
                installed_fixture_root,
            ));
    }

    Ok(negative_cases)
}

pub(crate) fn descriptor_base_matches_fixture(
    descriptor_base_fixture: &str,
    fixture: &ProofRoomAvailableFixture,
) -> bool {
    descriptor_base_fixture
        .strip_prefix(&fixture.path)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

pub(crate) fn available_fixture_negative_descriptor(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> Result<Option<ProofRoomAvailableFixtureNegativeDescriptor>, String> {
    let descriptor_path = available_fixture_negative_descriptor_path(fixture)?;
    let descriptor_bytes = match installed_fixture_root {
        Some(root) => {
            installed_available_fixture_descriptor_bytes(root, fixture, &descriptor_path)?
        }
        None => match embedded_fixture_file_bytes(&descriptor_path) {
            Some(bytes) => bytes.to_vec(),
            None => return Ok(None),
        },
    };
    serde_json::from_slice(&descriptor_bytes)
        .map(Some)
        .map_err(|error| {
            format!(
                "proof-room.fixture.negative-descriptor-invalid: {}: {}: {error}",
                fixture.id, descriptor_path
            )
        })
}

pub(crate) fn installed_available_fixture_descriptor_bytes(
    installed_fixture_root: &Path,
    fixture: &ProofRoomAvailableFixture,
    descriptor_path: &str,
) -> Result<Vec<u8>, String> {
    let root = fs::canonicalize(installed_fixture_root).map_err(|error| {
        format!(
            "proof-room.fixture.root-unreadable: {}: {error}",
            fixture.id
        )
    })?;
    validate_fixture_asset_path(descriptor_path).map_err(|(_status, error)| error)?;
    let path = fs::canonicalize(root.join(descriptor_path)).map_err(|error| {
        format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}: {error}",
            fixture.id, descriptor_path
        )
    })?;
    if !path.starts_with(&root) {
        return Err(format!(
            "proof-room.fixture.negative-descriptor-path-escape: {}: {}",
            fixture.id, descriptor_path
        ));
    }
    let metadata = fs::metadata(&path).map_err(|error| {
        format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}: {error}",
            fixture.id, descriptor_path
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}",
            fixture.id, descriptor_path
        ));
    }
    fs::read(&path).map_err(|error| {
        format!(
            "proof-room.fixture.negative-descriptor-missing: {}: {}: {error}",
            fixture.id, descriptor_path
        )
    })
}

pub(crate) fn available_fixture_negative_descriptor_path(
    fixture: &ProofRoomAvailableFixture,
) -> Result<String, String> {
    let relative_path = fixture
        .path
        .strip_prefix("fixtures/proof-room/")
        .ok_or_else(|| format!("proof-room.fixture.catalog-path-invalid: {}", fixture.path))?;
    let (fixture_family, fixture_leaf) = relative_path.rsplit_once('/').ok_or_else(|| {
        format!(
            "proof-room.fixture.catalog-path-missing-family: {}",
            fixture.path
        )
    })?;
    let descriptor_path = format!("{fixture_family}/negatives/{fixture_leaf}.json");
    let descriptor_path = validate_fixture_asset_path(&descriptor_path)
        .map_err(|(_status, error)| error)?
        .to_string();
    Ok(descriptor_path)
}

pub(crate) fn embedded_fixture_file_bytes(path: &str) -> Option<&'static [u8]> {
    EMBEDDED_PROOF_FIXTURE_FILES
        .iter()
        .find(|file| file.path == path)
        .map(|file| file.contents)
}

pub(crate) fn available_fixture_catalog_negative_case(
    fixture: &ProofRoomAvailableFixture,
    descriptor: &ProofRoomAvailableFixtureNegativeDescriptor,
    installed_fixture_root: Option<&Path>,
) -> ProofRoomFixtureCatalogNegativeCase {
    let report = proof_room_available_fixture_report(&fixture.id, installed_fixture_root);
    let observed_failure_code = available_fixture_observed_failure_code(&fixture.id, &report);
    ProofRoomFixtureCatalogNegativeCase {
        id: fixture.id.clone(),
        path: "transaction-passport.json".to_string(),
        expected_failure_code: descriptor.expected_failure_code.clone(),
        observed_failure_code,
    }
}

pub(crate) fn available_fixture_observed_failure_code(
    fixture_id: &str,
    report: &ProofRoomAvailableFixtureReport,
) -> Option<String> {
    report
        .error
        .as_deref()
        .map(|error| {
            crate::bundle_a::stable_negative_failure_code(fixture_verifier_domain_error(
                fixture_id, error,
            ))
        })
        .or_else(|| report.failure_code.clone())
}

pub(crate) fn fixture_verifier_domain_error<'a>(fixture_id: &str, error: &'a str) -> &'a str {
    let prefix = format!("proof-room.fixture.verify-failed: {fixture_id}: ");
    error.strip_prefix(&prefix).unwrap_or(error)
}

pub(crate) fn proof_room_available_fixture_report(
    fixture_id: &str,
    installed_fixture_root: Option<&Path>,
) -> ProofRoomAvailableFixtureReport {
    let path = format!("/proof-room-fixtures/{fixture_id}/verifier-report.json");
    match proof_room_fixture_asset_with_root(
        fixture_id,
        "verifier-report.json",
        installed_fixture_root,
    ) {
        Ok((contents, _content_type)) => {
            proof_room_available_fixture_report_from_contents(path, &contents)
        }
        Err((status, error)) => ProofRoomAvailableFixtureReport {
            path,
            status: status.as_u16(),
            verdict: "failed".to_string(),
            failure_code: Some(proof_room_fixture_failure_code(&error).to_string()),
            error: Some(error),
        },
    }
}

pub(crate) fn proof_room_available_fixture_report_for_fixture(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> ProofRoomAvailableFixtureReport {
    let report = proof_room_available_fixture_report(&fixture.id, installed_fixture_root);
    if fixture.kind != "proof-room" || report.verdict != "verified" {
        return report;
    }
    match verify_available_proof_room_fixture_bundle(fixture, installed_fixture_root) {
        Ok(()) => report,
        Err(error) => {
            let error = format!("proof-room.fixture.verify-failed: {}: {error}", fixture.id);
            ProofRoomAvailableFixtureReport {
                path: report.path,
                status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                verdict: "failed".to_string(),
                failure_code: Some(proof_room_fixture_failure_code(&error).to_string()),
                error: Some(error),
            }
        }
    }
}

pub(crate) fn verify_available_proof_room_fixture_bundle(
    fixture: &ProofRoomAvailableFixture,
    installed_fixture_root: Option<&Path>,
) -> Result<(), String> {
    let source = ProofRoomFixtureSource::new(fixture, installed_fixture_root)
        .map_err(|(_status, error)| error)?;
    let Some(manifest_path) = source
        .installed_file_path("proof-room-bundle/manifest.json", &fixture.id)
        .map_err(|(_status, error)| error)?
    else {
        return Ok(());
    };
    verify_proof_room_bundle_inner_with_options(&manifest_path, false, true, true)
}

pub(crate) fn proof_room_available_fixture_report_from_contents(
    path: String,
    contents: &[u8],
) -> ProofRoomAvailableFixtureReport {
    let report = match serde_json::from_slice::<serde_json::Value>(contents) {
        Ok(report) => report,
        Err(error) => {
            return ProofRoomAvailableFixtureReport {
                path,
                status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                verdict: "failed".to_string(),
                failure_code: Some("proof-room.fixture.report-invalid".to_string()),
                error: Some(format!("proof-room.fixture.report-invalid: {error}")),
            };
        }
    };

    let Some(verdict) = proof_room_fixture_report_string(&report, "verdict") else {
        return ProofRoomAvailableFixtureReport {
            path,
            status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            verdict: "failed".to_string(),
            failure_code: Some("proof-room.fixture.report-verdict-missing".to_string()),
            error: Some("proof-room.fixture.report-verdict-missing".to_string()),
        };
    };

    ProofRoomAvailableFixtureReport {
        path,
        status: proof_room_fixture_status_for_verdict(&verdict).as_u16(),
        verdict,
        failure_code: proof_room_fixture_report_string(&report, "failure_code"),
        error: proof_room_fixture_report_string(&report, "error"),
    }
}

pub fn proof_room_fixture_report_status(contents: &[u8]) -> StatusCode {
    let Ok(report) = serde_json::from_slice::<serde_json::Value>(contents) else {
        return StatusCode::UNPROCESSABLE_ENTITY;
    };
    let Some(verdict) = proof_room_fixture_report_string(&report, "verdict") else {
        return StatusCode::UNPROCESSABLE_ENTITY;
    };
    proof_room_fixture_status_for_verdict(&verdict)
}

pub(crate) fn proof_room_fixture_status_for_verdict(verdict: &str) -> StatusCode {
    if verdict == "failed" {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    }
}

pub(crate) fn proof_room_fixture_report_string(
    report: &serde_json::Value,
    field: &str,
) -> Option<String> {
    report
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

pub(crate) fn parse_available_proof_fixtures() -> Result<Vec<ProofRoomAvailableFixture>, String> {
    let catalog: ProofRoomAvailableFixtureCatalog =
        serde_json::from_str(PROOF_FIXTURE_CATALOG_JSON)
            .map_err(|error| format!("proof-room.catalog.available-fixtures-json: {error}"))?;
    parse_available_fixture_catalog(catalog)
}

pub(crate) fn parse_available_proof_fixtures_with_root(
    installed_fixture_root: Option<&Path>,
) -> Result<Vec<ProofRoomAvailableFixture>, String> {
    if let Some(root) = installed_fixture_root {
        if let Some(fixtures) = parse_installed_available_proof_fixtures(root)? {
            return Ok(fixtures);
        }
    }
    parse_available_proof_fixtures()
}

pub(crate) fn parse_installed_available_proof_fixtures(
    installed_fixture_root: &Path,
) -> Result<Option<Vec<ProofRoomAvailableFixture>>, String> {
    let catalog_path = installed_fixture_root.join("catalog.json");
    let catalog_bytes = match fs::read(&catalog_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "proof-room.catalog.available-fixtures-file: {}: {error}",
                catalog_path.display()
            ));
        }
    };
    let catalog: ProofRoomAvailableFixtureCatalog = serde_json::from_slice(&catalog_bytes)
        .map_err(|error| {
            format!(
                "proof-room.catalog.available-fixtures-json: {}: {error}",
                catalog_path.display()
            )
        })?;
    parse_available_fixture_catalog(catalog).map(Some)
}

pub(crate) fn parse_available_fixture_catalog(
    catalog: ProofRoomAvailableFixtureCatalog,
) -> Result<Vec<ProofRoomAvailableFixture>, String> {
    if catalog.schema != PROOF_FIXTURE_CATALOG_SCHEMA {
        return Err(format!(
            "proof-room.catalog.available-fixtures-schema: {}",
            catalog.schema
        ));
    }
    for fixture in &catalog.fixtures {
        validate_fixture_id(&fixture.id).map_err(|(_status, error)| error)?;
        available_fixture_embedded_root(fixture).map_err(|(_status, error)| error)?;
    }
    Ok(catalog.fixtures)
}
