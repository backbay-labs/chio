use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::{Keypair, PublicKey, Signature};
use serde::Serialize;

use super::types::{
    DisclosureCapsule, DisclosureContextVerdict, DisclosureCryptoContextReport,
    DisclosureHiddenPredicate, DisclosureLeakageLedger, DisclosureLineageBundle,
    DisclosureLineageError, DisclosureLineageVerifierReport, DisclosureVerifierPrivacyProfile,
    SignedLineageSubgraph, DISCLOSURE_CAPSULE_SCHEMA_V1,
    DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1, DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
    DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1, DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1,
    LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
};

const CLAIM_DISCLOSURE_LINEAGE_SUBGRAPH_BOUND: &str = "claim.disclosure.lineage_subgraph_bound";
const CLAIM_DISCLOSURE_LEAKAGE_LEDGER_COMPLETE: &str = "claim.disclosure.leakage_ledger_complete";
const CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND: &str = "claim.disclosure.crypto_context_bound";
const CLAIM_DISCLOSURE_PROFILE_CONTEXT_POLICY_ENFORCED: &str =
    "claim.disclosure.profile_context_policy_enforced";
const LINEAGE_SIGNATURE_PREFIX: &str = "sig-ed25519:";
const LINEAGE_NODE_KINDS: &[&str] = &[
    "receipt",
    "capability_snapshot",
    "session_anchor",
    "request_lineage_record",
    "receipt_lineage_statement",
    "continuation_token",
    "checkpoint",
    "bbs_projection",
    "bbs_proof",
    "passport_presentation",
    "governed_intent",
    "approval_token",
    "runtime_assurance",
];
const LINEAGE_EDGE_KINDS: &[&str] = &[
    "parent_of",
    "issued_under",
    "observed_in_session",
    "continued_by",
    "signed_lineage_statement",
    "included_in_checkpoint",
    "proves_projection",
    "governs_transaction",
    "approves_intent",
    "presented_by",
];
const LINEAGE_EVIDENCE_CLASSES: &[&str] = &["observed", "verified", "asserted", "derived"];
const REQUIRED_DISCLOSURE_DERIVED_FACTS: &[&str] = &[
    "derived.crypto.issuer_status",
    "derived.crypto.revocation_freshness",
    "derived.crypto.presentation_timing",
];
const SUPPORTED_HIDDEN_PREDICATES: &[SupportedHiddenPredicate] = &[SupportedHiddenPredicate {
    predicate_id: "amount_lte_100",
    kind: "amount_cap",
    field: "amount",
    operator: "<=",
    operand: "100",
    unit: "USD",
    proof_ref: "selective-disclosure-proof",
    projection_slot: 2,
}];

struct SupportedHiddenPredicate {
    predicate_id: &'static str,
    kind: &'static str,
    field: &'static str,
    operator: &'static str,
    operand: &'static str,
    unit: &'static str,
    proof_ref: &'static str,
    projection_slot: u32,
}

#[derive(Clone, Debug, Default)]
pub struct DisclosureLineageVerifierTrust {
    trusted_lineage_signer_keys: Vec<PublicKey>,
    trusted_crypto_context_report_signer_keys: Vec<PublicKey>,
}

impl DisclosureLineageVerifierTrust {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_trusted_lineage_signer_keys(mut self, keys: Vec<PublicKey>) -> Self {
        self.trusted_lineage_signer_keys = keys;
        self
    }

    pub fn with_trusted_crypto_context_report_signer_keys(mut self, keys: Vec<PublicKey>) -> Self {
        self.trusted_crypto_context_report_signer_keys = keys;
        self
    }

    pub fn trusted_lineage_signer_keys(&self) -> &[PublicKey] {
        &self.trusted_lineage_signer_keys
    }

    pub fn trusted_crypto_context_report_signer_keys(&self) -> &[PublicKey] {
        &self.trusted_crypto_context_report_signer_keys
    }
}

#[derive(Serialize)]
struct LineageSubgraphDigestMaterial<'a> {
    id: &'a str,
    transaction_passport_ref: &'a str,
    policy_profile_id: &'a str,
    generated_at: &'a str,
    audience: &'a str,
    challenge_nonce: &'a str,
    frontier_sha256: &'a str,
    checkpoint_ref: &'a str,
    checkpoint_inclusion_sha256: &'a str,
    max_depth: u32,
    required_evidence_class: &'a str,
    lineage_anchor_ref: &'a str,
    redaction_map_sha256: &'a str,
    leakage_ledger_sha256: &'a str,
    projection_manifest_sha256: &'a str,
    root_receipt_ids: &'a [String],
    nodes: &'a [super::types::DisclosureSignedLineageNode],
    edges: &'a [super::types::DisclosureSignedLineageEdge],
    redactions: &'a [super::types::DisclosureSignedLineageRedaction],
}

pub fn compute_signed_lineage_subgraph_digest(
    lineage: &SignedLineageSubgraph,
) -> Result<String, DisclosureLineageError> {
    let material = lineage_subgraph_digest_material(lineage);
    let bytes = chio_core_types::canonical_json_bytes(&material)
        .map_err(|error| invalid(format!("lineage digest canonicalization failed: {error}")))?;
    Ok(chio_core_types::sha256_hex(&bytes))
}

pub fn sign_lineage_subgraph(
    lineage: &SignedLineageSubgraph,
    signer: &Keypair,
) -> Result<String, DisclosureLineageError> {
    let digest = compute_signed_lineage_subgraph_digest(lineage)?;
    let signature = signer.sign(digest.as_bytes());
    Ok(format!(
        "{LINEAGE_SIGNATURE_PREFIX}{}:{}",
        signer.public_key().to_hex(),
        signature.to_hex()
    ))
}

pub fn sign_crypto_context_report(
    report: &DisclosureCryptoContextReport,
    signer: &Keypair,
) -> Result<String, DisclosureLineageError> {
    let mut material = report.clone();
    material.signature = None;
    let (signature, _) = signer
        .sign_canonical(&material)
        .map_err(|error| invalid(format!("crypto context report signature failed: {error}")))?;
    Ok(format!(
        "{LINEAGE_SIGNATURE_PREFIX}{}:{}",
        signer.public_key().to_hex(),
        signature.to_hex()
    ))
}

fn lineage_subgraph_digest_material(
    lineage: &SignedLineageSubgraph,
) -> LineageSubgraphDigestMaterial<'_> {
    LineageSubgraphDigestMaterial {
        id: &lineage.id,
        transaction_passport_ref: &lineage.transaction_passport_ref,
        policy_profile_id: &lineage.policy_profile_id,
        generated_at: &lineage.generated_at,
        audience: &lineage.audience,
        challenge_nonce: &lineage.challenge_nonce,
        frontier_sha256: &lineage.frontier_sha256,
        checkpoint_ref: &lineage.checkpoint_ref,
        checkpoint_inclusion_sha256: &lineage.checkpoint_inclusion_sha256,
        max_depth: lineage.max_depth,
        required_evidence_class: &lineage.required_evidence_class,
        lineage_anchor_ref: &lineage.lineage_anchor_ref,
        redaction_map_sha256: &lineage.redaction_map_sha256,
        leakage_ledger_sha256: &lineage.leakage_ledger_sha256,
        projection_manifest_sha256: &lineage.projection_manifest_sha256,
        root_receipt_ids: &lineage.root_receipt_ids,
        nodes: &lineage.nodes,
        edges: &lineage.edges,
        redactions: &lineage.redactions,
    }
}

pub fn verify_disclosure_lineage_bundle(
    bundle: &DisclosureLineageBundle,
) -> Result<DisclosureLineageVerifierReport, DisclosureLineageError> {
    verify_disclosure_lineage_bundle_with_trust(bundle, &DisclosureLineageVerifierTrust::new())
}

pub fn verify_disclosure_lineage_bundle_with_trust(
    bundle: &DisclosureLineageBundle,
    trust: &DisclosureLineageVerifierTrust,
) -> Result<DisclosureLineageVerifierReport, DisclosureLineageError> {
    validate_capsule(&bundle.capsule)?;
    validate_privacy_profile(&bundle.privacy_profile)?;
    validate_lineage(&bundle.lineage, trust)?;
    validate_leakage_ledger(&bundle.leakage_ledger, &bundle.privacy_profile)?;
    validate_bundle_bindings(bundle)?;
    validate_privacy_profile_policy(&bundle.capsule, &bundle.privacy_profile)?;
    validate_leakage_coverage(&bundle.capsule, &bundle.leakage_ledger)?;
    let mut verified_claims = vec![
        CLAIM_DISCLOSURE_LINEAGE_SUBGRAPH_BOUND.to_string(),
        CLAIM_DISCLOSURE_LEAKAGE_LEDGER_COMPLETE.to_string(),
    ];
    if let Some(report) = &bundle.crypto_context_report {
        verify_crypto_context_report_signature_with_trust(
            report,
            trust.trusted_crypto_context_report_signer_keys(),
        )?;
        verified_claims.extend(report.verified_claims.iter().cloned());
    }

    Ok(DisclosureLineageVerifierReport {
        schema: DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1.to_string(),
        id: format!("disclosure-lineage-verifier-report-{}", bundle.capsule.id),
        verdict: "verified".to_string(),
        capsule_id: bundle.capsule.id.clone(),
        transaction_passport_ref: bundle.capsule.transaction_passport_ref.clone(),
        lineage_subgraph_ref: bundle.lineage.id.clone(),
        leakage_ledger_ref: bundle.leakage_ledger.id.clone(),
        crypto_verified: true,
        privacy_profile_verified: true,
        disclosed_field_count: bundle.capsule.disclosed_fields.len(),
        hidden_predicate_count: bundle.capsule.hidden_predicates.len(),
        verified_claims,
    })
}

fn validate_capsule(capsule: &DisclosureCapsule) -> Result<(), DisclosureLineageError> {
    if capsule.schema != DISCLOSURE_CAPSULE_SCHEMA_V1 {
        return Err(invalid(format!(
            "unsupported disclosure capsule schema: {}",
            capsule.schema
        )));
    }
    for (field, value) in [
        ("capsule id", &capsule.id),
        (
            "transaction passport ref",
            &capsule.transaction_passport_ref,
        ),
        (
            "crypto context report ref",
            &capsule.crypto_context_report_ref,
        ),
        ("projection manifest ref", &capsule.projection_manifest_ref),
        ("privacy profile ref", &capsule.privacy_profile_ref),
        ("lineage subgraph ref", &capsule.lineage_subgraph_ref),
        ("leakage ledger ref", &capsule.leakage_ledger_ref),
    ] {
        require_non_empty(value, field)?;
    }
    require_unique_non_empty(&capsule.disclosed_fields, "disclosed field")?;
    require_unique_hidden_predicates(&capsule.hidden_predicates)?;
    Ok(())
}

fn validate_lineage(
    lineage: &SignedLineageSubgraph,
    trust: &DisclosureLineageVerifierTrust,
) -> Result<(), DisclosureLineageError> {
    if lineage.schema != LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1 {
        return Err(invalid(format!(
            "unsupported signed lineage subgraph schema: {}",
            lineage.schema
        )));
    }
    for (field, value) in [
        ("lineage subgraph id", &lineage.id),
        (
            "lineage transaction passport ref",
            &lineage.transaction_passport_ref,
        ),
        ("lineage policy profile id", &lineage.policy_profile_id),
        ("lineage generated at", &lineage.generated_at),
        ("lineage audience", &lineage.audience),
        ("lineage challenge nonce", &lineage.challenge_nonce),
        ("lineage frontier digest", &lineage.frontier_sha256),
        ("lineage checkpoint ref", &lineage.checkpoint_ref),
        (
            "lineage checkpoint inclusion digest",
            &lineage.checkpoint_inclusion_sha256,
        ),
        (
            "lineage required evidence class",
            &lineage.required_evidence_class,
        ),
        ("lineage anchor ref", &lineage.lineage_anchor_ref),
        (
            "lineage redaction map digest",
            &lineage.redaction_map_sha256,
        ),
        (
            "lineage leakage ledger digest",
            &lineage.leakage_ledger_sha256,
        ),
        (
            "lineage projection manifest digest",
            &lineage.projection_manifest_sha256,
        ),
        ("lineage subgraph digest", &lineage.subgraph_sha256),
        ("lineage signature", &lineage.signature),
    ] {
        require_non_empty(value, field)?;
    }
    require_sha256(&lineage.frontier_sha256, "lineage frontier digest")?;
    require_sha256(
        &lineage.checkpoint_inclusion_sha256,
        "lineage checkpoint inclusion digest",
    )?;
    require_sha256(
        &lineage.redaction_map_sha256,
        "lineage redaction map digest",
    )?;
    require_sha256(
        &lineage.leakage_ledger_sha256,
        "lineage leakage ledger digest",
    )?;
    require_sha256(
        &lineage.projection_manifest_sha256,
        "lineage projection manifest digest",
    )?;
    require_sha256(&lineage.subgraph_sha256, "lineage subgraph digest")?;
    require_unique_non_empty(&lineage.root_receipt_ids, "root receipt id")?;
    if lineage.nodes.is_empty() {
        return Err(invalid("lineage subgraph requires at least one node"));
    }

    let mut node_ids = BTreeSet::new();
    let mut redacted_nodes = BTreeSet::new();
    for node in &lineage.nodes {
        require_non_empty(&node.id, "lineage node id")?;
        require_non_empty(&node.kind, "lineage node kind")?;
        require_non_empty(&node.receipt_ref, "lineage node receipt ref")?;
        require_non_empty(&node.artifact_sha256, "lineage node artifact digest")?;
        require_non_empty(&node.artifact_schema, "lineage node artifact schema")?;
        require_non_empty(&node.evidence_class, "lineage node evidence class")?;
        require_non_empty(&node.tenant_hash, "lineage node tenant hash")?;
        require_non_empty(&node.source_table, "lineage node source table")?;
        require_non_empty(&node.source_id_hash, "lineage node source id digest")?;
        require_non_empty(&node.disclosure_state, "lineage node disclosure state")?;
        require_unique_optional(&node.parent_ids, "lineage node parent id")?;
        if !LINEAGE_NODE_KINDS.contains(&node.kind.as_str()) {
            return Err(invalid(format!(
                "unsupported lineage node kind: {}",
                node.kind
            )));
        }
        require_sha256(&node.artifact_sha256, "lineage node artifact digest")?;
        require_sha256(&node.tenant_hash, "lineage node tenant hash")?;
        require_sha256(&node.source_id_hash, "lineage node source id digest")?;
        if !LINEAGE_EVIDENCE_CLASSES.contains(&node.evidence_class.as_str()) {
            return Err(invalid(format!(
                "unsupported lineage node evidence class: {}",
                node.evidence_class
            )));
        }
        if chio_core_types::sha256_hex(node.receipt_ref.as_bytes()) != node.artifact_sha256 {
            return Err(invalid(format!(
                "lineage node artifact digest mismatch: {}",
                node.id
            )));
        }
        if chio_core_types::sha256_hex(node.receipt_ref.as_bytes()) != node.source_id_hash {
            return Err(invalid(format!(
                "lineage node source id digest mismatch: {}",
                node.id
            )));
        }
        if evidence_class_rank(&node.evidence_class)?
            < evidence_class_rank(&lineage.required_evidence_class)?
        {
            return Err(invalid(format!(
                "lineage node evidence class below floor: {}",
                node.id
            )));
        }
        if !node_ids.insert(node.id.as_str()) {
            return Err(invalid(format!("duplicate lineage node id: {}", node.id)));
        }
        match node.disclosure_state.as_str() {
            "disclosed" => {}
            "redacted" => {
                redacted_nodes.insert(node.id.as_str());
            }
            _ => return Err(invalid("unsupported lineage disclosure state")),
        }
    }
    for root in &lineage.root_receipt_ids {
        let Some(root_node) = lineage.nodes.iter().find(|node| node.id == *root) else {
            return Err(invalid(format!("unknown lineage root receipt: {root}")));
        };
        if root_node.receipt_ref != *root {
            return Err(invalid(format!(
                "lineage root receipt ref mismatch: {root}"
            )));
        }
        if root_node.depth != 0 {
            return Err(invalid(format!("lineage root depth mismatch: {root}")));
        }
        if !root_node.parent_ids.is_empty() {
            return Err(invalid(format!("lineage root has parents: {root}")));
        }
    }
    validate_lineage_edges(lineage, &node_ids)?;
    validate_lineage_closure(lineage, &node_ids)?;
    validate_lineage_redactions(lineage, &node_ids, &redacted_nodes)?;
    let frontier_sha256 = compute_lineage_frontier_digest(lineage)?;
    if frontier_sha256 != lineage.frontier_sha256 {
        return Err(invalid("lineage frontier digest mismatch"));
    }
    let checkpoint_inclusion_sha256 = chio_core_types::sha256_hex(
        format!("{}|{}", lineage.checkpoint_ref, lineage.frontier_sha256).as_bytes(),
    );
    if checkpoint_inclusion_sha256 != lineage.checkpoint_inclusion_sha256 {
        return Err(invalid("lineage checkpoint inclusion digest mismatch"));
    }

    let actual_digest = compute_signed_lineage_subgraph_digest(lineage)?;
    if actual_digest != lineage.subgraph_sha256 {
        return Err(invalid("lineage subgraph digest mismatch"));
    }
    verify_lineage_signature(lineage, &actual_digest, trust.trusted_lineage_signer_keys())?;
    Ok(())
}

fn verify_lineage_signature(
    lineage: &SignedLineageSubgraph,
    digest: &str,
    trusted_signer_keys: &[PublicKey],
) -> Result<(), DisclosureLineageError> {
    let signature = lineage
        .signature
        .strip_prefix(LINEAGE_SIGNATURE_PREFIX)
        .ok_or_else(|| invalid("lineage subgraph signature unsupported"))?;
    let Some((public_key, signature)) = signature.split_once(':') else {
        return Err(invalid("lineage subgraph signature malformed"));
    };
    let public_key = PublicKey::from_hex(public_key)
        .map_err(|error| invalid(format!("lineage subgraph signer invalid: {error}")))?;
    if !is_trusted_public_key(&public_key, trusted_signer_keys) {
        return Err(invalid("lineage subgraph signer untrusted"));
    }
    let signature = Signature::from_hex(signature)
        .map_err(|error| invalid(format!("lineage subgraph signature invalid: {error}")))?;
    let verified = public_key.verify(digest.as_bytes(), &signature);
    if !verified {
        return Err(invalid("lineage subgraph signature verification failed"));
    }
    Ok(())
}

pub fn verify_crypto_context_report_signature(
    report: &DisclosureCryptoContextReport,
) -> Result<(), DisclosureLineageError> {
    verify_crypto_context_report_signature_with_trust(report, &[])
}

pub fn verify_crypto_context_report_signature_with_trust(
    report: &DisclosureCryptoContextReport,
    trusted_signer_keys: &[PublicKey],
) -> Result<(), DisclosureLineageError> {
    let signature = report
        .signature
        .as_deref()
        .and_then(|signature| signature.strip_prefix(LINEAGE_SIGNATURE_PREFIX))
        .ok_or_else(|| invalid("crypto context report signature missing"))?;
    let Some((public_key, signature)) = signature.split_once(':') else {
        return Err(invalid("crypto context report signature malformed"));
    };
    let public_key = PublicKey::from_hex(public_key)
        .map_err(|error| invalid(format!("crypto context report signer invalid: {error}")))?;
    if !is_trusted_public_key(&public_key, trusted_signer_keys) {
        return Err(invalid("crypto context report signer untrusted"));
    }
    let signature = Signature::from_hex(signature)
        .map_err(|error| invalid(format!("crypto context report signature invalid: {error}")))?;
    let mut material = report.clone();
    material.signature = None;
    let verified = public_key
        .verify_canonical(&material, &signature)
        .map_err(|error| invalid(format!("crypto context report signature invalid: {error}")))?;
    if !verified {
        return Err(invalid(
            "crypto context report signature verification failed",
        ));
    }
    Ok(())
}

fn is_trusted_public_key(public_key: &PublicKey, trusted_signer_keys: &[PublicKey]) -> bool {
    let public_key_hex = public_key.to_hex();
    trusted_signer_keys
        .iter()
        .any(|trusted| trusted.to_hex() == public_key_hex)
}

fn validate_lineage_edges(
    lineage: &SignedLineageSubgraph,
    node_ids: &BTreeSet<&str>,
) -> Result<(), DisclosureLineageError> {
    let mut edges = BTreeSet::new();
    let mut edge_ids = BTreeSet::new();
    for edge in &lineage.edges {
        require_non_empty(&edge.edge_id, "lineage edge id")?;
        require_non_empty(&edge.from, "lineage edge from")?;
        require_non_empty(&edge.to, "lineage edge to")?;
        require_non_empty(&edge.relation, "lineage edge relation")?;
        require_non_empty(&edge.kind, "lineage edge kind")?;
        require_non_empty(&edge.evidence_class, "lineage edge evidence class")?;
        require_non_empty(
            &edge.source_artifact_sha256,
            "lineage edge source artifact digest",
        )?;
        require_non_empty(&edge.statement_sha256, "lineage edge statement digest")?;
        require_non_empty(&edge.disclosure_state, "lineage edge disclosure state")?;
        if !edge_ids.insert(edge.edge_id.as_str()) {
            return Err(invalid(format!(
                "duplicate lineage edge id: {}",
                edge.edge_id
            )));
        }
        if !node_ids.contains(edge.from.as_str()) {
            return Err(invalid(format!(
                "unknown lineage edge source: {}",
                edge.from
            )));
        }
        if !node_ids.contains(edge.to.as_str()) {
            return Err(invalid(format!("unknown lineage edge target: {}", edge.to)));
        }
        if !matches!(
            edge.relation.as_str(),
            "continued" | "derived" | "delegated"
        ) {
            return Err(invalid("unsupported lineage edge relation"));
        }
        if !LINEAGE_EDGE_KINDS.contains(&edge.kind.as_str()) {
            return Err(invalid(format!(
                "unsupported lineage edge kind: {}",
                edge.kind
            )));
        }
        if !LINEAGE_EVIDENCE_CLASSES.contains(&edge.evidence_class.as_str()) {
            return Err(invalid(format!(
                "unsupported lineage edge evidence class: {}",
                edge.evidence_class
            )));
        }
        require_sha256(
            &edge.source_artifact_sha256,
            "lineage edge source artifact digest",
        )?;
        require_sha256(&edge.statement_sha256, "lineage edge statement digest")?;
        if chio_core_types::sha256_hex(edge.edge_id.as_bytes()) != edge.source_artifact_sha256 {
            return Err(invalid(format!(
                "lineage edge source artifact digest mismatch: {}",
                edge.edge_id
            )));
        }
        let statement_sha256 = chio_core_types::sha256_hex(
            format!("{}|{}|{}", edge.from, edge.to, edge.kind).as_bytes(),
        );
        if statement_sha256 != edge.statement_sha256 {
            return Err(invalid(format!(
                "lineage edge statement digest mismatch: {}",
                edge.edge_id
            )));
        }
        if !matches!(edge.disclosure_state.as_str(), "disclosed" | "redacted") {
            return Err(invalid("unsupported lineage edge disclosure state"));
        }
        if !edges.insert((edge.from.as_str(), edge.to.as_str(), edge.relation.as_str())) {
            return Err(invalid("duplicate lineage edge"));
        }
    }
    Ok(())
}

fn validate_lineage_closure(
    lineage: &SignedLineageSubgraph,
    node_ids: &BTreeSet<&str>,
) -> Result<(), DisclosureLineageError> {
    let root_ids = lineage
        .root_receipt_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let node_depths = lineage
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.depth))
        .collect::<BTreeMap<_, _>>();
    let edges = lineage
        .edges
        .iter()
        .map(|edge| ((edge.from.as_str(), edge.to.as_str()), edge))
        .collect::<BTreeMap<_, _>>();
    let mut max_depth = 0_u32;
    for node in &lineage.nodes {
        max_depth = max_depth.max(node.depth);
        if !root_ids.contains(node.id.as_str()) && node.parent_ids.is_empty() {
            return Err(invalid(format!("lineage node missing parent: {}", node.id)));
        }
        for parent_id in &node.parent_ids {
            if !node_ids.contains(parent_id.as_str()) {
                return Err(invalid(format!(
                    "lineage node parent unknown: {}",
                    parent_id
                )));
            }
            let Some(parent_depth) = node_depths.get(parent_id.as_str()) else {
                return Err(invalid(format!(
                    "lineage node parent unknown: {}",
                    parent_id
                )));
            };
            if node.depth <= *parent_depth {
                return Err(invalid(format!(
                    "lineage node depth not greater than parent: {}",
                    node.id
                )));
            }
            if !edges.contains_key(&(parent_id.as_str(), node.id.as_str())) {
                return Err(invalid(format!(
                    "lineage node parent edge missing: {}",
                    node.id
                )));
            }
        }
    }
    if max_depth != lineage.max_depth {
        return Err(invalid("lineage max depth mismatch"));
    }
    Ok(())
}

fn compute_lineage_frontier_digest(
    lineage: &SignedLineageSubgraph,
) -> Result<String, DisclosureLineageError> {
    let parents = lineage
        .edges
        .iter()
        .map(|edge| edge.from.as_str())
        .collect::<BTreeSet<_>>();
    let mut frontier = lineage
        .nodes
        .iter()
        .filter(|node| !parents.contains(node.id.as_str()))
        .map(|node| format!("{}:{}:{}", node.id, node.artifact_sha256, node.depth))
        .collect::<Vec<_>>();
    if frontier.is_empty() {
        return Err(invalid("lineage frontier is empty"));
    }
    frontier.sort();
    Ok(chio_core_types::sha256_hex(frontier.join("|").as_bytes()))
}

fn evidence_class_rank(evidence_class: &str) -> Result<u8, DisclosureLineageError> {
    match evidence_class {
        "asserted" => Ok(0),
        "observed" => Ok(1),
        "verified" | "derived" => Ok(2),
        _ => Err(invalid(format!(
            "unsupported lineage evidence class: {evidence_class}"
        ))),
    }
}

fn validate_lineage_redactions(
    lineage: &SignedLineageSubgraph,
    node_ids: &BTreeSet<&str>,
    redacted_nodes: &BTreeSet<&str>,
) -> Result<(), DisclosureLineageError> {
    let mut redaction_nodes = BTreeSet::new();
    for redaction in &lineage.redactions {
        require_non_empty(&redaction.node_id, "lineage redaction node id")?;
        require_non_empty(&redaction.reason, "lineage redaction reason")?;
        if !node_ids.contains(redaction.node_id.as_str()) {
            return Err(invalid(format!(
                "unknown lineage redaction node: {}",
                redaction.node_id
            )));
        }
        if !redacted_nodes.contains(redaction.node_id.as_str()) {
            return Err(invalid("lineage redaction points to disclosed node"));
        }
        if !matches!(
            redaction.reason.as_str(),
            "privacy_profile" | "data_minimization" | "legal_hold"
        ) {
            return Err(invalid("invalid lineage redaction reason"));
        }
        if !redaction_nodes.insert(redaction.node_id.as_str()) {
            return Err(invalid("duplicate lineage redaction"));
        }
    }
    for node_id in redacted_nodes {
        if !redaction_nodes.contains(node_id) {
            return Err(invalid("redacted lineage node lacks redaction reason"));
        }
    }
    Ok(())
}

fn validate_leakage_ledger(
    ledger: &DisclosureLeakageLedger,
    profile: &DisclosureVerifierPrivacyProfile,
) -> Result<(), DisclosureLineageError> {
    if ledger.schema != DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1 {
        return Err(invalid(format!(
            "unsupported leakage ledger schema: {}",
            ledger.schema
        )));
    }
    for (field, value) in [
        ("leakage ledger id", &ledger.id),
        (
            "leakage transaction passport ref",
            &ledger.transaction_passport_ref,
        ),
        ("leakage privacy profile ref", &ledger.privacy_profile_ref),
        ("leakage policy profile id", &ledger.policy_profile_id),
        (
            "leakage subject artifact digest",
            &ledger.subject_artifact_sha256,
        ),
        ("leakage generated at", &ledger.generated_at),
        ("leakage audience", &ledger.audience),
        (
            "tenant leakage notice ref",
            &ledger.tenant_leakage_notice_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    require_sha256(
        &ledger.subject_artifact_sha256,
        "leakage subject artifact digest",
    )?;
    if ledger.policy_profile_id != profile.profile_id {
        return Err(invalid("leakage ledger policy profile mismatch"));
    }
    if ledger.privacy_profile_ref != profile.profile_id {
        return Err(invalid("leakage ledger privacy profile mismatch"));
    }
    if ledger.audience != profile.required_audience {
        return Err(invalid("leakage ledger audience mismatch"));
    }
    if !ledger.accepted {
        return Err(invalid("leakage ledger not accepted by policy"));
    }
    let sensitivity_fields = profile
        .sensitivity_classes
        .iter()
        .map(|sensitivity_class| {
            (
                sensitivity_class.class_id.as_str(),
                sensitivity_class
                    .fields
                    .iter()
                    .map(String::as_str)
                    .collect::<BTreeSet<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let mut entries = BTreeSet::new();
    let mut entry_ids = BTreeSet::new();
    let mut total_score = 0_u32;
    for entry in &ledger.entries {
        require_non_empty(&entry.entry_id, "leakage ledger entry id")?;
        require_non_empty(&entry.source, "leakage ledger entry source")?;
        require_non_empty(&entry.field, "leakage ledger field")?;
        require_non_empty(&entry.leakage_kind, "leakage ledger kind")?;
        require_non_empty(&entry.disclosure_kind, "leakage ledger disclosure kind")?;
        require_non_empty(&entry.sensitivity_class, "leakage ledger sensitivity class")?;
        require_non_empty(&entry.value_class, "leakage ledger value class")?;
        require_non_empty(&entry.reason, "leakage ledger reason")?;
        require_non_empty(&entry.policy_rule, "leakage ledger policy rule")?;
        require_unique_optional(
            &entry.derived_inferences,
            "leakage ledger derived inference",
        )?;
        if !entry_ids.insert(entry.entry_id.as_str()) {
            return Err(invalid(format!(
                "duplicate leakage ledger entry id: {}",
                entry.entry_id
            )));
        }
        if !entry.allowed_by_profile {
            return Err(invalid("leakage ledger entry not allowed by profile"));
        }
        if !matches!(
            entry.leakage_kind.as_str(),
            "disclosed_field" | "hidden_predicate" | "derived_fact"
        ) {
            return Err(invalid("unsupported leakage ledger kind"));
        }
        if entry.disclosure_kind != entry.leakage_kind {
            return Err(invalid("leakage ledger disclosure kind mismatch"));
        }
        let Some((_, class_fields)) = sensitivity_fields
            .iter()
            .find(|(class_id, _)| *class_id == entry.sensitivity_class)
        else {
            return Err(invalid(format!(
                "leakage ledger entry sensitivity class unknown: {}",
                entry.sensitivity_class
            )));
        };
        if entry.leakage_kind != "derived_fact" && !class_fields.contains(entry.field.as_str()) {
            return Err(invalid(format!(
                "leakage ledger entry field missing from sensitivity class: {}",
                entry.field
            )));
        }
        if (entry.leakage_kind == "hidden_predicate" || entry.score > 1 || entry.cross_tenant_risk)
            && entry
                .residual_inference_note
                .as_ref()
                .is_none_or(|note| note.is_empty())
        {
            return Err(invalid(
                "sensitive leakage entry requires residual inference note",
            ));
        }
        if !entries.insert((entry.field.as_str(), entry.leakage_kind.as_str())) {
            return Err(invalid("duplicate leakage ledger entry"));
        }
        total_score = total_score.saturating_add(entry.score);
    }
    if total_score != ledger.total_leakage_score {
        return Err(invalid("leakage ledger total score mismatch"));
    }
    if ledger.total_leakage_score > ledger.max_allowed_leakage_score {
        return Err(invalid("leakage ledger score exceeds policy maximum"));
    }
    Ok(())
}

fn validate_privacy_profile(
    profile: &DisclosureVerifierPrivacyProfile,
) -> Result<(), DisclosureLineageError> {
    if profile.schema != DISCLOSURE_VERIFIER_PRIVACY_PROFILE_SCHEMA_V1 {
        return Err(invalid(format!(
            "unsupported verifier privacy profile schema: {}",
            profile.schema
        )));
    }
    for (field, value) in [
        ("privacy profile id", &profile.profile_id),
        (
            "privacy profile required audience",
            &profile.required_audience,
        ),
        ("privacy profile nonce policy", &profile.nonce_policy),
        (
            "privacy profile transaction passport ref",
            &profile.transaction_passport_ref,
        ),
    ] {
        require_non_empty(value, field)?;
    }
    require_unique_non_empty(
        &profile.allowed_proof_mechanisms,
        "privacy profile proof mechanism",
    )?;
    require_unique_non_empty(&profile.allowed_issuer_keys, "privacy profile issuer key")?;
    require_unique_non_empty(
        &profile.allowed_algorithms,
        "privacy profile allowed algorithm",
    )?;
    require_unique_optional(
        &profile.forbidden_algorithms,
        "privacy profile forbidden algorithm",
    )?;
    require_unique_optional(
        &profile.allowed_disclosed_fields,
        "privacy profile allowed disclosed field",
    )?;
    require_unique_optional(
        &profile.forbidden_disclosed_fields,
        "privacy profile forbidden disclosed field",
    )?;
    require_unique_optional(
        &profile.allowed_hidden_predicates,
        "privacy profile allowed hidden predicate",
    )?;
    require_unique_optional(
        &profile.forbidden_hidden_predicates,
        "privacy profile forbidden hidden predicate",
    )?;
    validate_sensitivity_classes(profile)?;
    Ok(())
}

fn validate_sensitivity_classes(
    profile: &DisclosureVerifierPrivacyProfile,
) -> Result<(), DisclosureLineageError> {
    if profile.sensitivity_classes.is_empty() {
        return Err(invalid("privacy profile sensitivity classes missing"));
    }
    let mut class_ids = BTreeSet::new();
    for sensitivity_class in &profile.sensitivity_classes {
        require_non_empty(
            &sensitivity_class.class_id,
            "privacy profile sensitivity class id",
        )?;
        if !class_ids.insert(sensitivity_class.class_id.as_str()) {
            return Err(invalid(format!(
                "duplicate privacy profile sensitivity class: {}",
                sensitivity_class.class_id
            )));
        }
        require_unique_non_empty(
            &sensitivity_class.fields,
            "privacy profile sensitivity class field",
        )?;
    }
    Ok(())
}

fn validate_privacy_profile_policy(
    capsule: &DisclosureCapsule,
    profile: &DisclosureVerifierPrivacyProfile,
) -> Result<(), DisclosureLineageError> {
    if capsule.disclosed_fields.len() > profile.leakage_budget.max_disclosed_fields as usize
        || capsule.hidden_predicates.len() > profile.leakage_budget.max_hidden_predicates as usize
    {
        return Err(invalid("disclosure leakage budget exceeded"));
    }
    let classified_fields = profile
        .sensitivity_classes
        .iter()
        .flat_map(|sensitivity_class| sensitivity_class.fields.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    for disclosed_field in &capsule.disclosed_fields {
        if !classified_fields.contains(disclosed_field.as_str()) {
            return Err(invalid(format!(
                "disclosed field missing sensitivity class: {disclosed_field}"
            )));
        }
        if profile
            .forbidden_disclosed_fields
            .iter()
            .any(|field| field == disclosed_field)
        {
            return Err(invalid(format!(
                "disclosed field forbidden by privacy profile: {disclosed_field}"
            )));
        }
        if !profile
            .allowed_disclosed_fields
            .iter()
            .any(|field| field == disclosed_field)
        {
            return Err(invalid(format!(
                "disclosed field not allowed by privacy profile: {disclosed_field}"
            )));
        }
    }
    for hidden_predicate in &capsule.hidden_predicates {
        validate_hidden_predicate(hidden_predicate)?;
        if profile
            .forbidden_hidden_predicates
            .iter()
            .any(|predicate| predicate == &hidden_predicate.predicate_id)
        {
            return Err(invalid(format!(
                "hidden predicate forbidden by privacy profile: {}",
                hidden_predicate.predicate_id
            )));
        }
        if !profile
            .allowed_hidden_predicates
            .iter()
            .any(|predicate| predicate == &hidden_predicate.predicate_id)
        {
            return Err(invalid(format!(
                "hidden predicate not allowed by privacy profile: {}",
                hidden_predicate.predicate_id
            )));
        }
    }
    Ok(())
}

fn validate_hidden_predicate(
    predicate: &DisclosureHiddenPredicate,
) -> Result<(), DisclosureLineageError> {
    for (field, value) in [
        ("hidden predicate id", &predicate.predicate_id),
        ("hidden predicate kind", &predicate.kind),
        ("hidden predicate field", &predicate.field),
        ("hidden predicate operator", &predicate.operator),
        ("hidden predicate operand", &predicate.operand),
        ("hidden predicate unit", &predicate.unit),
        ("hidden predicate proof ref", &predicate.proof_ref),
    ] {
        require_non_empty(value, field)?;
    }
    let Some(supported) = SUPPORTED_HIDDEN_PREDICATES
        .iter()
        .find(|supported| supported.predicate_id == predicate.predicate_id)
    else {
        return Err(invalid(format!(
            "unsupported hidden predicate: {}",
            predicate.predicate_id
        )));
    };
    if predicate.kind != supported.kind {
        return Err(invalid(format!(
            "unsupported hidden predicate kind: {}",
            predicate.kind
        )));
    }
    if predicate.field != supported.field {
        return Err(invalid(format!(
            "hidden predicate field mismatch: {}",
            predicate.predicate_id
        )));
    }
    if predicate.operator != supported.operator {
        return Err(invalid(format!(
            "hidden predicate operator mismatch: {}",
            predicate.predicate_id
        )));
    }
    if predicate.operand != supported.operand {
        return Err(invalid(format!(
            "hidden predicate operand mismatch: {}",
            predicate.predicate_id
        )));
    }
    if predicate.unit != supported.unit {
        return Err(invalid(format!(
            "hidden predicate unit mismatch: {}",
            predicate.predicate_id
        )));
    }
    if predicate.proof_ref != supported.proof_ref {
        return Err(invalid(format!(
            "hidden predicate proof ref mismatch: {}",
            predicate.predicate_id
        )));
    }
    if predicate.projection_slot != supported.projection_slot {
        return Err(invalid(format!(
            "hidden predicate projection slot mismatch: {}",
            predicate.predicate_id
        )));
    }
    if !predicate.result {
        return Err(invalid(format!(
            "hidden predicate result false: {}",
            predicate.predicate_id
        )));
    }
    Ok(())
}

fn validate_bundle_bindings(
    bundle: &DisclosureLineageBundle,
) -> Result<(), DisclosureLineageError> {
    if bundle.capsule.lineage_subgraph_ref != bundle.lineage.id {
        return Err(invalid("disclosure capsule lineage ref mismatch"));
    }
    if bundle.capsule.leakage_ledger_ref != bundle.leakage_ledger.id {
        return Err(invalid("disclosure capsule leakage ledger ref mismatch"));
    }
    if bundle.capsule.transaction_passport_ref != bundle.lineage.transaction_passport_ref
        || bundle.capsule.transaction_passport_ref != bundle.leakage_ledger.transaction_passport_ref
    {
        return Err(invalid("disclosure transaction passport ref mismatch"));
    }
    if bundle.capsule.privacy_profile_ref != bundle.leakage_ledger.privacy_profile_ref {
        return Err(invalid("disclosure privacy profile ref mismatch"));
    }
    if bundle.capsule.privacy_profile_ref != bundle.privacy_profile.profile_id {
        return Err(invalid("disclosure privacy profile artifact mismatch"));
    }
    if bundle.capsule.transaction_passport_ref != bundle.privacy_profile.transaction_passport_ref {
        return Err(invalid("privacy profile transaction passport ref mismatch"));
    }
    let Some(report) = &bundle.crypto_context_report else {
        return Err(invalid("missing crypto context report"));
    };
    if report.schema != DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1 {
        return Err(invalid("unsupported crypto context report schema"));
    }
    if report.id != bundle.capsule.crypto_context_report_ref {
        return Err(invalid("crypto context report ref mismatch"));
    }
    if report.artifact_ref != bundle.capsule.id {
        return Err(invalid("crypto context artifact ref mismatch"));
    }
    if report.projection_manifest_ref != bundle.capsule.projection_manifest_ref {
        return Err(invalid("crypto context projection manifest ref mismatch"));
    }
    if report.verdict != DisclosureContextVerdict::Verified || !report.cryptographic_proof_verified
    {
        return Err(invalid("crypto context report was not verified"));
    }
    for verified_claim in &report.verified_claims {
        if !matches!(
            verified_claim.as_str(),
            CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND
                | CLAIM_DISCLOSURE_PROFILE_CONTEXT_POLICY_ENFORCED
        ) {
            return Err(invalid(format!(
                "crypto context report unsupported claim: {verified_claim}"
            )));
        }
    }
    for disclosed_field in &bundle.capsule.disclosed_fields {
        if !report
            .disclosed_fields
            .iter()
            .any(|field| field == disclosed_field)
        {
            return Err(invalid(format!(
                "crypto context report missing disclosed field: {disclosed_field}"
            )));
        }
    }
    for disclosed_field in &report.disclosed_fields {
        if !bundle
            .capsule
            .disclosed_fields
            .iter()
            .any(|field| field == disclosed_field)
        {
            return Err(invalid(format!(
                "crypto context report excess disclosed field: {disclosed_field}"
            )));
        }
    }
    for required_claim in [
        CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND,
        CLAIM_DISCLOSURE_PROFILE_CONTEXT_POLICY_ENFORCED,
    ] {
        if !report
            .verified_claims
            .iter()
            .any(|claim| claim == required_claim)
        {
            return Err(invalid(format!(
                "crypto context report missing claim: {required_claim}"
            )));
        }
    }
    Ok(())
}

fn validate_leakage_coverage(
    capsule: &DisclosureCapsule,
    ledger: &DisclosureLeakageLedger,
) -> Result<(), DisclosureLineageError> {
    for disclosed_field in &capsule.disclosed_fields {
        if !ledger.entries.iter().any(|entry| {
            entry.field == *disclosed_field
                && entry.leakage_kind == "disclosed_field"
                && entry.allowed_by_profile
        }) {
            return Err(invalid(format!(
                "disclosed field absent from leakage ledger: {disclosed_field}"
            )));
        }
    }
    for hidden_predicate in &capsule.hidden_predicates {
        if !ledger.entries.iter().any(|entry| {
            entry.field == hidden_predicate.predicate_id.as_str()
                && entry.leakage_kind == "hidden_predicate"
                && entry.allowed_by_profile
        }) {
            return Err(invalid(format!(
                "hidden predicate absent from leakage ledger: {}",
                hidden_predicate.predicate_id
            )));
        }
    }
    if !capsule.disclosed_fields.is_empty() || !capsule.hidden_predicates.is_empty() {
        for derived_fact in REQUIRED_DISCLOSURE_DERIVED_FACTS {
            if !ledger.entries.iter().any(|entry| {
                entry.field == *derived_fact
                    && entry.leakage_kind == "derived_fact"
                    && entry.allowed_by_profile
            }) {
                return Err(invalid(format!(
                    "derived fact absent from leakage ledger: {derived_fact}"
                )));
            }
        }
    }
    Ok(())
}

fn require_unique_hidden_predicates(
    values: &[DisclosureHiddenPredicate],
) -> Result<(), DisclosureLineageError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(&value.predicate_id, "hidden predicate id")?;
        if !seen.insert(value.predicate_id.as_str()) {
            return Err(invalid(format!(
                "duplicate hidden predicate: {}",
                value.predicate_id
            )));
        }
    }
    Ok(())
}

fn require_unique_non_empty(
    values: &[String],
    label: &'static str,
) -> Result<(), DisclosureLineageError> {
    let mut seen = BTreeSet::new();
    for value in values {
        require_non_empty(value, label)?;
        if !seen.insert(value.as_str()) {
            return Err(invalid(format!("duplicate {label}: {value}")));
        }
    }
    Ok(())
}

fn require_unique_optional(
    values: &[String],
    label: &'static str,
) -> Result<(), DisclosureLineageError> {
    let mut seen = BTreeSet::new();
    for value in values {
        if value.is_empty() {
            return Err(invalid(format!("{label} must not be empty")));
        }
        if !seen.insert(value.as_str()) {
            return Err(invalid(format!("duplicate {label}: {value}")));
        }
    }
    Ok(())
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), DisclosureLineageError> {
    if value.is_empty() {
        Err(invalid(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn require_sha256(value: &str, field: &'static str) -> Result<(), DisclosureLineageError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(invalid(format!("{field} must be a sha256 hex digest")))
    } else {
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> DisclosureLineageError {
    DisclosureLineageError::InvalidArtifact(message.into())
}
