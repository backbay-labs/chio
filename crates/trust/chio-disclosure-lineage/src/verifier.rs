use std::collections::BTreeSet;

use chio_core_types::{Keypair, PublicKey, Signature};
use serde::Serialize;

use super::types::{
    DisclosureCapsule, DisclosureContextVerdict, DisclosureCryptoContextReport,
    DisclosureLeakageLedger, DisclosureLineageBundle, DisclosureLineageError,
    DisclosureLineageVerifierReport, SignedLineageSubgraph, DISCLOSURE_CAPSULE_SCHEMA_V1,
    DISCLOSURE_CRYPTO_CONTEXT_REPORT_SCHEMA_V1, DISCLOSURE_LEAKAGE_LEDGER_SCHEMA_V1,
    DISCLOSURE_LINEAGE_VERIFIER_REPORT_SCHEMA_V1, LINEAGE_SIGNED_SUBGRAPH_SCHEMA_V1,
};

const CLAIM_DISCLOSURE_LINEAGE_SUBGRAPH_BOUND: &str = "claim.disclosure.lineage_subgraph_bound";
const CLAIM_DISCLOSURE_LEAKAGE_LEDGER_COMPLETE: &str = "claim.disclosure.leakage_ledger_complete";
const CLAIM_DISCLOSURE_CRYPTO_CONTEXT_BOUND: &str = "claim.disclosure.crypto_context_bound";
const CLAIM_DISCLOSURE_PROFILE_CONTEXT_POLICY_ENFORCED: &str =
    "claim.disclosure.profile_context_policy_enforced";
const LINEAGE_SIGNATURE_PREFIX: &str = "sig-ed25519:";
const TRUSTED_LINEAGE_SIGNER_PUBLIC_KEYS: &[&str] =
    &["e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa"];
const TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_PUBLIC_KEYS: &[&str] =
    &["e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa"];

#[derive(Serialize)]
struct LineageSubgraphDigestMaterial<'a> {
    id: &'a str,
    transaction_passport_ref: &'a str,
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
        root_receipt_ids: &lineage.root_receipt_ids,
        nodes: &lineage.nodes,
        edges: &lineage.edges,
        redactions: &lineage.redactions,
    }
}

pub fn verify_disclosure_lineage_bundle(
    bundle: &DisclosureLineageBundle,
) -> Result<DisclosureLineageVerifierReport, DisclosureLineageError> {
    validate_capsule(&bundle.capsule)?;
    validate_lineage(&bundle.lineage)?;
    validate_leakage_ledger(&bundle.leakage_ledger)?;
    validate_bundle_bindings(bundle)?;
    validate_leakage_coverage(&bundle.capsule, &bundle.leakage_ledger)?;
    let mut verified_claims = vec![
        CLAIM_DISCLOSURE_LINEAGE_SUBGRAPH_BOUND.to_string(),
        CLAIM_DISCLOSURE_LEAKAGE_LEDGER_COMPLETE.to_string(),
    ];
    if let Some(report) = &bundle.crypto_context_report {
        verify_crypto_context_report_signature(report)?;
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
        ("privacy profile ref", &capsule.privacy_profile_ref),
        ("lineage subgraph ref", &capsule.lineage_subgraph_ref),
        ("leakage ledger ref", &capsule.leakage_ledger_ref),
    ] {
        require_non_empty(value, field)?;
    }
    require_unique_non_empty(&capsule.disclosed_fields, "disclosed field")?;
    require_unique_non_empty(&capsule.hidden_predicates, "hidden predicate")?;
    if capsule.disclosed_fields.is_empty() && capsule.hidden_predicates.is_empty() {
        return Err(invalid(
            "disclosure capsule must declare disclosed fields or hidden predicates",
        ));
    }
    Ok(())
}

fn validate_lineage(lineage: &SignedLineageSubgraph) -> Result<(), DisclosureLineageError> {
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
        ("lineage subgraph digest", &lineage.subgraph_sha256),
        ("lineage signature", &lineage.signature),
    ] {
        require_non_empty(value, field)?;
    }
    require_sha256(&lineage.subgraph_sha256, "lineage subgraph digest")?;
    require_unique_non_empty(&lineage.root_receipt_ids, "root receipt id")?;
    if lineage.nodes.is_empty() {
        return Err(invalid("lineage subgraph requires at least one node"));
    }

    let mut node_ids = BTreeSet::new();
    let mut redacted_nodes = BTreeSet::new();
    for node in &lineage.nodes {
        require_non_empty(&node.id, "lineage node id")?;
        require_non_empty(&node.receipt_ref, "lineage node receipt ref")?;
        require_non_empty(&node.disclosure_state, "lineage node disclosure state")?;
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
    }
    validate_lineage_edges(lineage, &node_ids)?;
    validate_lineage_redactions(lineage, &node_ids, &redacted_nodes)?;

    let actual_digest = compute_signed_lineage_subgraph_digest(lineage)?;
    if actual_digest != lineage.subgraph_sha256 {
        return Err(invalid("lineage subgraph digest mismatch"));
    }
    verify_lineage_signature(lineage, &actual_digest)?;
    Ok(())
}

fn verify_lineage_signature(
    lineage: &SignedLineageSubgraph,
    digest: &str,
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
    let public_key_hex = public_key.to_hex();
    if !TRUSTED_LINEAGE_SIGNER_PUBLIC_KEYS.contains(&public_key_hex.as_str()) {
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

fn verify_crypto_context_report_signature(
    report: &DisclosureCryptoContextReport,
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
    let public_key_hex = public_key.to_hex();
    if !TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_PUBLIC_KEYS.contains(&public_key_hex.as_str()) {
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

fn validate_lineage_edges(
    lineage: &SignedLineageSubgraph,
    node_ids: &BTreeSet<&str>,
) -> Result<(), DisclosureLineageError> {
    let mut edges = BTreeSet::new();
    for edge in &lineage.edges {
        require_non_empty(&edge.from, "lineage edge from")?;
        require_non_empty(&edge.to, "lineage edge to")?;
        require_non_empty(&edge.relation, "lineage edge relation")?;
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
        if !edges.insert((edge.from.as_str(), edge.to.as_str(), edge.relation.as_str())) {
            return Err(invalid("duplicate lineage edge"));
        }
    }
    Ok(())
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

fn validate_leakage_ledger(ledger: &DisclosureLeakageLedger) -> Result<(), DisclosureLineageError> {
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
    ] {
        require_non_empty(value, field)?;
    }
    if ledger.entries.is_empty() {
        return Err(invalid("leakage ledger requires at least one entry"));
    }
    let mut entries = BTreeSet::new();
    for entry in &ledger.entries {
        require_non_empty(&entry.field, "leakage ledger field")?;
        require_non_empty(&entry.leakage_kind, "leakage ledger kind")?;
        if !entry.allowed_by_profile {
            return Err(invalid("leakage ledger entry not allowed by profile"));
        }
        if !matches!(
            entry.leakage_kind.as_str(),
            "disclosed_field" | "hidden_predicate" | "derived_fact"
        ) {
            return Err(invalid("unsupported leakage ledger kind"));
        }
        if entry.leakage_kind == "hidden_predicate"
            && entry
                .residual_inference_note
                .as_ref()
                .is_none_or(|note| note.is_empty())
        {
            return Err(invalid(
                "hidden predicate leakage entry requires residual inference note",
            ));
        }
        if !entries.insert((entry.field.as_str(), entry.leakage_kind.as_str())) {
            return Err(invalid("duplicate leakage ledger entry"));
        }
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
            entry.field == *hidden_predicate
                && entry.leakage_kind == "hidden_predicate"
                && entry.allowed_by_profile
        }) {
            return Err(invalid(format!(
                "hidden predicate absent from leakage ledger: {hidden_predicate}"
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
