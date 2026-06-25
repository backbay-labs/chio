use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use chio_commerce_order::CommerceOrderContext;
use chio_core_types::{
    receipt::{
        body::ChioReceipt,
        decision::Decision,
        kinds::{ReceiptKind, TrustLevel},
    },
    PublicKey,
};
use chio_transaction_passport::{
    verify_minimal_passport_artifacts, verify_transaction_passport_signature_with_evidence_graph,
    TransactionPassport, TransactionPassportError,
};

mod artifacts;
mod claims;
mod evidence;
mod policy;
mod protocols;

use artifacts::{
    validate_envelope, validate_external_subject, validate_projection_manifest,
    AgentWebProofEnvelope, ProjectionManifest,
};
use claims::{
    push_claim_once, CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND, CLAIM_PROJECTION_MANIFEST_BOUND,
    CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY, CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
};
use evidence::{
    find_node_by_id, find_node_by_path, graph_has_edge, parse_artifact, parse_graph,
    raw_artifact_bytes, AgentWebEvidenceRole,
};
use policy::parse_policy;

#[derive(Debug, Clone)]
pub struct AgentWebInteropBundle {
    pub passport: TransactionPassport,
    pub evidence_graph_bytes: Vec<u8>,
    pub root_evidence_graph_bytes: Option<Vec<u8>>,
    pub verifier_policy_bytes: Vec<u8>,
    pub artifacts: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct AgentWebVerifierTrust {
    trusted_passport_signer_keys: Vec<PublicKey>,
    default_standard_webhooks_secret: Option<Vec<u8>>,
    standard_webhooks_secrets: BTreeMap<String, Vec<u8>>,
    standard_webhooks_replay_window: Option<StandardWebhooksReplayWindow>,
    seen_standard_webhooks_ids: BTreeSet<String>,
    trusted_receipt_kernel_keys: Vec<PublicKey>,
    trusted_envelope_sidecar_keys: Vec<PublicKey>,
}

#[derive(Debug, Clone)]
pub(crate) struct StandardWebhooksReplayWindow {
    pub now_unix_seconds: u64,
    pub max_age_seconds: u64,
}

impl AgentWebVerifierTrust {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_standard_webhooks_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.default_standard_webhooks_secret = Some(secret.into());
        self
    }

    pub fn with_trusted_passport_signer_keys(
        mut self,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.trusted_passport_signer_keys.extend(keys);
        self
    }

    pub fn with_standard_webhooks_secret_for(
        mut self,
        webhook_id: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Self {
        self.standard_webhooks_secrets
            .insert(webhook_id.into(), secret.into());
        self
    }

    pub fn with_standard_webhooks_replay_window(
        mut self,
        now_unix_seconds: u64,
        max_age_seconds: u64,
    ) -> Self {
        self.standard_webhooks_replay_window = Some(StandardWebhooksReplayWindow {
            now_unix_seconds,
            max_age_seconds,
        });
        self
    }

    pub fn with_seen_standard_webhooks_id(mut self, webhook_id: impl Into<String>) -> Self {
        self.seen_standard_webhooks_ids.insert(webhook_id.into());
        self
    }

    pub fn with_trusted_receipt_kernel_keys(
        mut self,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.trusted_receipt_kernel_keys.extend(keys);
        self
    }

    pub fn with_trusted_envelope_sidecar_keys(
        mut self,
        keys: impl IntoIterator<Item = PublicKey>,
    ) -> Self {
        self.trusted_envelope_sidecar_keys.extend(keys);
        self
    }

    pub(crate) fn standard_webhooks_secret(&self, webhook_id: &str) -> Option<&[u8]> {
        let secret = self
            .standard_webhooks_secrets
            .get(webhook_id)
            .or(self.default_standard_webhooks_secret.as_ref())?;
        if secret.is_empty() {
            None
        } else {
            Some(secret.as_slice())
        }
    }

    pub(crate) fn standard_webhooks_replay_window(&self) -> Option<&StandardWebhooksReplayWindow> {
        self.standard_webhooks_replay_window.as_ref()
    }

    pub(crate) fn has_seen_standard_webhooks_id(&self, webhook_id: &str) -> bool {
        self.seen_standard_webhooks_ids.contains(webhook_id)
    }

    fn trusts_receipt_kernel_key(&self, key: &PublicKey) -> bool {
        self.trusted_receipt_kernel_keys
            .iter()
            .any(|trusted_key| trusted_key == key)
    }

    fn trusts_envelope_sidecar_key(&self, key: &PublicKey) -> bool {
        self.trusted_envelope_sidecar_keys
            .iter()
            .any(|trusted_key| trusted_key == key)
    }
}

struct ProjectionManifestEntry {
    node_id: String,
    node_sha256: String,
    manifest: ProjectionManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWebInteropReport {
    pub schema: String,
    pub id: String,
    pub issued_at: String,
    pub verdict: String,
    pub passport_id: String,
    pub verified_claims: Vec<String>,
    pub projections: Vec<AgentWebProjectionResult>,
    pub unsupported_claims: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWebProjectionResult {
    pub source_protocol: String,
    pub envelope_ref: String,
    pub projection_manifest_ref: String,
    pub external_subject_digest: String,
    pub evidence_classes: Vec<String>,
    pub claim_evidence: Vec<AgentWebClaimEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentWebClaimEvidence {
    pub claim_ref: String,
    pub evidence_class: String,
}

pub fn verify_agent_web_interop(
    bundle: &AgentWebInteropBundle,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    verify_agent_web_interop_with_trust(bundle, &AgentWebVerifierTrust::new())
}

pub fn verify_agent_web_interop_with_trust(
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
) -> Result<AgentWebInteropReport, TransactionPassportError> {
    let signed_evidence_graph_bytes = bundle
        .root_evidence_graph_bytes
        .as_deref()
        .unwrap_or(&bundle.evidence_graph_bytes);
    verify_transaction_passport_signature_with_evidence_graph(
        &bundle.passport,
        signed_evidence_graph_bytes,
        &bundle.evidence_graph_bytes,
        &trust.trusted_passport_signer_keys,
    )?;
    verify_minimal_passport_artifacts(
        &bundle.passport,
        "transaction-passport.json".to_string(),
        &bundle.evidence_graph_bytes,
        &bundle.verifier_policy_bytes,
    )?;

    let graph = parse_graph(&bundle.evidence_graph_bytes)?;
    let policy = parse_policy(&bundle.verifier_policy_bytes)?;

    let mut manifests = BTreeMap::new();
    for node in graph
        .nodes
        .iter()
        .filter(|node| node.role == AgentWebEvidenceRole::ExternalProjectionManifest)
    {
        let manifest: ProjectionManifest = parse_artifact(
            bundle,
            node,
            "chio.agent-web.external-projection-manifest.v1",
        )?;
        validate_projection_manifest(&manifest)?;
        validate_required_unsupported_claims(&manifest)?;
        manifests.insert(
            manifest.projection_id.clone(),
            ProjectionManifestEntry {
                node_id: node.id.clone(),
                node_sha256: node.sha256.clone(),
                manifest,
            },
        );
    }

    let mut verified_claims = Vec::new();
    let mut projections = Vec::new();
    let mut unsupported_claims = Vec::new();
    let mut limitations = Vec::new();

    for envelope_node in graph
        .nodes
        .iter()
        .filter(|node| node.role == AgentWebEvidenceRole::AgentWebProofEnvelope)
    {
        let envelope: AgentWebProofEnvelope =
            parse_artifact(bundle, envelope_node, "chio.agent-web-proof-envelope.v1")?;
        validate_envelope(&bundle.passport, &envelope, trust)?;
        let manifest_entry = manifests
            .get(&envelope.projection_manifest_ref)
            .ok_or_else(|| claim_failed("missing projection manifest"))?;
        validate_envelope_manifest_binding(&envelope, manifest_entry)?;
        validate_required_edge(
            &graph,
            &envelope_node.id,
            &manifest_entry.node_id,
            "projects-to",
            "chio-sidecar-proof",
            "missing Agent Web manifest binding edge",
        )?;

        let external_node = find_node_by_path(
            &graph,
            AgentWebEvidenceRole::ExternalSubject,
            &envelope.external_subject_path,
        )
        .ok_or_else(|| claim_failed("missing external subject"))?;
        validate_required_edge(
            &graph,
            &envelope_node.id,
            &external_node.id,
            "binds",
            "digest-bound-reference",
            "missing Agent Web external subject binding edge",
        )?;
        validate_external_subject_schema(external_node, &envelope.source_protocol)?;
        let external_bytes = raw_artifact_bytes(bundle, external_node)?;
        validate_external_subject(&envelope, &manifest_entry.manifest, external_bytes, trust)?;
        if matches!(
            envelope.source_protocol.as_str(),
            "acp-commerce" | "ap2" | "x402"
        ) {
            validate_order_context_binding(
                &graph,
                bundle,
                external_node,
                external_bytes,
                &envelope.source_protocol,
            )?;
        }
        validate_receipt_refs(
            &graph,
            bundle,
            trust,
            &envelope_node.id,
            &envelope,
            &bundle.passport.verifier_policy_sha256,
        )?;

        verify_claim_mapping(
            &manifest_entry.manifest,
            &envelope.chio_claim_refs,
            &mut verified_claims,
        )?;
        extend_unique(
            &mut unsupported_claims,
            &manifest_entry.manifest.unsupported_claims,
        );
        extend_unique(&mut limitations, &manifest_entry.manifest.copy_limitations);
        extend_unique(&mut limitations, &envelope.limitations);

        projections.push(AgentWebProjectionResult {
            source_protocol: envelope.source_protocol.clone(),
            envelope_ref: envelope.envelope_id,
            projection_manifest_ref: manifest_entry.manifest.projection_id.clone(),
            external_subject_digest: envelope.external_subject_digest,
            evidence_classes: manifest_entry
                .manifest
                .claim_mapping
                .iter()
                .map(|mapping| mapping.evidence_class.clone())
                .collect(),
            claim_evidence: manifest_entry
                .manifest
                .claim_mapping
                .iter()
                .map(|mapping| AgentWebClaimEvidence {
                    claim_ref: mapping.claim_ref.clone(),
                    evidence_class: mapping.evidence_class.clone(),
                })
                .collect(),
        });
    }

    if projections.is_empty() {
        return Err(claim_failed("missing Agent Web proof envelope"));
    }
    reject_required_external_authority_claims(&policy.required_claims)?;
    ensure_required_claims_verified(&policy.required_claims, &verified_claims)?;

    Ok(AgentWebInteropReport {
        schema: "chio.agent-web.interop-verifier-report.v1".to_string(),
        id: format!("agent-web-interop-report-{}", bundle.passport.id),
        issued_at: bundle.passport.issued_at.clone(),
        verdict: "verified".to_string(),
        passport_id: bundle.passport.id.clone(),
        verified_claims,
        projections,
        unsupported_claims,
        limitations,
    })
}

fn validate_receipt_refs(
    graph: &evidence::AgentWebEvidenceGraph,
    bundle: &AgentWebInteropBundle,
    trust: &AgentWebVerifierTrust,
    envelope_node_id: &str,
    envelope: &AgentWebProofEnvelope,
    verifier_policy_sha256: &str,
) -> Result<(), TransactionPassportError> {
    for receipt_ref in &envelope.receipt_refs {
        let receipt_node = find_node_by_id(graph, AgentWebEvidenceRole::Receipt, receipt_ref)
            .ok_or_else(|| claim_failed(format!("missing Agent Web receipt ref: {receipt_ref}")))?;
        validate_required_edge(
            graph,
            envelope_node_id,
            &receipt_node.id,
            "binds",
            "digest-bound-reference",
            "missing Agent Web receipt binding edge",
        )?;
        let receipt_bytes = raw_artifact_bytes(bundle, receipt_node)?;
        validate_agent_web_receipt(
            receipt_bytes,
            receipt_ref,
            envelope,
            verifier_policy_sha256,
            trust,
        )?;
    }
    Ok(())
}

fn validate_agent_web_receipt(
    receipt_bytes: &[u8],
    receipt_ref: &str,
    envelope: &AgentWebProofEnvelope,
    verifier_policy_sha256: &str,
    trust: &AgentWebVerifierTrust,
) -> Result<(), TransactionPassportError> {
    let receipt: ChioReceipt = serde_json::from_slice(receipt_bytes)
        .map_err(|_| claim_failed("Agent Web receipt signature invalid"))?;
    let signature_valid = receipt
        .verify_signature()
        .map_err(|_| claim_failed("Agent Web receipt signature invalid"))?;
    if !signature_valid {
        return Err(claim_failed("Agent Web receipt signature invalid"));
    }
    let action_hash_valid = receipt
        .action
        .verify_hash()
        .map_err(|_| claim_failed("Agent Web receipt signature invalid"))?;
    if !action_hash_valid {
        return Err(claim_failed("Agent Web receipt signature invalid"));
    }
    if receipt.receipt_kind != ReceiptKind::MediatedDecision
        || receipt.trust_level != TrustLevel::Mediated
    {
        return Err(claim_failed("Agent Web receipt signature invalid"));
    }
    if !trust.trusts_receipt_kernel_key(&receipt.kernel_key) {
        return Err(claim_failed("Agent Web receipt kernel key untrusted"));
    }
    if receipt.decision.as_ref() != Some(&Decision::Allow) {
        return Err(claim_failed("Agent Web receipt did not execute"));
    }
    if receipt.content_hash != envelope.external_subject_digest {
        return Err(claim_failed("Agent Web receipt content digest mismatch"));
    }
    if receipt.policy_hash != verifier_policy_sha256 {
        return Err(claim_failed("Agent Web receipt policy digest mismatch"));
    }
    let bound_ref = receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| claim_failed("Agent Web receipt ref mismatch"))?;
    if bound_ref != receipt_ref {
        return Err(claim_failed("Agent Web receipt ref mismatch"));
    }
    Ok(())
}

fn validate_external_subject_schema(
    external_node: &evidence::AgentWebEvidenceNode,
    source_protocol: &str,
) -> Result<(), TransactionPassportError> {
    let expected_schema = expected_external_subject_schema(source_protocol)?;
    if external_node.schema != expected_schema {
        return Err(claim_failed(format!(
            "external subject schema mismatch: expected {expected_schema}, got {}",
            external_node.schema
        )));
    }
    Ok(())
}

fn expected_external_subject_schema(
    source_protocol: &str,
) -> Result<&'static str, TransactionPassportError> {
    protocols::external_subject_schema(source_protocol).ok_or_else(|| {
        claim_failed(format!(
            "unsupported Agent Web source protocol: {source_protocol}"
        ))
    })
}

fn validate_order_context_binding(
    graph: &evidence::AgentWebEvidenceGraph,
    bundle: &AgentWebInteropBundle,
    payment_node: &evidence::AgentWebEvidenceNode,
    payment_bytes: &[u8],
    source_protocol: &str,
) -> Result<(), TransactionPassportError> {
    let payment: serde_json::Value = serde_json::from_slice(payment_bytes).map_err(|error| {
        TransactionPassportError::InvalidAgentWebArtifact {
            path: payment_node.path.clone(),
            message: error.to_string(),
        }
    })?;
    let payment_order_id = payment
        .get("order_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| claim_failed(format!("missing {source_protocol} order id")))?;

    for order_node in graph.nodes.iter().filter(|node| {
        node.role == AgentWebEvidenceRole::ExternalSubject && node.id != payment_node.id
    }) {
        if !graph_has_edge(
            graph,
            &payment_node.id,
            &order_node.id,
            "binds",
            "digest-bound-reference",
        ) {
            continue;
        }
        let order_bytes = raw_artifact_bytes(bundle, order_node)?;
        let order_context: CommerceOrderContext =
            serde_json::from_slice(order_bytes).map_err(|error| {
                TransactionPassportError::InvalidAgentWebArtifact {
                    path: order_node.path.clone(),
                    message: error.to_string(),
                }
            })?;
        order_context.validate_shape().map_err(|error| {
            TransactionPassportError::InvalidAgentWebArtifact {
                path: order_node.path.clone(),
                message: error.to_string(),
            }
        })?;
        if order_context.order_id != payment_order_id {
            return Err(claim_failed(format!(
                "{source_protocol} payment order mismatch"
            )));
        }
        if source_protocol == "acp-commerce" {
            let order_context_digest = payment
                .get("order_context_digest")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing acp-commerce order context digest"))?;
            if order_context_digest != chio_core_types::sha256_hex(order_bytes) {
                return Err(claim_failed("acp-commerce order context digest mismatch"));
            }
        }
        if source_protocol == "ap2" {
            let transaction_context_digest = payment
                .get("transaction_context_digest")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing ap2 transaction context digest"))?;
            if transaction_context_digest != chio_core_types::sha256_hex(order_bytes) {
                return Err(claim_failed("ap2 transaction context digest mismatch"));
            }
        }
        if matches!(source_protocol, "acp-commerce" | "x402") {
            let payment_amount = payment
                .get("amount_units")
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| claim_failed(format!("missing {source_protocol} amount")))?;
            if payment_amount != order_context.quote_amount_minor {
                return Err(claim_failed(format!(
                    "{source_protocol} payment amount mismatch"
                )));
            }
        }
        if source_protocol == "acp-commerce" {
            let payment_currency = payment
                .get("currency")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing acp-commerce currency"))?;
            if payment_currency != order_context.quote_currency {
                return Err(claim_failed("acp-commerce payment currency mismatch"));
            }
        }
        if source_protocol == "x402" {
            let payment_asset = payment
                .get("asset")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| claim_failed("missing x402 asset"))?;
            if !x402_asset_matches_quote_currency(payment_asset, &order_context.quote_currency) {
                return Err(claim_failed("x402 payment asset mismatch"));
            }
        }
        return Ok(());
    }

    Err(claim_failed(format!(
        "missing {source_protocol} order binding"
    )))
}

fn x402_asset_matches_quote_currency(asset: &str, quote_currency: &str) -> bool {
    match quote_currency {
        "USD" => matches!(asset, "USD" | "USDC"),
        _ => asset == quote_currency,
    }
}

fn validate_required_edge(
    graph: &evidence::AgentWebEvidenceGraph,
    from: &str,
    to: &str,
    predicate: &str,
    evidence_class: &str,
    message: &'static str,
) -> Result<(), TransactionPassportError> {
    if graph_has_edge(graph, from, to, predicate, evidence_class) {
        Ok(())
    } else {
        Err(claim_failed(message))
    }
}

fn validate_envelope_manifest_binding(
    envelope: &AgentWebProofEnvelope,
    manifest_entry: &ProjectionManifestEntry,
) -> Result<(), TransactionPassportError> {
    let manifest = &manifest_entry.manifest;
    if envelope.source_protocol != manifest.source_protocol
        || envelope.source_protocol_version != manifest.source_version
    {
        return Err(claim_failed("projection manifest protocol mismatch"));
    }
    if envelope.projection_manifest_sha256 != manifest_entry.node_sha256 {
        return Err(claim_failed("projection manifest digest mismatch"));
    }
    Ok(())
}

fn verify_claim_mapping(
    manifest: &ProjectionManifest,
    envelope_claims: &[String],
    verified_claims: &mut Vec<String>,
) -> Result<(), TransactionPassportError> {
    for mapping in &manifest.claim_mapping {
        if mapping.evidence_class == "native-external-proof"
            && manifest
                .unsupported_claims
                .iter()
                .any(|unsupported_claim| unsupported_claim == &mapping.claim_ref)
        {
            return Err(claim_failed(
                "unsupported external authority claim cannot be mapped as native external proof",
            ));
        }
    }

    for claim in envelope_claims {
        if is_agent_web_claim(claim) {
            continue;
        }
        if manifest
            .unsupported_claims
            .iter()
            .any(|unsupported_claim| unsupported_claim == claim)
        {
            continue;
        }
        return Err(claim_failed("unsupported claim was not limited"));
    }

    for required_claim in [
        CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
        CLAIM_PROJECTION_MANIFEST_BOUND,
        CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
        CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
    ] {
        if !envelope_claims.iter().any(|claim| claim == required_claim) {
            return Err(claim_failed(format!(
                "Agent Web envelope missing required claim: {required_claim}"
            )));
        }
        let mapping = manifest
            .claim_mapping
            .iter()
            .find(|mapping| mapping.claim_ref == required_claim)
            .ok_or_else(|| claim_failed(format!("missing claim mapping: {required_claim}")))?;
        if mapping.evidence_class == "native-external-proof" {
            return Err(claim_failed(
                "sidecar claim presented as native external proof",
            ));
        }
        push_claim_once(verified_claims, required_claim);
    }
    Ok(())
}

fn validate_required_unsupported_claims(
    manifest: &ProjectionManifest,
) -> Result<(), TransactionPassportError> {
    for required_claim in protocols::required_unsupported_claims(manifest.source_protocol.as_str())
    {
        if manifest
            .unsupported_claims
            .iter()
            .any(|unsupported_claim| unsupported_claim == required_claim)
        {
            continue;
        }
        return Err(claim_failed(format!(
            "missing Agent Web unsupported authority limitation: {required_claim}"
        )));
    }
    Ok(())
}

fn is_agent_web_claim(claim: &str) -> bool {
    matches!(
        claim,
        CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND
            | CLAIM_PROJECTION_MANIFEST_BOUND
            | CLAIM_UNSUPPORTED_CLAIMS_LIMITED
            | CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
    )
}

fn ensure_required_claims_verified(
    required_claims: &[String],
    verified_claims: &[String],
) -> Result<(), TransactionPassportError> {
    for required_claim in required_claims
        .iter()
        .filter(|claim| claim.starts_with("claim.agent_web."))
    {
        if !verified_claims
            .iter()
            .any(|verified_claim| verified_claim == required_claim)
        {
            return Err(claim_failed(format!(
                "required claim not verified: {required_claim}"
            )));
        }
    }
    Ok(())
}

fn reject_required_external_authority_claims(
    required_claims: &[String],
) -> Result<(), TransactionPassportError> {
    if let Some(required_claim) = required_claims
        .iter()
        .find(|claim| claim.starts_with("claim.external."))
    {
        return Err(claim_failed(format!(
            "Agent Web policy requires unsupported external claim: {required_claim}"
        )));
    }
    Ok(())
}

fn extend_unique(target: &mut Vec<String>, values: &[String]) {
    for value in values {
        if !target.iter().any(|existing| existing == value) {
            target.push(value.clone());
        }
    }
}

fn claim_failed(message: impl Into<String>) -> TransactionPassportError {
    TransactionPassportError::AgentWebClaimFailed(message.into())
}
