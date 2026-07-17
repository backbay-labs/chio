use super::{
    json_array_mut, read_json_value, required_json_string, sha256_file, write_json_line_file,
    CliError,
};
use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    receipt::decision::ToolCallAction,
    Keypair,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::Path,
};

const AGENT_WEB_RECEIPT_KERNEL_SIGNATURE_SEED: [u8; 32] = [18; 32];
const AGENT_WEB_SIDECAR_SIGNATURE_SEED: [u8; 32] = [17; 32];

#[derive(Clone)]
struct AgentWebReceiptIntent {
    passport_scope_sha256: String,
    envelope_id: String,
    projection_manifest_sha256: String,
    source_protocol: String,
    source_protocol_version: String,
}

pub(super) fn resign_agent_web_receipts_for_policy(
    bundle: &Path,
    policy_sha256: &str,
) -> Result<(), CliError> {
    let receipt_intents = agent_web_receipt_intents(bundle)?;
    if receipt_intents.is_empty() {
        return Ok(());
    }
    let receipts_dir = bundle.join("receipts");
    if !receipts_dir.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "proof fixture Agent Web receipts directory missing: {}",
            receipts_dir.display()
        )));
    }
    let passport_path = bundle.join("transaction-passport.json");
    let passport = read_json_value(&passport_path)?;
    let passport_id = required_json_string(&passport, "id", &passport_path)?.to_string();
    let passport_issuer = required_json_string(&passport, "issuer", &passport_path)?.to_string();
    let keypair = Keypair::from_seed(&AGENT_WEB_RECEIPT_KERNEL_SIGNATURE_SEED);
    let mut normalized_refs = BTreeSet::new();
    for entry in fs::read_dir(&receipts_dir)? {
        let entry = entry?;
        let receipt_path = entry.path();
        if receipt_path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let receipt: ChioReceipt = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        let receipt_ref = receipt
            .action
            .parameters
            .get("agent_web_receipt_ref")
            .or_else(|| {
                receipt
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            })
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let path_stem = receipt_path
            .file_stem()
            .and_then(OsStr::to_str)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture Agent Web receipt path has no UTF-8 stem: {}",
                    receipt_path.display()
                ))
            })?;
        let Some(receipt_ref) = receipt_ref else {
            if receipt_intents.contains_key(path_stem) {
                return Err(CliError::cli_other_error(format!(
                    "proof fixture Agent Web receipt ref missing: {}",
                    receipt_path.display()
                )));
            }
            continue;
        };
        validate_agent_web_receipt_ref_path(&receipt_path, path_stem, &receipt_ref)?;
        let Some(intent) = receipt_intents.get(&receipt_ref) else {
            if receipt_ref.starts_with("receipt-agent-web-")
                && !is_intentional_unbound_receipt_fixture(bundle)
            {
                return Err(CliError::cli_other_error(format!(
                    "proof fixture Agent Web receipt has no envelope intent: {}: {receipt_ref}",
                    receipt_path.display()
                )));
            }
            continue;
        };
        if !normalized_refs.insert(receipt_ref.clone()) {
            return Err(CliError::cli_other_error(format!(
                "proof fixture Agent Web receipt ref is duplicated: {receipt_ref}"
            )));
        }
        let content_hash = agent_web_receipt_subject_path(&receipt_ref)
            .map(|subject_path| bundle.join(subject_path))
            .filter(|subject_path| subject_path.is_file())
            .map(|subject_path| sha256_file(&subject_path))
            .transpose()?
            .unwrap_or_else(|| receipt.content_hash.clone());
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "agent_web_receipt_ref": receipt_ref,
            "content_hash": content_hash,
            "transaction_passport_id": passport_id,
            "transaction_passport_issuer": passport_issuer,
            "agent_web_passport_scope_sha256": intent.passport_scope_sha256,
            "agent_web_envelope_id": intent.envelope_id,
            "projection_manifest_sha256": intent.projection_manifest_sha256,
            "source_protocol": intent.source_protocol,
            "source_protocol_version": intent.source_protocol_version
        }))
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture Agent Web receipt action hashing failed: {}: {error}",
                receipt_path.display()
            ))
        })?;
        let body = ChioReceiptBody {
            id: receipt_ref,
            timestamp: receipt.timestamp,
            capability_id: receipt.capability_id,
            tool_server: receipt.tool_server,
            tool_name: receipt.tool_name,
            action,
            decision: receipt.decision,
            receipt_kind: receipt.receipt_kind,
            boundary_class: receipt.boundary_class,
            observation_outcome: receipt.observation_outcome,
            tool_origin: receipt.tool_origin,
            redaction_mode: receipt.redaction_mode,
            actor_chain: receipt.actor_chain,
            content_hash,
            policy_hash: policy_sha256.to_string(),
            evidence: receipt.evidence,
            metadata: receipt.metadata,
            trust_level: receipt.trust_level,
            tenant_id: receipt.tenant_id,
            kernel_key: keypair.public_key(),
            bbs_projection_version: receipt.bbs_projection_version,
        };
        let signed_receipt = ChioReceipt::sign(body, &keypair).map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture Agent Web receipt signing failed: {}: {error}",
                receipt_path.display()
            ))
        })?;
        write_json_line_file(&receipt_path, &signed_receipt)?;
    }
    if !is_intentional_unbound_receipt_fixture(bundle) {
        if let Some(missing_ref) = receipt_intents
            .keys()
            .find(|receipt_ref| !normalized_refs.contains(*receipt_ref))
        {
            return Err(CliError::cli_other_error(format!(
                "proof fixture Agent Web envelope receipt was not normalized: {missing_ref}"
            )));
        }
    }
    Ok(())
}

fn validate_agent_web_receipt_ref_path(
    receipt_path: &Path,
    path_stem: &str,
    receipt_ref: &str,
) -> Result<(), CliError> {
    if receipt_ref != path_stem {
        return Err(CliError::cli_other_error(format!(
            "proof fixture Agent Web receipt ref does not match its canonical path stem: {}: {receipt_ref}",
            receipt_path.display()
        )));
    }
    Ok(())
}

fn is_intentional_unbound_receipt_fixture(bundle: &Path) -> bool {
    bundle
        .components()
        .any(|component| component.as_os_str().to_str() == Some("agent-web-vc-unbound-receipt"))
}

fn agent_web_receipt_intents(
    bundle: &Path,
) -> Result<BTreeMap<String, AgentWebReceiptIntent>, CliError> {
    let passport_scope_sha256 = agent_web_passport_scope_sha256(bundle)?;
    let mut intents = BTreeMap::new();
    for entry in fs::read_dir(bundle)? {
        let entry = entry?;
        let envelope_path = entry.path();
        if envelope_path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let envelope = read_json_value(&envelope_path)?;
        if envelope.get("schema").and_then(serde_json::Value::as_str)
            != Some("chio.agent-web-proof-envelope.v2")
        {
            continue;
        }
        let intent = AgentWebReceiptIntent {
            passport_scope_sha256: passport_scope_sha256.clone(),
            envelope_id: required_json_string(&envelope, "envelope_id", &envelope_path)?
                .to_string(),
            projection_manifest_sha256: required_json_string(
                &envelope,
                "projection_manifest_sha256",
                &envelope_path,
            )?
            .to_string(),
            source_protocol: required_json_string(&envelope, "source_protocol", &envelope_path)?
                .to_string(),
            source_protocol_version: required_json_string(
                &envelope,
                "source_protocol_version",
                &envelope_path,
            )?
            .to_string(),
        };
        let receipt_refs = envelope
            .get("receipt_refs")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture Agent Web envelope receipt refs missing: {}",
                    envelope_path.display()
                ))
            })?;
        for receipt_ref in receipt_refs {
            let receipt_ref = receipt_ref.as_str().ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture Agent Web envelope receipt ref is not a string: {}",
                    envelope_path.display()
                ))
            })?;
            if intents
                .insert(receipt_ref.to_string(), intent.clone())
                .is_some()
            {
                return Err(CliError::cli_other_error(format!(
                    "proof fixture Agent Web receipt resolves to multiple envelopes: {receipt_ref}"
                )));
            }
        }
    }
    Ok(intents)
}

pub(super) fn normalize_agent_web_bilateral_in_toto_statement(
    bundle: &Path,
) -> Result<(), CliError> {
    let statement_path = bundle.join("external/in-toto-statement.json");
    if !statement_path.is_file() {
        return Ok(());
    }
    let mut statement = read_json_value(&statement_path)?;
    let object = statement.as_object_mut().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "proof fixture in-toto statement is not an object: {}",
            statement_path.display()
        ))
    })?;
    object.insert(
        "predicate_type".to_string(),
        serde_json::Value::String("chio.bilateral-cosign-invocation.v1".to_string()),
    );
    object.insert(
        "peer_pin_digest".to_string(),
        serde_json::Value::String("a8".repeat(32)),
    );
    object.insert(
        "policy_summary_digest".to_string(),
        serde_json::Value::String("a9".repeat(32)),
    );
    object.insert(
        "capability_lease_ref".to_string(),
        serde_json::Value::String("lease-agent-web-in-toto-bilateral".to_string()),
    );
    write_json_line_file(&statement_path, &statement)
}

pub(super) fn refresh_agent_web_envelopes_for_subjects(
    bundle: &Path,
    evidence_graph: &mut serde_json::Value,
    preserve_standard_webhooks_digest_mismatch: bool,
) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&AGENT_WEB_SIDECAR_SIGNATURE_SEED);
    let public_key = keypair.public_key().to_hex();
    let passport_scope_sha256 = agent_web_passport_scope_sha256(bundle)?;
    let projection_manifest_paths = agent_web_projection_manifest_paths(bundle, evidence_graph)?;
    let openapi_subject_path = bundle.join("external/openapi-operation.json");
    if openapi_subject_path.is_file() {
        let mut subject = read_json_value(&openapi_subject_path)?;
        subject["x_chio_proof_envelope_profile"] =
            serde_json::Value::String("chio.agent-web-proof-envelope.v2".to_string());
        write_json_line_file(&openapi_subject_path, &subject)?;
    }
    let mut envelope_ids = BTreeSet::new();
    for node in json_array_mut(evidence_graph, "nodes", &bundle.join("evidence-graph.json"))? {
        if node.get("role").and_then(serde_json::Value::as_str) != Some("agent-web-proof-envelope")
        {
            continue;
        }
        let path = node
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture Agent Web envelope path missing: {}",
                    bundle.display()
                ))
            })?
            .to_string();
        let envelope_path = bundle.join(&path);
        let mut envelope = read_json_value(&envelope_path)?;
        let subject_path =
            required_json_string(&envelope, "external_subject_path", &envelope_path)?;
        if !preserve_standard_webhooks_digest_mismatch
            || envelope
                .get("source_protocol")
                .and_then(serde_json::Value::as_str)
                != Some("standard-webhooks")
        {
            envelope["external_subject_digest"] =
                serde_json::Value::String(sha256_file(&bundle.join(subject_path))?);
        }
        let manifest_ref =
            required_json_string(&envelope, "projection_manifest_ref", &envelope_path)?;
        let manifest_path = projection_manifest_paths
            .get(&manifest_ref)
            .map(String::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture Agent Web projection manifest missing for ref: {manifest_ref}"
                ))
            })?;
        envelope["projection_manifest_sha256"] =
            serde_json::Value::String(sha256_file(&bundle.join(manifest_path))?);
        envelope["schema"] =
            serde_json::Value::String("chio.agent-web-proof-envelope.v2".to_string());
        envelope["agent_web_passport_scope_sha256"] =
            serde_json::Value::String(passport_scope_sha256.clone());
        sign_agent_web_envelope_value(&mut envelope, &keypair, &public_key)?;
        let envelope_id = required_json_string(&envelope, "envelope_id", &envelope_path)?;
        if !envelope_ids.insert(envelope_id.clone()) {
            return Err(CliError::cli_other_error(format!(
                "proof fixture Agent Web envelope id is duplicated: {envelope_id}"
            )));
        }
        write_json_line_file(&envelope_path, &envelope)?;
        node["schema"] = serde_json::Value::String("chio.agent-web-proof-envelope.v2".to_string());
        node["sha256"] = serde_json::Value::String(sha256_file(&envelope_path)?);
    }
    Ok(())
}

fn agent_web_projection_manifest_paths(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
) -> Result<BTreeMap<String, String>, CliError> {
    let mut manifests = BTreeMap::new();
    let Some(nodes) = evidence_graph
        .get("nodes")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(manifests);
    };
    for node in nodes {
        if node.get("role").and_then(serde_json::Value::as_str)
            != Some("external-projection-manifest")
        {
            continue;
        }
        let path = node
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error(format!(
                    "proof fixture Agent Web projection manifest node path missing: {}",
                    bundle.display()
                ))
            })?;
        let manifest_path = bundle.join(path);
        let manifest = read_json_value(&manifest_path)?;
        let projection_id = required_json_string(&manifest, "projection_id", &manifest_path)?;
        if manifests
            .insert(projection_id.to_string(), path.to_string())
            .is_some()
        {
            return Err(CliError::cli_other_error(format!(
                "proof fixture Agent Web projection id is duplicated: {projection_id}"
            )));
        }
    }
    Ok(manifests)
}

fn sign_agent_web_envelope_value(
    envelope: &mut serde_json::Value,
    keypair: &Keypair,
    public_key: &str,
) -> Result<(), CliError> {
    envelope["envelope_id"] = serde_json::Value::String(agent_web_envelope_id(envelope)?);
    let payload = agent_web_envelope_signature_payload(envelope)?;
    let canonical = chio_core_types::canonical_json_bytes(&payload).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture Agent Web envelope signing failed: {error}"
        ))
    })?;
    let signature = keypair.sign(&canonical).to_hex();
    envelope["signature"] =
        serde_json::Value::String(format!("sig-ed25519:{public_key}:{signature}"));
    Ok(())
}

fn agent_web_envelope_id(envelope: &serde_json::Value) -> Result<String, CliError> {
    let payload = agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "transaction_passport_ref",
            "agent_web_passport_scope_sha256",
            "source_protocol",
            "source_protocol_version",
            "external_subject",
            "external_subject_path",
            "external_subject_digest",
            "external_subject_signature_ref",
            "projection_manifest_ref",
            "projection_manifest_sha256",
            "chio_claim_refs",
            "receipt_refs",
            "disclosure_capsule_refs",
            "settlement_refs",
            "risk_refs",
            "limitations",
        ],
    )?;
    let canonical = chio_core_types::canonical_json_bytes(&payload).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture Agent Web envelope id failed: {error}"
        ))
    })?;
    Ok(chio_core_types::sha256_hex(&canonical))
}

fn agent_web_envelope_signature_payload(
    envelope: &serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    agent_web_envelope_payload(
        envelope,
        &[
            "schema",
            "envelope_id",
            "transaction_passport_ref",
            "agent_web_passport_scope_sha256",
            "source_protocol",
            "source_protocol_version",
            "external_subject",
            "external_subject_path",
            "external_subject_digest",
            "external_subject_signature_ref",
            "projection_manifest_ref",
            "projection_manifest_sha256",
            "chio_claim_refs",
            "receipt_refs",
            "disclosure_capsule_refs",
            "settlement_refs",
            "risk_refs",
            "limitations",
        ],
    )
}

fn agent_web_passport_scope_sha256(bundle: &Path) -> Result<String, CliError> {
    let passport_path = bundle.join("transaction-passport.json");
    let passport: chio_control_plane::transaction_passport::TransactionPassport =
        serde_json::from_value(read_json_value(&passport_path)?)?;
    chio_control_plane::agent_web::agent_web_passport_scope_sha256(&passport).map_err(|error| {
        CliError::cli_other_error(format!(
            "proof fixture Agent Web passport scope digest failed: {}: {error}",
            passport_path.display()
        ))
    })
}

fn agent_web_envelope_payload(
    envelope: &serde_json::Value,
    fields: &[&str],
) -> Result<serde_json::Value, CliError> {
    let object = envelope.as_object().ok_or_else(|| {
        CliError::cli_other_error("proof fixture Agent Web envelope is not an object")
    })?;
    let mut payload = serde_json::Map::new();
    for field in fields {
        let value = object.get(*field).ok_or_else(|| {
            CliError::cli_other_error(format!(
                "proof fixture Agent Web envelope missing field: {field}"
            ))
        })?;
        payload.insert((*field).to_string(), value.clone());
    }
    Ok(serde_json::Value::Object(payload))
}

fn agent_web_receipt_subject_path(receipt_id: &str) -> Option<&'static str> {
    Some(match receipt_id {
        "receipt-agent-web-webhook-allow" => "external/webhook-delivery.json",
        "receipt-agent-web-cloudevents-allow" => "external/cloudevent.json",
        "receipt-agent-web-graphql-mutation-allow" => "external/graphql-operation.json",
        "receipt-agent-web-mcp-tool-call-allow" => "external/mcp-tool-call.json",
        "receipt-agent-web-a2a-task-allow" => "external/a2a-task.json",
        "receipt-agent-web-openapi-operation-allow" => "external/openapi-operation.json",
        "receipt-agent-web-acp-client-permission-allow" => "external/acp-client-permission.json",
        "receipt-agent-web-acp-commerce-checkout-allow" => "external/acp-commerce-checkout.json",
        "receipt-agent-web-ag-ui-event-allow" => "external/ag-ui-event.json",
        "receipt-agent-web-browser-command-allow" => "external/browser-command.json",
        "receipt-agent-web-rpa-transcript-allow" => "external/rpa-transcript.json",
        "receipt-agent-web-email-message-allow" => "external/email-message.json",
        "receipt-agent-web-calendar-event-allow" => "external/calendar-event.json",
        "receipt-agent-web-slack-message-allow" => "external/slack-message.json",
        "receipt-agent-web-oauth2-authorization-allow" => "external/oauth2-authorization.json",
        "receipt-agent-web-openid-connect-identity-allow" => {
            "external/openid-connect-identity.json"
        }
        "receipt-agent-web-scim-lifecycle-allow" => "external/scim-lifecycle.json",
        "receipt-agent-web-spiffe-workload-allow" => "external/spiffe-workload-identity.json",
        "receipt-agent-web-kubernetes-admission-allow" => {
            "external/kubernetes-admission-review.json"
        }
        "receipt-agent-web-oci-ref-allow" => "external/oci-ref.json",
        "receipt-agent-web-vc-allow" => "external/verifiable-credential.json",
        "receipt-agent-web-sd-jwt-vc-presentation-allow" => "external/sd-jwt-vc-presentation.json",
        "receipt-agent-web-bbs-disclosure-allow" => "external/bbs-receipt-disclosure.json",
        "receipt-agent-web-sigstore-bundle-allow" => "external/sigstore-bundle.json",
        "receipt-agent-web-in-toto-statement-allow" => "external/in-toto-statement.json",
        "receipt-agent-web-dsse-envelope-allow" => "external/dsse-envelope.json",
        "receipt-agent-web-slsa-provenance-allow" => "external/slsa-provenance.json",
        "receipt-agent-web-asyncapi-message-allow" => "external/asyncapi-message.json",
        "receipt-agent-web-ap2-mandate-allow" => "external/ap2-mandate-chain.json",
        "receipt-agent-web-x402-payment-allow" => "external/x402-payment.json",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_test_support::prelude::*;

    #[test]
    fn receipt_ref_must_match_canonical_file_stem() {
        let receipt_path = Path::new("receipts/receipt-agent-web-cloudevents-allow.json");
        let error = validate_agent_web_receipt_ref_path(
            receipt_path,
            "receipt-agent-web-cloudevents-allow",
            "receipt-agent-web-webhook-allow",
        )
        .test_expect_err("a receipt swap must be rejected");

        assert!(error
            .to_string()
            .contains("receipt ref does not match its canonical path stem"));
    }
}
