use super::{
    json_array_mut, read_json_value, required_json_string, sha256_file, write_json_line_file,
    CliError,
};
use chio_core_types::{
    receipt::body::{ChioReceipt, ChioReceiptBody},
    receipt::decision::ToolCallAction,
    Keypair,
};
use std::{collections::BTreeMap, ffi::OsStr, fs, path::Path};

pub(super) fn resign_agent_web_receipts_for_policy(
    bundle: &Path,
    policy_sha256: &str,
) -> Result<(), CliError> {
    let receipts_dir = bundle.join("receipts");
    if !receipts_dir.is_dir() {
        return Ok(());
    }
    let keypair = Keypair::from_seed(&[17u8; 32]);
    for entry in fs::read_dir(&receipts_dir)? {
        let entry = entry?;
        let receipt_path = entry.path();
        if receipt_path.extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let receipt: ChioReceipt = serde_json::from_slice(&fs::read(&receipt_path)?)?;
        let Some(receipt_ref) = receipt
            .metadata
            .as_ref()
            .and_then(|metadata| metadata.get("agent_web_receipt_ref"))
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let content_hash = agent_web_receipt_subject_path(receipt_ref)
            .map(|subject_path| bundle.join(subject_path))
            .filter(|subject_path| subject_path.is_file())
            .map(|subject_path| sha256_file(&subject_path))
            .transpose()?
            .unwrap_or_else(|| receipt.content_hash.clone());
        let action = ToolCallAction::from_parameters(serde_json::json!({
            "agent_web_receipt_ref": receipt_ref,
            "content_hash": content_hash
        }))
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "proof fixture Agent Web receipt action hashing failed: {}: {error}",
                receipt_path.display()
            ))
        })?;
        let body = ChioReceiptBody {
            id: receipt_ref.to_string(),
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
    Ok(())
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
) -> Result<(), CliError> {
    let keypair = Keypair::from_seed(&[17u8; 32]);
    let public_key = keypair.public_key().to_hex();
    let projection_manifest_paths = agent_web_projection_manifest_paths(bundle, evidence_graph)?;
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
        envelope["external_subject_digest"] =
            serde_json::Value::String(sha256_file(&bundle.join(subject_path))?);
        let manifest_ref = required_json_string(&envelope, "projection_manifest_ref", &envelope_path)?;
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
        sign_agent_web_envelope_value(&mut envelope, &keypair, &public_key)?;
        write_json_line_file(&envelope_path, &envelope)?;
        node["sha256"] = serde_json::Value::String(sha256_file(&envelope_path)?);
    }
    Ok(())
}

fn agent_web_projection_manifest_paths(
    bundle: &Path,
    evidence_graph: &serde_json::Value,
) -> Result<BTreeMap<String, String>, CliError> {
    let mut manifests = BTreeMap::new();
    let Some(nodes) = evidence_graph.get("nodes").and_then(serde_json::Value::as_array) else {
        return Ok(manifests);
    };
    for node in nodes {
        if node.get("role").and_then(serde_json::Value::as_str)
            != Some("external-projection-manifest")
        {
            continue;
        }
        let Some(path) = node.get("path").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let manifest_path = bundle.join(path);
        let manifest = read_json_value(&manifest_path)?;
        let projection_id = required_json_string(&manifest, "projection_id", &manifest_path)?;
        manifests.insert(projection_id.to_string(), path.to_string());
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
