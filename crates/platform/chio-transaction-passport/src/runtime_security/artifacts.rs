use std::collections::BTreeSet;

use chio_core_types::crypto::{PublicKey, Signature};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::super::error::TransactionPassportError;
use super::super::ids::RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID;
use super::super::validation::validate_sha256_hex;
use super::evidence::{parse_artifact, RuntimeEvidenceGraph, RuntimeEvidenceRole};
use super::RuntimeSecurityBundle;

const DID_CHIO_PREFIX: &str = "did:chio:";
const RUNTIME_REVOCATION_FRESHNESS_PROOF_SIGNATURE_SCHEMA: &str =
    "chio.runtime.revocation-freshness-proof-signature.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeExecutionLease {
    schema: String,
    pub(super) lease_id: String,
    tool_server_id: String,
    tool_instance_id: String,
    tool_manifest_digest: String,
    pub(super) sandbox_attestation_ref: String,
    request_digest: String,
    pub(super) revocation_freshness_ref: String,
    policy_digest: String,
    pub(super) nonce: String,
    side_effect_class: String,
    issued_at: String,
    expires_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeRevocationFreshnessProof {
    schema: String,
    pub(super) proof_id: String,
    oracle_id: String,
    epoch_id: String,
    epoch_root: String,
    sequence: u64,
    fetched_at: String,
    max_staleness_ms: u64,
    revoked_leaf_result: bool,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeSandboxAttestation {
    schema: String,
    pub(super) attestation_id: String,
    tool_server_id: String,
    tool_instance_id: String,
    tool_manifest_digest: String,
    sandbox_profile_digest: String,
    egress_policy_digest: String,
    started_at: String,
    expires_at: String,
    attester: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeToolServerAck {
    schema: String,
    ack_id: String,
    pub(super) lease_id: String,
    tool_server_id: String,
    tool_instance_id: String,
    sandbox_attestation_ref: String,
    nonce: String,
    terminal_status: String,
    issued_at: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeTerminalReceipt {
    schema: String,
    receipt_id: String,
    pub(super) terminal_status: String,
    policy_digest: String,
    #[serde(default)]
    pub(super) execution_lease_ref: Option<String>,
    #[serde(default)]
    incident_ref: Option<String>,
}

pub(super) fn validate_execution_lease(
    lease: &RuntimeExecutionLease,
    policy_digest: &str,
) -> Result<(), TransactionPassportError> {
    for (field, value) in [
        ("schema", &lease.schema),
        ("lease_id", &lease.lease_id),
        ("tool_server_id", &lease.tool_server_id),
        ("tool_instance_id", &lease.tool_instance_id),
        ("sandbox_attestation_ref", &lease.sandbox_attestation_ref),
        ("revocation_freshness_ref", &lease.revocation_freshness_ref),
        ("nonce", &lease.nonce),
        ("side_effect_class", &lease.side_effect_class),
        ("issued_at", &lease.issued_at),
        ("expires_at", &lease.expires_at),
    ] {
        require_non_empty(value, field)?;
    }
    for (field, digest) in [
        ("tool_manifest_digest", &lease.tool_manifest_digest),
        ("request_digest", &lease.request_digest),
        ("policy_digest", &lease.policy_digest),
    ] {
        validate_digest_field(field, digest)?;
    }
    if lease.policy_digest != policy_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "policy digest mismatch".to_string(),
        ));
    }
    if !is_governed_side_effect_class(&lease.side_effect_class) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease side effect class is not governed".to_string(),
        ));
    }
    let issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    if expires_at <= issued_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "execution lease expired before issuance".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_revocation_freshness(
    lease: &RuntimeExecutionLease,
    proof: &RuntimeRevocationFreshnessProof,
) -> Result<(), TransactionPassportError> {
    if proof.proof_id != lease.revocation_freshness_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness proof mismatch".to_string(),
        ));
    }
    require_non_empty(&proof.schema, "revocation freshness proof schema")?;
    require_non_empty(&proof.oracle_id, "oracle_id")?;
    require_non_empty(&proof.epoch_id, "epoch_id")?;
    require_non_empty(&proof.fetched_at, "fetched_at")?;
    require_non_empty(&proof.signature, "signature")?;
    validate_digest_field("epoch_root", &proof.epoch_root)?;
    if proof.sequence == 0 || proof.max_staleness_ms == 0 || proof.revoked_leaf_result {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness failed".to_string(),
        ));
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let fetched_at = parse_rfc3339_utc(&proof.fetched_at, "revocation fetched_at")?;
    if fetched_at > lease_issued_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness fetched after lease issuance".to_string(),
        ));
    }
    let freshness_age_ms = lease_issued_at
        .signed_duration_since(fetched_at)
        .num_milliseconds();
    let freshness_age_ms = u64::try_from(freshness_age_ms).map_err(|_| {
        TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness age overflow".to_string(),
        )
    })?;
    if freshness_age_ms > proof.max_staleness_ms {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness stale".to_string(),
        ));
    }
    verify_revocation_freshness_signature(proof)?;
    Ok(())
}

fn verify_revocation_freshness_signature(
    proof: &RuntimeRevocationFreshnessProof,
) -> Result<(), TransactionPassportError> {
    let public_key = revocation_oracle_public_key(&proof.oracle_id)?;
    let signature = Signature::from_hex(&proof.signature).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "revocation freshness signature invalid: {error}"
        ))
    })?;
    let verified = public_key
        .verify_canonical(&revocation_freshness_signature_body(proof), &signature)
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "revocation freshness signature invalid: {error}"
            ))
        })?;
    if verified {
        Ok(())
    } else {
        Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "revocation freshness signature invalid".to_string(),
        ))
    }
}

fn revocation_oracle_public_key(oracle_id: &str) -> Result<PublicKey, TransactionPassportError> {
    let public_key_hex = if let Some(public_key_hex) = oracle_id.strip_prefix(DID_CHIO_PREFIX) {
        if public_key_hex.len() != 64 || !public_key_hex.bytes().all(is_lower_hex_byte) {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "revocation freshness oracle id is not self-certifying".to_string(),
            ));
        }
        public_key_hex
    } else {
        oracle_id
    };
    PublicKey::from_hex(public_key_hex).map_err(|error| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!(
            "revocation freshness oracle public key invalid: {error}"
        ))
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeRevocationFreshnessSignatureBody<'a> {
    schema: &'static str,
    proof_id: &'a str,
    oracle_id: &'a str,
    epoch_id: &'a str,
    epoch_root: &'a str,
    sequence: u64,
    fetched_at: &'a str,
    max_staleness_ms: u64,
    revoked_leaf_result: bool,
}

fn revocation_freshness_signature_body(
    proof: &RuntimeRevocationFreshnessProof,
) -> RuntimeRevocationFreshnessSignatureBody<'_> {
    RuntimeRevocationFreshnessSignatureBody {
        schema: RUNTIME_REVOCATION_FRESHNESS_PROOF_SIGNATURE_SCHEMA,
        proof_id: &proof.proof_id,
        oracle_id: &proof.oracle_id,
        epoch_id: &proof.epoch_id,
        epoch_root: &proof.epoch_root,
        sequence: proof.sequence,
        fetched_at: &proof.fetched_at,
        max_staleness_ms: proof.max_staleness_ms,
        revoked_leaf_result: proof.revoked_leaf_result,
    }
}

pub(super) fn validate_sandbox_attestation(
    lease: &RuntimeExecutionLease,
    sandbox: &RuntimeSandboxAttestation,
) -> Result<(), TransactionPassportError> {
    if sandbox.attestation_id != lease.sandbox_attestation_ref {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation mismatch".to_string(),
        ));
    }
    if sandbox.tool_server_id != lease.tool_server_id
        || sandbox.tool_instance_id != lease.tool_instance_id
        || sandbox.tool_manifest_digest != lease.tool_manifest_digest
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox tool binding mismatch".to_string(),
        ));
    }
    require_non_empty(&sandbox.schema, "sandbox attestation schema")?;
    for (field, value) in [
        ("sandbox_profile_digest", &sandbox.sandbox_profile_digest),
        ("egress_policy_digest", &sandbox.egress_policy_digest),
    ] {
        validate_digest_field(field, value)?;
    }
    for (field, value) in [
        ("started_at", &sandbox.started_at),
        ("expires_at", &sandbox.expires_at),
        ("attester", &sandbox.attester),
        ("signature", &sandbox.signature),
    ] {
        require_non_empty(value, field)?;
    }
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let sandbox_started_at = parse_rfc3339_utc(&sandbox.started_at, "sandbox started_at")?;
    let sandbox_expires_at = parse_rfc3339_utc(&sandbox.expires_at, "sandbox expires_at")?;
    if sandbox_expires_at <= sandbox_started_at
        || sandbox_started_at > lease_issued_at
        || sandbox_expires_at < lease_expires_at
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "sandbox attestation not valid for execution lease".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_tool_server_ack(
    lease: &RuntimeExecutionLease,
    sandbox: &RuntimeSandboxAttestation,
    ack: &RuntimeToolServerAck,
) -> Result<(), TransactionPassportError> {
    if ack.lease_id != lease.lease_id
        || ack.tool_server_id != lease.tool_server_id
        || ack.tool_instance_id != lease.tool_instance_id
        || ack.sandbox_attestation_ref != sandbox.attestation_id
        || ack.nonce != lease.nonce
    {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement mismatch".to_string(),
        ));
    }
    if ack.terminal_status != "allowed_executed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "tool-server acknowledgement did not execute".to_string(),
        ));
    }
    require_non_empty(&ack.schema, "tool-server acknowledgement schema")?;
    require_non_empty(&ack.ack_id, "ack_id")?;
    require_non_empty(&ack.issued_at, "issued_at")?;
    require_non_empty(&ack.signature, "signature")?;
    let lease_issued_at = parse_rfc3339_utc(&lease.issued_at, "execution lease issued_at")?;
    let lease_expires_at = parse_rfc3339_utc(&lease.expires_at, "execution lease expires_at")?;
    let ack_issued_at = parse_rfc3339_utc(&ack.issued_at, "tool-server acknowledgement issued_at")?;
    if ack_issued_at < lease_issued_at || ack_issued_at > lease_expires_at {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "acknowledgement outside execution lease".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_nonce_uniqueness(
    bundle: &RuntimeSecurityBundle,
    graph: &RuntimeEvidenceGraph,
) -> Result<(), TransactionPassportError> {
    let mut consumed_nonces = BTreeSet::new();
    for ack_node in graph
        .nodes
        .iter()
        .filter(|node| node.role == RuntimeEvidenceRole::ToolServerAck)
    {
        let ack: RuntimeToolServerAck =
            parse_artifact(bundle, ack_node, RUNTIME_TOOL_SERVER_ACK_SCHEMA_ID)?;
        let nonce_key = (ack.lease_id, ack.nonce);
        if !consumed_nonces.insert(nonce_key) {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "reused nonce".to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_allow_receipt(
    lease: &RuntimeExecutionLease,
    receipt: &RuntimeTerminalReceipt,
) -> Result<(), TransactionPassportError> {
    validate_terminal_receipt(receipt, &lease.policy_digest)?;
    if receipt.terminal_status != "allowed_executed" {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "receipt totality failed".to_string(),
        ));
    }
    if receipt.execution_lease_ref.as_deref() != Some(lease.lease_id.as_str()) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "receipt totality failed".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn validate_terminal_receipt(
    receipt: &RuntimeTerminalReceipt,
    policy_digest: &str,
) -> Result<(), TransactionPassportError> {
    require_non_empty(&receipt.schema, "receipt schema")?;
    require_non_empty(&receipt.receipt_id, "receipt_id")?;
    require_non_empty(&receipt.terminal_status, "terminal_status")?;
    validate_digest_field("policy_digest", &receipt.policy_digest)?;
    if receipt.policy_digest != policy_digest {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            "terminal receipt policy digest mismatch".to_string(),
        ));
    }
    if !is_terminal_receipt_status(&receipt.terminal_status) {
        return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
            format!(
                "unsupported terminal receipt status: {}",
                receipt.terminal_status
            ),
        ));
    }
    if receipt.terminal_status == "allowed_executed" {
        let Some(execution_lease_ref) = receipt.execution_lease_ref.as_deref() else {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "allowed terminal receipt missing execution lease".to_string(),
            ));
        };
        require_non_empty(execution_lease_ref, "execution_lease_ref")?;
    }
    if receipt.terminal_status.starts_with("failed_") {
        let Some(incident_ref) = receipt.incident_ref.as_deref() else {
            return Err(TransactionPassportError::RuntimeSecurityClaimFailed(
                "failed terminal receipt missing incident".to_string(),
            ));
        };
        require_non_empty(incident_ref, "incident_ref")?;
    }
    Ok(())
}

fn is_terminal_receipt_status(status: &str) -> bool {
    matches!(
        status,
        "allowed_executed"
            | "allowed_tool_rejected"
            | "denied_pre_dispatch"
            | "denied_guard_request"
            | "denied_guard_response"
            | "denied_revocation_stale"
            | "denied_policy_reload_conflict"
            | "denied_missing_execution_lease"
            | "denied_sandbox_attestation_mismatch"
            | "failed_receipt_log_unavailable"
            | "failed_tool_unreachable"
            | "failed_timeout_before_tool_entry"
            | "failed_timeout_after_tool_entry"
    )
}

fn is_governed_side_effect_class(side_effect_class: &str) -> bool {
    matches!(
        side_effect_class,
        "network-write" | "filesystem-write" | "process-spawn" | "state-write"
    )
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn parse_rfc3339_utc(
    value: &str,
    field: &'static str,
) -> Result<DateTime<Utc>, TransactionPassportError> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| {
            TransactionPassportError::RuntimeSecurityClaimFailed(format!(
                "invalid {field}: {error}"
            ))
        })
}

fn validate_digest_field(
    field: &'static str,
    digest: &str,
) -> Result<(), TransactionPassportError> {
    validate_sha256_hex(digest).map_err(|_| {
        TransactionPassportError::RuntimeSecurityClaimFailed(format!("invalid {field}: {digest}"))
    })
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
