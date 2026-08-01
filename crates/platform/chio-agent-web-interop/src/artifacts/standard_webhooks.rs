use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_transaction_passport::TransactionPassportError;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::super::evidence::validate_sha256_hex;
use super::super::{
    validate_standard_webhook_id, AgentWebReplayEntry, AgentWebReplayScope, AgentWebVerifierTrust,
};
use super::{claim_failed, required_json_str};

type HmacSha256 = Hmac<Sha256>;

pub(super) fn validate_subject(
    value: &serde_json::Value,
    envelope_signature_ref: &str,
    trust: &AgentWebVerifierTrust,
) -> Result<AgentWebReplayEntry, TransactionPassportError> {
    let webhook_id = required_json_str(value, "webhook_id", "missing Standard Webhooks id")?;
    let webhook_timestamp = required_json_str(
        value,
        "webhook_timestamp",
        "missing Standard Webhooks timestamp",
    )?;
    let webhook_signature = required_json_str(
        value,
        "webhook_signature",
        "missing Standard Webhooks signature",
    )?;
    let body_digest = required_json_str(value, "body_digest", "missing Standard Webhooks body")?;
    let endpoint_url_digest = required_json_str(
        value,
        "endpoint_url_digest",
        "missing Standard Webhooks endpoint digest",
    )?;
    for digest_value in [endpoint_url_digest, body_digest] {
        validate_sha256_hex(digest_value).map_err(|_| {
            claim_failed(format!("invalid Standard Webhooks digest: {digest_value}"))
        })?;
    }
    if webhook_timestamp.is_empty() || webhook_signature.is_empty() {
        return Err(claim_failed("missing Standard Webhooks field"));
    }
    validate_standard_webhook_id(webhook_id).map_err(claim_failed)?;
    let expires_at_unix_seconds = validate_replay_window(webhook_timestamp, trust)?;
    validate_signature_ref(webhook_signature)?;
    validate_signature_ref(envelope_signature_ref)?;
    if webhook_signature != envelope_signature_ref {
        return Err(claim_failed("external signature mismatch"));
    }
    let verifier_secret = trust
        .standard_webhooks_secret(webhook_id)
        .ok_or_else(|| claim_failed("missing Standard Webhooks verifier secret"))?;
    verify_signature_ref(
        webhook_signature,
        verifier_secret,
        webhook_id,
        webhook_timestamp,
        body_digest,
        endpoint_url_digest,
    )?;
    let replay_scope = derive_replay_scope(endpoint_url_digest);
    AgentWebReplayEntry::new(replay_scope, webhook_id, expires_at_unix_seconds)
        .map_err(|error| claim_failed(error.to_string()))
}

fn validate_signature_ref(signature_ref: &str) -> Result<Vec<u8>, TransactionPassportError> {
    let Some((version, signature)) = signature_ref.split_once(',') else {
        return Err(claim_failed("invalid Standard Webhooks signature"));
    };
    if version != "v1" || signature.is_empty() || signature.chars().any(char::is_whitespace) {
        return Err(claim_failed("invalid Standard Webhooks signature"));
    }
    let signature = STANDARD
        .decode(signature)
        .map_err(|_| claim_failed("invalid Standard Webhooks signature"))?;
    if signature.len() != 32 {
        return Err(claim_failed("invalid Standard Webhooks signature"));
    }
    Ok(signature)
}

fn verify_signature_ref(
    signature_ref: &str,
    verifier_secret: &[u8],
    webhook_id: &str,
    webhook_timestamp: &str,
    body_digest: &str,
    endpoint_url_digest: &str,
) -> Result<(), TransactionPassportError> {
    let signature = validate_signature_ref(signature_ref)?;
    let mut mac = HmacSha256::new_from_slice(verifier_secret)
        .map_err(|_| claim_failed("invalid Standard Webhooks signature"))?;
    mac.update(webhook_id.as_bytes());
    mac.update(b".");
    mac.update(webhook_timestamp.as_bytes());
    mac.update(b".");
    mac.update(body_digest.as_bytes());
    mac.update(b".");
    mac.update(endpoint_url_digest.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| claim_failed("invalid Standard Webhooks signature"))
}

fn derive_replay_scope(endpoint_url_digest: &str) -> AgentWebReplayScope {
    let mut hasher = Sha256::new();
    hasher.update(b"chio.agent-web.replay-scope.v2\0");
    hasher.update(endpoint_url_digest.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    AgentWebReplayScope::from_digest(digest)
}

fn validate_replay_window(
    webhook_timestamp: &str,
    trust: &AgentWebVerifierTrust,
) -> Result<u64, TransactionPassportError> {
    let replay_window = trust
        .standard_webhooks_replay_window()
        .ok_or_else(|| claim_failed("missing Standard Webhooks replay window"))?;
    if replay_window.max_age_seconds == 0 {
        return Err(claim_failed("invalid Standard Webhooks replay window"));
    }
    let timestamp = webhook_timestamp
        .parse::<u64>()
        .map_err(|_| claim_failed("invalid Standard Webhooks timestamp"))?;
    if timestamp > replay_window.now_unix_seconds {
        return Err(claim_failed("future Standard Webhooks timestamp"));
    }
    let age = replay_window.now_unix_seconds - timestamp;
    if age > replay_window.max_age_seconds {
        return Err(claim_failed("stale Standard Webhooks timestamp"));
    }
    timestamp
        .checked_add(replay_window.max_age_seconds)
        .ok_or_else(|| claim_failed("invalid Standard Webhooks timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AgentWebReplayStore, AgentWebReplayStoreError, InMemoryAgentWebReplayStore};

    fn signature_ref(
        secret: &[u8],
        webhook_id: &str,
        timestamp: &str,
        body_digest: &str,
        endpoint_digest: &str,
    ) -> String {
        let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
            panic!("static Standard Webhooks test secret must initialize HMAC");
        };
        mac.update(webhook_id.as_bytes());
        mac.update(b".");
        mac.update(timestamp.as_bytes());
        mac.update(b".");
        mac.update(body_digest.as_bytes());
        mac.update(b".");
        mac.update(endpoint_digest.as_bytes());
        format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn replay_scope_survives_verifier_secret_rotation() {
        let webhook_id = "msg_rotation_regression";
        let timestamp = "1770508560";
        let body_digest = "b".repeat(64);
        let endpoint_digest = "a".repeat(64);
        let store = InMemoryAgentWebReplayStore::new();

        for (index, secret) in [b"old-secret".as_slice(), b"rotated-secret".as_slice()]
            .into_iter()
            .enumerate()
        {
            let signature = signature_ref(
                secret,
                webhook_id,
                timestamp,
                &body_digest,
                &endpoint_digest,
            );
            assert!(verify_signature_ref(
                &signature,
                secret,
                webhook_id,
                timestamp,
                &body_digest,
                &endpoint_digest,
            )
            .is_ok());
            let entry = match AgentWebReplayEntry::new(
                derive_replay_scope(&endpoint_digest),
                webhook_id,
                300,
            ) {
                Ok(entry) => entry,
                Err(error) => panic!("static replay entry must validate: {error}"),
            };
            let result = store.check_and_insert(200, &[entry]);
            if index == 0 {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(AgentWebReplayStoreError::Replayed(ref replayed))
                        if replayed == webhook_id
                ));
            }
        }
    }
}
