use std::{collections::BTreeSet, io::Read, sync::Arc, time::Duration};

use super::CliError;
use chio_egress_contract::HttpEgressContract;

const AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV: &str = "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET";
const AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV: &str =
    "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS";
const AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV: &str =
    "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS";
const AGENT_WEB_REPLAY_STORE_PATH_ENV: &str = "CHIO_AGENT_WEB_REPLAY_STORE_PATH";
const AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV: &str = "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS";
const AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV: &str =
    "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS";
const TRANSACTION_TRUSTED_ROOT_KEYS_ENV: &str = "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS";
const TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV: &str =
    "CHIO_TRANSACTION_TRUSTED_CHECKPOINT_KEYS";
const FINDING_VERIFIER_AUTHORITY_KEY_ENV: &str = "CHIO_FINDING_VERIFIER_AUTHORITY_KEY";
const FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV: &str =
    "CHIO_FINDING_VERIFIER_SIGNER_POLICY_PATH";
const FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256_ENV: &str =
    "CHIO_FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256";
const FINDING_VERIFIER_PROFILE_REQUIRED_FACETS_ENV: &str =
    "CHIO_FINDING_VERIFIER_PROFILE_REQUIRED_FACETS";
const FINDING_TRUST_ROOT_SNAPSHOT_SHA256_ENV: &str =
    "CHIO_FINDING_TRUST_ROOT_SNAPSHOT_SHA256";
const FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV: &str =
    "CHIO_FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH";
const FINDING_STATUS_AUTHORITY_DATABASE_PATH_ENV: &str =
    "CHIO_FINDING_STATUS_AUTHORITY_DATABASE_PATH";
const FINDING_STATUS_AUTHORITY_LOCK_ROOT_ENV: &str = "CHIO_FINDING_STATUS_AUTHORITY_LOCK_ROOT";
const FINDING_STATUS_NOW_UNIX_SECONDS_ENV: &str = "CHIO_FINDING_STATUS_NOW_UNIX_SECONDS";
const FINDING_STATUS_MAX_AGE_SECONDS_ENV: &str = "CHIO_FINDING_STATUS_MAX_AGE_SECONDS";
const FINDING_STATUS_AUTHORIZATION_MAX_BYTES: usize = 64 * 1024;
const FINDING_VERIFIER_SIGNER_POLICY_MAX_BYTES: usize = 16 * 1024;
const RUNTIME_TRUSTED_ROOT_KEYS_ENV: &str = "CHIO_RUNTIME_TRUSTED_ROOT_KEYS";
const ENTERPRISE_TRUSTED_APPROVAL_KEYS_ENV: &str = "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS";
const ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS_ENV: &str =
    "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS";
const ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS_ENV: &str =
    "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS";
const COMMERCE_TRUSTED_PROVIDER_KEYS_ENV: &str = "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS";
const COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS_ENV: &str =
    "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS";
const COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS_ENV: &str = "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS";
const TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV: &str = "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS";
const SWARM_TRUSTED_WITNESS_KEYS_ENV: &str = "CHIO_SWARM_TRUSTED_WITNESS_KEYS";
const DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS_ENV: &str =
    "CHIO_DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS";
const DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS_ENV: &str =
    "CHIO_DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS";
const PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS_ENV: &str = "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS";
const PUBLIC_SETTLEMENT_MAINNET_BLOCKED_ENV: &str = "CHIO_PUBLIC_SETTLEMENT_MAINNET_BLOCKED";
const PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL";
const PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS";
const PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID";
const PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH";
const PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH";
const PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH";
const PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH";
const PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AgentWebReplayMode {
    ReadOnly,
    Consume,
}

pub(super) fn agent_web_verifier_trust_from_env(
    replay_mode: AgentWebReplayMode,
    replay_reservation_id: Option<&str>,
) -> Result<chio_control_plane::agent_web::AgentWebVerifierTrust, CliError> {
    let mut trust = match std::env::var(AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV) {
        Ok(secret) => chio_control_plane::agent_web::AgentWebVerifierTrust::new()
            .with_standard_webhooks_secret(secret.into_bytes()),
        Err(std::env::VarError::NotPresent) => {
            chio_control_plane::agent_web::AgentWebVerifierTrust::new()
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::cli_other_error(format!(
                "{AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV} must be valid UTF-8"
            )))
        }
    };
    if let Some((now_unix_seconds, max_age_seconds)) = standard_webhooks_replay_window_from_env()? {
        trust = trust.with_standard_webhooks_replay_window(now_unix_seconds, max_age_seconds);
        if replay_mode == AgentWebReplayMode::Consume {
            let replay_store = agent_web_replay_store_from_env()?;
            trust = trust.with_standard_webhooks_replay_store(Arc::new(replay_store));
        }
    }
    if let Some(reservation_id) = replay_reservation_id {
        trust = trust
            .with_standard_webhooks_replay_reservation_id(reservation_id)
            .map_err(|error| CliError::cli_other_error(error.to_string()))?;
    }
    match std::env::var(AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV) {
        Ok(keys) => {
            trust = trust.with_trusted_receipt_kernel_keys(parse_public_keys(
                AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV,
                &keys,
            )?);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::cli_other_error(format!(
                "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must be valid UTF-8"
            )))
        }
    }
    match std::env::var(AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV) {
        Ok(keys) => {
            trust = trust.with_trusted_envelope_sidecar_keys(parse_public_keys(
                AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV,
                &keys,
            )?);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::cli_other_error(format!(
                "{AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV} must be valid UTF-8"
            )))
        }
    }
    Ok(trust)
}

pub(super) fn agent_web_replay_store_from_env(
) -> Result<chio_store_sqlite::SqliteAgentWebReplayStore, CliError> {
    agent_web_replay_store_from_env_if_configured()?.ok_or_else(|| {
        CliError::cli_other_error(format!(
            "{AGENT_WEB_REPLAY_STORE_PATH_ENV} must be set and non-empty"
        ))
    })
}

pub(super) fn agent_web_replay_store_from_env_if_configured(
) -> Result<Option<chio_store_sqlite::SqliteAgentWebReplayStore>, CliError> {
    let replay_store_path = match std::env::var(AGENT_WEB_REPLAY_STORE_PATH_ENV) {
        Ok(value) if value.trim().is_empty() => {
            return Err(CliError::cli_other_error(format!(
                "{AGENT_WEB_REPLAY_STORE_PATH_ENV} must be non-empty"
            )))
        }
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(CliError::cli_other_error(format!(
                "{AGENT_WEB_REPLAY_STORE_PATH_ENV} must be valid UTF-8"
            )))
        }
    };
    chio_store_sqlite::SqliteAgentWebReplayStore::open(replay_store_path)
        .map(Some)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "{AGENT_WEB_REPLAY_STORE_PATH_ENV} could not be opened: {error}"
            ))
        })
}

fn standard_webhooks_replay_window_from_env() -> Result<Option<(u64, u64)>, CliError> {
    match (
        optional_u64_from_env(AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV)?,
        optional_u64_from_env(AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV)?,
    ) {
        (None, None) => Ok(None),
        (Some(now_unix_seconds), Some(max_age_seconds)) => {
            Ok(Some((now_unix_seconds, max_age_seconds)))
        }
        (None, Some(_)) => Err(CliError::cli_other_error(format!(
            "{AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV} must be set with {AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV}"
        ))),
        (Some(_), None) => Err(CliError::cli_other_error(format!(
            "{AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV} must be set with {AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV}"
        ))),
    }
}

fn optional_u64_from_env(env_name: &str) -> Result<Option<u64>, CliError> {
    match std::env::var(env_name) {
        Ok(value) => value.trim().parse::<u64>().map(Some).map_err(|error| {
            CliError::cli_other_error(format!("{env_name} must be a u64: {error}"))
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

pub(super) fn cognition_market_proof_trust_from_env(
    trusted_passport_signer_keys: &[chio_core_types::PublicKey],
    trusted_checkpoint_signer_keys: &[chio_core_types::PublicKey],
    status_claim_selected: bool,
) -> Result<chio_control_plane::transaction_passport::CognitionMarketProofTrust, CliError> {
    let verifier_keys = required_public_keys_from_env(
        FINDING_VERIFIER_AUTHORITY_KEY_ENV,
        "Finding verifier authority",
    )?;
    if verifier_keys.len() != 1 {
        return Err(CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_AUTHORITY_KEY_ENV} must contain exactly one public key"
        )));
    }
    let finding_verifier_authority = verifier_keys
        .into_iter()
        .next()
        .ok_or_else(|| CliError::cli_other_error("Finding verifier authority key is missing"))?;
    let finding_verifier_signer = finding_verifier_signer_policy_from_env()?;
    if finding_verifier_signer.key != finding_verifier_authority {
        return Err(CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV} key does not match {FINDING_VERIFIER_AUTHORITY_KEY_ENV}"
        )));
    }
    let trusted_verifier_profile_envelope_sha256 =
        required_sha256_env(FINDING_VERIFIER_PROFILE_ENVELOPE_SHA256_ENV)?;
    let trusted_verifier_profile_required_facets = required_finding_facets_from_env()?;
    let trusted_trust_root_snapshot_sha256 =
        required_sha256_env(FINDING_TRUST_ROOT_SNAPSHOT_SHA256_ENV)?;
    let status = if status_claim_selected {
        Some(cognition_market_status_trust_from_env()?)
    } else {
        None
    };
    Ok(
        chio_control_plane::transaction_passport::CognitionMarketProofTrust {
            trusted_passport_signer_keys: trusted_passport_signer_keys.to_vec(),
            trusted_checkpoint_signer_keys: trusted_checkpoint_signer_keys.to_vec(),
            finding_verifier_authority,
            finding_verifier_signer,
            trusted_verifier_profile_envelope_sha256,
            trusted_verifier_profile_required_facets,
            trusted_trust_root_snapshot_sha256,
            status,
        },
    )
}

fn required_finding_facets_from_env() -> Result<Vec<chio_finding::FindingFacetKind>, CliError> {
    let raw = required_utf8_env(FINDING_VERIFIER_PROFILE_REQUIRED_FACETS_ENV)?;
    let facets: Vec<chio_finding::FindingFacetKind> = serde_json::from_str(&raw).map_err(|error| {
        CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_PROFILE_REQUIRED_FACETS_ENV} must be a JSON array of Finding facet names: {error}"
        ))
    })?;
    let mut unique = BTreeSet::new();
    for facet in &facets {
        if !unique.insert(*facet) {
            return Err(CliError::cli_other_error(format!(
                "{FINDING_VERIFIER_PROFILE_REQUIRED_FACETS_ENV} contains duplicate facets"
            )));
        }
    }
    Ok(facets)
}

fn finding_verifier_signer_policy_from_env(
) -> Result<chio_finding::FindingAuthorityKeyPolicy, CliError> {
    let path = required_utf8_env(FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV)?;
    let mut reader = std::fs::File::open(&path)?
        .take((FINDING_VERIFIER_SIGNER_POLICY_MAX_BYTES as u64).saturating_add(1));
    let mut bytes = Vec::with_capacity(FINDING_VERIFIER_SIGNER_POLICY_MAX_BYTES.saturating_add(1));
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > FINDING_VERIFIER_SIGNER_POLICY_MAX_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV} exceeds the signer-policy size bound"
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV} is not valid UTF-8: {error}"
        ))
    })?;
    let canonical = chio_core_types::canonical_json_bytes_from_str(text).map_err(|error| {
        CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV} is not strict canonical I-JSON: {error}"
        ))
    })?;
    if canonical != bytes {
        return Err(CliError::cli_other_error(format!(
            "{FINDING_VERIFIER_SIGNER_POLICY_PATH_ENV} is not the canonical signer-policy serialization"
        )));
    }
    let policy: chio_finding::FindingAuthorityKeyPolicy = serde_json::from_slice(&bytes)?;
    policy.validate("finding_verifier_signer").map_err(|error| {
        CliError::cli_other_error(format!("Finding verifier signer policy is invalid: {error}"))
    })?;
    Ok(policy)
}

fn cognition_market_status_trust_from_env(
) -> Result<chio_control_plane::transaction_passport::CognitionMarketStatusTrust, CliError> {
    let authorization_path = required_utf8_env(FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV)?;
    let mut reader = std::fs::File::open(&authorization_path)?
        .take((FINDING_STATUS_AUTHORIZATION_MAX_BYTES as u64).saturating_add(1));
    let mut authorization_bytes =
        Vec::with_capacity(FINDING_STATUS_AUTHORIZATION_MAX_BYTES.saturating_add(1));
    reader.read_to_end(&mut authorization_bytes)?;
    if authorization_bytes.len() > FINDING_STATUS_AUTHORIZATION_MAX_BYTES {
        return Err(CliError::cli_other_error(format!(
            "{FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV} exceeds the authorization size bound"
        )));
    }
    let authorization_text = std::str::from_utf8(&authorization_bytes).map_err(|error| {
        CliError::cli_other_error(format!(
            "{FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV} is not valid UTF-8: {error}"
        ))
    })?;
    let canonical = chio_core_types::canonical_json_bytes_from_str(authorization_text).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "{FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV} is not strict canonical I-JSON: {error}"
            ))
        },
    )?;
    if canonical != authorization_bytes {
        return Err(CliError::cli_other_error(format!(
            "{FINDING_STATUS_OPERATOR_AUTHORIZATION_PATH_ENV} is not the canonical authorization serialization"
        )));
    }
    let status_operator_authorization: chio_finding::FindingStatusOperatorAuthorization =
        serde_json::from_slice(&authorization_bytes)?;
    status_operator_authorization.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "Finding status operator authorization is invalid: {error}"
        ))
    })?;
    let now = required_positive_u64_env(FINDING_STATUS_NOW_UNIX_SECONDS_ENV)?;
    let max_epoch_age_secs = required_positive_u64_env(FINDING_STATUS_MAX_AGE_SECONDS_ENV)?;
    let authority_database = required_utf8_env(FINDING_STATUS_AUTHORITY_DATABASE_PATH_ENV)?;
    let authority_lock_root = required_utf8_env(FINDING_STATUS_AUTHORITY_LOCK_ROOT_ENV)?;
    let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving(
        &authority_database,
        &authority_lock_root,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "durable Finding status authority store could not be opened: {error}"
        ))
    })?;
    let status_store = authority.finding_status_store();
    Ok(
        chio_control_plane::transaction_passport::CognitionMarketStatusTrust {
            status_operator_authorization,
            status_freshness: chio_finding::FindingStatusFreshnessPolicy {
                now,
                max_epoch_age_secs,
            },
            status_store: Arc::new(status_store),
        },
    )
}

pub(super) fn claim_set_bytes_advertise_verified_prefix(
    bytes: &[u8],
    prefix: &str,
) -> Result<bool, CliError> {
    claim_set_bytes_advertise_verified(bytes, |claim_id| claim_id.starts_with(prefix))
}

pub(super) fn claim_set_bytes_advertise_verified_claim(
    bytes: &[u8],
    expected_claim_id: &str,
) -> Result<bool, CliError> {
    claim_set_bytes_advertise_verified(bytes, |claim_id| claim_id == expected_claim_id)
}

fn claim_set_bytes_advertise_verified(
    bytes: &[u8],
    matches_claim: impl Fn(&str) -> bool,
) -> Result<bool, CliError> {
    let claim_set: serde_json::Value = serde_json::from_slice(bytes)?;
    let claims = claim_set
        .get("claims")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CliError::cli_other_error("proof verify: claim set missing claims array"))?;
    for claim in claims {
        let claim_id = claim
            .get("claim_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error("proof verify: claim set claim_id must be a string")
            })?;
        let status = claim
            .get("status")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::cli_other_error("proof verify: claim set status must be a string")
            })?;
        if matches_claim(claim_id) && status == "verified" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn required_utf8_env(env_name: &str) -> Result<String, CliError> {
    match std::env::var(env_name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        Ok(_) => Err(CliError::cli_other_error(format!(
            "{env_name} must be non-empty"
        ))),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{env_name} must be set"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn required_positive_u64_env(env_name: &str) -> Result<u64, CliError> {
    let raw = required_utf8_env(env_name)?;
    raw.parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| CliError::cli_other_error(format!("{env_name} must be a nonzero u64")))
}

fn required_sha256_env(env_name: &str) -> Result<String, CliError> {
    let value = required_utf8_env(env_name)?;
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(value)
    } else {
        Err(CliError::cli_other_error(format!(
            "{env_name} must be a lowercase 64-character SHA-256 digest"
        )))
    }
}

fn parse_public_keys(
    env_name: &str,
    keys: &str,
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    if keys.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{env_name} must contain comma-separated public keys"
        )));
    }

    keys.split(',')
        .map(|key| {
            let key = key.trim();
            if key.is_empty() {
                return Err(CliError::cli_other_error(format!(
                    "{env_name} must not contain empty public keys"
                )));
            }
            chio_core_types::PublicKey::from_hex(key).map_err(|error| {
                CliError::cli_other_error(format!(
                    "{env_name} contains invalid public key: {error}"
                ))
            })
        })
        .collect()
}

pub(super) fn trust_market_trusted_authority_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    match std::env::var(TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV) {
        Ok(keys) => parse_public_keys(TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV, &keys),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV} must pin trusted market authority keys"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV} must be valid UTF-8"
        ))),
    }
}

pub(super) fn enterprise_trusted_approval_signer_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    required_public_keys_from_env(
        ENTERPRISE_TRUSTED_APPROVAL_KEYS_ENV,
        "enterprise approval signer",
    )
}

pub(super) fn enterprise_trusted_risk_comptroller_signer_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    required_public_keys_from_env(
        ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS_ENV,
        "enterprise risk comptroller signer",
    )
}

pub(super) fn enterprise_trusted_receipt_kernel_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    required_public_keys_from_env(
        ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS_ENV,
        "enterprise receipt kernel",
    )
}

fn required_public_keys_from_env(
    env_name: &str,
    label: &str,
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    match std::env::var(env_name) {
        Ok(keys) => parse_public_keys(env_name, &keys),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{env_name} must pin trusted {label} keys"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn parse_string_list(env_name: &str, values: &str) -> Result<Vec<String>, CliError> {
    if values.trim().is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{env_name} must contain comma-separated values"
        )));
    }

    values
        .split(',')
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                return Err(CliError::cli_other_error(format!(
                    "{env_name} must not contain empty values"
                )));
            }
            Ok(value.to_string())
        })
        .collect()
}

fn required_string_list_from_env(env_name: &str, label: &str) -> Result<Vec<String>, CliError> {
    match std::env::var(env_name) {
        Ok(values) => parse_string_list(env_name, &values),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{env_name} must pin trusted {label}"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn required_string_from_env(env_name: &str, label: &str) -> Result<String, CliError> {
    match std::env::var(env_name) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Err(CliError::cli_other_error(format!(
                    "{env_name} must pin trusted {label}"
                )));
            }
            Ok(value.to_string())
        }
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{env_name} must pin trusted {label}"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn optional_bool_from_env(env_name: &str) -> Result<bool, CliError> {
    match std::env::var(env_name) {
        Ok(value) => match value.trim() {
            "1" | "true" | "TRUE" | "True" => Ok(true),
            "0" | "false" | "FALSE" | "False" => Ok(false),
            _ => Err(CliError::cli_other_error(format!(
                "{env_name} must be true or false"
            ))),
        },
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn optional_u32_from_env(env_name: &str) -> Result<Option<u32>, CliError> {
    match std::env::var(env_name) {
        Ok(value) => value.trim().parse::<u32>().map(Some).map_err(|error| {
            CliError::cli_other_error(format!("{env_name} must be a u32: {error}"))
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{env_name} must be valid UTF-8"
        ))),
    }
}

fn optional_public_settlement_independent_chain_head_from_env(
    proof_bundle: &chio_web3::settlement_proof::PublicSettlementProofBundle,
) -> Result<Option<chio_web3::settlement_proof::PublicSettlementIndependentChainHead>, CliError> {
    let head_from_json = match std::env::var(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV) {
        Ok(value) => serde_json::from_str(value.trim())
            .map(Some)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV} must be valid JSON: {error}"
            ))
            }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV} must be valid UTF-8"
        ))),
    }?;
    if head_from_json.is_some() {
        return Ok(head_from_json);
    }

    match std::env::var(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV) {
        Ok(value) => {
            fetch_public_settlement_independent_chain_head_from_rpc(value.trim(), proof_bundle)
                .map(Some)
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must be valid UTF-8"
        ))),
    }
}

fn fetch_public_settlement_independent_chain_head_from_rpc(
    url: &str,
    proof_bundle: &chio_web3::settlement_proof::PublicSettlementProofBundle,
) -> Result<chio_web3::settlement_proof::PublicSettlementIndependentChainHead, CliError> {
    if url.is_empty() {
        return Err(CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must not be empty"
        )));
    }
    let egress_contract = public_settlement_rpc_egress_contract(url)?;
    let latest_block_number = parse_json_rpc_hex_u64(
        &public_settlement_rpc_call(
            &egress_contract,
            url,
            "eth_blockNumber",
            serde_json::json!([]),
        )?,
        "eth_blockNumber result",
    )?;
    let observed_block_number = proof_bundle.chain_snapshot.observed_block_number;
    let observed_block = public_settlement_rpc_call(
        &egress_contract,
        url,
        "eth_getBlockByNumber",
        serde_json::json!([format!("0x{observed_block_number:x}"), false]),
    )?;
    let observed_block_hash =
        required_json_rpc_string(&observed_block, "hash", "eth_getBlockByNumber result")?;

    Ok(
        chio_web3::settlement_proof::PublicSettlementIndependentChainHead {
            chain_id: proof_bundle.chain_id.clone(),
            observed_block_number,
            observed_block_hash: observed_block_hash.to_string(),
            latest_block_number,
        },
    )
}

fn public_settlement_rpc_egress_contract(url: &str) -> Result<HttpEgressContract, CliError> {
    let parsed = reqwest::Url::parse(url).map_err(|error| {
        CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must be a valid URL: {error}"
        ))
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must include a host"
        ))
    })?;
    let normalized_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{}]", host.to_ascii_lowercase())
    } else {
        host.trim_end_matches('.').to_ascii_lowercase()
    };
    let authority = match parsed.port() {
        Some(port) => format!("{normalized_host}:{port}"),
        None => normalized_host,
    };
    let mut allowed_schemes = BTreeSet::new();
    allowed_schemes.insert(parsed.scheme().to_ascii_lowercase());
    let mut allowed_authority_set = BTreeSet::new();
    allowed_authority_set.insert(authority);
    let contract = HttpEgressContract {
        tenant_egress_namespace: "proof.public-settlement.rpc".to_string(),
        allowed_schemes,
        allowed_authority_set,
        deny_loopback: cfg!(not(debug_assertions))
            || !optional_bool_from_env("CHIO_TEST_PUBLIC_SETTLEMENT_ALLOW_LOOPBACK_RPC")?,
        deny_link_local: true,
        deny_ipv6_ula: true,
        max_redirect_chain: 0,
        max_response_bytes: 1024 * 1024,
    };
    contract.validate().map_err(|error| {
        CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} rejected by HttpEgressContract: {error}"
        ))
    })?;
    Ok(contract)
}

fn public_settlement_rpc_call(
    egress_contract: &HttpEgressContract,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, CliError> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response =
        dispatch_public_settlement_rpc(egress_contract, url, &request_body).map_err(|reason| {
            CliError::cli_other_error(format!(
                "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} {reason}"
            ))
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} returned HTTP {status}"
        )));
    }
    let body = serde_json::from_slice::<serde_json::Value>(response.body()).map_err(|error| {
        CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} returned invalid JSON: {error}"
        ))
    })?;
    if let Some(error) = body.get("error") {
        return Err(CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} returned JSON-RPC error: {error}"
        )));
    }
    body.get("result").cloned().ok_or_else(|| {
        CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} response missing result"
        ))
    })
}

/// Dispatch one settlement JSON-RPC POST through the pinned-DNS egress helper.
///
/// The helper (`chio_egress_contract::send_with_contract`) resolves the target
/// once through a contract-backed resolver and connects to that same
/// resolution, so a rebinding host cannot pass the address-class check with a
/// global IP and then connect to a loopback/private address. It also enforces
/// the response byte ceiling while streaming, so an oversized chunked body
/// aborts before the whole response is buffered. Redirects are denied
/// (`client_builder_with_contract` sets `Policy::none`).
///
/// The helper is async while this verifier path is synchronous, so the request
/// runs on a dedicated current-thread runtime. A fresh thread keeps this
/// correct whether or not the caller already runs inside a tokio runtime.
fn dispatch_public_settlement_rpc(
    egress_contract: &HttpEgressContract,
    url: &str,
    request_body: &serde_json::Value,
) -> Result<chio_egress_contract::ContractResponse, String> {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("HTTP runtime failed: {error}"))?;
                runtime.block_on(async {
                    let client =
                        chio_egress_contract::client_builder_with_contract(egress_contract)
                            .timeout(Duration::from_secs(10))
                            .build()
                            .map_err(|error| format!("HTTP client failed: {error}"))?;
                    let request = client
                        .post(url)
                        .json(request_body)
                        .build()
                        .map_err(|error| format!("request build failed: {error}"))?;
                    chio_egress_contract::send_with_contract(egress_contract, &client, request)
                        .await
                        .map_err(|error| format!("rejected by HttpEgressContract: {error}"))
                })
            })
            .join()
            .map_err(|_| "settlement RPC dispatch thread panicked".to_string())?
    })
}

fn parse_json_rpc_hex_u64(value: &serde_json::Value, label: &str) -> Result<u64, CliError> {
    let raw = value
        .as_str()
        .ok_or_else(|| CliError::cli_other_error(format!("{label} must be a hex string")))?;
    let hex = raw
        .strip_prefix("0x")
        .ok_or_else(|| CliError::cli_other_error(format!("{label} must start with 0x")))?;
    u64::from_str_radix(hex, 16)
        .map_err(|error| CliError::cli_other_error(format!("{label} is not a u64: {error}")))
}

fn required_json_rpc_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<&'a str, CliError> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::cli_other_error(format!("{label}.{field} must be a string")))
}

pub(super) fn public_settlement_verifier_trust_from_env(
    proof_bundle: &chio_web3::settlement_proof::PublicSettlementProofBundle,
) -> Result<chio_web3::settlement_proof::PublicSettlementVerifierTrust, CliError> {
    Ok(chio_web3::settlement_proof::PublicSettlementVerifierTrust {
        trusted_bundle_signer_keys: required_public_keys_from_env(
            PUBLIC_SETTLEMENT_TRUSTED_BUNDLE_SIGNER_KEYS_ENV,
            "public settlement bundle signer",
        )?,
        trusted_capital_signer_keys: required_public_keys_from_env(
            PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS_ENV,
            "public settlement capital signer",
        )?,
        trusted_anchor_kernel_keys: required_public_keys_from_env(
            PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS_ENV,
            "public settlement anchor kernel",
        )?,
        trusted_beneficiary_identity_keys: required_public_keys_from_env(
            PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS_ENV,
            "public settlement beneficiary identity",
        )?,
        trusted_oracle_keys: required_public_keys_from_env(
            PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS_ENV,
            "public settlement oracle",
        )?,
        allowed_chain_ids: required_string_list_from_env(
            PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS_ENV,
            "public settlement chain IDs",
        )?,
        mainnet_blocked: optional_bool_from_env(PUBLIC_SETTLEMENT_MAINNET_BLOCKED_ENV)?,
        minimum_confirmations: optional_u32_from_env(PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS_ENV)?,
        expected_trust_market_context: None,
        independent_chain_head: optional_public_settlement_independent_chain_head_from_env(
            proof_bundle,
        )?,
        trusted_dispute_event_blocks: Vec::new(),
        trusted_release_event_blocks: Vec::new(),
        trusted_release_event_logs: Vec::new(),
        trusted_refund_event_logs: Vec::new(),
        verifier_now_unix_seconds: optional_u64_from_env(
            PUBLIC_SETTLEMENT_VERIFIER_NOW_UNIX_SECONDS_ENV,
        )?,
        trusted_runtime_codehashes: Some(
            chio_web3::settlement_proof::PublicSettlementRuntimeCodehashTrust {
                contract_package_id: required_string_from_env(
                    PUBLIC_SETTLEMENT_TRUSTED_CONTRACT_PACKAGE_ID_ENV,
                    "public settlement contract package id",
                )?,
                reviewed_manifest_hash: required_string_from_env(
                    PUBLIC_SETTLEMENT_TRUSTED_REVIEWED_MANIFEST_HASH_ENV,
                    "public settlement reviewed manifest hash",
                )?,
                root_registry_runtime_codehash: required_string_from_env(
                    PUBLIC_SETTLEMENT_TRUSTED_ROOT_REGISTRY_RUNTIME_CODEHASH_ENV,
                    "public settlement root registry runtime codehash",
                )?,
                identity_registry_runtime_codehash: required_string_from_env(
                    PUBLIC_SETTLEMENT_TRUSTED_IDENTITY_REGISTRY_RUNTIME_CODEHASH_ENV,
                    "public settlement identity registry runtime codehash",
                )?,
                escrow_runtime_codehash: required_string_from_env(
                    PUBLIC_SETTLEMENT_TRUSTED_ESCROW_RUNTIME_CODEHASH_ENV,
                    "public settlement escrow runtime codehash",
                )?,
                bond_vault_runtime_codehash: required_string_from_env(
                    PUBLIC_SETTLEMENT_TRUSTED_BOND_VAULT_RUNTIME_CODEHASH_ENV,
                    "public settlement bond vault runtime codehash",
                )?,
            },
        ),
    })
}

pub(super) fn commerce_trusted_provider_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    match std::env::var(COMMERCE_TRUSTED_PROVIDER_KEYS_ENV) {
        Ok(keys) => parse_public_keys(COMMERCE_TRUSTED_PROVIDER_KEYS_ENV, &keys),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{COMMERCE_TRUSTED_PROVIDER_KEYS_ENV} must pin trusted commerce provider keys"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{COMMERCE_TRUSTED_PROVIDER_KEYS_ENV} must be valid UTF-8"
        ))),
    }
}

pub(super) fn commerce_trusted_event_authority_receipt_kernel_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    required_public_keys_from_env(
        COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS_ENV,
        "commerce event authority receipt kernel",
    )
}

pub(super) fn commerce_trusted_payment_signer_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    required_public_keys_from_env(
        COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS_ENV,
        "commerce payment signer",
    )
}

pub(super) fn disclosure_lineage_verifier_trust_from_env(
) -> Result<chio_selective_disclosure::DisclosureLineageVerifierTrust, CliError> {
    Ok(
        chio_selective_disclosure::DisclosureLineageVerifierTrust::new()
            .with_trusted_lineage_signer_keys(required_public_keys_from_env(
                DISCLOSURE_TRUSTED_LINEAGE_SIGNER_KEYS_ENV,
                "disclosure lineage signer",
            )?)
            .with_trusted_crypto_context_report_signer_keys(required_public_keys_from_env(
                DISCLOSURE_TRUSTED_CRYPTO_CONTEXT_REPORT_SIGNER_KEYS_ENV,
                "disclosure crypto context report signer",
            )?),
    )
}

pub(super) fn transaction_trusted_root_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    match std::env::var(TRANSACTION_TRUSTED_ROOT_KEYS_ENV) {
        Ok(keys) => parse_public_keys(TRANSACTION_TRUSTED_ROOT_KEYS_ENV, &keys),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{TRANSACTION_TRUSTED_ROOT_KEYS_ENV} must pin trusted transaction root keys"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{TRANSACTION_TRUSTED_ROOT_KEYS_ENV} must be valid UTF-8"
        ))),
    }
}

pub(super) fn transaction_trusted_checkpoint_keys_from_env(
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    match std::env::var(TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV) {
        Ok(keys) => parse_public_keys(TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV, &keys),
        Err(std::env::VarError::NotPresent) => Ok(Vec::new()),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV} must be valid UTF-8"
        ))),
    }
}

pub(super) fn runtime_trust_from_env(
) -> Result<chio_control_plane::transaction_passport::RuntimeSecurityTrust, CliError> {
    let trusted_passport_signer_keys = transaction_trusted_root_keys_from_env()?;
    let trusted_root_signer_keys = match std::env::var(RUNTIME_TRUSTED_ROOT_KEYS_ENV) {
        Ok(keys) => parse_public_keys(RUNTIME_TRUSTED_ROOT_KEYS_ENV, &keys),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{RUNTIME_TRUSTED_ROOT_KEYS_ENV} must pin trusted runtime root keys"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{RUNTIME_TRUSTED_ROOT_KEYS_ENV} must be valid UTF-8"
        ))),
    }?;
    Ok(
        chio_control_plane::transaction_passport::RuntimeSecurityTrust {
            trusted_passport_signer_keys,
            trusted_root_signer_keys,
        },
    )
}

fn swarm_trusted_witness_keys_from_env() -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    match std::env::var(SWARM_TRUSTED_WITNESS_KEYS_ENV) {
        Ok(keys) => parse_public_keys(SWARM_TRUSTED_WITNESS_KEYS_ENV, &keys),
        Err(std::env::VarError::NotPresent) => Err(CliError::cli_other_error(format!(
            "{SWARM_TRUSTED_WITNESS_KEYS_ENV} must pin trusted swarm witness keys"
        ))),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{SWARM_TRUSTED_WITNESS_KEYS_ENV} must be valid UTF-8"
        ))),
    }
}

pub(super) fn swarm_trusted_witness_keys_for_bundle(
    _bundle: &chio_swarm_authority::SwarmAuthorityBundle,
) -> Result<Vec<chio_core_types::PublicKey>, CliError> {
    swarm_trusted_witness_keys_from_env()
}
