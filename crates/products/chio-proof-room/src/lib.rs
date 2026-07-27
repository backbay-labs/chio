use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::http::StatusCode;
use chio_core_types::{PublicKey, Signature};
use chio_egress_contract::HttpEgressContract;
use sha2::{Digest, Sha256};

mod bundle_a;
mod bundle_b;
mod crypto_context;
mod fixture_a;
mod fixture_b;
mod receipt_coverage;
mod server;
mod source_verifier;
#[cfg(test)]
mod tests;

pub(crate) use bundle_a::*;
pub(crate) use bundle_b::*;
pub use crypto_context::{
    crypto_context_rejected_report_bytes_with_bbs, crypto_context_verified_report_bytes_with_bbs,
};
pub(crate) use fixture_a::*;
pub(crate) use fixture_b::*;
pub use server::{
    build_proof_room_fixture_catalog_json, build_proof_room_fixture_catalog_json_with_fixture_root,
    is_proof_room_bundle_namespace, parse_listen_addr, proof_room_content_type,
    proof_room_fixture_asset_response, proof_room_router, proof_room_router_with_fixture_root,
    proof_room_router_with_optional_ui_root, proof_room_served_bundle_paths,
    resolve_proof_room_served_asset_path, serve_proof_room, ProofRoomServeConfig,
};
pub(crate) use source_verifier::*;

const PROOF_ROOM_BUNDLE_SCHEMA: &str = "chio.proof-room.bundle.v1";
const PROOF_ROOM_VERIFIER_REPORT_SCHEMA: &str = "chio.proof-room.verifier-report.v1";
const PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA: &str =
    "chio.proof.docker-quickstart-evidence.v1";
const PROOF_ROOM_RELEASE_TRUTH_SCHEMA: &str = "chio.proof.release-truth.v1";
const PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA: &str =
    "chio.proof.first-run.capability-proof.v1";
const PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA: &str = "chio.proof.first-run.guard-report.v1";
const PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA: &str = "chio.proof.first-run.trust-roots.v1";
const PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA: &str = "chio.proof.first-run.command-log.v1";
const PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA: &str = "chio.proof-room.receipt-evidence.v1";
const TRANSACTION_REQUEST_DIGEST_SCHEMA: &str = "chio.request.digest.v1";
const TRANSACTION_RESPONSE_DIGEST_SCHEMA: &str = "chio.response.digest.v1";
const RUNTIME_TERMINAL_RECEIPT_SCHEMA: &str = "chio.runtime.terminal-receipt.v1";
const RUNTIME_TRUSTED_TIME_PROOF_SCHEMA: &str = "chio.runtime.trusted-time-proof.v1";
const PROOF_ROOM_SIGNATURE_KIND: &str = "detached-dsse";
const PROOF_ROOM_DSSE_PAYLOAD_TYPE: &str = "application/vnd.chio.proof-room.bundle.v1+json";
const PROOF_ROOM_BUNDLE_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/bundle.schema.json"
));
const PROOF_ROOM_VERIFIER_REPORT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/verifier-report.schema.json"
));
const PROOF_ROOM_DOCKER_QUICKSTART_EVIDENCE_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/docker-quickstart-evidence.schema.json"
));
const PROOF_ROOM_RELEASE_TRUTH_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/release-truth.schema.json"
));
const PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-capability-proof.schema.json"
));
const PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-guard-report.schema.json"
));
const PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-trust-roots.schema.json"
));
const PROOF_ROOM_FIRST_RUN_COMMAND_LOG_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/first-run-command-log.schema.json"
));
const PROOF_ROOM_RECEIPT_EVIDENCE_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-proof-room/v1/receipt-evidence.schema.json"
));
const TRANSACTION_REQUEST_DIGEST_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-transaction/v1/request-digest.schema.json"
));
const TRANSACTION_RESPONSE_DIGEST_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-transaction/v1/response-digest.schema.json"
));
const RUNTIME_TERMINAL_RECEIPT_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-runtime/v1/terminal-receipt.schema.json"
));
const RUNTIME_TRUSTED_TIME_PROOF_SCHEMA_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../spec/schemas/chio-runtime/v1/trusted-time-proof.schema.json"
));
const PROOF_FIXTURE_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";
const PROOF_FIXTURE_CATALOG_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../fixtures/proof-room/catalog.json"
));
const CLAIM_TRANSACTION_PASSPORT_ROOT_VERIFIED: &str = "claim.transaction.passport_root_verified";
const CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND: &str = "claim.proof_room.verifier_report_bound";
const CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE: &str = "claim.proof_room.allow_and_deny_visible";
const CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND: &str =
    "claim.proof_room.receipt_coverage_matrix_bound";
const CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND: &str = "claim.proof_room.authority_evidence_bound";
const CLAIM_RISK_COMPTROLLER_REPORT_BOUND: &str = "claim.risk.comptroller_report_bound";
const CLAIM_PREFIX_RUNTIME: &str = "claim.runtime.";
const CLAIM_PREFIX_RISK: &str = "claim.risk.";
const CLAIM_PREFIX_ENTERPRISE: &str = "claim.enterprise.";
const CLAIM_PREFIX_AGENT_WEB: &str = "claim.agent_web.";
const CLAIM_PREFIX_TRUST_MARKET: &str = "claim.trust_market.";
const CLAIM_PREFIX_PUBLIC_SETTLEMENT: &str = "claim.public_settlement.";
const CLAIM_PREFIX_SWARM: &str = "claim.swarm.";
const CLAIM_PREFIX_DISCLOSURE: &str = "claim.disclosure.";
const CLAIM_PREFIX_COMMERCE: &str = "claim.commerce.";
const CLAIM_PREFIX_TRANSACTION: &str = "claim.transaction.";
const CLAIM_PREFIX_MARKET: &str = "claim.market.";
const AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV: &str = "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET";
const AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV: &str =
    "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS";
const AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV: &str =
    "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS";
const AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV: &str = "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS";
const AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV: &str =
    "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS";
const TRANSACTION_TRUSTED_ROOT_KEYS_ENV: &str = "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS";
const TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV: &str = "CHIO_TRANSACTION_TRUSTED_CHECKPOINT_KEYS";
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
const PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON: &str =
    "{\"chain_id\":\"eip155:8453\",\"observed_block_number\":12345678,\"observed_block_hash\":\"0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"latest_block_number\":12345701}";
const PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS_ENV: &str =
    "CHIO_PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS";
const PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS_ENV: &str =
    "CHIO_PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS";
const SOURCE_VERIFIER_CLAIM_PREFIXES: [&str; 11] = [
    CLAIM_PREFIX_RUNTIME,
    CLAIM_PREFIX_RISK,
    CLAIM_PREFIX_ENTERPRISE,
    CLAIM_PREFIX_AGENT_WEB,
    CLAIM_PREFIX_TRUST_MARKET,
    CLAIM_PREFIX_PUBLIC_SETTLEMENT,
    CLAIM_PREFIX_SWARM,
    CLAIM_PREFIX_DISCLOSURE,
    CLAIM_PREFIX_COMMERCE,
    CLAIM_PREFIX_TRANSACTION,
    CLAIM_PREFIX_MARKET,
];
pub(crate) fn agent_web_verifier_trust_from_env(
) -> Result<chio_agent_web_interop::AgentWebVerifierTrust, String> {
    let mut trust = match env::var(AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV) {
        Ok(secret) => chio_agent_web_interop::AgentWebVerifierTrust::new()
            .with_standard_webhooks_secret(secret.into_bytes()),
        Err(env::VarError::NotPresent) => chio_agent_web_interop::AgentWebVerifierTrust::new(),
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!(
                "{AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV} must be valid UTF-8"
            ))
        }
    };
    if let Some((now_unix_seconds, max_age_seconds)) = standard_webhooks_replay_window_from_env()? {
        trust = trust.with_standard_webhooks_replay_window(now_unix_seconds, max_age_seconds);
    }
    match env::var(AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV) {
        Ok(keys) => {
            trust = trust.with_trusted_receipt_kernel_keys(parse_public_keys(
                AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV,
                &keys,
            )?);
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!(
                "{AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV} must be valid UTF-8"
            ))
        }
    }
    match env::var(AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV) {
        Ok(keys) => {
            trust = trust.with_trusted_envelope_sidecar_keys(parse_public_keys(
                AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV,
                &keys,
            )?);
        }
        Err(env::VarError::NotPresent) => {}
        Err(env::VarError::NotUnicode(_)) => {
            return Err(format!(
                "{AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV} must be valid UTF-8"
            ))
        }
    }
    Ok(trust)
}

fn standard_webhooks_replay_window_from_env() -> Result<Option<(u64, u64)>, String> {
    match (
        optional_u64_from_env(AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV)?,
        optional_u64_from_env(AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV)?,
    ) {
        (None, None) => Ok(None),
        (Some(now_unix_seconds), Some(max_age_seconds)) => Ok(Some((
            now_unix_seconds,
            max_age_seconds,
        ))),
        (None, Some(_)) => Err(format!(
            "{AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV} must be set with {AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV}"
        )),
        (Some(_), None) => Err(format!(
            "{AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV} must be set with {AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV}"
        )),
    }
}

fn optional_u64_from_env(env_name: &str) -> Result<Option<u64>, String> {
    match env::var(env_name) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|error| format!("{env_name} must be a u64: {error}")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn parse_public_keys(env_name: &str, keys: &str) -> Result<Vec<PublicKey>, String> {
    if keys.trim().is_empty() {
        return Err(format!(
            "{env_name} must contain comma-separated public keys"
        ));
    }

    keys.split(',')
        .map(|key| {
            let key = key.trim();
            if key.is_empty() {
                return Err(format!("{env_name} must not contain empty public keys"));
            }
            PublicKey::from_hex(key)
                .map_err(|error| format!("{env_name} contains invalid public key: {error}"))
        })
        .collect()
}

pub(crate) fn trust_market_trusted_authority_keys_from_env() -> Result<Vec<PublicKey>, String> {
    match env::var(TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV) {
        Ok(keys) => parse_public_keys(TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV, &keys),
        Err(env::VarError::NotPresent) => Err(format!(
            "{TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV} must pin trusted market authority keys"
        )),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV} must be valid UTF-8"
        )),
    }
}

pub(crate) fn enterprise_trusted_approval_signer_keys_from_env() -> Result<Vec<PublicKey>, String> {
    required_public_keys_from_env(
        ENTERPRISE_TRUSTED_APPROVAL_KEYS_ENV,
        "enterprise approval signer",
    )
}

pub(crate) fn enterprise_trusted_risk_comptroller_signer_keys_from_env(
) -> Result<Vec<PublicKey>, String> {
    required_public_keys_from_env(
        ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS_ENV,
        "enterprise risk comptroller signer",
    )
}

pub(crate) fn enterprise_trusted_receipt_kernel_keys_from_env() -> Result<Vec<PublicKey>, String> {
    required_public_keys_from_env(
        ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS_ENV,
        "enterprise receipt kernel",
    )
}

pub(crate) fn commerce_trusted_provider_keys_from_env() -> Result<Vec<PublicKey>, String> {
    required_public_keys_from_env(COMMERCE_TRUSTED_PROVIDER_KEYS_ENV, "commerce provider")
}

pub(crate) fn commerce_trusted_event_authority_receipt_kernel_keys_from_env(
) -> Result<Vec<PublicKey>, String> {
    required_public_keys_from_env(
        COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS_ENV,
        "commerce event authority receipt kernel",
    )
}

pub(crate) fn commerce_trusted_payment_signer_keys_from_env() -> Result<Vec<PublicKey>, String> {
    required_public_keys_from_env(
        COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS_ENV,
        "commerce payment signer",
    )
}

pub(crate) fn disclosure_lineage_verifier_trust_from_env(
) -> Result<chio_disclosure_lineage::DisclosureLineageVerifierTrust, String> {
    Ok(
        chio_disclosure_lineage::DisclosureLineageVerifierTrust::new()
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

fn required_public_keys_from_env(env_name: &str, label: &str) -> Result<Vec<PublicKey>, String> {
    match env::var(env_name) {
        Ok(keys) => parse_public_keys(env_name, &keys),
        Err(env::VarError::NotPresent) => Err(format!("{env_name} must pin trusted {label} keys")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn parse_string_list(env_name: &str, values: &str) -> Result<Vec<String>, String> {
    if values.trim().is_empty() {
        return Err(format!("{env_name} must contain comma-separated values"));
    }

    values
        .split(',')
        .map(|value| {
            let value = value.trim();
            if value.is_empty() {
                return Err(format!("{env_name} must not contain empty values"));
            }
            Ok(value.to_string())
        })
        .collect()
}

fn required_string_list_from_env(env_name: &str, label: &str) -> Result<Vec<String>, String> {
    match env::var(env_name) {
        Ok(values) => parse_string_list(env_name, &values),
        Err(env::VarError::NotPresent) => Err(format!("{env_name} must pin trusted {label}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn required_string_from_env(env_name: &str, label: &str) -> Result<String, String> {
    match env::var(env_name) {
        Ok(value) => {
            let value = value.trim();
            if value.is_empty() {
                Err(format!("{env_name} must pin trusted {label}"))
            } else {
                Ok(value.to_string())
            }
        }
        Err(env::VarError::NotPresent) => Err(format!("{env_name} must pin trusted {label}")),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn optional_bool_from_env(env_name: &str) -> Result<bool, String> {
    match env::var(env_name) {
        Ok(value) => match value.trim() {
            "1" | "true" | "TRUE" | "True" => Ok(true),
            "0" | "false" | "FALSE" | "False" => Ok(false),
            _ => Err(format!("{env_name} must be true or false")),
        },
        Err(env::VarError::NotPresent) => Ok(false),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn optional_u32_from_env(env_name: &str) -> Result<Option<u32>, String> {
    match env::var(env_name) {
        Ok(value) => value
            .trim()
            .parse::<u32>()
            .map(Some)
            .map_err(|error| format!("{env_name} must be a u32: {error}")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn optional_public_settlement_independent_chain_head_from_env(
    proof_bundle: &chio_web3::settlement_proof::PublicSettlementProofBundle,
) -> Result<Option<chio_web3::settlement_proof::PublicSettlementIndependentChainHead>, String> {
    let head_from_json = match env::var(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV) {
        Ok(value) => serde_json::from_str(value.trim())
            .map(Some)
            .map_err(|error| {
                format!(
                "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV} must be valid JSON: {error}"
            )
            }),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV} must be valid UTF-8"
        )),
    }?;
    if head_from_json.is_some() {
        return Ok(head_from_json);
    }

    match env::var(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV) {
        Ok(value) => {
            fetch_public_settlement_independent_chain_head_from_rpc(value.trim(), proof_bundle)
                .map(Some)
        }
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must be valid UTF-8"
        )),
    }
}

fn fetch_public_settlement_independent_chain_head_from_rpc(
    url: &str,
    proof_bundle: &chio_web3::settlement_proof::PublicSettlementProofBundle,
) -> Result<chio_web3::settlement_proof::PublicSettlementIndependentChainHead, String> {
    if url.is_empty() {
        return Err(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must not be empty"
        ));
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

fn public_settlement_rpc_egress_contract(url: &str) -> Result<HttpEgressContract, String> {
    let parsed = reqwest::Url::parse(url).map_err(|error| {
        format!("{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must be a valid URL: {error}")
    })?;
    let host = parsed.host_str().ok_or_else(|| {
        format!("{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} must include a host")
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
        format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} rejected by HttpEgressContract: {error}"
        )
    })?;
    Ok(contract)
}

fn public_settlement_rpc_call(
    egress_contract: &HttpEgressContract,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let request_body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let response =
        dispatch_public_settlement_rpc(egress_contract, url, &request_body).map_err(|reason| {
            format!("{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} {reason}")
        })?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} returned HTTP {status}"
        ));
    }
    let body = serde_json::from_slice::<serde_json::Value>(response.body()).map_err(|error| {
        format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} returned invalid JSON: {error}"
        )
    })?;
    if let Some(error) = body.get("error") {
        return Err(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} returned JSON-RPC error: {error}"
        ));
    }
    body.get("result").cloned().ok_or_else(|| {
        format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV} {method} response missing result"
        )
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

fn parse_json_rpc_hex_u64(value: &serde_json::Value, label: &str) -> Result<u64, String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("{label} must be a hex string"))?;
    let hex = raw
        .strip_prefix("0x")
        .ok_or_else(|| format!("{label} must start with 0x"))?;
    u64::from_str_radix(hex, 16).map_err(|error| format!("{label} is not a u64: {error}"))
}

fn required_json_rpc_string<'a>(
    value: &'a serde_json::Value,
    field: &str,
    label: &str,
) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("{label}.{field} must be a string"))
}

pub(crate) fn public_settlement_verifier_trust_from_env(
    proof_bundle: &chio_web3::settlement_proof::PublicSettlementProofBundle,
) -> Result<chio_web3::settlement_proof::PublicSettlementVerifierTrust, String> {
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

pub(crate) fn transaction_trusted_root_keys_from_env() -> Result<Vec<PublicKey>, String> {
    match env::var(TRANSACTION_TRUSTED_ROOT_KEYS_ENV) {
        Ok(keys) => parse_public_keys(TRANSACTION_TRUSTED_ROOT_KEYS_ENV, &keys),
        Err(env::VarError::NotPresent) => Err(format!(
            "{TRANSACTION_TRUSTED_ROOT_KEYS_ENV} must pin trusted transaction root keys"
        )),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{TRANSACTION_TRUSTED_ROOT_KEYS_ENV} must be valid UTF-8"
        )),
    }
}

pub(crate) fn transaction_trusted_checkpoint_keys_from_env() -> Result<Vec<PublicKey>, String> {
    match env::var(TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV) {
        Ok(keys) => parse_public_keys(TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV, &keys),
        Err(env::VarError::NotPresent) => Ok(Vec::new()),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{TRANSACTION_TRUSTED_CHECKPOINT_KEYS_ENV} must be valid UTF-8"
        )),
    }
}
pub(crate) fn runtime_trust_from_env(
) -> Result<chio_transaction_passport::RuntimeSecurityTrust, String> {
    let trusted_passport_signer_keys = transaction_trusted_root_keys_from_env()?;
    let trusted_root_signer_keys = match env::var(RUNTIME_TRUSTED_ROOT_KEYS_ENV) {
        Ok(keys) => parse_public_keys(RUNTIME_TRUSTED_ROOT_KEYS_ENV, &keys),
        Err(env::VarError::NotPresent) => Err(format!(
            "{RUNTIME_TRUSTED_ROOT_KEYS_ENV} must pin trusted runtime root keys"
        )),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{RUNTIME_TRUSTED_ROOT_KEYS_ENV} must be valid UTF-8"
        )),
    }?;
    Ok(chio_transaction_passport::RuntimeSecurityTrust {
        trusted_passport_signer_keys,
        trusted_root_signer_keys,
    })
}

pub(crate) fn swarm_trusted_witness_keys_from_env() -> Result<Vec<PublicKey>, String> {
    match env::var(SWARM_TRUSTED_WITNESS_KEYS_ENV) {
        Ok(keys) => parse_public_keys(SWARM_TRUSTED_WITNESS_KEYS_ENV, &keys),
        Err(env::VarError::NotPresent) => Err(format!(
            "{SWARM_TRUSTED_WITNESS_KEYS_ENV} must pin trusted swarm witness keys"
        )),
        Err(env::VarError::NotUnicode(_)) => Err(format!(
            "{SWARM_TRUSTED_WITNESS_KEYS_ENV} must be valid UTF-8"
        )),
    }
}

pub(crate) fn swarm_trusted_witness_keys_for_bundle(
    _bundle: &chio_swarm_authority::SwarmAuthorityBundle,
) -> Result<Vec<PublicKey>, String> {
    swarm_trusted_witness_keys_from_env()
}

pub(crate) fn proof_room_trusted_bundle_signer_keys_from_env() -> Result<BTreeSet<String>, String> {
    proof_room_public_key_set_from_env(PROOF_ROOM_TRUSTED_BUNDLE_SIGNER_KEYS_ENV)
}

pub(crate) fn proof_room_trusted_receipt_kernel_keys_from_env() -> Result<BTreeSet<String>, String>
{
    proof_room_public_key_set_from_env(PROOF_ROOM_TRUSTED_RECEIPT_KERNEL_KEYS_ENV)
}

fn proof_room_public_key_set_from_env(env_name: &str) -> Result<BTreeSet<String>, String> {
    match env::var(env_name) {
        Ok(keys) => parse_proof_room_public_key_set(env_name, &keys),
        Err(env::VarError::NotPresent) => Ok(BTreeSet::new()),
        Err(env::VarError::NotUnicode(_)) => Err(format!("{env_name} must be valid UTF-8")),
    }
}

fn parse_proof_room_public_key_set(env_name: &str, keys: &str) -> Result<BTreeSet<String>, String> {
    if keys.trim().is_empty() {
        return Err(format!(
            "{env_name} must contain comma-separated public keys"
        ));
    }

    keys.split(',')
        .map(|key| {
            let key = key.trim();
            if key.is_empty() {
                return Err(format!("{env_name} must not contain empty public keys"));
            }
            PublicKey::from_hex(key)
                .map(|key| key.to_hex())
                .map_err(|error| format!("{env_name} contains invalid public key: {error}"))
        })
        .collect()
}
const ENTERPRISE_APPROVAL_CASE_SCHEMA: &str = "chio.enterprise.approval-case.v1";
const ENTERPRISE_CONTROL_EVIDENCE_MAP_SCHEMA: &str = "chio.enterprise.control-evidence-map.v1";
const ENTERPRISE_DATA_GOVERNANCE_REPORT_SCHEMA: &str = "chio.enterprise.data-governance-report.v1";
const ENTERPRISE_EVIDENCE_EXPORT_BUNDLE_SCHEMA: &str = "chio.enterprise.evidence-export-bundle.v1";
const ENTERPRISE_TELEMETRY_PROJECTION_SCHEMA: &str = "chio.enterprise.telemetry-projection.v1";
const RISK_ADJUDICATION_JURISDICTION_RECEIPT_SCHEMA: &str =
    "chio.risk.adjudication-jurisdiction-receipt.v1";
const RISK_GUARANTEE_DECISION_SCHEMA: &str = "chio.risk.guarantee-decision.v1";
const COMMERCE_PROVIDER_SELECTION_REPORT_SCHEMA: &str =
    "chio.commerce.provider-selection-report.v1";
const CHIO_RECEIPT_SCHEMA: &str = "chio.receipt.v1";
const WEB3_SETTLEMENT_EXECUTION_RECEIPT_SCHEMA: &str = "chio.web3-settlement-execution-receipt.v2";
const WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA: &str = "chio.web3-settlement-proof-bundle.v1";

const REQUIRED_AUTHORITY_ARTIFACTS: &[(&str, &str)] = &[
    (
        "artifacts/authority/capability-proof.json",
        PROOF_ROOM_FIRST_RUN_CAPABILITY_PROOF_SCHEMA,
    ),
    (
        "artifacts/authority/guard-report.json",
        PROOF_ROOM_FIRST_RUN_GUARD_REPORT_SCHEMA,
    ),
    (
        "artifacts/authority/trust-roots.json",
        PROOF_ROOM_FIRST_RUN_TRUST_ROOTS_SCHEMA,
    ),
];
const REQUIRED_RECEIPT_ARTIFACTS: &[&str] = &[
    "artifacts/receipts/allow-receipt.json",
    "artifacts/receipts/denial-receipt.json",
];

const ALLOWED_BUNDLE_CLAIMS: &[&str] = &[
    CLAIM_TRANSACTION_PASSPORT_ROOT_VERIFIED,
    CLAIM_PROOF_ROOM_VERIFIER_REPORT_BOUND,
    CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE,
    CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND,
    CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND,
];
const REQUIRED_FIRST_RUN_PROOF_ROOM_CLAIMS: &[&str] = &[
    CLAIM_PROOF_ROOM_ALLOW_AND_DENY_VISIBLE,
    CLAIM_PROOF_ROOM_RECEIPT_COVERAGE_MATRIX_BOUND,
    CLAIM_PROOF_ROOM_AUTHORITY_EVIDENCE_BOUND,
];
const REQUIRED_RECEIPT_COVERAGE_CATEGORIES: &[&str] = &[
    "runtime_terminal_allow",
    "runtime_terminal_denial",
    "runtime_terminal_failure",
];

struct EmbeddedProofFixtureFile {
    path: &'static str,
    contents: &'static [u8],
}

include!(concat!(env!("OUT_DIR"), "/proof_fixture_files.rs"));

#[derive(Debug, thiserror::Error)]
pub enum ProofRoomError {
    #[error("{0}")]
    Validation(String),
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: {source}")]
    Json {
        context: &'static str,
        #[source]
        source: serde_json::Error,
    },
    #[error("proof-room.listen.invalid: {0}")]
    ListenAddress(std::net::AddrParseError),
    #[error("proof-room.serve: {0}")]
    Serve(std::io::Error),
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomBundleManifest {
    schema: String,
    bundle_id: String,
    fixture_id: String,
    hash_algorithm: String,
    transaction_passport_ref: ProofRoomArtifactRef,
    evidence_graph_ref: ProofRoomArtifactRef,
    verifier_report_ref: ProofRoomArtifactRef,
    #[serde(default)]
    proof_room_verifier_report_ref: Option<ProofRoomArtifactRef>,
    #[serde(default)]
    artifacts: Vec<ProofRoomArtifactRef>,
    claims: Vec<ProofRoomClaim>,
    receipt_coverage: Vec<ProofRoomReceiptCoverage>,
    negative_cases: Vec<ProofRoomNegativeCase>,
    #[serde(default)]
    signature: Option<ProofRoomBundleSignature>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomBundleSignature {
    kind: String,
    signature_ref: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomDetachedDsse {
    #[serde(rename = "payloadType")]
    payload_type: String,
    #[serde(rename = "payloadRef")]
    payload_ref: ProofRoomArtifactRef,
    signatures: Vec<ProofRoomDsseSignature>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomDsseSignature {
    keyid: String,
    sig: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomTrustRoots {
    roots: Vec<ProofRoomTrustedRoot>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomTrustedRoot {
    key_id: String,
    key_digest: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomClaim {
    claim_id: String,
    #[serde(default)]
    required_artifacts: Vec<String>,
    result: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomReceiptCoverage {
    category: String,
    status: String,
    #[serde(default)]
    artifact_path: Option<String>,
    #[serde(default)]
    terminal_status: Option<String>,
    #[serde(default)]
    exclusion_reason: Option<String>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomNegativeCase {
    id: String,
    path: String,
    expected_failure_code: String,
    #[serde(default)]
    observed_failure_code: Option<String>,
    #[serde(default)]
    verifier_context: ProofRoomVerifierContext,
}

#[derive(Debug, Default, serde::Deserialize, serde::Serialize)]
struct ProofRoomVerifierContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    public_settlement_independent_chain_head: Option<PublicSettlementIndependentChainHeadContext>,
}

#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum PublicSettlementIndependentChainHeadContext {
    Missing,
    BlockHashMismatch,
}

struct EnvVarOverride {
    name: &'static str,
    previous: Option<OsString>,
}

impl EnvVarOverride {
    fn remove(name: &'static str) -> Self {
        let previous = env::var_os(name);
        env::remove_var(name);
        Self { name, previous }
    }

    fn set(name: &'static str, value: &'static str) -> Self {
        let previous = env::var_os(name);
        env::set_var(name, value);
        Self { name, previous }
    }
}

impl Drop for EnvVarOverride {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => env::set_var(self.name, value),
            None => env::remove_var(self.name),
        }
    }
}

impl ProofRoomVerifierContext {
    fn apply(&self) -> Vec<EnvVarOverride> {
        match self.public_settlement_independent_chain_head {
            Some(PublicSettlementIndependentChainHeadContext::Missing) => vec![
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV),
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV),
            ],
            Some(PublicSettlementIndependentChainHeadContext::BlockHashMismatch) => vec![
                EnvVarOverride::set(
                    PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV,
                    PUBLIC_SETTLEMENT_REORGED_INDEPENDENT_CHAIN_HEAD_JSON,
                ),
                EnvVarOverride::remove(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_RPC_URL_ENV),
            ],
            None => Vec::new(),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomArtifactRef {
    path: String,
    sha256: String,
    schema: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomNegativeDescriptor {
    #[serde(default)]
    schema: String,
    id: String,
    #[serde(default = "default_base_manifest")]
    base_manifest: String,
    mutation: serde_json::Value,
    expected_failure_code: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomVerifierReport {
    schema: String,
    verdict: String,
    bundle_id: String,
    fixture_id: String,
    source_verifier_report_ref: ProofRoomArtifactRef,
    ui_verdict_source: String,
    rendered_claims: Vec<ProofRoomRenderedClaim>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomRenderedClaim {
    claim_id: String,
    source: String,
    verdict: String,
}

#[derive(Debug, serde::Serialize)]
struct ProofRoomDoctorReport<'a> {
    schema: &'a str,
    verdict: &'a str,
    bundle: &'a str,
    bundle_id: &'a str,
    fixture_id: &'a str,
    verifier_report_ref: &'a ProofRoomArtifactRef,
    receipt_coverage: &'a [ProofRoomReceiptCoverage],
    negative_cases: &'a [ProofRoomNegativeCase],
}

#[derive(Debug, serde::Serialize)]
struct ProofRoomFixtureCatalog {
    schema: &'static str,
    fixtures: Vec<ProofRoomFixtureCatalogEntry>,
    available_fixtures: Vec<ProofRoomAvailableFixture>,
}

#[derive(Debug, serde::Serialize)]
struct ProofRoomFixtureCatalogEntry {
    fixture_id: String,
    bundle_id: String,
    verdict: String,
    manifest_path: &'static str,
    load_report_path: String,
    negative_cases: Vec<ProofRoomFixtureCatalogNegativeCase>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomAvailableFixtureCatalog {
    schema: String,
    fixtures: Vec<ProofRoomAvailableFixture>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomAvailableFixture {
    id: String,
    kind: String,
    path: String,
    description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    negative_cases: Vec<ProofRoomFixtureCatalogNegativeCase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verifier_report: Option<ProofRoomAvailableFixtureReport>,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ProofRoomAvailableFixtureReport {
    path: String,
    status: u16,
    verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
struct ProofRoomFixtureCatalogNegativeCase {
    id: String,
    path: String,
    expected_failure_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_failure_code: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomAvailableFixtureNegativeDescriptor {
    #[serde(default)]
    base_fixture: Option<String>,
    expected_failure_code: String,
}

#[derive(Debug, serde::Deserialize)]
struct ProofRoomCatalogLoadReport {
    verdict: String,
}

pub fn verify_proof_room_bundle(manifest_path: &Path) -> Result<(), ProofRoomError> {
    verify_proof_room_bundle_inner(manifest_path).map_err(ProofRoomError::Validation)
}

pub fn build_proof_room_source_verifier_report(
    bundle_root: &Path,
    transaction_passport_path: &Path,
) -> Result<serde_json::Value, String> {
    source_verifier::verify_transaction_passport_family_report_with_options(
        bundle_root,
        transaction_passport_path,
        true,
    )
}

pub fn validate_proof_room_bundle_relative_path(relative_path: &str) -> Result<(), String> {
    validate_bundle_relative_path(relative_path)
}

pub fn verify_proof_room_quickstart(
    bundle: &Path,
    doctor_report: Option<&Path>,
) -> Result<(), ProofRoomError> {
    let manifest_path = bundle.join("manifest.json");
    verify_proof_room_bundle(&manifest_path)?;
    if let Some(report_path) = doctor_report {
        write_doctor_report(report_path, bundle)?;
    }
    Ok(())
}
