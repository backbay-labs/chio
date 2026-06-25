use super::CliError;

const AGENT_WEB_STANDARD_WEBHOOKS_SECRET_ENV: &str = "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_SECRET";
const AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS_ENV: &str =
    "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_NOW_UNIX_SECONDS";
const AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS_ENV: &str =
    "CHIO_AGENT_WEB_STANDARD_WEBHOOKS_MAX_AGE_SECONDS";
const AGENT_WEB_TRUSTED_KERNEL_KEYS_ENV: &str = "CHIO_AGENT_WEB_TRUSTED_KERNEL_KEYS";
const AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS_ENV: &str =
    "CHIO_AGENT_WEB_TRUSTED_ENVELOPE_SIDECAR_KEYS";
const TRANSACTION_TRUSTED_ROOT_KEYS_ENV: &str = "CHIO_TRANSACTION_TRUSTED_ROOT_KEYS";
const RUNTIME_TRUSTED_ROOT_KEYS_ENV: &str = "CHIO_RUNTIME_TRUSTED_ROOT_KEYS";
const ENTERPRISE_TRUSTED_APPROVAL_KEYS_ENV: &str = "CHIO_ENTERPRISE_TRUSTED_APPROVAL_KEYS";
const ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS_ENV: &str =
    "CHIO_ENTERPRISE_TRUSTED_RISK_COMPTROLLER_KEYS";
const ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS_ENV: &str =
    "CHIO_ENTERPRISE_TRUSTED_RECEIPT_KERNEL_KEYS";
const COMMERCE_TRUSTED_PROVIDER_KEYS_ENV: &str = "CHIO_COMMERCE_TRUSTED_PROVIDER_KEYS";
const COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS_ENV: &str =
    "CHIO_COMMERCE_TRUSTED_EVENT_AUTHORITY_RECEIPT_KERNEL_KEYS";
const COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS_ENV: &str =
    "CHIO_COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS";
const TRUST_MARKET_TRUSTED_AUTHORITY_KEYS_ENV: &str = "CHIO_TRUST_MARKET_TRUSTED_AUTHORITY_KEYS";
const SWARM_TRUSTED_WITNESS_KEYS_ENV: &str = "CHIO_SWARM_TRUSTED_WITNESS_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_CAPITAL_SIGNER_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ANCHOR_KERNEL_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_BENEFICIARY_IDENTITY_KEYS";
const PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_TRUSTED_ORACLE_KEYS";
const PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS_ENV: &str = "CHIO_PUBLIC_SETTLEMENT_ALLOWED_CHAIN_IDS";
const PUBLIC_SETTLEMENT_MAINNET_BLOCKED_ENV: &str = "CHIO_PUBLIC_SETTLEMENT_MAINNET_BLOCKED";
const PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_MINIMUM_CONFIRMATIONS";
const PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV: &str =
    "CHIO_PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON";

pub(super) fn agent_web_verifier_trust_from_env(
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
    if let Some((now_unix_seconds, max_age_seconds)) =
        standard_webhooks_replay_window_from_env()?
    {
        trust = trust.with_standard_webhooks_replay_window(now_unix_seconds, max_age_seconds);
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
) -> Result<Option<chio_web3::settlement_proof::PublicSettlementIndependentChainHead>, CliError> {
    match std::env::var(PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV) {
        Ok(value) => serde_json::from_str(value.trim()).map(Some).map_err(|error| {
            CliError::cli_other_error(format!(
                "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV} must be valid JSON: {error}"
            ))
        }),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(CliError::cli_other_error(format!(
            "{PUBLIC_SETTLEMENT_INDEPENDENT_CHAIN_HEAD_JSON_ENV} must be valid UTF-8"
        ))),
    }
}

pub(super) fn public_settlement_verifier_trust_from_env(
) -> Result<chio_web3::settlement_proof::PublicSettlementVerifierTrust, CliError> {
    Ok(chio_web3::settlement_proof::PublicSettlementVerifierTrust {
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
        independent_chain_head: optional_public_settlement_independent_chain_head_from_env()?,
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
    required_public_keys_from_env(COMMERCE_TRUSTED_PAYMENT_SIGNER_KEYS_ENV, "commerce payment signer")
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
