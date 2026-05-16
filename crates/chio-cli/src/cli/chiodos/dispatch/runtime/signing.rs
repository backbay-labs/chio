use std::path::Path;

use chio_core::crypto::Keypair;

use crate::CliError;

use super::super::{read_utf8_json_file, write_json_string, write_pretty_json};

pub(crate) fn cmd_chiodos_runtime_sign_trust_input(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimeVerifierTrustBundleV4 =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime trust input body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime trust input body parse: {error}"))
        })?;
    let seed_hex = read_utf8_json_file(signing_seed_file, "Chiodos runtime trust signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime trust signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime trust input signing: {error}"))
    })?;
    write_pretty_json(out, &signed, "Chiodos runtime trust input")
}

pub(crate) fn cmd_chiodos_runtime_sign_policy(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimePheromonePolicy =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime pheromone policy body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime pheromone policy parse: {error}"))
        })?;
    let seed_hex = read_utf8_json_file(signing_seed_file, "Chiodos runtime policy signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime policy signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime pheromone policy signing: {error}"))
    })?;
    write_pretty_json(out, &signed, "Chiodos runtime pheromone policy")
}

pub(crate) fn cmd_chiodos_runtime_sign_peer_weights(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimePeerWeights =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime peer weights body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime peer weights parse: {error}"))
        })?;
    let seed_hex =
        read_utf8_json_file(signing_seed_file, "Chiodos runtime peer weights signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos runtime peer weights signing seed: {error}"
        ))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime peer weights signing: {error}"))
    })?;
    write_pretty_json(out, &signed, "Chiodos runtime peer weights")
}

pub(crate) fn cmd_chiodos_runtime_sign_pheromone_query_report(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: serde_json::Value =
        serde_json::from_str(&read_utf8_json_file(body, "Chiodos pheromone query report body")?)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos pheromone query report body parse: {error}"
                ))
            })?;
    chio_chiodos_runtime::runtime_pheromone_advisory_from_query_report_json(
        &serde_json::to_string(&body).map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos pheromone query report validation: {error}"
            ))
        })?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos pheromone query report validation: {error}"
        ))
    })?;
    let seed_hex = read_utf8_json_file(
        signing_seed_file,
        "Chiodos pheromone query report signing seed",
    )?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos pheromone query report signing seed: {error}"
        ))
    })?;
    let signed = chio_core::receipt::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "Chiodos pheromone query report signing: {error}"
            ))
        },
    )?;
    write_pretty_json(out, &signed, "Chiodos pheromone query report")
}

pub(crate) fn cmd_chiodos_runtime_peer_weights_hash(body: &Path, out: &Path) -> Result<(), CliError> {
    let body: chio_chiodos_runtime::RuntimePeerWeights =
        serde_json::from_str(&read_utf8_json_file(
            body,
            "Chiodos runtime peer weights body",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime peer weights parse: {error}"))
        })?;
    let hash = chio_chiodos_runtime::runtime_peer_weights_sha256(&body).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime peer weights hash: {error}"))
    })?;
    write_json_string(out, &format!("{hash}\n"))
}
