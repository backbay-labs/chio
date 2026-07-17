use std::path::Path;

use chio_core::crypto::Keypair;

use crate::CliError;

use super::super::{read_utf8_json_file, write_json_string, write_pretty_json};

pub(crate) fn cmd_chio_runtime_sign_trust_input(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_runtime::RuntimeVerifierTrustBundleV4 =
        serde_json::from_str(&read_utf8_json_file(body, "Chio runtime trust input body")?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime trust input body parse: {error}"))
            })?;
    let seed_hex = read_utf8_json_file(signing_seed_file, "Chio runtime trust signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime trust signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| CliError::cli_other_error(format!("Chio runtime trust input signing: {error}")),
    )?;
    write_pretty_json(out, &signed, "Chio runtime trust input")
}

pub(crate) fn cmd_chio_runtime_sign_policy(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_runtime::RuntimePheromonePolicy = serde_json::from_str(&read_utf8_json_file(
        body,
        "Chio runtime pheromone policy body",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime pheromone policy parse: {error}"))
    })?;
    let seed_hex = read_utf8_json_file(signing_seed_file, "Chio runtime policy signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime policy signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| {
            CliError::cli_other_error(format!("Chio runtime pheromone policy signing: {error}"))
        },
    )?;
    write_pretty_json(out, &signed, "Chio runtime pheromone policy")
}

pub(crate) fn cmd_chio_runtime_sign_peer_weights(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: chio_runtime::RuntimePeerWeights = serde_json::from_str(&read_utf8_json_file(
        body,
        "Chio runtime peer weights body",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime peer weights parse: {error}"))
    })?;
    let seed_hex =
        read_utf8_json_file(signing_seed_file, "Chio runtime peer weights signing seed")?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime peer weights signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| CliError::cli_other_error(format!("Chio runtime peer weights signing: {error}")),
    )?;
    write_pretty_json(out, &signed, "Chio runtime peer weights")
}

pub(crate) fn cmd_chio_runtime_sign_pheromone_query_report(
    body: &Path,
    signing_seed_file: &Path,
    out: &Path,
) -> Result<(), CliError> {
    let body: serde_json::Value = serde_json::from_str(&read_utf8_json_file(
        body,
        "Chio pheromone query report body",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio pheromone query report body parse: {error}"))
    })?;
    chio_runtime::runtime_pheromone_advisory_from_query_report_json(
        &serde_json::to_string(&body).map_err(|error| {
            CliError::cli_other_error(format!("Chio pheromone query report validation: {error}"))
        })?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio pheromone query report validation: {error}"))
    })?;
    let seed_hex = read_utf8_json_file(
        signing_seed_file,
        "Chio pheromone query report signing seed",
    )?;
    let keypair = Keypair::from_seed_hex(seed_hex.trim()).map_err(|error| {
        CliError::cli_other_error(format!("Chio pheromone query report signing seed: {error}"))
    })?;
    let signed = chio_core::receipt::lineage::SignedExportEnvelope::sign(body, &keypair).map_err(
        |error| CliError::cli_other_error(format!("Chio pheromone query report signing: {error}")),
    )?;
    write_pretty_json(out, &signed, "Chio pheromone query report")
}

pub(crate) fn cmd_chio_runtime_peer_weights_hash(body: &Path, out: &Path) -> Result<(), CliError> {
    let body: chio_runtime::RuntimePeerWeights = serde_json::from_str(&read_utf8_json_file(
        body,
        "Chio runtime peer weights body",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime peer weights parse: {error}"))
    })?;
    let hash = chio_runtime::runtime_peer_weights_sha256(&body).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime peer weights hash: {error}"))
    })?;
    write_json_string(out, &format!("{hash}\n"))
}
