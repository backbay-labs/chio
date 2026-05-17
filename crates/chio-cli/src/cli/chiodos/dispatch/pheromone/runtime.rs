use crate::CliError;
use std::path::Path;
use super::{
    read_utf8_json_file,
    unix_now_ms,
    write_json_string,
};


pub(crate) fn cmd_chiodos_pheromone_receive(
    batch: &Path,
    transit_policy: &Path,
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
    store: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let batch_json = read_utf8_json_file(batch, "Chiodos pheromone gossip batch")?;
    let batch: chio_federation::PheromoneGossipBatch = serde_json::from_str(&batch_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone batch: {error}")))?;
    let policy_json = read_utf8_json_file(transit_policy, "Chiodos pheromone transit policy")?;
    let now_unix_ms = now_unix_ms.unwrap_or(batch.flushed_at_unix_ms);
    let (transit_policy, receiver_config) =
        chio_pheromone_runtime::runtime_policy_from_json(&policy_json, now_unix_ms).map_err(
            |error| {
                CliError::cli_other_error(format!("Chiodos pheromone runtime policy: {error}"))
            },
        )?;
    let package_json = read_utf8_json_file(proof_package, "Chiodos proof package")?;
    let package = chio_chiodos::proof_package_from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos package parse: {error}")))?;
    let trust_bundle_json = read_utf8_json_file(trust_bundle, "Chiodos verifier trust bundle")?;
    let trust_bundle = chio_chiodos::verifier_trust_bundle_from_json(&trust_bundle_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos trust bundle parse: {error}"))
        })?;
    let context_json = read_utf8_json_file(context, "Chiodos verification context")?;
    let context = chio_chiodos::verification_context_from_json(&context_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos context parse: {error}")))?;
    let resolver = chio_pheromone_runtime::VerifiedChiodosWorkflowResolver::from_verified_package(
        &package,
        &trust_bundle,
        &context,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos workflow resolver: {error}")))?;
    let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone store: {error}")))?;
    let receiver = chio_pheromone_runtime::PheromoneReceiver::new(
        store,
        resolver,
        receiver_config,
    );
    let receive_report = receiver
        .receive_batch(&batch, &transit_policy)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone receive: {error}")))?;
    let report_json = serde_json::to_string_pretty(&receive_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))?;
    if receive_report.accepted {
        Ok(())
    } else {
        let failure = receive_report
            .frames
            .iter()
            .find(|frame| !frame.accepted)
            .map_or_else(
                || "unknown pheromone receiver rejection".to_string(),
                |frame| format!("{}: {}", frame.code, frame.detail),
            );
        Err(CliError::cli_other_error(format!(
            "Chiodos pheromone receive rejected batch: {failure}"
        )))
    }
}

pub(crate) fn cmd_chiodos_pheromone_query(
    store: &Path,
    subject_class: &str,
    namespace: &str,
    reputation_epoch: u64,
    peer_weights: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let store = chio_pheromone_runtime::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone store: {error}")))?;
    let weights_json = read_utf8_json_file(peer_weights, "Chiodos pheromone peer weights")?;
    let weights = chio_pheromone_runtime::peer_weights_from_json(&weights_json)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos peer weights: {error}")))?;
    let validation_context = chio_pheromone::PheromoneValidationContext {
        now_unix_ms: now_unix_ms.unwrap_or_else(unix_now_ms),
        replay_window_ms: 0,
        active_peers_in_treaty: 0,
        known_reputation_epochs: vec![reputation_epoch],
        passports: Vec::new(),
        kernel_public_keys: Vec::new(),
        subject_classes: Vec::new(),
        max_deposits_per_pair: 0,
    };
    let concentration = chio_pheromone_runtime::PheromoneRuntimeStore::query_concentration(
        &store,
        subject_class,
        namespace,
        validation_context.now_unix_ms,
        reputation_epoch,
        &validation_context,
        &weights,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone query: {error}")))?;
    let query_report = chio_pheromone_runtime::PheromoneQueryReport {
        schema: chio_pheromone_runtime::PHEROMONE_QUERY_REPORT_SCHEMA.to_string(),
        accepted: true,
        concentration,
    };
    let report_json = serde_json::to_string_pretty(&query_report)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))
}
