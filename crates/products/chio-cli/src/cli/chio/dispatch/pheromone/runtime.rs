use super::{
    load_chio_verified_workflow_resolver, load_chio_workflow_verifier_trust_bundle,
    read_utf8_json_file, unix_now_ms, write_json_string,
};
use crate::CliError;
use std::path::Path;

pub(crate) fn cmd_chio_pheromone_receive(
    batch: &Path,
    transit_policy: &Path,
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
    store: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let batch_json = read_utf8_json_file(batch, "Chio pheromone gossip batch")?;
    let batch: chio_federation::pheromone_gossip::PheromoneGossipBatch =
        serde_json::from_str(&batch_json)
            .map_err(|error| CliError::cli_other_error(format!("Chio pheromone batch: {error}")))?;
    let policy_json = read_utf8_json_file(transit_policy, "Chio pheromone transit policy")?;
    let now_unix_ms = now_unix_ms.unwrap_or(batch.flushed_at_unix_ms);
    let workflow_trust_bundle = load_chio_workflow_verifier_trust_bundle(trust_bundle)?;
    let (transit_policy, receiver_config) = chio_pheromone_runtime::runtime_policy_from_json(
        &policy_json,
        now_unix_ms,
        workflow_trust_bundle.runtime_policy_issuer_public_keys(),
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio pheromone runtime policy: {error}"))
    })?;
    let resolver = load_chio_verified_workflow_resolver(proof_package, trust_bundle, context)?;
    let store = chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio pheromone store: {error}")))?;
    let receiver = chio_pheromone_runtime::PheromoneReceiver::new(store, resolver, receiver_config);
    let receive_report = receiver
        .receive_batch(&batch, &transit_policy)
        .map_err(|error| CliError::cli_other_error(format!("Chio pheromone receive: {error}")))?;
    let report_json = serde_json::to_string_pretty(&receive_report)
        .map_err(|error| CliError::cli_other_error(format!("Chio pheromone report: {error}")))?;
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
            "Chio pheromone receive rejected batch: {failure}"
        )))
    }
}

pub(crate) fn cmd_chio_pheromone_query(
    store: &Path,
    subject_class: &str,
    namespace: &str,
    reputation_epoch: u64,
    peer_weights: &Path,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let store = chio_pheromone_runtime::store::SqlitePheromoneRuntimeStore::open(store)
        .map_err(|error| CliError::cli_other_error(format!("Chio pheromone store: {error}")))?;
    let weights_json = read_utf8_json_file(peer_weights, "Chio pheromone peer weights")?;
    let weights = chio_pheromone_runtime::peer_weights_from_json(&weights_json)
        .map_err(|error| CliError::cli_other_error(format!("Chio peer weights: {error}")))?;
    let validation_context = chio_pheromone::PheromoneValidationContext {
        now_unix_ms: now_unix_ms.unwrap_or_else(unix_now_ms),
        replay_window_ms: 0,
        active_peers_in_treaty: 0,
        active_reputation_epoch: reputation_epoch,
        known_reputation_epochs: vec![reputation_epoch],
        passports: Vec::new(),
        kernel_public_keys: Vec::new(),
        subject_classes: Vec::new(),
        max_deposits_per_pair: 0,
        scarcity_policies: Vec::new(),
        runtime_policy_sha256: None,
        runtime_policy_issuer_public_keys: Vec::new(),
        observation_cost_verifier_roots: Vec::new(),
        runtime_trust_floor_state: chio_pheromone::PheromoneRuntimeTrustFloorState::default(),
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
    .map_err(|error| CliError::cli_other_error(format!("Chio pheromone query: {error}")))?;
    let query_report = chio_pheromone_runtime::PheromoneQueryReport {
        schema: chio_pheromone_runtime::PHEROMONE_QUERY_REPORT_SCHEMA.to_string(),
        accepted: true,
        concentration,
    };
    let report_json = serde_json::to_string_pretty(&query_report)
        .map_err(|error| CliError::cli_other_error(format!("Chio pheromone report: {error}")))?;
    write_json_string(report, &format!("{report_json}\n"))
}
