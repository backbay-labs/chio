#[path = "pheromone/alerts.rs"]
mod alerts;
#[path = "pheromone/assurance.rs"]
mod assurance;
#[path = "pheromone/delivery.rs"]
mod delivery;
#[path = "pheromone/directory.rs"]
mod directory;
#[path = "pheromone/io.rs"]
mod io;
#[path = "pheromone/iroh_mount.rs"]
mod iroh_mount;
#[path = "pheromone/relay.rs"]
mod relay;
#[path = "pheromone/runtime.rs"]
mod runtime;

pub(crate) use self::alerts::{
    cmd_chio_pheromone_relay_alert_evaluate, cmd_chio_pheromone_relay_alert_handoff,
    cmd_chio_pheromone_relay_alert_normalize, cmd_chio_pheromone_relay_alert_review,
    read_relay_alert_handoff_reports,
};
pub(crate) use self::assurance::{
    cmd_chio_pheromone_relay_alert_assurance_archive_package_create,
    cmd_chio_pheromone_relay_alert_assurance_archive_package_extract,
    cmd_chio_pheromone_relay_alert_assurance_archive_package_verify,
    cmd_chio_pheromone_relay_alert_assurance_archive_plan,
    cmd_chio_pheromone_relay_alert_assurance_archive_restore_drill_review,
    cmd_chio_pheromone_relay_alert_assurance_closeout_review,
    cmd_chio_pheromone_relay_alert_assurance_physical_drill_review,
    cmd_chio_pheromone_relay_alert_assurance_export,
    cmd_chio_pheromone_relay_alert_assurance_package,
    cmd_chio_pheromone_relay_alert_assurance_recovery_drill,
    cmd_chio_pheromone_relay_alert_assurance_replay,
    cmd_chio_pheromone_relay_alert_assurance_retention_external_review,
    cmd_chio_pheromone_relay_alert_assurance_retention_handoff_review,
    cmd_chio_pheromone_relay_alert_assurance_retention_plan,
    cmd_chio_pheromone_relay_alert_assurance_verify,
};
pub(crate) use self::delivery::{
    cmd_chio_pheromone_relay_alert_delivery_acknowledge,
    cmd_chio_pheromone_relay_alert_delivery_drift,
    cmd_chio_pheromone_relay_alert_delivery_drift_window,
    cmd_chio_pheromone_relay_alert_delivery_import,
};
pub(crate) use self::directory::{
    build_peer_directory_bundle_trust, cmd_chio_pheromone_relay_directory_inspect,
    cmd_chio_pheromone_relay_directory_promote, cmd_chio_pheromone_relay_directory_reject,
    cmd_chio_pheromone_relay_supervisor_lint, load_relay_peer_directory_from_paths,
    write_pretty_json,
};
pub(crate) use self::io::{
    load_relay_signing_key, read_json_documents_from_dir, read_json_file, unix_now_ms,
};
pub(crate) use self::iroh_mount::{
    build_iroh_outbound_endpoint, build_iroh_router, iroh_transport_metrics_prometheus,
    load_iroh_serve_inputs, note_router_liveness, run_directory_reloader, DirectoryReloadConfig,
    IrohServeInputs,
};
pub(crate) use self::relay::{
    RelaySigningKeyDocument, RelayTrustedIssuersDocument, cmd_chio_pheromone_relay_catchup,
    cmd_chio_pheromone_relay_enqueue, cmd_chio_pheromone_relay_lint,
    cmd_chio_pheromone_relay_metrics, cmd_chio_pheromone_relay_observe,
    cmd_chio_pheromone_relay_serve, cmd_chio_pheromone_relay_status,
    cmd_chio_pheromone_relay_tick, cmd_chio_pheromone_relay_trend, read_relay_event_reports,
};
pub(crate) use self::runtime::{
    cmd_chio_pheromone_query, cmd_chio_pheromone_receive,
};
pub(crate) use super::{
    read_utf8_json_file, write_json_string,
};
use crate::CliError;
use std::path::Path;

pub(crate) fn load_chio_verified_workflow_resolver(
    proof_package: &Path,
    trust_bundle: &Path,
    context: &Path,
) -> Result<chio_pheromone_runtime::VerifiedChioWorkflowResolver, CliError> {
    let package_json = read_utf8_json_file(proof_package, "Chio proof package")?;
    let package = chio_pheromone_runtime::ChioWorkflowProofPackage::from_json(&package_json)
        .map_err(|error| CliError::cli_other_error(format!("Chio proof package parse: {error}")))?;
    let trust_bundle = load_chio_workflow_verifier_trust_bundle(trust_bundle)?;
    let context_json = read_utf8_json_file(context, "Chio verification context")?;
    let context = chio_pheromone_runtime::ChioWorkflowVerificationContext::from_json(&context_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio verification context parse: {error}"))
        })?;
    chio_pheromone_runtime::VerifiedChioWorkflowResolver::from_verified_package(
        &package,
        &trust_bundle,
        &context,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chio workflow resolver: {error}")))
}

pub(crate) fn load_chio_workflow_verifier_trust_bundle(
    trust_bundle: &Path,
) -> Result<chio_pheromone_runtime::ChioWorkflowVerifierTrustBundle, CliError> {
    let trust_bundle_json = read_utf8_json_file(trust_bundle, "Chio verifier trust bundle")?;
    chio_pheromone_runtime::ChioWorkflowVerifierTrustBundle::from_json(&trust_bundle_json)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio verifier trust bundle parse: {error}"))
        })
}
