use std::path::Path;

use crate::evidence_io::{canonical_sha256_json, write_runtime_json_artifact_string};
use crate::kernel::{execute_runtime_loopback_step, runtime_loopback_policy_inputs};
use crate::scenario::RuntimeLoopbackStep;
use crate::treaty::RuntimeLoopbackTreatyContext;
use crate::RuntimeLoopbackError;

pub(crate) struct RuntimeLoopbackAdmissionOutput {
    pub(crate) accepted: bool,
    pub(crate) failure_code: Option<String>,
    pub(crate) evidence_paths: Vec<String>,
    pub(crate) admission_hashes: Vec<String>,
    pub(crate) terminal_admission_report_sha256: Option<String>,
    pub(crate) evidence_manifest_entries: Vec<chio_runtime_core::RuntimeEvidenceManifestEntry>,
    pub(crate) live_tool_receipts: Vec<chio_core::receipt::body::ChioReceipt>,
    pub(crate) live_treaty_contexts: Vec<Option<RuntimeLoopbackTreatyContext>>,
}

pub(crate) fn execute_runtime_admission_loop(
    steps: &[RuntimeLoopbackStep],
    store: &chio_runtime_core::JsonRuntimeAdmissionStore,
    authority: &chio_store_sqlite::SqliteAuthorityStore,
    receipt_store: &std::sync::Arc<chio_store_sqlite::SqliteReceiptStore>,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<RuntimeLoopbackAdmissionOutput, RuntimeLoopbackError> {
    let mut accepted = true;
    let mut failure_code = None;
    let mut evidence_paths = Vec::new();
    let mut admission_hashes = Vec::new();
    let mut terminal_admission_report_sha256 = None;
    let mut evidence_manifest_entries = Vec::new();
    let mut live_tool_receipts = Vec::new();
    let mut live_treaty_contexts = Vec::new();

    for (index, step) in steps.iter().enumerate() {
        let admission_id = step.admission_bundle.admission_id.clone();
        store
            .insert_bundle(step.admission_bundle.clone())
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback admission store update: {error}"
                ))
            })?;
        let (signed_trust, trusted_keys, query_report, signed_policy, signed_weights) =
            runtime_loopback_policy_inputs(step, now_unix_ms)?;
        let admission_report = chio_runtime_core::evaluate_runtime_admission(
            chio_runtime_core::RuntimeAdmissionInput {
                profile: &step.admission_profile,
                store,
                admission_id: &admission_id,
                request: &step.request,
                action_class_id: None,
                runtime_trust_input: Some(&signed_trust),
                trusted_verifier_keys: &trusted_keys,
                pheromone_query_report: Some(&query_report),
                runtime_pheromone_policy: Some(&signed_policy),
                runtime_peer_weights: Some(&signed_weights),
                now_unix_ms,
            },
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!("Chio runtime loopback admission: {error}"))
        })?;
        let suffix = if steps.len() == 1 {
            String::new()
        } else {
            format!("-{}", index + 1)
        };
        let admission_report_name = format!("runtime-admission-report{suffix}.json");
        let admission_json = chio_runtime_core::runtime_admission_report_json(&admission_report)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime admission report JSON: {error}"
                ))
            })?;
        let admission_artifact_hash = write_runtime_json_artifact_string(
            out_dir,
            "admission_report",
            &admission_report_name,
            &admission_json,
            &mut evidence_manifest_entries,
            &mut evidence_paths,
        )?;
        let admission_hash = canonical_sha256_json(
            &admission_report,
            "Chio runtime admission report canonical hash",
        )?;
        if admission_artifact_hash.is_empty() {
            return Err(RuntimeLoopbackError::message(
                "Chio runtime admission artifact hash was empty".to_string(),
            ));
        }
        terminal_admission_report_sha256 = Some(admission_hash.clone());
        if !admission_report.accepted {
            accepted = false;
            failure_code = admission_report.failure_code.clone();
            break;
        }
        admission_hashes.push(admission_hash);
        let arguments = step.arguments.clone().ok_or_else(|| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime accepted step {} did not carry executable arguments",
                step.admission_bundle.step_index
            ))
        })?;
        let execution = execute_runtime_loopback_step(
            index,
            step,
            arguments,
            authority,
            receipt_store,
            now_unix_ms,
        )?;
        live_tool_receipts.push(execution.receipt);
        live_treaty_contexts.push(execution.treaty);
    }

    Ok(RuntimeLoopbackAdmissionOutput {
        accepted,
        failure_code,
        evidence_paths,
        admission_hashes,
        terminal_admission_report_sha256,
        evidence_manifest_entries,
        live_tool_receipts,
        live_treaty_contexts,
    })
}
