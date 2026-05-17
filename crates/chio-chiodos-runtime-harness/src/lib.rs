//! Live runtime loopback harness for Chiodos proof regeneration.

mod admission_loop;
mod buyer_closure;
mod evidence_io;
mod kernel;
mod proof_assembly;
mod proof_parity;
mod scenario;
mod treaty;

use std::fs;
use std::path::Path;

use admission_loop::execute_runtime_admission_loop;
use evidence_io::read_utf8_json_file;
use proof_assembly::assemble_runtime_loopback_outputs;
#[cfg(test)]
use proof_assembly::{
    runtime_admission_report_sha256_for_workflow, step_admission_binding,
    validate_step_admission_binding_counts,
};
use scenario::{normalize_runtime_loopback_steps, RuntimeLoopbackScenario};

pub use evidence_io::runtime_loopback_capability_window;

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct RuntimeLoopbackError {
    message: String,
}

impl RuntimeLoopbackError {
    fn message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub fn run_runtime_loopback_scenario(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), RuntimeLoopbackError> {
    let scenario: RuntimeLoopbackScenario = serde_json::from_str(&read_utf8_json_file(
        scenario,
        "Chiodos runtime loopback scenario",
    )?)
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chiodos runtime loopback scenario parse: {error}"))
    })?;
    let (run_id, steps) = normalize_runtime_loopback_steps(scenario)?;

    fs::create_dir_all(store_dir).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chiodos runtime store directory {}: {error}",
            store_dir.display()
        ))
    })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chiodos runtime output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    let store_path = store_dir.join("admission-store.json");
    let store =
        chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(&store_path).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chiodos runtime loopback admission store open: {error}"
            ))
        })?;

    let admission = execute_runtime_admission_loop(&steps, &store, now_unix_ms, out_dir)?;
    assemble_runtime_loopback_outputs(&run_id, &steps, out_dir, now_unix_ms, admission)
}

#[cfg(test)]
mod tests {
    use super::{
        runtime_admission_report_sha256_for_workflow, step_admission_binding,
        validate_step_admission_binding_counts,
    };

    #[test]
    fn step_admission_binding_rejects_more_workflow_steps_than_admission_hashes() {
        let error = match validate_step_admission_binding_counts(2, 1, 2) {
            Ok(()) => panic!("accepted mismatched workflow/admission hash counts"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("workflow step count 2 did not match admission report hash count 1"));
    }

    #[test]
    fn step_admission_binding_rejects_more_workflow_steps_than_admission_ids() {
        let error = match validate_step_admission_binding_counts(2, 2, 1) {
            Ok(()) => panic!("accepted mismatched workflow/admission id counts"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("workflow step count 2 did not match admission id count 1"));
    }

    #[test]
    fn step_admission_binding_uses_exact_index_without_fallback(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let hashes = ["hash-a".to_string(), "hash-b".to_string()];
        let ids = ["admission-a".to_string(), "admission-b".to_string()];

        let binding = step_admission_binding(1, &hashes, &ids)?;

        assert_eq!(binding.admission_report_sha256, "hash-b");
        assert_eq!(binding.admission_id, "admission-b");
        Ok(())
    }

    #[test]
    fn runtime_workflow_admission_hash_uses_report_hash_without_rehashing(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let admission_hash = "a".repeat(64);
        let selected = runtime_admission_report_sha256_for_workflow(
            None,
            std::slice::from_ref(&admission_hash),
            None,
        )?;

        assert_eq!(selected, admission_hash);
        assert_ne!(selected, chio_core::sha256_hex(admission_hash.as_bytes()));
        Ok(())
    }

    #[test]
    fn runtime_workflow_admission_hash_uses_terminal_denial_hash(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let denied_hash = "b".repeat(64);
        let selected = runtime_admission_report_sha256_for_workflow(None, &[], Some(&denied_hash))?;

        assert_eq!(selected, denied_hash);
        Ok(())
    }
}
