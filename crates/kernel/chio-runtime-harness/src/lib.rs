//! Live runtime loopback harness for Chio proof regeneration.

#![forbid(unsafe_code)]

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
use proof_assembly::{assemble_runtime_loopback_outputs, StaticProofBaseline};
#[cfg(test)]
use proof_assembly::{
    runtime_admission_report_sha256_for_workflow, step_admission_binding,
    validate_step_admission_binding_counts,
};
use scenario::{normalize_runtime_loopback_steps, RuntimeLoopbackScenario};

const RUNTIME_LOOPBACK_AUTHORITY_STORE_UUID: &str = "018bcfe5-6800-7000-8000-000000000001";
const RUNTIME_LOOPBACK_AUTHORITY_LEASE_ID: &str = "018bcfe5-6800-7000-8000-000000000002";

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
    let static_package = chio_attest_loopback::fixture_proof_package().map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio static proof package: {error}"))
    })?;
    let static_report = chio_attest_loopback::fixture_verifier_report().map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio static verifier report: {error}"))
    })?;
    run_runtime_loopback_scenario_with_static_baseline(
        scenario,
        store_dir,
        now_unix_ms,
        out_dir,
        static_package,
        static_report,
    )
}

pub fn run_runtime_loopback_scenario_with_static_artifacts(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    static_package_json: &str,
    static_report_json: &str,
) -> Result<(), RuntimeLoopbackError> {
    let static_package =
        chio_attest_buyer_core::proof_package::proof_package_from_json(static_package_json)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!("Chio static proof package: {error}"))
            })?;
    let static_report =
        chio_attest_buyer_core::report::verifier_report_from_json(static_report_json).map_err(
            |error| RuntimeLoopbackError::message(format!("Chio static verifier report: {error}")),
        )?;
    run_runtime_loopback_scenario_with_static_baseline(
        scenario,
        store_dir,
        now_unix_ms,
        out_dir,
        static_package,
        static_report,
    )
}

fn run_runtime_loopback_scenario_with_static_baseline(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
    static_package: chio_attest_buyer_core::proof_package::ChioProofPackage,
    static_report: chio_attest_buyer_core::report::VerifierReport,
) -> Result<(), RuntimeLoopbackError> {
    let scenario: RuntimeLoopbackScenario = serde_json::from_str(&read_utf8_json_file(
        scenario,
        "Chio runtime loopback scenario",
    )?)
    .map_err(|error| {
        RuntimeLoopbackError::message(format!("Chio runtime loopback scenario parse: {error}"))
    })?;
    let (run_id, steps) = normalize_runtime_loopback_steps(scenario)?;

    fs::create_dir_all(store_dir).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chio runtime store directory {}: {error}",
            store_dir.display()
        ))
    })?;
    fs::create_dir_all(out_dir).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chio runtime output directory {}: {error}",
            out_dir.display()
        ))
    })?;
    let store_path = store_dir.join("admission-store.json");
    let store =
        chio_runtime_core::JsonRuntimeAdmissionStore::open(&store_path).map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback admission store open: {error}"
            ))
        })?;
    let authority_path = store_dir.join("kernel-authority.sqlite3");
    let authority_lock_root = store_dir.join("kernel-authority-locks");
    fs::create_dir_all(&authority_lock_root).map_err(|error| {
        RuntimeLoopbackError::message(format!(
            "failed to create Chio runtime authority lock directory {}: {error}",
            authority_lock_root.display()
        ))
    })?;
    let authority = {
        let _identity_scope = chio_store_sqlite::scope_fixed_authority_ids_for_current_thread(
            RUNTIME_LOOPBACK_AUTHORITY_STORE_UUID,
            [RUNTIME_LOOPBACK_AUTHORITY_LEASE_ID.to_string()],
        )
        .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback authority identity: {error}"
            ))
        })?;
        chio_store_sqlite::SqliteAuthorityStore::provision(&authority_path, &authority_lock_root)
            .map_err(|error| {
            RuntimeLoopbackError::message(format!(
                "Chio runtime loopback authority provision: {error}"
            ))
        })?;
        chio_store_sqlite::SqliteAuthorityStore::open_serving(&authority_path, &authority_lock_root)
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback authority open: {error}"
                ))
            })?
    };
    let receipt_store = std::sync::Arc::new(
        chio_store_sqlite::SqliteReceiptStore::open(store_dir.join("kernel-receipts.sqlite3"))
            .map_err(|error| {
                RuntimeLoopbackError::message(format!(
                    "Chio runtime loopback receipt store open: {error}"
                ))
            })?,
    );

    let admission = execute_runtime_admission_loop(
        &steps,
        &store,
        &authority,
        &receipt_store,
        now_unix_ms,
        out_dir,
    )?;
    assemble_runtime_loopback_outputs(
        &run_id,
        &steps,
        out_dir,
        now_unix_ms,
        admission,
        StaticProofBaseline {
            package: static_package,
            report: static_report,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::{
        run_runtime_loopback_scenario, runtime_admission_report_sha256_for_workflow,
        step_admission_binding, validate_step_admission_binding_counts,
    };
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> Result<PathBuf, crate::RuntimeLoopbackError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                crate::RuntimeLoopbackError::message(format!(
                    "runtime loopback temp clock failed: {error}"
                ))
            })?;
        Ok(std::env::temp_dir().join(format!(
            "chio-runtime-harness-{label}-{}-{}",
            std::process::id(),
            duration.as_nanos()
        )))
    }

    fn read_json(path: &Path) -> Result<serde_json::Value, crate::RuntimeLoopbackError> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to read runtime loopback output {}: {error}",
                path.display()
            ))
        })?;
        serde_json::from_str(&text).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to parse runtime loopback output {}: {error}",
                path.display()
            ))
        })
    }

    fn write_executable_scenario(
        source: &Path,
        destination: &Path,
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let mut scenario = read_json(source)?;
        let arguments = [
            serde_json::json!({
                "caseRef": "refund-250",
                "tool": "read_refund_case",
                "workflowId": "wf-chio-refund-001"
            }),
            serde_json::json!({
                "caseRef": "refund-250",
                "tool": "verify_customer",
                "workflowId": "wf-chio-refund-001"
            }),
            serde_json::json!({
                "caseRef": "refund-250",
                "tool": "stage_refund",
                "workflowId": "wf-chio-refund-001"
            }),
        ];
        let tool_arg_sha256s = [
            "3f31b68cde492ccb216e04bb62d975141dbed7b3c4f96a73d21398eaa88fb5cc",
            "5e9312cae8fac5f26d60c004f5e371a48d649b1c5fb234803727f478d18a0ccd",
            "47e6e096b5d5888a3f90d057de3bce595d8ea5dd8624ccde387bb739d5a6464b",
        ];
        let host_kernel_ids = [
            "did:chio:vendor-a",
            "did:chio:vendor-b",
            "did:chio:vendor-c",
        ];
        let capability_ids = [
            "lease-vendor-a-read",
            "lease-vendor-b-kyc",
            "lease-vendor-c-refund",
        ];
        let steps = scenario
            .get_mut("steps")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or_else(|| {
                crate::RuntimeLoopbackError::message(
                    "runtime loopback fixture scenario has no steps".to_string(),
                )
            })?;
        if steps.len() != arguments.len() {
            return Err(crate::RuntimeLoopbackError::message(format!(
                "runtime loopback fixture has {} steps, expected {}",
                steps.len(),
                arguments.len()
            )));
        }
        for (index, step) in steps.iter_mut().enumerate() {
            let step_object = step.as_object_mut().ok_or_else(|| {
                crate::RuntimeLoopbackError::message(format!(
                    "runtime loopback fixture step {index} is not an object"
                ))
            })?;
            step_object.insert("arguments".to_string(), arguments[index].clone());
            let request = step_object
                .get_mut("request")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    crate::RuntimeLoopbackError::message(format!(
                        "runtime loopback fixture step {index} has no request"
                    ))
                })?;
            request.insert(
                "toolArgsSha256".to_string(),
                serde_json::Value::String(tool_arg_sha256s[index].to_string()),
            );
            request.insert(
                "hostKernelId".to_string(),
                serde_json::Value::String(host_kernel_ids[index].to_string()),
            );
            request.insert(
                "capabilityId".to_string(),
                serde_json::Value::String(capability_ids[index].to_string()),
            );
            let binding = step_object
                .get_mut("admissionBundle")
                .and_then(serde_json::Value::as_object_mut)
                .and_then(|bundle| bundle.get_mut("binding"))
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    crate::RuntimeLoopbackError::message(format!(
                        "runtime loopback fixture step {index} has no admission bundle binding"
                    ))
                })?;
            binding.insert(
                "toolArgsSha256".to_string(),
                serde_json::Value::String(tool_arg_sha256s[index].to_string()),
            );
            binding.insert(
                "hostKernelId".to_string(),
                serde_json::Value::String(host_kernel_ids[index].to_string()),
            );
            binding.insert(
                "capabilityId".to_string(),
                serde_json::Value::String(capability_ids[index].to_string()),
            );
            let profile = step_object
                .get_mut("admissionProfile")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| {
                    crate::RuntimeLoopbackError::message(format!(
                        "runtime loopback fixture step {index} has no admission profile"
                    ))
                })?;
            profile.insert(
                "localKernelId".to_string(),
                serde_json::Value::String(host_kernel_ids[index].to_string()),
            );
            profile.insert(
                "issuedAtUnixMs".to_string(),
                serde_json::Value::from(1_700_000_000_000_u64),
            );
            profile.insert(
                "expiresAtUnixMs".to_string(),
                serde_json::Value::from(1_900_000_000_000_u64),
            );
        }
        let scenario_text = serde_json::to_string_pretty(&scenario).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "runtime loopback executable scenario JSON failed: {error}"
            ))
        })?;
        std::fs::write(destination, format!("{scenario_text}\n")).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to write runtime loopback executable scenario {}: {error}",
                destination.display()
            ))
        })
    }

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

    #[test]
    fn runtime_loopback_outputs_chio_native_buyer_and_federation_schemas(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let root = temp_root("schema-cutover")?;
        let store_dir = root.join("store");
        let out_dir = root.join("out");
        std::fs::create_dir_all(&root).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to create runtime loopback temp root {}: {error}",
                root.display()
            ))
        })?;
        let fixture_scenario = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../examples/chio-3vendor/fixtures/runtime-spine/scenario.json");
        let scenario = root.join("scenario.json");
        write_executable_scenario(&fixture_scenario, &scenario)?;

        let error =
            match run_runtime_loopback_scenario(&scenario, &store_dir, 1_800_000_001_000, &out_dir)
            {
                Ok(_) => panic!("runtime package drift from static fixture must fail closed"),
                Err(error) => error,
            };
        assert!(
            error
                .to_string()
                .contains("runtime_proof_semantic_parity_mismatch"),
            "{error}"
        );

        assert_eq!(
            read_json(&out_dir.join("buyer-attestation-packet.json"))?
                .get("schema")
                .and_then(serde_json::Value::as_str),
            Some(chio_runtime_core::CHIO_ATTEST_BUYER_ATTESTATION_PACKET_SCHEMA)
        );
        assert_eq!(
            read_json(&out_dir.join("cross-kernel-continuation.json"))?
                .get("schema")
                .and_then(serde_json::Value::as_str),
            Some(chio_runtime_core::CHIO_FEDERATION_CROSS_KERNEL_CONTINUATION_SCHEMA)
        );
        assert_eq!(
            read_json(&out_dir.join("receipt-lineage-statement.json"))?
                .get("schema")
                .and_then(serde_json::Value::as_str),
            Some(chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_STATEMENT_SCHEMA)
        );
        assert_eq!(
            read_json(&out_dir.join("receipt-lineage-bundle.json"))?
                .get("schema")
                .and_then(serde_json::Value::as_str),
            Some(chio_runtime_core::CHIO_FEDERATION_RECEIPT_LINEAGE_BUNDLE_SCHEMA)
        );
        assert_eq!(
            read_json(&out_dir.join("bilateral-invocation.json"))?
                .get("schema")
                .and_then(serde_json::Value::as_str),
            Some(chio_runtime_core::CHIO_FEDERATION_BILATERAL_INVOCATION_SCHEMA)
        );

        std::fs::remove_dir_all(&root).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to remove runtime loopback temp output {}: {error}",
                root.display()
            ))
        })?;
        Ok(())
    }

    #[test]
    fn runtime_loopback_rejects_runtime_package_drift_from_static_fixture(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let root = temp_root("runtime-parity-static-baseline")?;
        let store_dir = root.join("store");
        let out_dir = root.join("out");
        std::fs::create_dir_all(&root).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to create runtime loopback temp root {}: {error}",
                root.display()
            ))
        })?;
        let fixture_scenario = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../examples/chio-3vendor/fixtures/runtime-spine/scenario.json");
        let scenario = root.join("scenario.json");
        write_executable_scenario(&fixture_scenario, &scenario)?;

        let error =
            match run_runtime_loopback_scenario(&scenario, &store_dir, 1_800_000_001_000, &out_dir)
            {
                Ok(_) => panic!("runtime package drift from static fixture must fail closed"),
                Err(error) => error,
            };
        assert!(
            error
                .to_string()
                .contains("runtime_proof_semantic_parity_mismatch"),
            "{error}"
        );

        let parity_report = read_json(&out_dir.join("runtime-proof-parity-report.json"))?;
        assert_eq!(
            parity_report
                .get("accepted")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            parity_report
                .get("failureCode")
                .and_then(serde_json::Value::as_str),
            Some("runtime_proof_semantic_parity_mismatch")
        );
        assert_ne!(
            parity_report
                .get("staticProofPackageSha256")
                .and_then(serde_json::Value::as_str),
            parity_report
                .get("runtimeProofPackageSha256")
                .and_then(serde_json::Value::as_str)
        );
        let proof_report = read_json(&out_dir.join("proof-regeneration-report.json"))?;
        assert_eq!(
            proof_report
                .get("accepted")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            proof_report
                .get("failureCode")
                .and_then(serde_json::Value::as_str),
            Some("runtime_proof_semantic_parity_mismatch")
        );

        std::fs::remove_dir_all(&root).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to remove runtime loopback temp output {}: {error}",
                root.display()
            ))
        })?;
        Ok(())
    }

    #[test]
    fn runtime_loopback_proof_package_is_semantically_deterministic(
    ) -> Result<(), crate::RuntimeLoopbackError> {
        let root = temp_root("runtime-determinism")?;
        std::fs::create_dir_all(&root).map_err(|error| {
            crate::RuntimeLoopbackError::message(format!(
                "failed to create runtime loopback temp root {}: {error}",
                root.display()
            ))
        })?;
        let fixture_scenario = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../examples/chio-3vendor/fixtures/runtime-spine/scenario.json");
        let scenario = root.join("scenario.json");
        write_executable_scenario(&fixture_scenario, &scenario)?;

        for suffix in ["a", "b"] {
            run_runtime_loopback_scenario(
                &scenario,
                &root.join(format!("store-{suffix}")),
                1_766_000_001_000,
                &root.join(format!("out-{suffix}")),
            )?;
        }

        let mut first = read_json(&root.join("out-a/proof-package.json"))?;
        let mut second = read_json(&root.join("out-b/proof-package.json"))?;
        for package in [&mut first, &mut second] {
            let proof_bytes = package
                .pointer_mut("/selectiveDisclosureProof/proof_bytes_hex")
                .ok_or_else(|| {
                    crate::RuntimeLoopbackError::message(
                        "runtime proof package omitted BBS proof bytes",
                    )
                })?;
            *proof_bytes = serde_json::Value::Null;
        }
        assert_eq!(first, second);
        Ok(())
    }
}
