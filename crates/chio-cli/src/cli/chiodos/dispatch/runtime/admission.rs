use std::path::Path;

use crate::CliError;

use super::super::{read_utf8_json_file, write_pretty_json};

pub(crate) fn cmd_chiodos_runtime_admit(
    request: &Path,
    admission_profile: &Path,
    admission_bundle: &Path,
    runtime_trust_input: Option<&Path>,
    trusted_verifiers: Option<&Path>,
    pheromone_query_report: Option<&Path>,
    runtime_pheromone_policy: Option<&Path>,
    runtime_peer_weights: Option<&Path>,
    trust_floor_state: Option<&Path>,
    store: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_chiodos_runtime::runtime_admission_profile_from_json(&read_utf8_json_file(
        admission_profile,
        "Chiodos runtime admission profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission profile parse: {error}"))
    })?;
    let bundle = chio_chiodos_runtime::runtime_admission_bundle_from_json(&read_utf8_json_file(
        admission_bundle,
        "Chiodos runtime admission bundle",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission bundle parse: {error}"))
    })?;
    let request = chio_chiodos_runtime::runtime_request_binding_from_json(&read_utf8_json_file(
        request,
        "Chiodos runtime request binding",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime request binding parse: {error}"))
    })?;
    let runtime_trust_input = runtime_trust_input
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_verifier_trust_bundle_from_json(
                &read_utf8_json_file(path, "Chiodos runtime trust input")?,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime trust input parse: {error}"))
            })
        })
        .transpose()?;
    let trusted_verifiers = trusted_verifiers
        .map(|path| {
            chio_chiodos_runtime::runtime_trusted_verifier_keys_from_json(&read_utf8_json_file(
                path,
                "Chiodos runtime trusted verifiers",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime trusted verifiers parse: {error}"))
            })
        })
        .transpose()?;
    if runtime_trust_input.is_some() != trusted_verifiers.is_some() {
        return Err(CliError::cli_other_error(
            "Chiodos runtime strict trust requires both --runtime-trust-input and --trusted-verifiers"
                .to_string(),
        ));
    }
    let trusted_verifier_keys = trusted_verifiers
        .as_ref()
        .map_or(&[][..], |document| document.verifier_keys.as_slice());
    let pheromone_query_report = pheromone_query_report
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_pheromone_query_report_from_json(
                &read_utf8_json_file(path, "Chiodos pheromone query report")?,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos signed pheromone query report parse: {error}"
                ))
            })
        })
        .transpose()?;
    let runtime_pheromone_policy = runtime_pheromone_policy
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_pheromone_policy_from_json(&read_utf8_json_file(
                path,
                "Chiodos runtime pheromone policy",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime pheromone policy parse: {error}"
                ))
            })
        })
        .transpose()?;
    let runtime_peer_weights = runtime_peer_weights
        .map(|path| {
            chio_chiodos_runtime::signed_runtime_peer_weights_from_json(&read_utf8_json_file(
                path,
                "Chiodos runtime peer weights",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime peer weights parse: {error}"
                ))
            })
        })
        .transpose()?;
    let store = chio_chiodos_runtime::JsonRuntimeAdmissionStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission store open: {error}"))
    })?;
    let admission_id = bundle.admission_id.clone();
    store.insert_bundle(bundle).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission store update: {error}"))
    })?;
    let trust_floor_store = trust_floor_state
        .map(|path| {
            chio_chiodos_runtime::JsonRuntimeTrustFloorStateStore::open(path).map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime trust-floor state open: {error}"
                ))
            })
        })
        .transpose()?;
    let layered_store = trust_floor_store
        .as_ref()
        .map(|trust_floor_store| {
            chio_chiodos_runtime::LayeredRuntimeAdmissionStore::new(&store, trust_floor_store)
        });
    let evaluation_store: &dyn chio_chiodos_runtime::RuntimeAdmissionStore =
        if let Some(layered_store) = layered_store.as_ref() {
            layered_store
        } else {
            &store
        };
    let admission_report =
        chio_chiodos_runtime::evaluate_runtime_admission(chio_chiodos_runtime::RuntimeAdmissionInput {
            profile: &profile,
            store: evaluation_store,
            admission_id: &admission_id,
            request: &request,
            action_class_id: None,
            runtime_trust_input: runtime_trust_input.as_ref(),
            trusted_verifier_keys,
            pheromone_query_report: pheromone_query_report.as_ref(),
            runtime_pheromone_policy: runtime_pheromone_policy.as_ref(),
            runtime_peer_weights: runtime_peer_weights.as_ref(),
            now_unix_ms,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime admission evaluation: {error}"))
        })?;
    write_pretty_json(report, &admission_report, "Chiodos runtime admission report")?;
    if admission_report.accepted {
        Ok(())
    } else {
        Err(CliError::policy_error(format!(
            "Chiodos runtime admission rejected request: {}",
            admission_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_runtime_admission_failure")
        )))
    }
}

pub(crate) fn cmd_chiodos_runtime_pheromone_evaluate(
    admission_bundle: &Path,
    runtime_trust_input: &Path,
    trusted_verifiers: &Path,
    pheromone_query_report: &Path,
    runtime_pheromone_policy: &Path,
    runtime_peer_weights: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = chio_chiodos_runtime::runtime_admission_bundle_from_json(&read_utf8_json_file(
        admission_bundle,
        "Chiodos runtime admission bundle",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime admission bundle parse: {error}"))
    })?;
    let profile = chio_chiodos_runtime::RuntimeAdmissionProfile {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "policy-evaluate".to_string(),
        local_kernel_id: bundle.binding.host_kernel_id.clone(),
        verifier_id: "policy-evaluate".to_string(),
        issued_at_unix_ms: now_unix_ms.saturating_sub(1),
        expires_at_unix_ms: now_unix_ms.saturating_add(1),
    };
    let runtime_trust_input =
        chio_chiodos_runtime::signed_runtime_verifier_trust_bundle_from_json(
            &read_utf8_json_file(runtime_trust_input, "Chiodos runtime trust input")?,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime trust input parse: {error}"))
        })?;
    let trusted_verifiers =
        chio_chiodos_runtime::runtime_trusted_verifier_keys_from_json(&read_utf8_json_file(
            trusted_verifiers,
            "Chiodos runtime trusted verifiers",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime trusted verifiers parse: {error}"))
        })?;
    let query_report = chio_chiodos_runtime::signed_runtime_pheromone_query_report_from_json(
        &read_utf8_json_file(pheromone_query_report, "Chiodos pheromone query report")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chiodos signed pheromone query report parse: {error}"
        ))
    })?;
    let policy = chio_chiodos_runtime::signed_runtime_pheromone_policy_from_json(
        &read_utf8_json_file(runtime_pheromone_policy, "Chiodos runtime pheromone policy")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime pheromone policy parse: {error}"))
    })?;
    let weights = chio_chiodos_runtime::signed_runtime_peer_weights_from_json(
        &read_utf8_json_file(runtime_peer_weights, "Chiodos runtime peer weights")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime peer weights parse: {error}"))
    })?;
    let store = chio_chiodos_runtime::InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle.clone()).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime policy store update: {error}"))
    })?;
    let report_value = chio_chiodos_runtime::evaluate_runtime_admission(
        chio_chiodos_runtime::RuntimeAdmissionInput {
            profile: &profile,
            store: &store,
            admission_id: &bundle.admission_id,
            request: &bundle.binding,
            action_class_id: None,
            runtime_trust_input: Some(&runtime_trust_input),
            trusted_verifier_keys: &trusted_verifiers.verifier_keys,
            pheromone_query_report: Some(&query_report),
            runtime_pheromone_policy: Some(&policy),
            runtime_peer_weights: Some(&weights),
            now_unix_ms,
        },
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime pheromone evaluation: {error}"))
    })?;
    let decision = report_value.pheromone_policy_decision.ok_or_else(|| {
        CliError::cli_other_error("Chiodos runtime pheromone evaluation produced no decision")
    })?;
    write_pretty_json(report, &decision, "Chiodos runtime pheromone policy decision")
}
