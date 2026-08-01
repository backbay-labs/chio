use std::path::Path;

use crate::CliError;

use super::super::{read_utf8_json_file, write_pretty_json};

pub(crate) fn cmd_chio_runtime_admit(
    request: &Path,
    admission_profile: &Path,
    admission_bundle: &Path,
    runtime_trust_input: Option<&Path>,
    trusted_verifiers: Option<&Path>,
    pheromone_query_report: Option<&Path>,
    runtime_pheromone_policy: Option<&Path>,
    runtime_peer_weights: Option<&Path>,
    action_class_id: Option<&str>,
    trust_floor_state: Option<&Path>,
    store: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = chio_runtime::runtime_admission_profile_from_json(&read_utf8_json_file(
        admission_profile,
        "Chio runtime admission profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime admission profile parse: {error}"))
    })?;
    let bundle = chio_runtime::runtime_admission_bundle_from_json(&read_utf8_json_file(
        admission_bundle,
        "Chio runtime admission bundle",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime admission bundle parse: {error}"))
    })?;
    let request = chio_runtime::runtime_request_binding_from_json(&read_utf8_json_file(
        request,
        "Chio runtime request binding",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime request binding parse: {error}"))
    })?;
    let runtime_trust_input = runtime_trust_input
        .map(|path| {
            chio_runtime::signed_runtime_verifier_trust_bundle_from_json(&read_utf8_json_file(
                path,
                "Chio runtime trust input",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime trust input parse: {error}"))
            })
        })
        .transpose()?;
    let trusted_verifiers = trusted_verifiers
        .map(|path| {
            chio_runtime::runtime_trusted_verifier_keys_from_json(&read_utf8_json_file(
                path,
                "Chio runtime trusted verifiers",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime trusted verifiers parse: {error}"))
            })
        })
        .transpose()?;
    if runtime_trust_input.is_some() != trusted_verifiers.is_some() {
        return Err(CliError::cli_other_error(
            "Chio runtime strict trust requires both --runtime-trust-input and --trusted-verifiers"
                .to_string(),
        ));
    }
    let trusted_verifier_keys = trusted_verifiers
        .as_ref()
        .map_or(&[][..], |document| document.verifier_keys.as_slice());
    let pheromone_query_report = pheromone_query_report
        .map(read_chio_runtime_pheromone_query_report)
        .transpose()?;
    let runtime_pheromone_policy = runtime_pheromone_policy
        .map(|path| {
            chio_runtime::signed_runtime_pheromone_policy_from_json(&read_utf8_json_file(
                path,
                "Chio runtime pheromone policy",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime pheromone policy parse: {error}"))
            })
        })
        .transpose()?;
    let runtime_peer_weights = runtime_peer_weights
        .map(|path| {
            chio_runtime::signed_runtime_peer_weights_from_json(&read_utf8_json_file(
                path,
                "Chio runtime peer weights",
            )?)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime peer weights parse: {error}"))
            })
        })
        .transpose()?;
    let action_class_id = resolve_runtime_action_class_id(
        &request,
        runtime_pheromone_policy.as_ref().map(|policy| &policy.body),
        action_class_id,
    )?;
    let store = chio_runtime::JsonRuntimeAdmissionStore::open(store).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime admission store open: {error}"))
    })?;
    let admission_id = bundle.admission_id.clone();
    store.insert_bundle(bundle).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime admission store update: {error}"))
    })?;
    let trust_floor_store = trust_floor_state
        .map(|path| {
            chio_runtime::JsonRuntimeTrustFloorStateStore::open(path).map_err(|error| {
                CliError::cli_other_error(format!("Chio runtime trust-floor state open: {error}"))
            })
        })
        .transpose()?;
    let layered_store = trust_floor_store.as_ref().map(|trust_floor_store| {
        chio_runtime::LayeredRuntimeAdmissionStore::new(&store, trust_floor_store)
    });
    let evaluation_store: &dyn chio_runtime::ChioRuntimeAdmissionStore =
        if let Some(layered_store) = layered_store.as_ref() {
            layered_store
        } else {
            &store
        };
    let admission_report =
        chio_runtime::evaluate_runtime_admission(chio_runtime::ChioRuntimeAdmissionInput {
            profile: &profile,
            store: evaluation_store,
            admission_id: &admission_id,
            request: &request,
            action_class_id: action_class_id.as_deref(),
            runtime_trust_input: runtime_trust_input.as_ref(),
            trusted_verifier_keys,
            pheromone_query_report: pheromone_query_report.as_ref(),
            runtime_pheromone_policy: runtime_pheromone_policy.as_ref(),
            runtime_peer_weights: runtime_peer_weights.as_ref(),
            now_unix_ms,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime admission evaluation: {error}"))
        })?;
    write_pretty_json(report, &admission_report, "Chio runtime admission report")?;
    if admission_report.accepted {
        Ok(())
    } else {
        Err(CliError::policy_error(format!(
            "Chio runtime admission rejected request: {}",
            admission_report
                .failure_code
                .as_deref()
                .unwrap_or("unknown_runtime_admission_failure")
        )))
    }
}

pub(crate) fn cmd_chio_runtime_pheromone_evaluate(
    admission_bundle: &Path,
    runtime_trust_input: &Path,
    trusted_verifiers: &Path,
    pheromone_query_report: &Path,
    runtime_pheromone_policy: &Path,
    runtime_peer_weights: &Path,
    action_class_id: Option<&str>,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let bundle = chio_runtime::runtime_admission_bundle_from_json(&read_utf8_json_file(
        admission_bundle,
        "Chio runtime admission bundle",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime admission bundle parse: {error}"))
    })?;
    let runtime_trust_input = chio_runtime::signed_runtime_verifier_trust_bundle_from_json(
        &read_utf8_json_file(runtime_trust_input, "Chio runtime trust input")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime trust input parse: {error}"))
    })?;
    let trusted_verifiers = chio_runtime::runtime_trusted_verifier_keys_from_json(
        &read_utf8_json_file(trusted_verifiers, "Chio runtime trusted verifiers")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime trusted verifiers parse: {error}"))
    })?;
    let query_report = read_chio_runtime_pheromone_query_report(pheromone_query_report)?;
    let policy = chio_runtime::signed_runtime_pheromone_policy_from_json(&read_utf8_json_file(
        runtime_pheromone_policy,
        "Chio runtime pheromone policy",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime pheromone policy parse: {error}"))
    })?;
    let verifier_id = resolve_runtime_pheromone_evaluation_verifier_id(
        &runtime_trust_input.body.verifier_id,
        &policy.body.verifier_id,
    )?;
    let profile = chio_runtime::RuntimeAdmissionProfile {
        schema: chio_runtime::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
        profile_id: "policy-evaluate".to_string(),
        local_kernel_id: bundle.binding.host_kernel_id.clone(),
        verifier_id,
        issued_at_unix_ms: now_unix_ms.saturating_sub(1),
        expires_at_unix_ms: now_unix_ms.saturating_add(1),
    };
    let weights = chio_runtime::signed_runtime_peer_weights_from_json(&read_utf8_json_file(
        runtime_peer_weights,
        "Chio runtime peer weights",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime peer weights parse: {error}"))
    })?;
    let action_class_id =
        resolve_runtime_action_class_id(&bundle.binding, Some(&policy.body), action_class_id)?;
    let store = chio_runtime::InMemoryRuntimeAdmissionStore::new();
    store.insert_bundle(bundle.clone()).map_err(|error| {
        CliError::cli_other_error(format!("Chio runtime policy store update: {error}"))
    })?;
    let report_value =
        chio_runtime::evaluate_runtime_admission(chio_runtime::ChioRuntimeAdmissionInput {
            profile: &profile,
            store: &store,
            admission_id: &bundle.admission_id,
            request: &bundle.binding,
            action_class_id: action_class_id.as_deref(),
            runtime_trust_input: Some(&runtime_trust_input),
            trusted_verifier_keys: &trusted_verifiers.verifier_keys,
            pheromone_query_report: Some(&query_report),
            runtime_pheromone_policy: Some(&policy),
            runtime_peer_weights: Some(&weights),
            now_unix_ms,
        })
        .map_err(|error| {
            CliError::cli_other_error(format!("Chio runtime pheromone evaluation: {error}"))
        })?;
    let decision = report_value.pheromone_policy_decision.ok_or_else(|| {
        CliError::cli_other_error("Chio runtime pheromone evaluation produced no decision")
    })?;
    write_pretty_json(report, &decision, "Chio runtime pheromone policy decision")
}

fn resolve_runtime_pheromone_evaluation_verifier_id(
    runtime_trust_verifier_id: &str,
    policy_verifier_id: &str,
) -> Result<String, CliError> {
    if runtime_trust_verifier_id != policy_verifier_id {
        return Err(CliError::cli_other_error(format!(
            "Chio runtime pheromone policy verifier {} does not match trust input verifier {}",
            policy_verifier_id, runtime_trust_verifier_id
        )));
    }
    Ok(runtime_trust_verifier_id.to_string())
}

fn read_chio_runtime_pheromone_query_report(
    path: &Path,
) -> Result<chio_runtime::SignedRuntimePheromoneQueryReport, CliError> {
    chio_runtime::signed_runtime_pheromone_query_report_from_json(&read_utf8_json_file(
        path,
        "Chio runtime pheromone query report",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!(
            "Chio runtime pheromone query report parse: {error}"
        ))
    })
}

fn resolve_runtime_action_class_id(
    request: &chio_runtime::RuntimeRequestBinding,
    policy: Option<&chio_runtime::RuntimePheromonePolicy>,
    action_class_id: Option<&str>,
) -> Result<Option<String>, CliError> {
    if let Some(action_class_id) = action_class_id {
        let action_class_id = action_class_id.trim();
        if action_class_id.is_empty() {
            return Err(CliError::cli_other_error(
                "Chio runtime action class id must not be empty".to_string(),
            ));
        }
        return Ok(Some(action_class_id.to_string()));
    }

    let Some(policy) = policy else {
        return Ok(None);
    };
    let requires_action_class_id = policy.rules.iter().any(|rule| {
        let rule_action_class_id = rule.action_class_id.trim();
        !rule_action_class_id.is_empty()
            && rule_action_class_id != "*"
            && rule_action_class_id != request.tool_name
    });
    if requires_action_class_id {
        return Err(CliError::cli_other_error(
            "Chio runtime action class id is required when policy rules use governance actionClassId values; pass --action-class-id".to_string(),
        ));
    }

    Ok(None)
}

#[cfg(test)]
mod verifier_tests {
    use super::resolve_runtime_pheromone_evaluation_verifier_id;

    #[test]
    fn pheromone_evaluation_uses_verifier_from_signed_inputs() {
        let verifier_id = match resolve_runtime_pheromone_evaluation_verifier_id(
            "did:chio:buyer-verifier",
            "did:chio:buyer-verifier",
        ) {
            Ok(verifier_id) => verifier_id,
            Err(error) => panic!("expected matching verifier ids to resolve: {error}"),
        };

        assert_eq!(verifier_id, "did:chio:buyer-verifier");
    }

    #[test]
    fn pheromone_evaluation_rejects_mismatched_signed_verifiers() {
        let error = match resolve_runtime_pheromone_evaluation_verifier_id(
            "did:chio:trust-verifier",
            "did:chio:policy-verifier",
        ) {
            Ok(verifier_id) => panic!("expected verifier mismatch, got {verifier_id}"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("does not match"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_binding() -> chio_runtime::RuntimeRequestBinding {
        chio_runtime::RuntimeRequestBinding {
            request_id: "req-1".to_string(),
            capability_id: "cap-1".to_string(),
            server_id: "server.vendor".to_string(),
            tool_name: "vendor.write_refund".to_string(),
            tool_args_sha256: "1".repeat(64),
            origin_kernel_id: Some("kernel.buyer".to_string()),
            host_kernel_id: "kernel.vendor".to_string(),
        }
    }

    fn policy_body(action_class_id: &str) -> chio_runtime::RuntimePheromonePolicy {
        chio_runtime::RuntimePheromonePolicy {
            schema: chio_runtime::CHIO_RUNTIME_PHEROMONE_POLICY_SCHEMA.to_string(),
            policy_id: "runtime-policy-1".to_string(),
            verifier_id: "did:chio:buyer-verifier".to_string(),
            key_id: "verifier-key-1".to_string(),
            policy_version: 1,
            mode: "enforce".to_string(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
            allowed_reputation_epochs: vec![7],
            max_query_report_age_ms: 60_000,
            min_distinct_origin_pairs: 1,
            runtime_trust_bundle_sha256: "2".repeat(64),
            peer_weights_sha256: "3".repeat(64),
            rules: vec![chio_runtime::RuntimePheromonePolicyRule {
                rule_id: "deny-high-risk-action".to_string(),
                subject_class: "workflow.destructive_step".to_string(),
                subject_class_namespace: "chio.runtime".to_string(),
                action_class_id: action_class_id.to_string(),
                direction: "deny_if_at_or_above".to_string(),
                threshold_total_strength: 0.75,
                effect: "deny".to_string(),
            }],
        }
    }

    #[test]
    fn runtime_action_class_id_trims_explicit_cli_value() {
        let action_class_id = resolve_runtime_action_class_id(
            &request_binding(),
            Some(&policy_body("workflow.destructive.vendor_call")),
            Some(" workflow.destructive.vendor_call "),
        )
        .expect("explicit action class id should resolve");

        assert_eq!(
            action_class_id.as_deref(),
            Some("workflow.destructive.vendor_call")
        );
    }

    #[test]
    fn runtime_action_class_id_rejects_policy_rules_that_need_governance_id() {
        let error = resolve_runtime_action_class_id(
            &request_binding(),
            Some(&policy_body("workflow.destructive.vendor_call")),
            None,
        )
        .expect_err("governance action-class policies must require an explicit action class id");

        assert!(error.to_string().contains("--action-class-id"));
    }

    #[test]
    fn runtime_action_class_id_allows_wildcard_or_tool_scoped_policy_rules() {
        let wildcard =
            resolve_runtime_action_class_id(&request_binding(), Some(&policy_body("*")), None)
                .expect("wildcard policy should return None action class id");
        assert!(wildcard.is_none());

        let tool_scoped = resolve_runtime_action_class_id(
            &request_binding(),
            Some(&policy_body("vendor.write_refund")),
            None,
        )
        .expect("tool-scoped policy should return None action class id");
        assert!(tool_scoped.is_none());
    }
}
