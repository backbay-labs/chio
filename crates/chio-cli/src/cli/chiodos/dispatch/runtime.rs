use super::*;

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

pub(crate) fn cmd_chiodos_runtime_orchestrate_lint(profile: &Path, report: &Path) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let profile_sha256 =
        chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration profile hash: {error}"
                ))
            },
        )?;
    let report_value = chio_chiodos_runtime::RuntimeOrchestrationStatusReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ORCHESTRATION_STATUS_REPORT_SCHEMA
            .to_string(),
        accepted: true,
        failure_code: None,
        generated_at_unix_ms: profile.issued_at_unix_ms,
        profile_sha256: profile_sha256.clone(),
        store_backend: "profile_lint".to_string(),
        store_path_sha256: profile_sha256,
        run_counts: std::collections::BTreeMap::new(),
        consumed_lease_count: 0,
        trust_floor_count: 0,
        latest_failure_code: None,
        evidence_sink_healthy: true,
        ready: true,
        degraded: false,
    };
    write_pretty_json(
        report,
        &report_value,
        "Chiodos runtime orchestration lint report",
    )
}

pub(crate) fn cmd_chiodos_runtime_orchestrate_plan(
    profile: &Path,
    run_contract: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let run_contract = load_runtime_run_contract(run_contract)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let plan = chio_chiodos_runtime::build_runtime_orchestration_plan(
        &profile,
        &run_contract,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime orchestration plan: {error}"))
    })?;
    if plan.accepted {
        store
            .record_run_state(&plan.run_id, "planned", None, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration planned run state: {error}"
                ))
            })?;
        for step in &plan.planned_steps {
            store
                .record_run_step_state(
                    &plan.run_id,
                    chio_chiodos_runtime::RuntimeOrchestrationStepState {
                        step_index: step.step_index,
                        admission_id: step.admission_id.clone(),
                        state: step.state.clone(),
                        destructive: false,
                        admission_report_sha256: None,
                        tool_receipt_sha256: None,
                        lease_id: None,
                    },
                )
                .map_err(|error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime orchestration planned step state: {error}"
                    ))
                })?;
        }
    }
    write_pretty_json(report, &plan, "Chiodos runtime orchestration plan")
}

pub(crate) fn cmd_chiodos_runtime_orchestrate_run(
    profile: &Path,
    run_contract: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let run_contract = load_runtime_run_contract(run_contract)?;
    let profile_sha256 =
        chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration profile hash: {error}"
                ))
            },
        )?;
    let run_contract_sha256 =
        chio_chiodos_runtime::runtime_run_contract_sha256(&run_contract).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime run contract hash: {error}"))
        })?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    let evidence =
        chio_chiodos_runtime::load_runtime_orchestration_evidence(evidence_dir).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration evidence: {error}"
                ))
            },
        )?;
    let mut accepted = evidence.proof_regeneration_report.accepted;
    let mut failure_code = evidence.proof_regeneration_report.failure_code.clone();
    if evidence.proof_regeneration_report.accepted && !evidence.verifier_report_accepted {
        accepted = false;
        failure_code = Some(
            evidence
                .verifier_report_failure_code
                .clone()
                .unwrap_or_else(|| "runtime_orchestration_verifier_report_rejected".to_string()),
        );
    } else if profile_sha256 != run_contract.profile_sha256 {
        accepted = false;
        failure_code = Some("runtime_orchestration_profile_hash_mismatch".to_string());
    } else if now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms {
        accepted = false;
        failure_code = Some("runtime_orchestration_profile_stale".to_string());
    } else if let Err(failure) =
        chio_chiodos_runtime::validate_runtime_orchestration_evidence_binding(
            &run_contract,
            &evidence,
        )
    {
        accepted = false;
        failure_code = Some(failure.code().to_string());
    }
    let status = if accepted {
        "proof_accepted"
    } else {
        "terminal_failure"
    };
    store
        .record_run_state(&run_contract.run_id, status, failure_code.as_deref(), now_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime orchestration run state: {error}"))
        })?;
    let mut step_states = Vec::new();
    for step in evidence.workflow_run_report.step_evidence {
        let state = chio_chiodos_runtime::RuntimeOrchestrationStepState {
            step_index: step.step_index,
            admission_id: step.admission_id,
            state: status.to_string(),
            destructive: step.destructive,
            admission_report_sha256: Some(step.admission_report_sha256),
            tool_receipt_sha256: Some(step.tool_receipt_sha256),
            lease_id: step.lease_id,
        };
        store
            .record_run_step_state(&run_contract.run_id, state.clone())
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration step state: {error}"
                ))
            })?;
        step_states.push(state);
    }
    for entry in &evidence.manifest.entries {
        store
            .record_evidence_artifact(&run_contract.run_id, entry, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration evidence artifact: {error}"
                ))
            })?;
    }
    let report_value = chio_chiodos_runtime::RuntimeOrchestrationRunReport {
        schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ORCHESTRATION_RUN_REPORT_SCHEMA.to_string(),
        run_id: run_contract.run_id,
        accepted,
        failure_code,
        status: status.to_string(),
        generated_at_unix_ms: now_unix_ms,
        profile_sha256,
        run_contract_sha256,
        workflow_run_report_sha256: Some(evidence.workflow_report_sha256),
        evidence_manifest_sha256: Some(evidence.manifest_sha256),
        proof_regeneration_report_sha256: Some(evidence.proof_report_sha256),
        verifier_report_sha256: Some(evidence.verifier_report_sha256),
        step_states,
        checks: vec![
            "runtime_orchestration.evidence_sink_loaded".to_string(),
            "runtime_orchestration.proof_regeneration_bound".to_string(),
        ],
    };
    write_pretty_json(
        report,
        &report_value,
        "Chiodos runtime orchestration run report",
    )
}

pub(crate) fn cmd_chiodos_runtime_orchestrate_resume(
    profile: &Path,
    resume_plan: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let mut resolved: chio_chiodos_runtime::RuntimeOrchestrationResumePlan =
        serde_json::from_str(&read_utf8_json_file(
            resume_plan,
            "Chiodos runtime orchestration resume plan",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime orchestration resume plan parse: {error}"
            ))
        })?;
    chio_chiodos_runtime::validate_runtime_orchestration_resume_plan(&resolved).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime orchestration resume plan: {error}"
            ))
        },
    )?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    ensure_runtime_evidence_dir(evidence_dir)?;
    resolved.generated_at_unix_ms = now_unix_ms;
    resolved
        .checks
        .push("runtime_orchestration.resume_inputs_loaded".to_string());
    let profile_stale =
        now_unix_ms < profile.issued_at_unix_ms || now_unix_ms >= profile.expires_at_unix_ms;
    if profile_stale {
        resolved.accepted = false;
        resolved.failure_code = Some("runtime_orchestration_profile_stale".to_string());
        resolved.blocked = true;
        resolved.next_step_index = None;
        resolved.reusable_step_indices.clear();
        resolved
            .checks
            .push("runtime_orchestration.profile_window".to_string());
    }
    chio_chiodos_runtime::validate_runtime_orchestration_resume_plan(&resolved).map_err(
        |error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime orchestration resume report: {error}"
            ))
        },
    )?;
    write_pretty_json(
        report,
        &resolved,
        "Chiodos runtime orchestration resume report",
    )
}

pub(crate) fn cmd_chiodos_runtime_orchestrate_status(
    profile: &Path,
    store: &Path,
    evidence_dir: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    let profile_sha256 =
        chio_chiodos_runtime::runtime_orchestration_profile_sha256(&profile).map_err(
            |error| {
                CliError::cli_other_error(format!(
                    "Chiodos runtime orchestration profile hash: {error}"
                ))
            },
        )?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime orchestration store: {error}")),
    )?;
    let evidence_sink_healthy =
        chio_chiodos_runtime::runtime_orchestration_evidence_sink_healthy(
            &profile,
            evidence_dir,
            now_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime orchestration evidence health: {error}"
            ))
        })?;
    let report_value = store
        .status_report(
            &profile,
            profile_sha256,
            now_unix_ms,
            evidence_sink_healthy,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime orchestration status: {error}"))
        })?;
    write_pretty_json(
        report,
        &report_value,
        "Chiodos runtime orchestration status report",
    )
}

pub(crate) fn cmd_chiodos_runtime_orchestrate_drift(
    profile: &Path,
    runs_dir: &Path,
    since_unix_ms: u64,
    until_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_orchestration_profile(profile)?;
    if since_unix_ms > until_unix_ms {
        return Err(CliError::cli_other_error(
            "Chiodos runtime drift since-unix-ms must not exceed until-unix-ms".to_string(),
        ));
    }
    chio_chiodos_runtime::validate_runtime_orchestration_profile_fresh(&profile, until_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!(
                "Chiodos runtime proof drift profile: {error}"
            ))
        })?;
    let mut runs_in_window = Vec::new();
    for run_dir in sorted_child_dirs(runs_dir)? {
        let evidence =
            chio_chiodos_runtime::load_runtime_orchestration_evidence(&run_dir).map_err(
                |error| {
                    CliError::cli_other_error(format!(
                        "Chiodos runtime orchestration evidence: {error}"
                    ))
                },
            )?;
        if evidence.manifest.generated_at_unix_ms >= since_unix_ms
            && evidence.manifest.generated_at_unix_ms <= until_unix_ms
        {
            runs_in_window.push((evidence.manifest.generated_at_unix_ms, run_dir, evidence));
        }
    }
    runs_in_window.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
    });
    if runs_in_window.len() < 2 {
        return Err(CliError::cli_other_error(
            "Chiodos runtime drift requires at least two run directories inside the requested time window"
                .to_string(),
        ));
    }
    let (_, _, baseline) = runs_in_window.remove(0);
    let mut selected_drift = None;
    for (_, _, candidate) in runs_in_window {
        let drift = chio_chiodos_runtime::generate_runtime_proof_drift_report(
            &baseline.manifest,
            &candidate.manifest,
            &baseline.proof_regeneration_report,
            &candidate.proof_regeneration_report,
            until_unix_ms,
        )
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime proof drift report: {error}"))
        })?;
        let drift_detected = !drift.accepted;
        selected_drift = Some(drift);
        if drift_detected {
            break;
        }
    }
    let Some(drift) = selected_drift else {
        return Err(CliError::cli_other_error(
            "Chiodos runtime drift requires a candidate run inside the requested time window"
                .to_string(),
        ));
    };
    write_pretty_json(report, &drift, "Chiodos runtime proof drift report")
}

pub(crate) fn load_runtime_orchestration_profile(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeOrchestrationProfile, CliError> {
    let profile = chio_chiodos_runtime::runtime_orchestration_profile_from_json(
        &read_utf8_json_file(path, "Chiodos runtime orchestration profile")?,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime orchestration profile: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_orchestration_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime orchestration profile: {error}"))
    })?;
    Ok(profile)
}

pub(crate) fn load_runtime_run_contract(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeRunContract, CliError> {
    let contract = chio_chiodos_runtime::runtime_run_contract_from_json(&read_utf8_json_file(
        path,
        "Chiodos runtime run contract",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime run contract: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_run_contract(&contract).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime run contract: {error}"))
    })?;
    Ok(contract)
}

pub(crate) fn ensure_runtime_evidence_dir(evidence_dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(evidence_dir).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to create Chiodos runtime evidence directory {}: {error}",
            evidence_dir.display()
        ))
    })
}

pub(crate) fn sorted_child_dirs(path: &Path) -> Result<Vec<PathBuf>, CliError> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(path).map_err(|error| {
        CliError::cli_io_error(format!(
            "failed to read Chiodos runtime runs directory {}: {error}",
            path.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            CliError::cli_io_error(format!(
                "failed to read Chiodos runtime runs directory entry: {error}"
            ))
        })?;
        if entry.path().is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

pub(crate) fn cmd_chiodos_runtime_ops_tick(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    owner_id: &str,
    now_unix_ms: u64,
    max_runs: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let tick = store
        .scheduler_tick_report(&profile, owner_id, now_unix_ms, max_runs)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime scheduler tick: {error}"))
        })?;
    write_pretty_json(report, &tick, "Chiodos runtime scheduler tick report")
}

pub(crate) fn cmd_chiodos_runtime_ops_status(
    supervisor_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    provider_bindings: Option<&Path>,
    now_unix_ms: Option<u64>,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let generated_at = now_unix_ms.unwrap_or_else(unix_now_ms);
    let provider_healthy = provider_bindings
        .map(|path| {
            let bindings = load_runtime_provider_bindings(path)?;
            let health = chio_chiodos_runtime::generate_runtime_provider_health_report(
                &profile,
                &bindings,
                generated_at,
            )
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime provider health: {error}"))
            })?;
            Ok::<bool, CliError>(health.accepted)
        })
        .transpose()?
        .unwrap_or(false);
    let evidence_sink_healthy =
        runtime_ops_status_evidence_sink_healthy(&profile, evidence_root, generated_at)?;
    let status = store
        .ops_status_report(&profile, generated_at, evidence_sink_healthy, provider_healthy)
        .map_err(|error| CliError::cli_other_error(format!("Chiodos runtime ops status: {error}")))?;
    write_pretty_json(report, &status, "Chiodos runtime ops status report")
}

pub(crate) fn runtime_ops_status_evidence_sink_healthy(
    profile: &chio_chiodos_runtime::RuntimeSupervisorProfile,
    evidence_root: &Path,
    now_unix_ms: u64,
) -> Result<bool, CliError> {
    if !evidence_root.is_dir() {
        return Ok(false);
    }
    let run_dirs = sorted_child_dirs(evidence_root)?;
    if run_dirs.is_empty() {
        return Ok(true);
    }
    for run_dir in run_dirs {
        let Some(run_id) = run_dir.file_name().and_then(|name| name.to_str()) else {
            return Ok(false);
        };
        let manifest_json = match read_utf8_json_file(
            &run_dir.join("runtime-evidence-manifest.json"),
            "Chiodos runtime evidence manifest",
        ) {
            Ok(json) => json,
            Err(_) => return Ok(false),
        };
        let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
            match serde_json::from_str(&manifest_json) {
                Ok(manifest) => manifest,
                Err(_) => return Ok(false),
            };
        let health = match chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
            run_id,
            &run_dir,
            &manifest,
            &profile.evidence_required_roles,
            now_unix_ms,
            true,
        ) {
            Ok(health) => health,
            Err(_) => return Ok(false),
        };
        if !health.accepted {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn cmd_chiodos_runtime_ops_recovery_drill(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    ensure_runtime_evidence_dir(evidence_root)?;
    let store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let drill = store
        .recovery_drill_report_for_profile(&profile, run_id, now_unix_ms)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime recovery drill: {error}"))
        })?;
    write_pretty_json(report, &drill, "Chiodos runtime recovery drill report")
}

pub(crate) fn cmd_chiodos_runtime_ops_evidence_health(
    supervisor_profile: &Path,
    run_id: &str,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    let evidence_dir = evidence_root.join(run_id);
    if !evidence_dir.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos runtime evidence health requires evidence-root/run-id directory {}",
            evidence_dir.display()
        )));
    }
    let manifest_json = read_utf8_json_file(
        &evidence_dir.join("runtime-evidence-manifest.json"),
        "Chiodos runtime evidence manifest",
    )?;
    let manifest: chio_chiodos_runtime::RuntimeEvidenceManifest =
        serde_json::from_str(&manifest_json).map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime evidence manifest: {error}"))
        })?;
    let health = chio_chiodos_runtime::generate_runtime_evidence_sink_health_report(
        run_id,
        &evidence_dir,
        &manifest,
        &profile.evidence_required_roles,
        now_unix_ms,
        true,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime evidence health: {error}"))
    })?;
    write_pretty_json(report, &health, "Chiodos runtime evidence health report")
}

pub(crate) fn cmd_chiodos_runtime_ops_provider_health(
    supervisor_profile: &Path,
    provider_bindings: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile = load_runtime_supervisor_profile(supervisor_profile)?;
    let bindings = load_runtime_provider_bindings(provider_bindings)?;
    let health = chio_chiodos_runtime::generate_runtime_provider_health_report(
        &profile,
        &bindings,
        now_unix_ms,
    )
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime provider health: {error}"))
    })?;
    write_pretty_json(report, &health, "Chiodos runtime provider health report")
}

pub(crate) fn load_runtime_provider_bindings(
    provider_bindings: &Path,
) -> Result<chio_chiodos_runtime::RuntimeProviderBindingsDocument, CliError> {
    chio_chiodos_runtime::runtime_provider_bindings_from_json(&read_utf8_json_file(
        provider_bindings,
        "Chiodos runtime provider bindings",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime provider bindings: {error}"))
    })
}

pub(crate) fn cmd_chiodos_runtime_ops_retention_plan(
    retention_profile: &Path,
    store: &Path,
    evidence_root: &Path,
    now_unix_ms: u64,
    report: &Path,
) -> Result<(), CliError> {
    let profile =
        chio_chiodos_runtime::runtime_artifact_retention_profile_from_json(&read_utf8_json_file(
            retention_profile,
            "Chiodos runtime artifact retention profile",
        )?)
        .map_err(|error| {
            CliError::cli_other_error(format!("Chiodos runtime artifact retention profile: {error}"))
        })?;
    let _store = chio_chiodos_runtime::SqliteRuntimeOrchestrationStore::open(store).map_err(
        |error| CliError::cli_other_error(format!("Chiodos runtime ops store: {error}")),
    )?;
    if !evidence_root.is_dir() {
        return Err(CliError::cli_other_error(format!(
            "Chiodos runtime retention plan requires existing evidence root {}",
            evidence_root.display()
        )));
    }
    let run_ids = sorted_child_dirs(evidence_root)?
        .into_iter()
        .filter_map(|path| path.file_name().map(|name| name.to_string_lossy().to_string()))
        .collect::<Vec<_>>();
    let plan =
        chio_chiodos_runtime::generate_runtime_artifact_retention_plan(&profile, &run_ids, now_unix_ms)
            .map_err(|error| {
                CliError::cli_other_error(format!("Chiodos runtime retention plan: {error}"))
            })?;
    write_pretty_json(report, &plan, "Chiodos runtime retention plan")
}

pub(crate) fn load_runtime_supervisor_profile(
    path: &Path,
) -> Result<chio_chiodos_runtime::RuntimeSupervisorProfile, CliError> {
    let profile = chio_chiodos_runtime::runtime_supervisor_profile_from_json(&read_utf8_json_file(
        path,
        "Chiodos runtime supervisor profile",
    )?)
    .map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime supervisor profile: {error}"))
    })?;
    chio_chiodos_runtime::validate_runtime_supervisor_profile(&profile).map_err(|error| {
        CliError::cli_other_error(format!("Chiodos runtime supervisor profile: {error}"))
    })?;
    Ok(profile)
}

pub(crate) fn cmd_chiodos_runtime_run_loopback(
    scenario: &Path,
    store_dir: &Path,
    now_unix_ms: u64,
    out_dir: &Path,
) -> Result<(), CliError> {
    chio_chiodos_runtime_harness::run_runtime_loopback_scenario(
        scenario,
        store_dir,
        now_unix_ms,
        out_dir,
    )
    .map_err(|error| CliError::cli_other_error(format!("Chiodos runtime loopback: {error}")))
}

pub(crate) fn validate_runtime_relative_path(relative_path: &str) -> Result<(), CliError> {
    if relative_path.trim() != relative_path
        || relative_path.is_empty()
        || relative_path.starts_with('/')
        || relative_path.contains('\\')
        || relative_path.contains(':')
        || relative_path.contains("//")
        || relative_path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(CliError::cli_other_error(format!(
            "Chiodos runtime artifact path {relative_path:?} is not safe relative evidence"
        )));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn canonical_sha256_json<T: serde::Serialize>(value: &T, label: &str) -> Result<String, CliError> {
    let bytes = chio_core_types::canonical::canonical_json_bytes(value)
        .map_err(|error| CliError::cli_other_error(format!("{label}: {error}")))?;
    Ok(chio_core::sha256_hex(&bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod chiodos_orchestration_cli_tests {
    use super::*;
    use serde::de::DeserializeOwned;
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    const ISSUED_AT: u64 = 1_800_000_000_000;
    const EXPIRES_AT: u64 = 1_800_003_600_000;
    const NOW: u64 = 1_800_000_010_000;

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn orchestration_profile() -> chio_chiodos_runtime::RuntimeOrchestrationProfile {
        chio_chiodos_runtime::RuntimeOrchestrationProfile {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ORCHESTRATION_PROFILE_SCHEMA
                .to_string(),
            profile_id: "profile-runtime-orchestration-cli".to_string(),
            local_kernel_id: "kernel.vendor-b".to_string(),
            verifier_id: "did:chio:buyer-verifier".to_string(),
            mode: "enforce".to_string(),
            issued_at_unix_ms: ISSUED_AT,
            expires_at_unix_ms: EXPIRES_AT,
            max_concurrent_runs: 2,
            fail_closed_on: vec!["runtime_orchestration_profile_stale".to_string()],
        }
    }

    fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(value)?;
        fs::write(path, format!("{json}\n"))?;
        Ok(())
    }

    fn write_json_with_hashes<T: serde::Serialize>(
        path: &Path,
        value: &T,
    ) -> Result<(String, String, u64), Box<dyn Error>> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(value)?;
        let bytes = format!("{json}\n").into_bytes();
        let file_sha256 = chio_core::sha256_hex(&bytes);
        let canonical_sha256 = canonical_sha256_json(value, "test canonical hash")?;
        let byte_count = u64::try_from(bytes.len())?;
        fs::write(path, bytes)?;
        Ok((file_sha256, canonical_sha256, byte_count))
    }

    fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
        Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
    }

    fn write_profile(
        dir: &Path,
        profile: &chio_chiodos_runtime::RuntimeOrchestrationProfile,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let path = dir.join("profile.json");
        write_json(&path, profile)?;
        Ok(path)
    }

    fn write_runtime_evidence(
        dir: &Path,
        run_id: &str,
        generated_at_unix_ms: u64,
        proof_marker: &str,
    ) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(dir)?;
        let proof_package = serde_json::json!({
            "schema": "chio.test.runtime-proof-package.v1",
            "marker": proof_marker
        });
        let (proof_package_file_sha256, proof_package_canonical_sha256, proof_package_byte_count) =
            write_json_with_hashes(&dir.join("proof-package.json"), &proof_package)?;
        let verifier_report = serde_json::json!({
            "schema": chio_chiodos::VERIFIER_REPORT_SCHEMA,
            "packageSha256": proof_package_canonical_sha256.clone(),
            "trustBundleSha256": fixed_hash('8'),
            "contextSha256": fixed_hash('9'),
            "revocationEpochHeight": 1,
            "accepted": true,
            "checks": [{
                "code": "runtime_verifier.accepted",
                "name": "runtime verifier accepted",
                "passed": true
            }]
        });
        let verifier_report_sha256 =
            canonical_sha256_json(&verifier_report, "test verifier report hash")?;
        let source_record = chio_chiodos_runtime::RuntimeProofSourceRecord {
            step_index: 0,
            admission_report_sha256: fixed_hash('1'),
            tool_receipt_sha256: fixed_hash('2'),
            bilateral_dsse_sha256: fixed_hash('3'),
            workflow_step_sha256: fixed_hash('4'),
        };
        let proof_report = chio_chiodos_runtime::RuntimeProofRegenerationReport {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_PROOF_REGENERATION_REPORT_SCHEMA
                .to_string(),
            run_id: run_id.to_string(),
            accepted: true,
            failure_code: None,
            generated_at_unix_ms,
            proof_package_sha256: Some(proof_package_canonical_sha256),
            verifier_report_sha256: Some(verifier_report_sha256.clone()),
            workflow_receipt_sha256: Some(fixed_hash('5')),
            source_records: vec![source_record.clone()],
            checks: vec!["runtime_source_records.bound".to_string()],
        };
        let proof_report_sha256 =
            canonical_sha256_json(&proof_report, "test proof report hash")?;
        let workflow_report = chio_chiodos_runtime::RuntimeWorkflowRunReport {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_WORKFLOW_RUN_REPORT_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            accepted: true,
            failure_code: None,
            generated_at_unix_ms,
            admission_report_sha256: fixed_hash('6'),
            evidence_paths: vec!["proof-package.json".to_string()],
            step_evidence: vec![chio_chiodos_runtime::RuntimeStepEvidence {
                schema: chio_chiodos_runtime::CHIODOS_RUNTIME_STEP_EVIDENCE_SCHEMA.to_string(),
                step_index: 0,
                admission_id: "adm-runtime-cli-0".to_string(),
                admission_report_sha256: source_record.admission_report_sha256.clone(),
                tool_receipt_id: format!("receipt-{run_id}"),
                tool_receipt_sha256: source_record.tool_receipt_sha256.clone(),
                output_sha256: fixed_hash('7'),
                bilateral_dsse_sha256: source_record.bilateral_dsse_sha256.clone(),
                workflow_step_sha256: source_record.workflow_step_sha256.clone(),
                parent_receipt_sha256: None,
                consistency_anchor: format!("chiodos:runtime:{run_id}:0"),
                destructive: false,
                lease_id: None,
                governance_receipt_id: None,
            }],
            proof_regeneration_report_sha256: Some(proof_report_sha256.clone()),
        };
        let workflow_report_sha256 =
            canonical_sha256_json(&workflow_report, "test workflow report hash")?;
        let manifest = chio_chiodos_runtime::RuntimeEvidenceManifest {
            schema: chio_chiodos_runtime::CHIODOS_RUNTIME_EVIDENCE_MANIFEST_SCHEMA.to_string(),
            run_id: run_id.to_string(),
            generated_at_unix_ms,
            workflow_run_report_sha256: workflow_report_sha256,
            proof_regeneration_report_sha256: proof_report_sha256,
            entries: vec![chio_chiodos_runtime::RuntimeEvidenceManifestEntry {
                role: "proof_package".to_string(),
                path: "proof-package.json".to_string(),
                sha256: proof_package_file_sha256,
                byte_count: proof_package_byte_count,
            }],
        };

        write_json(&dir.join("workflow-run-report.json"), &workflow_report)?;
        write_json(&dir.join("proof-regeneration-report.json"), &proof_report)?;
        write_json(&dir.join("runtime-evidence-manifest.json"), &manifest)?;
        write_json(&dir.join("verifier-report.json"), &verifier_report)?;
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_drift_rejects_stale_profile_window() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let mut profile = orchestration_profile();
        profile.expires_at_unix_ms = NOW;
        let profile_path = write_profile(dir.path(), &profile)?;
        let report_path = dir.path().join("drift-report.json");

        let error = cmd_chiodos_runtime_orchestrate_drift(
            &profile_path,
            &dir.path().join("runs"),
            ISSUED_AT,
            NOW,
            &report_path,
        )
        .expect_err("stale drift profile unexpectedly passed");

        assert!(error
            .to_string()
            .contains("runtime_orchestration_profile_stale"));
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_drift_compares_every_run_in_window() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let runs_dir = dir.path().join("runs");
        write_runtime_evidence(&runs_dir.join("run-a"), "run-a", NOW, "same")?;
        write_runtime_evidence(&runs_dir.join("run-b"), "run-b", NOW + 1, "same")?;
        write_runtime_evidence(&runs_dir.join("run-c"), "run-c", NOW + 2, "changed")?;
        let report_path = dir.path().join("drift-report.json");

        cmd_chiodos_runtime_orchestrate_drift(
            &profile_path,
            &runs_dir,
            NOW - 1,
            NOW + 3,
            &report_path,
        )?;
        let report: chio_chiodos_runtime::RuntimeProofDriftReport = read_json(&report_path)?;

        assert!(!report.accepted);
        assert_eq!(report.baseline_run_id, "run-a");
        assert_eq!(report.candidate_run_id, "run-c");
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_proof_drift_detected")
        );
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_rejects_missing_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let report_path = dir.path().join("status-report.json");

        cmd_chiodos_runtime_orchestrate_status(
            &profile_path,
            &dir.path().join("runtime.sqlite3"),
            &dir.path().join("missing-evidence"),
            NOW,
            &report_path,
        )?;
        let report: chio_chiodos_runtime::RuntimeOrchestrationStatusReport =
            read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        assert_eq!(
            report.failure_code.as_deref(),
            Some("runtime_ops_status_degraded")
        );
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_rejects_corrupt_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let evidence_dir = dir.path().join("evidence");
        fs::create_dir_all(&evidence_dir)?;
        fs::write(evidence_dir.join("workflow-run-report.json"), "{not json")?;
        let report_path = dir.path().join("status-report.json");

        cmd_chiodos_runtime_orchestrate_status(
            &profile_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_chiodos_runtime::RuntimeOrchestrationStatusReport =
            read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_status_rejects_stale_evidence() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let evidence_dir = dir.path().join("evidence");
        write_runtime_evidence(&evidence_dir, "run-stale", ISSUED_AT - 1, "stale")?;
        let report_path = dir.path().join("status-report.json");

        cmd_chiodos_runtime_orchestrate_status(
            &profile_path,
            &dir.path().join("runtime.sqlite3"),
            &evidence_dir,
            NOW,
            &report_path,
        )?;
        let report: chio_chiodos_runtime::RuntimeOrchestrationStatusReport =
            read_json(&report_path)?;

        assert!(!report.accepted);
        assert!(!report.evidence_sink_healthy);
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_resume_validates_forged_input() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let resume_path = dir.path().join("resume-plan.json");
        write_json(
            &resume_path,
            &chio_chiodos_runtime::RuntimeOrchestrationResumePlan {
                schema: chio_chiodos_runtime::CHIODOS_RUNTIME_ORCHESTRATION_RESUME_PLAN_SCHEMA
                    .to_string(),
                run_id: "run-forged".to_string(),
                accepted: true,
                failure_code: None,
                generated_at_unix_ms: NOW,
                next_step_index: Some(1),
                reusable_step_indices: vec![0],
                blocked: true,
                checks: vec!["runtime_orchestration.resume_inputs_loaded".to_string()],
            },
        )?;

        let error = cmd_chiodos_runtime_orchestrate_resume(
            &profile_path,
            &resume_path,
            &dir.path().join("runtime.sqlite3"),
            &dir.path().join("evidence"),
            NOW,
            &dir.path().join("resume-report.json"),
        )
        .expect_err("forged accepted blocked resume plan unexpectedly passed");

        assert!(error
            .to_string()
            .contains("runtime_orchestration_resume_accepted_blocked"));
        Ok(())
    }

    #[test]
    fn runtime_orchestrate_resume_validates_corrupt_input() -> Result<(), Box<dyn Error>> {
        let dir = TempDir::new()?;
        let profile_path = write_profile(dir.path(), &orchestration_profile())?;
        let resume_path = dir.path().join("resume-plan.json");
        write_json(
            &resume_path,
            &serde_json::json!({
                "schema": "chio.chiodos.runtime-orchestration-resume-plan.v0",
                "runId": "run-corrupt",
                "accepted": true,
                "generatedAtUnixMs": NOW,
                "nextStepIndex": 1,
                "reusableStepIndices": [0],
                "blocked": false,
                "checks": []
            }),
        )?;

        let error = cmd_chiodos_runtime_orchestrate_resume(
            &profile_path,
            &resume_path,
            &dir.path().join("runtime.sqlite3"),
            &dir.path().join("evidence"),
            NOW,
            &dir.path().join("resume-report.json"),
        )
        .expect_err("corrupt resume plan unexpectedly passed");

        assert!(error
            .to_string()
            .contains("unsupported_runtime_orchestration_resume_plan_schema"));
        Ok(())
    }
}
