#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackScenario {
    pub(crate) run_id: String,
    #[serde(default)]
    pub(crate) admission_profile: Option<chio_runtime_core::RuntimeAdmissionProfile>,
    #[serde(default)]
    pub(crate) admission_bundle: Option<chio_runtime_core::RuntimeAdmissionBundle>,
    #[serde(default)]
    pub(crate) request: Option<chio_runtime_core::RuntimeRequestBinding>,
    #[serde(default)]
    pub(crate) steps: Vec<RuntimeLoopbackStep>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackStep {
    pub(crate) admission_profile: chio_runtime_core::RuntimeAdmissionProfile,
    pub(crate) admission_bundle: chio_runtime_core::RuntimeAdmissionBundle,
    pub(crate) request: chio_runtime_core::RuntimeRequestBinding,
    #[serde(default)]
    pub(crate) arguments: Option<serde_json::Value>,
}

pub(crate) fn normalize_runtime_loopback_steps(
    scenario: RuntimeLoopbackScenario,
) -> Result<(String, Vec<RuntimeLoopbackStep>), crate::RuntimeLoopbackError> {
    let RuntimeLoopbackScenario {
        run_id,
        admission_profile,
        admission_bundle,
        request,
        steps,
    } = scenario;
    if run_id.is_empty() || run_id.trim() != run_id {
        return Err(crate::RuntimeLoopbackError::message(
            "Chio runtime loopback scenario runId must be non-empty and unpadded".to_string(),
        ));
    }
    let steps = if steps.is_empty() {
        let admission_profile = admission_profile.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing admissionProfile".to_string(),
            )
        })?;
        let admission_bundle = admission_bundle.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing admissionBundle".to_string(),
            )
        })?;
        let request = request.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing request".to_string(),
            )
        })?;
        vec![RuntimeLoopbackStep {
            admission_profile,
            admission_bundle,
            request,
            arguments: None,
        }]
    } else {
        if admission_profile.is_some() || admission_bundle.is_some() || request.is_some() {
            return Err(crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario cannot mix top-level admission fields with steps"
                    .to_string(),
            ));
        }
        steps
    };
    Ok((run_id, steps))
}

#[cfg(test)]
mod tests {
    use super::{normalize_runtime_loopback_steps, RuntimeLoopbackScenario};

    fn fixed_hash(ch: char) -> String {
        ch.to_string().repeat(64)
    }

    fn runtime_request() -> chio_runtime_core::RuntimeRequestBinding {
        chio_runtime_core::RuntimeRequestBinding {
            request_id: "req-loopback-scenario".to_string(),
            capability_id: "cap-loopback-scenario".to_string(),
            server_id: "server.loopback".to_string(),
            tool_name: "tool.loopback".to_string(),
            tool_args_sha256: fixed_hash('a'),
            origin_kernel_id: None,
            host_kernel_id: "kernel.loopback".to_string(),
        }
    }

    fn runtime_profile() -> chio_runtime_core::RuntimeAdmissionProfile {
        chio_runtime_core::RuntimeAdmissionProfile {
            schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_PROFILE_SCHEMA.to_string(),
            profile_id: "profile-loopback-scenario".to_string(),
            local_kernel_id: "kernel.loopback".to_string(),
            verifier_id: "did:chio:verifier".to_string(),
            issued_at_unix_ms: 1_800_000_000_000,
            expires_at_unix_ms: 1_800_003_600_000,
        }
    }

    fn runtime_bundle(
        request: chio_runtime_core::RuntimeRequestBinding,
    ) -> chio_runtime_core::RuntimeAdmissionBundle {
        chio_runtime_core::RuntimeAdmissionBundle {
            schema: chio_runtime_core::CHIO_RUNTIME_ADMISSION_BUNDLE_SCHEMA.to_string(),
            admission_id: "adm-loopback-scenario".to_string(),
            binding: request,
            workflow_id: "wf-loopback-scenario".to_string(),
            workflow_grant_id: "grant-loopback-scenario".to_string(),
            step_index: 0,
            destructive: false,
            lease_id: None,
            governance_receipt_id: None,
            trust_bundle_sha256: fixed_hash('b'),
            verification_context_sha256: fixed_hash('c'),
        }
    }

    fn runtime_step() -> super::RuntimeLoopbackStep {
        let request = runtime_request();
        super::RuntimeLoopbackStep {
            admission_profile: runtime_profile(),
            admission_bundle: runtime_bundle(request.clone()),
            request,
            arguments: None,
        }
    }

    fn scenario_with_run_id(run_id: &str) -> RuntimeLoopbackScenario {
        RuntimeLoopbackScenario {
            run_id: run_id.to_string(),
            admission_profile: None,
            admission_bundle: None,
            request: None,
            steps: Vec::new(),
        }
    }

    #[test]
    fn scenario_run_id_must_be_non_empty_and_unpadded() {
        for run_id in ["", " runtime-loopback-1", "runtime-loopback-1 "] {
            let error = match normalize_runtime_loopback_steps(scenario_with_run_id(run_id)) {
                Ok(_) => panic!("accepted invalid runtime loopback run id"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("runId"), "{error}");
        }
    }

    #[test]
    fn scenario_rejects_mixed_legacy_fields_and_steps() {
        let scenario = RuntimeLoopbackScenario {
            run_id: "runtime-loopback-1".to_string(),
            admission_profile: Some(runtime_profile()),
            admission_bundle: None,
            request: None,
            steps: vec![runtime_step()],
        };

        let error = match normalize_runtime_loopback_steps(scenario) {
            Ok(_) => panic!("accepted mixed top-level fields and step list"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("cannot mix top-level admission fields with steps"),
            "{error}"
        );
    }
}
