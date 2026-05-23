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
    let run_id = scenario.run_id;
    let steps = if scenario.steps.is_empty() {
        let admission_profile = scenario.admission_profile.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing admissionProfile".to_string(),
            )
        })?;
        let admission_bundle = scenario.admission_bundle.ok_or_else(|| {
            crate::RuntimeLoopbackError::message(
                "Chio runtime loopback scenario missing admissionBundle".to_string(),
            )
        })?;
        let request = scenario.request.ok_or_else(|| {
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
        scenario.steps
    };
    Ok((run_id, steps))
}
