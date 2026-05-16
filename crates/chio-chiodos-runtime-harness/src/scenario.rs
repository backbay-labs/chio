#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackScenario {
    pub(crate) run_id: String,
    #[serde(default)]
    pub(crate) admission_profile: Option<chio_chiodos_runtime::RuntimeAdmissionProfile>,
    #[serde(default)]
    pub(crate) admission_bundle: Option<chio_chiodos_runtime::RuntimeAdmissionBundle>,
    #[serde(default)]
    pub(crate) request: Option<chio_chiodos_runtime::RuntimeRequestBinding>,
    #[serde(default)]
    pub(crate) steps: Vec<RuntimeLoopbackStep>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RuntimeLoopbackStep {
    pub(crate) admission_profile: chio_chiodos_runtime::RuntimeAdmissionProfile,
    pub(crate) admission_bundle: chio_chiodos_runtime::RuntimeAdmissionBundle,
    pub(crate) request: chio_chiodos_runtime::RuntimeRequestBinding,
    #[serde(default)]
    pub(crate) arguments: Option<serde_json::Value>,
}
