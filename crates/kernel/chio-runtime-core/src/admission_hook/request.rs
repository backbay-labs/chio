use chio_kernel::ToolCallRequest;

use crate::*;

impl RuntimeRequestBinding {
    pub fn from_tool_call_request(
        request: &ToolCallRequest,
        host_kernel_id: &str,
    ) -> Result<Self, ChioRuntimeError> {
        Ok(Self {
            request_id: request.request_id.clone(),
            capability_id: request.capability.id.clone(),
            server_id: request.server_id.clone(),
            tool_name: request.tool_name.clone(),
            tool_args_sha256: tool_args_sha256(&request.arguments)?,
            origin_kernel_id: request.federated_origin_kernel_id.clone(),
            host_kernel_id: host_kernel_id.to_string(),
        })
    }
}

pub(super) struct AdmissionReference {
    pub(super) admission_id: String,
    pub(super) bundle_sha256: Option<String>,
}

pub(super) fn admission_ref_from_request(
    request: &ToolCallRequest,
) -> Result<AdmissionReference, &'static str> {
    let Some(intent) = request.governed_intent.as_ref() else {
        return Err("missing_governed_intent");
    };
    let Some(context) = intent.context.as_ref() else {
        return Err("missing_chio_admission_context");
    };
    let Some(admission) = context.get("chioAdmission") else {
        return Err("missing_chio_admission_context");
    };
    let Some(object) = admission.as_object() else {
        return Err("invalid_chio_admission_context");
    };
    let Some(admission_id) = object.get("admissionId").and_then(|value| value.as_str()) else {
        return Err("missing_admission_id");
    };
    if admission_id.trim().is_empty() {
        return Err("missing_admission_id");
    }
    let bundle_sha256 = object
        .get("bundleSha256")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    Ok(AdmissionReference {
        admission_id: admission_id.to_string(),
        bundle_sha256,
    })
}

pub(super) fn request_has_chio_runtime_context(request: &ToolCallRequest) -> bool {
    request
        .governed_intent
        .as_ref()
        .and_then(|intent| intent.context.as_ref())
        .and_then(serde_json::Value::as_object)
        .is_some_and(|context| {
            context.contains_key("chioAdmission")
                || context.contains_key("chioTreaty")
                || context.contains_key("chioSwarm")
        })
}
