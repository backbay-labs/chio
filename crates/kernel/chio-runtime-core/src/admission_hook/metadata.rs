pub(super) fn runtime_denial_metadata(admission_id: &str, failure_code: &str) -> serde_json::Value {
    serde_json::json!({
        "chio_runtime": {
            "admission_id": admission_id,
            "accepted": false,
            "failure_code": failure_code
        }
    })
}

pub(super) fn runtime_context_denial_metadata(failure_code: &str) -> serde_json::Value {
    serde_json::json!({
        "chio_runtime": {
            "accepted": false,
            "failure_code": failure_code
        }
    })
}
