use super::*;

pub(crate) fn evaluation_error_response(error: &ProtectError) -> Response {
    match error {
        ProtectError::PendingApproval {
            approval_id,
            kernel_receipt_id,
        } => {
            let mut body = serde_json::json!({
                "error": "chio_approval_required",
                "message": "request requires human approval before it can proceed",
                "kernel_receipt_id": kernel_receipt_id,
            });
            if let Some(approval_id) = approval_id {
                body["approval_id"] = serde_json::Value::String(approval_id.clone());
                body["resume_path"] =
                    serde_json::Value::String(format!("/approvals/{approval_id}/respond"));
            }
            (StatusCode::CONFLICT, axum::Json(body)).into_response()
        }
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": "chio_evaluation_failed",
                "message": error.to_string(),
            })),
        )
            .into_response(),
    }
}

pub(crate) fn approval_json<T>(status: StatusCode, response: T) -> Response
where
    T: Serialize,
{
    (status, Json(response)).into_response()
}

pub(crate) fn approval_error_response(error: ApprovalHandlerError) -> Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(error.body())).into_response()
}

pub(crate) fn internal_json_error_response(error: &str, message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(serde_json::json!({
            "error": error,
            "message": message,
        })),
    )
        .into_response()
}

pub(crate) fn sidecar_bad_request(message: &str) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({
            "error": "chio_bad_request",
            "message": message,
        })),
    )
}
