use super::*;

/// HTTP response header mirroring the signed receipt's advisory trust level.
/// Gate clients on this value (or on receipt `trust_level`) before treating
/// `POST /v1/evaluate` as kernel-mediated authorization.
pub(crate) const CHIO_TRUST_LEVEL_HEADER: &str = "chio-trust-level";

/// HTTP response header on routes that are documented stubs, not production
/// authorization paths (for example `POST /v1/capabilities/attenuate`).
pub(crate) const CHIO_ROUTE_STATUS_HEADER: &str = "chio-route-status";

pub(crate) fn parse_query_params(raw_query: Option<&str>) -> HashMap<String, String> {
    raw_query
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn forwarded_query_string(raw_query: Option<&str>) -> Option<String> {
    let raw_query = raw_query?;
    let filtered = url::form_urlencoded::parse(raw_query.as_bytes())
        .filter(|(key, _)| key != "chio_capability")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();

    if filtered.is_empty() {
        return None;
    }

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in filtered {
        serializer.append_pair(&key, &value);
    }
    let query = serializer.finish();
    (!query.is_empty()).then_some(query)
}

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

pub(crate) fn sidecar_advisory_tool_call_evaluate_response(receipt: ChioReceipt) -> Response {
    let body = match serde_json::to_vec(&receipt) {
        Ok(body) => body,
        Err(error) => {
            warn!("failed to serialize advisory evaluate receipt: {error}");
            return internal_json_error_response(
                "chio_receipt_serialize_failed",
                &error.to_string(),
            );
        }
    };

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header(CHIO_TRUST_LEVEL_HEADER, TrustLevel::Advisory.as_str())
        .body(Body::from(body))
        .unwrap_or_else(|_| sidecar_advisory_tool_call_evaluate_json_response(receipt))
}

pub(crate) fn sidecar_advisory_tool_call_evaluate_json_response(receipt: ChioReceipt) -> Response {
    let mut response = (StatusCode::OK, axum::Json(receipt)).into_response();
    response.headers_mut().insert(
        CHIO_TRUST_LEVEL_HEADER,
        axum::http::HeaderValue::from_static("advisory"),
    );
    response
}

pub(crate) fn sidecar_not_implemented_route_response(
    status: StatusCode,
    error: &str,
    message: &str,
    route_status: &str,
    extra_fields: serde_json::Value,
) -> Response {
    let mut body = serde_json::json!({
        "error": error,
        "message": message,
        "chio_route_status": route_status,
    });
    if let Some(extra) = extra_fields.as_object() {
        for (key, value) in extra {
            body[key] = value.clone();
        }
    }

    let body_text = serde_json::to_string(&body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header(CHIO_ROUTE_STATUS_HEADER, route_status)
        .body(Body::from(body_text))
        .unwrap_or_else(|_| (status, axum::Json(body)).into_response())
}

pub(crate) fn extract_presented_capability_from_maps<'a>(
    headers: &'a HashMap<String, String>,
    query: &'a HashMap<String, String>,
) -> Option<&'a str> {
    crate::evaluator::header_value(headers, "x-chio-capability")
        .or_else(|| query.get("chio_capability").map(String::as_str))
}

pub(crate) fn extract_caller_identity(headers: &HashMap<String, String>) -> CallerIdentity {
    crate::evaluator::caller_identity_from_headers(headers)
}

pub(crate) fn presented_capability_id(raw_capability: Option<&str>) -> Option<String> {
    serde_json::from_str::<CapabilityToken>(raw_capability?)
        .ok()
        .map(|token| token.id)
}

pub(crate) fn revoked_capability_verdict() -> Verdict {
    Verdict::deny_with_status(
        "capability token has been revoked",
        "CapabilityRevocation",
        403,
    )
}

pub(crate) fn should_forward_request_header(name: &str) -> bool {
    const LOCAL_HEADERS: &[&str] = &[
        "connection",
        "proxy-connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "x-chio-capability",
    ];
    !LOCAL_HEADERS
        .iter()
        .any(|local| name.eq_ignore_ascii_case(local))
}

pub(crate) fn verdict_http_status(verdict: &Verdict) -> u16 {
    match verdict {
        Verdict::Allow => 200,
        Verdict::Deny { http_status, .. } => *http_status,
        Verdict::Cancel { .. } | Verdict::Incomplete { .. } => 500,
    }
}

pub(crate) fn extract_transport_capability(
    headers: &axum::http::HeaderMap,
    query: &HashMap<String, String>,
) -> Option<String> {
    headers
        .get("x-chio-capability")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned)
        .or_else(|| query.get("chio_capability").cloned())
}
