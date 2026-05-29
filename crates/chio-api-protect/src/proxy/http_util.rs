use super::*;

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

pub(crate) fn extract_presented_capability_from_maps<'a>(
    headers: &'a HashMap<String, String>,
    query: &'a HashMap<String, String>,
) -> Option<&'a str> {
    headers
        .get("x-chio-capability")
        .or_else(|| headers.get("X-Chio-Capability"))
        .map(String::as_str)
        .or_else(|| query.get("chio_capability").map(String::as_str))
}

pub(crate) fn extract_caller_identity(headers: &HashMap<String, String>) -> CallerIdentity {
    if let Some(auth) = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))
    {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            let token_hash = chio_core_types::sha256_hex(token.as_bytes());
            return CallerIdentity {
                subject: format!("bearer:{}", &token_hash[..16]),
                auth_method: AuthMethod::Bearer { token_hash },
                verified: false,
                tenant: None,
                agent_id: None,
            };
        }
    }

    for key_header in &["x-api-key", "X-Api-Key", "X-API-Key"] {
        if let Some(key_value) = headers.get(*key_header) {
            let key_hash = chio_core_types::sha256_hex(key_value.as_bytes());
            return CallerIdentity {
                subject: format!("apikey:{}", &key_hash[..16]),
                auth_method: AuthMethod::ApiKey {
                    key_name: key_header.to_string(),
                    key_hash,
                },
                verified: false,
                tenant: None,
                agent_id: None,
            };
        }
    }

    CallerIdentity::anonymous()
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
    !matches!(
        name,
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
            | "x-chio-capability"
    )
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
