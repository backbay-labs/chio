use super::*;
use std::collections::HashSet;

/// HTTP response header mirroring the signed receipt's advisory trust level.
/// Gate clients on this value (or on receipt `trust_level`) before treating
/// advisory sidecar evaluation as kernel-mediated authorization.
pub(crate) const CHIO_TRUST_LEVEL_HEADER: &str = "chio-trust-level";
pub(crate) const CHIO_EXECUTION_NONCE_HEADER: &str = "x-chio-execution-nonce";

pub(crate) fn parse_query_params(raw_query: Option<&str>) -> HashMap<String, String> {
    raw_query
        .map(|query| {
            url::form_urlencoded::parse(query.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn duplicate_query_key(raw_query: Option<&str>) -> Option<String> {
    let raw_query = raw_query?;
    let mut seen = HashSet::new();
    for (key, _) in url::form_urlencoded::parse(raw_query.as_bytes()) {
        let key = key.into_owned();
        if !seen.insert(key.clone()) {
            return Some(key);
        }
    }
    None
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

const SIDECAR_ADVISORY_EVALUATION_SCHEMA: &str = "chio.sidecar.advisory-evaluation.v1";
const SIDECAR_ADVISORY_AUTHORIZATION_BASIS: &str = "advisory_only";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SidecarAdvisoryEvaluationResponse {
    schema: &'static str,
    authorization: bool,
    authorization_basis: &'static str,
    receipt: ChioReceipt,
}

fn sidecar_advisory_evaluation_response_body(
    receipt: ChioReceipt,
) -> SidecarAdvisoryEvaluationResponse {
    SidecarAdvisoryEvaluationResponse {
        schema: SIDECAR_ADVISORY_EVALUATION_SCHEMA,
        authorization: false,
        authorization_basis: SIDECAR_ADVISORY_AUTHORIZATION_BASIS,
        receipt,
    }
}

pub(crate) fn sidecar_advisory_tool_call_evaluate_response(receipt: ChioReceipt) -> Response {
    let body = sidecar_advisory_evaluation_response_body(receipt);
    let body_bytes = match serde_json::to_vec(&body) {
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
        .body(Body::from(body_bytes))
        .unwrap_or_else(|_| sidecar_advisory_tool_call_evaluate_json_response(body.receipt))
}

pub(crate) fn sidecar_advisory_tool_call_evaluate_json_response(receipt: ChioReceipt) -> Response {
    let mut response = (
        StatusCode::OK,
        axum::Json(sidecar_advisory_evaluation_response_body(receipt)),
    )
        .into_response();
    response.headers_mut().insert(
        CHIO_TRUST_LEVEL_HEADER,
        axum::http::HeaderValue::from_static("advisory"),
    );
    response
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
        CHIO_EXECUTION_NONCE_HEADER,
    ];
    !LOCAL_HEADERS
        .iter()
        .any(|local| name.eq_ignore_ascii_case(local))
}

pub(crate) fn extract_execution_nonce_from_maps(
    headers: &HashMap<String, String>,
) -> Result<Option<chio_kernel::SignedExecutionNonce>, String> {
    let Some(raw_nonce) = crate::evaluator::header_value(headers, CHIO_EXECUTION_NONCE_HEADER)
    else {
        return Ok(None);
    };
    if raw_nonce.trim().is_empty() {
        return Err("blank execution nonce header".to_string());
    }
    serde_json::from_str(raw_nonce)
        .map(Some)
        .map_err(|error| format!("invalid execution nonce header: {error}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_query_key_detects_decoded_duplicates() {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("role", "user")
            .append_pair("mode", "full")
            .append_pair("role", "admin")
            .finish();

        assert_eq!(duplicate_query_key(Some(&query)).as_deref(), Some("role"));
    }
}
