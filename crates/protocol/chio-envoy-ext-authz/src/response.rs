//! Envoy `CheckResponse` construction for the ext_authz service.

use tonic::Code;

use crate::metadata::{
    allow_dynamic_metadata, deny_dynamic_metadata, fail_closed_dynamic_metadata,
};
use crate::proto::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
use crate::proto::envoy::r#type::v3::{HttpStatus, StatusCode as EnvoyStatusCode};
use crate::proto::envoy::service::auth::v3::{
    check_response::HttpResponse, CheckResponse, DeniedHttpResponse, OkHttpResponse,
};
use crate::proto::google::rpc::Status as RpcStatus;
use crate::translate::Verdict;

const FAIL_CLOSED_REASON: &str = "ext_authz request denied fail closed";

/// Convert a Chio [`Verdict`] into the wire-level `CheckResponse` expected by
/// Envoy. Allow becomes status OK + `OkHttpResponse`; Deny becomes
/// `PERMISSION_DENIED` + `DeniedHttpResponse` with the Chio-supplied HTTP
/// status code (defaulting to 403).
pub(crate) fn verdict_to_response(verdict: &Verdict) -> CheckResponse {
    match verdict {
        Verdict::Allow => CheckResponse {
            status: Some(RpcStatus {
                code: Code::Ok as i32,
                message: String::new(),
                details: Vec::new(),
            }),
            http_response: Some(HttpResponse::OkResponse(OkHttpResponse {
                headers: Vec::new(),
                headers_to_remove: Vec::new(),
                response_headers_to_add: Vec::new(),
                query_parameters_to_set: Vec::new(),
                query_parameters_to_remove: Vec::new(),
            })),
            dynamic_metadata: Some(allow_dynamic_metadata()),
        },
        Verdict::Deny {
            reason,
            guard,
            http_status,
        } => {
            let headers = vec![
                header_option("x-chio-denial-reason", reason),
                header_option("x-chio-denial-guard", guard),
            ];
            let admitted_http_status = envoy_status_code(*http_status);
            denied_check_response(
                Code::PermissionDenied,
                reason.clone(),
                admitted_http_status,
                headers,
                format!(
                    "{{\"verdict\":\"deny\",\"reason\":{},\"guard\":{}}}",
                    json_string(reason),
                    json_string(guard),
                ),
                Some(deny_dynamic_metadata(
                    reason,
                    guard,
                    status_code_to_http_status(admitted_http_status),
                )),
            )
        }
    }
}

/// Build the fail-closed `CheckResponse` returned whenever translation or
/// kernel evaluation errors out. The specific internal fault is only logged by
/// the service. The client-visible payload uses a stable reason so kernel
/// internals and malformed-input details do not cross the trust boundary.
pub(crate) fn fail_closed_response() -> CheckResponse {
    denied_check_response(
        Code::Internal,
        FAIL_CLOSED_REASON.to_string(),
        EnvoyStatusCode::InternalServerError as i32,
        vec![header_option("x-chio-denial-reason", FAIL_CLOSED_REASON)],
        format!(
            "{{\"verdict\":\"deny\",\"reason\":{},\"guard\":\"fail_closed\"}}",
            json_string(FAIL_CLOSED_REASON),
        ),
        Some(fail_closed_dynamic_metadata(FAIL_CLOSED_REASON)),
    )
}

fn denied_check_response(
    rpc_code: Code,
    message: String,
    http_status_code: i32,
    headers: Vec<HeaderValueOption>,
    body: String,
    dynamic_metadata: Option<prost_types::Struct>,
) -> CheckResponse {
    CheckResponse {
        status: Some(RpcStatus {
            code: rpc_code as i32,
            message,
            details: Vec::new(),
        }),
        http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
            status: Some(HttpStatus {
                code: http_status_code,
            }),
            headers,
            body,
        })),
        dynamic_metadata,
    }
}

fn header_option(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_string(),
            value: sanitize_header_value(value),
            raw_value: Vec::new(),
        }),
        append: None,
        append_action: 0,
        keep_empty_value: false,
    }
}

fn sanitize_header_value(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    let trimmed = sanitized.trim();
    if trimmed.is_empty() {
        "unspecified".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Translate an arbitrary HTTP status integer into the nearest Envoy
/// `StatusCode` enum value. Envoy's enum does not cover every possible HTTP
/// code, so we map the common Chio denial codes explicitly and fall back to
/// 403 Forbidden when we cannot represent the input faithfully.
fn envoy_status_code(code: u16) -> i32 {
    let mapped = match code {
        400 => EnvoyStatusCode::BadRequest,
        401 => EnvoyStatusCode::Unauthorized,
        402 => EnvoyStatusCode::PaymentRequired,
        403 => EnvoyStatusCode::Forbidden,
        404 => EnvoyStatusCode::NotFound,
        405 => EnvoyStatusCode::MethodNotAllowed,
        409 => EnvoyStatusCode::Conflict,
        410 => EnvoyStatusCode::Gone,
        418 => EnvoyStatusCode::Forbidden,
        422 => EnvoyStatusCode::UnprocessableEntity,
        423 => EnvoyStatusCode::Locked,
        424 => EnvoyStatusCode::FailedDependency,
        429 => EnvoyStatusCode::TooManyRequests,
        451 => EnvoyStatusCode::Forbidden,
        500 => EnvoyStatusCode::InternalServerError,
        501 => EnvoyStatusCode::NotImplemented,
        502 => EnvoyStatusCode::BadGateway,
        503 => EnvoyStatusCode::ServiceUnavailable,
        504 => EnvoyStatusCode::GatewayTimeout,
        _ => EnvoyStatusCode::Forbidden,
    };
    mapped as i32
}

fn status_code_to_http_status(code: i32) -> u16 {
    u16::try_from(code).unwrap_or(403)
}

/// JSON-escape a string so it can be embedded inside the fail-closed body
/// template without pulling `serde_json` into the dependency graph.
fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use prost_types::value::Kind;

    fn metadata_string(metadata: &prost_types::Struct, key: &str) -> Option<String> {
        metadata.fields.get(key).and_then(|value| {
            value.kind.as_ref().and_then(|kind| match kind {
                Kind::StringValue(value) => Some(value.clone()),
                _ => None,
            })
        })
    }

    fn metadata_number(metadata: &prost_types::Struct, key: &str) -> Option<f64> {
        metadata.fields.get(key).and_then(|value| {
            value.kind.as_ref().and_then(|kind| match kind {
                Kind::NumberValue(value) => Some(*value),
                _ => None,
            })
        })
    }

    fn metadata_bool(metadata: &prost_types::Struct, key: &str) -> Option<bool> {
        metadata.fields.get(key).and_then(|value| {
            value.kind.as_ref().and_then(|kind| match kind {
                Kind::BoolValue(value) => Some(*value),
                _ => None,
            })
        })
    }

    #[test]
    fn allow_verdict_produces_ok_response() {
        let response = verdict_to_response(&Verdict::Allow);
        let status = response.status.unwrap();
        assert_eq!(status.code, Code::Ok as i32);
        let metadata = response
            .dynamic_metadata
            .expect("allow response carries dynamic metadata");
        assert_eq!(
            metadata_string(&metadata, "chio.verdict").as_deref(),
            Some("allow")
        );
        match response.http_response.unwrap() {
            HttpResponse::OkResponse(_) => (),
            other => panic!("expected OkResponse, got {other:?}"),
        }
    }

    #[test]
    fn deny_verdict_sets_http_status_and_body() {
        let verdict = Verdict::deny("scope missing", "ScopeGuard");
        let response = verdict_to_response(&verdict);
        let status = response.status.unwrap();
        assert_eq!(status.code, Code::PermissionDenied as i32);
        let metadata = response
            .dynamic_metadata
            .expect("deny response carries dynamic metadata");
        assert_eq!(
            metadata_string(&metadata, "chio.verdict").as_deref(),
            Some("deny")
        );
        assert_eq!(
            metadata_string(&metadata, "chio.denial_reason").as_deref(),
            Some("scope missing")
        );
        assert_eq!(
            metadata_string(&metadata, "chio.denial_guard").as_deref(),
            Some("ScopeGuard")
        );
        assert_eq!(metadata_number(&metadata, "chio.http_status"), Some(403.0));
        match response.http_response.unwrap() {
            HttpResponse::DeniedResponse(denied) => {
                assert_eq!(
                    denied.status.unwrap().code,
                    EnvoyStatusCode::Forbidden as i32
                );
                assert!(denied.body.contains("\"reason\":\"scope missing\""));
                assert!(denied.body.contains("\"guard\":\"ScopeGuard\""));
            }
            other => panic!("expected DeniedResponse, got {other:?}"),
        }
    }

    #[test]
    fn deny_verdict_metadata_reports_admitted_envoy_status() {
        let verdict = Verdict::Deny {
            reason: "unsupported downstream status".to_string(),
            guard: "StatusGuard".to_string(),
            http_status: 999,
        };
        let response = verdict_to_response(&verdict);
        let metadata = response
            .dynamic_metadata
            .expect("deny response carries dynamic metadata");
        assert_eq!(metadata_number(&metadata, "chio.http_status"), Some(403.0));

        match response.http_response.unwrap() {
            HttpResponse::DeniedResponse(denied) => {
                assert_eq!(
                    denied.status.unwrap().code,
                    EnvoyStatusCode::Forbidden as i32
                );
            }
            other => panic!("expected DeniedResponse, got {other:?}"),
        }
    }

    #[test]
    fn deny_verdict_sanitizes_control_characters_before_headers() {
        let verdict = Verdict::Deny {
            reason: "scope\nmissing".to_string(),
            guard: "Guard\rName\tInjected".to_string(),
            http_status: 403,
        };
        let response = verdict_to_response(&verdict);

        match response.http_response.unwrap() {
            HttpResponse::DeniedResponse(denied) => {
                assert_eq!(denied.headers.len(), 2);
                for header in denied.headers {
                    let value = header.header.unwrap().value;
                    assert!(
                        !value.chars().any(char::is_control),
                        "header value retained control characters: {value:?}"
                    );
                }
            }
            other => panic!("expected DeniedResponse, got {other:?}"),
        }
    }

    #[test]
    fn fail_closed_uses_500_with_stable_reason() {
        let response = fail_closed_response();
        let status = response.status.unwrap();
        assert_eq!(status.code, Code::Internal as i32);
        assert_eq!(status.message, FAIL_CLOSED_REASON);
        let metadata = response
            .dynamic_metadata
            .expect("fail-closed response carries dynamic metadata");
        assert_eq!(
            metadata_string(&metadata, "chio.verdict").as_deref(),
            Some("deny")
        );
        assert_eq!(
            metadata_string(&metadata, "chio.denial_reason").as_deref(),
            Some(FAIL_CLOSED_REASON)
        );
        assert_eq!(
            metadata_string(&metadata, "chio.denial_guard").as_deref(),
            Some("fail_closed")
        );
        assert_eq!(metadata_number(&metadata, "chio.http_status"), Some(500.0));
        assert_eq!(metadata_bool(&metadata, "chio.fail_closed"), Some(true));
        match response.http_response.unwrap() {
            HttpResponse::DeniedResponse(denied) => {
                assert_eq!(
                    denied.status.unwrap().code,
                    EnvoyStatusCode::InternalServerError as i32
                );
                assert!(denied.body.contains("fail_closed"));
                assert!(denied.body.contains(FAIL_CLOSED_REASON));
            }
            other => panic!("expected DeniedResponse, got {other:?}"),
        }
    }

    #[test]
    fn denied_check_response_sets_rpc_and_http_status() {
        let response = denied_check_response(
            Code::PermissionDenied,
            "policy denied".to_string(),
            EnvoyStatusCode::TooManyRequests as i32,
            vec![header_option("x-chio-denial-reason", "policy denied")],
            "{\"verdict\":\"deny\"}".to_string(),
            None,
        );

        let status = response.status.unwrap();
        assert_eq!(status.code, Code::PermissionDenied as i32);
        assert_eq!(status.message, "policy denied");

        match response.http_response.unwrap() {
            HttpResponse::DeniedResponse(denied) => {
                assert_eq!(
                    denied.status.unwrap().code,
                    EnvoyStatusCode::TooManyRequests as i32
                );
                assert_eq!(denied.headers.len(), 1);
                assert_eq!(denied.body, "{\"verdict\":\"deny\"}");
            }
            other => panic!("expected DeniedResponse, got {other:?}"),
        }
    }

    #[test]
    fn envoy_status_code_falls_back_to_forbidden() {
        assert_eq!(envoy_status_code(999), EnvoyStatusCode::Forbidden as i32);
        assert_eq!(envoy_status_code(403), EnvoyStatusCode::Forbidden as i32);
        assert_eq!(envoy_status_code(418), EnvoyStatusCode::Forbidden as i32);
        assert_eq!(
            envoy_status_code(429),
            EnvoyStatusCode::TooManyRequests as i32
        );
    }

    #[test]
    fn json_string_escapes_special_characters() {
        let escaped = json_string("hello\n\"quoted\"");
        assert_eq!(escaped, "\"hello\\n\\\"quoted\\\"\"");
    }
}
