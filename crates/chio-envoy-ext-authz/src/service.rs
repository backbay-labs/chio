//! gRPC service implementation for Envoy's `envoy.service.auth.v3.Authorization`
//! interface. Each `Check` RPC is translated into a Chio
//! [`crate::translate::ToolCallRequest`], routed through the
//! [`EnvoyKernel`] abstraction, and the returned [`Verdict`] is mapped back
//! onto an Envoy `CheckResponse`.

use async_trait::async_trait;
use tonic::{Code, Request, Response, Status};
use tracing::{debug, warn};

use crate::error::KernelError;
use crate::proto::envoy::config::core::v3::{HeaderValue, HeaderValueOption};
use crate::proto::envoy::r#type::v3::{HttpStatus, StatusCode as EnvoyStatusCode};
use crate::proto::envoy::service::auth::v3::{
    authorization_server::Authorization, check_response::HttpResponse, CheckRequest, CheckResponse,
    DeniedHttpResponse, OkHttpResponse,
};
use crate::proto::google::rpc::Status as RpcStatus;
use crate::translate::{check_request_to_tool_call, ToolCallRequest, Verdict};

/// Kernel abstraction used by [`ChioExtAuthzService`]. Real deployments supply
/// an implementation that delegates to `chio-kernel` (or `HttpAuthority` in
/// `chio-http-core`); tests can stub this trait to verify the adapter's
/// request/response plumbing in isolation.
#[async_trait]
pub trait EnvoyKernel: Send + Sync + 'static {
    /// Evaluate a translated tool call. Implementations must be fail-closed:
    /// return [`KernelError`] rather than panicking on internal faults so the
    /// adapter can deny with a 500 response.
    async fn evaluate(&self, request: ToolCallRequest) -> Result<Verdict, KernelError>;
}

/// Canonical `Authorization` service implementation. Construct it with the
/// concrete [`EnvoyKernel`] you want to route checks through, then register
/// it with a `tonic::transport::Server` via
/// [`authorization_server::AuthorizationServer::new`][asn].
///
/// [asn]: crate::proto::envoy::service::auth::v3::authorization_server::AuthorizationServer::new
pub struct ChioExtAuthzService<K: EnvoyKernel> {
    kernel: K,
}

impl<K: EnvoyKernel> ChioExtAuthzService<K> {
    /// Create a new service bound to `kernel`.
    pub fn new(kernel: K) -> Self {
        Self { kernel }
    }
}

#[async_trait]
impl<K: EnvoyKernel> Authorization for ChioExtAuthzService<K> {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let check = request.into_inner();

        let tool_call = match check_request_to_tool_call(&check) {
            Ok(call) => call,
            Err(err) => {
                warn!(error = %err, "ext_authz translation failed");
                return Ok(Response::new(fail_closed_response(&format!(
                    "ext_authz translation failed: {err}"
                ))));
            }
        };

        debug!(
            tool = %tool_call.tool,
            request_id = %tool_call.request_id,
            "evaluating ext_authz check"
        );

        match self.kernel.evaluate(tool_call).await {
            Ok(verdict) => Ok(Response::new(verdict_to_response(&verdict))),
            Err(err) => {
                warn!(error = %err, "ext_authz kernel evaluation failed");
                Ok(Response::new(fail_closed_response(&err.to_string())))
            }
        }
    }
}

/// Convert a Chio [`Verdict`] into the wire-level `CheckResponse` expected by
/// Envoy. Allow becomes status OK + `OkHttpResponse`; Deny becomes
/// `PERMISSION_DENIED` + `DeniedHttpResponse` with the Chio-supplied HTTP
/// status code (defaulting to 403).
fn verdict_to_response(verdict: &Verdict) -> CheckResponse {
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
            dynamic_metadata: None,
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
            CheckResponse {
                status: Some(RpcStatus {
                    code: Code::PermissionDenied as i32,
                    message: reason.clone(),
                    details: Vec::new(),
                }),
                http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
                    status: Some(HttpStatus {
                        code: envoy_status_code(*http_status),
                    }),
                    headers,
                    body: format!(
                        "{{\"verdict\":\"deny\",\"reason\":{},\"guard\":{}}}",
                        json_string(reason),
                        json_string(guard),
                    ),
                })),
                dynamic_metadata: None,
            }
        }
    }
}

/// Build the fail-closed `CheckResponse` returned whenever translation or
/// kernel evaluation errors out. The response denies with status 500 so the
/// downstream client sees an internal-error rather than a false allow.
fn fail_closed_response(reason: &str) -> CheckResponse {
    CheckResponse {
        status: Some(RpcStatus {
            code: Code::Internal as i32,
            message: reason.to_string(),
            details: Vec::new(),
        }),
        http_response: Some(HttpResponse::DeniedResponse(DeniedHttpResponse {
            status: Some(HttpStatus {
                code: EnvoyStatusCode::InternalServerError as i32,
            }),
            headers: vec![header_option("x-chio-denial-reason", reason)],
            body: format!(
                "{{\"verdict\":\"deny\",\"reason\":{},\"guard\":\"fail_closed\"}}",
                json_string(reason),
            ),
        })),
        dynamic_metadata: None,
    }
}

fn header_option(key: &str, value: &str) -> HeaderValueOption {
    HeaderValueOption {
        header: Some(HeaderValue {
            key: key.to_string(),
            value: value.to_string(),
            raw_value: Vec::new(),
        }),
        append: None,
        append_action: 0,
        keep_empty_value: false,
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
        451 => EnvoyStatusCode::Forbidden, // legal deny falls back to Forbidden
        500 => EnvoyStatusCode::InternalServerError,
        501 => EnvoyStatusCode::NotImplemented,
        502 => EnvoyStatusCode::BadGateway,
        503 => EnvoyStatusCode::ServiceUnavailable,
        504 => EnvoyStatusCode::GatewayTimeout,
        _ => EnvoyStatusCode::Forbidden,
    };
    mapped as i32
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

    #[test]
    fn allow_verdict_produces_ok_response() {
        let response = verdict_to_response(&Verdict::Allow);
        let status = response.status.unwrap();
        assert_eq!(status.code, Code::Ok as i32);
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
    fn fail_closed_uses_500() {
        let response = fail_closed_response("boom");
        match response.http_response.unwrap() {
            HttpResponse::DeniedResponse(denied) => {
                assert_eq!(
                    denied.status.unwrap().code,
                    EnvoyStatusCode::InternalServerError as i32
                );
                assert!(denied.body.contains("fail_closed"));
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
