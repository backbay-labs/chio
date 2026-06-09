//! Translation layer between Envoy's `CheckRequest` and the Chio-flavoured
//! [`ToolCallRequest`] consumed by the [`crate::EnvoyKernel`] trait.
//!
//! The types defined here are deliberately self-contained. The adapter does
//! not pull in `chio-kernel` or `chio-http-core`; instead it exposes a small
//! protocol-agnostic request / verdict pair that callers map onto the richer
//! Chio substrate types downstream.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::error::TranslateError;
use crate::proto::envoy::service::auth::v3::{
    attribute_context::{HttpRequest as ProtoHttpRequest, Peer as ProtoPeer},
    AttributeContext, CheckRequest,
};

/// HTTP method of the Envoy-intercepted request, preserved as a normalised
/// uppercase string. The Chio adapter treats the method opaquely so we avoid
/// pinning it to an enum that `chio-http-core` already owns.
pub type HttpMethod = String;

/// Simplified caller identity extracted from the CheckRequest. The adapter
/// records how the caller authenticated so downstream policy can enforce
/// stronger checks without forwarding raw secrets.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallerIdentity {
    /// Stable subject string, or `"anonymous"` when no principal was found.
    pub subject: String,

    /// How the caller authenticated.
    pub auth_method: AuthMethod,

    /// Whether the identity was cryptographically verified by the upstream
    /// (mTLS peer validation, for example). The adapter does not perform
    /// verification itself; it reports what Envoy asserted.
    pub verified: bool,
}

/// Minimal set of authentication methods understood by the ext_authz adapter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthMethod {
    /// Bearer token seen in the `Authorization` header. The raw token is
    /// never stored; only its SHA-256 hex digest is retained.
    Bearer {
        /// SHA-256 hex digest of the bearer token value.
        token_hash: String,
    },
    /// Explicit Chio capability token header.
    Capability {
        /// Opaque capability token identifier copied from
        /// `x-chio-capability-token`.
        capability_id: String,
    },
    /// mTLS peer certificate reported by Envoy.
    Mtls {
        /// Peer principal (SPIFFE URI or subject DN).
        principal: String,
    },
    /// No authentication credential was presented.
    #[default]
    Anonymous,
}

/// Chio-flavoured tool call request produced by [`check_request_to_tool_call`].
///
/// The adapter uses the HTTP method and request path to derive the tool
/// identity (`http.<method>.<path>`) so that Chio policies written against
/// HTTP resources can be evaluated uniformly with tool-style policies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCallRequest {
    /// Correlation identifier for this invocation. The adapter reuses the
    /// Envoy request id (`x-request-id`) when present, otherwise falls back
    /// to the HTTP request id from the attribute context.
    pub request_id: String,

    /// Derived tool identity, e.g. `http.get.resource`.
    pub tool: String,

    /// Tool server identifier. Chio's ext_authz bridge always reports
    /// `envoy` so that downstream authorities can tell the request came
    /// through the Envoy shim.
    pub server_id: String,

    /// Uppercase HTTP method.
    pub method: HttpMethod,

    /// Raw HTTP path (without query string).
    pub path: String,

    /// Query string portion of the path (without leading `?`).
    pub query: String,

    /// Selected request headers, keyed by lowercase name. Only policy-
    /// relevant headers are forwarded; secrets are stripped before they
    /// land in this map.
    pub headers: BTreeMap<String, String>,

    /// Extracted caller identity.
    pub caller: CallerIdentity,

    /// SHA-256 hex digest of the request body, when a body was forwarded.
    pub body_hash: Option<String>,

    /// Length in bytes of the request body as reported by Envoy.
    pub body_length: u64,

    /// Chio session id pulled from `x-chio-session-id`.
    pub session_id: Option<String>,

    /// Chio capability id pulled from `x-chio-capability-token`.
    pub capability_id: Option<String>,
}

/// Verdict returned by an [`crate::EnvoyKernel`] implementation.
///
/// This mirrors `chio_http_core::Verdict` but is kept local to avoid pulling
/// the substrate into the adapter's dependency graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Allow the request. The adapter returns an `OkHttpResponse`.
    Allow,

    /// Deny the request with an explicit HTTP status, reason, and guard name.
    /// Defaults follow the Chio convention of 403 Forbidden when the guard
    /// does not set an explicit status.
    Deny {
        /// Human-readable reason for denial.
        reason: String,
        /// Name of the guard or policy rule that denied the request.
        guard: String,
        /// HTTP status code to surface to the downstream client.
        http_status: u16,
    },
}

impl Verdict {
    /// Helper used by downstream wiring to produce a 403 deny verdict.
    pub fn deny(reason: impl Into<String>, guard: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
            guard: guard.into(),
            http_status: 403,
        }
    }

    /// True when the verdict is [`Verdict::Allow`].
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Chio identifies the Envoy shim as the tool server for every call it
/// processes. Policies that want to restrict to Envoy-originated traffic
/// match on this server id.
pub const ENVOY_SERVER_ID: &str = "envoy";

/// Translate an Envoy `CheckRequest` into a Chio [`ToolCallRequest`]. Returns
/// [`TranslateError`] when the request is malformed. The adapter treats a
/// translation error as an internal fault and denies fail-closed.
pub fn check_request_to_tool_call(check: &CheckRequest) -> Result<ToolCallRequest, TranslateError> {
    let attrs = check
        .attributes
        .as_ref()
        .ok_or(TranslateError::MissingAttributes)?;
    let request = attrs
        .request
        .as_ref()
        .ok_or(TranslateError::MissingRequest)?;
    let http = request
        .http
        .as_ref()
        .ok_or(TranslateError::MissingHttpRequest)?;

    let method = normalise_method(&http.method)?;
    let (path, query) = split_path_and_query(http);
    let headers = collect_policy_headers(&http.headers);
    let caller = extract_caller_identity(&http.headers, attrs.source.as_ref());

    let (body_hash, body_length) = derive_body_binding(http);

    let session_id = header_value(&http.headers, "x-chio-session-id");
    let capability_id = header_value(&http.headers, "x-chio-capability-token");

    let tool = derive_tool_identity(&method, &path);
    let request_id = choose_request_id(http, attrs);

    Ok(ToolCallRequest {
        request_id,
        tool,
        server_id: ENVOY_SERVER_ID.to_string(),
        method,
        path,
        query,
        headers,
        caller,
        body_hash,
        body_length,
        session_id,
        capability_id,
    })
}

/// Strip a leading `?` from a raw query string (Envoy includes the `?` in
/// the `path` field but not in the `query` field; we normalise both).
fn split_path_and_query(http: &ProtoHttpRequest) -> (String, String) {
    if !http.query.is_empty() {
        let path = if let Some(idx) = http.path.find('?') {
            http.path[..idx].to_string()
        } else {
            http.path.clone()
        };
        return (path, http.query.clone());
    }

    if let Some(idx) = http.path.find('?') {
        let path = http.path[..idx].to_string();
        let query = http.path[idx + 1..].to_string();
        return (path, query);
    }

    (http.path.clone(), String::new())
}

/// Envoy uppercases methods but defensive callers may pass lower-case or
/// mixed-case values; we normalise to uppercase and reject empty strings.
fn normalise_method(method: &str) -> Result<String, TranslateError> {
    let trimmed = method.trim();
    if trimmed.is_empty()
        || trimmed != method
        || method
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(TranslateError::InvalidHttpMethod(method.to_string()));
    }
    Ok(method.to_ascii_uppercase())
}

/// Collect only the headers a policy engine is expected to consume. Bearer
/// tokens and capability tokens are *not* forwarded in plain text; they are
/// consumed by [`extract_caller_identity`] and replaced with hashes.
fn collect_policy_headers(
    raw: &std::collections::HashMap<String, String>,
) -> BTreeMap<String, String> {
    const ALLOW_HEADERS: &[&str] = &[
        "content-type",
        "content-length",
        "host",
        "user-agent",
        "x-request-id",
        "x-chio-session-id",
        "x-chio-source",
    ];
    const STRIP_HEADERS: &[&str] = &["authorization", "x-chio-capability-token"];

    let mut out = BTreeMap::new();
    for (key, value) in raw {
        let lower = key.to_ascii_lowercase();
        if STRIP_HEADERS.contains(&lower.as_str()) {
            continue;
        }
        if ALLOW_HEADERS.contains(&lower.as_str()) {
            out.insert(lower, value.clone());
        }
    }
    out
}

/// Derive the caller identity in three steps:
/// 1. Prefer Chio's explicit capability header.
/// 2. Fall back to `Authorization: Bearer <jwt>`.
/// 3. Finally fall back to mTLS peer principal, if Envoy reported one.
fn extract_caller_identity(
    headers: &std::collections::HashMap<String, String>,
    source: Option<&ProtoPeer>,
) -> CallerIdentity {
    if let Some(cap_id) = header_value(headers, "x-chio-capability-token") {
        return CallerIdentity {
            subject: cap_id.clone(),
            auth_method: AuthMethod::Capability {
                capability_id: cap_id,
            },
            verified: false,
        };
    }

    if let Some(token) = bearer_token(headers) {
        let token_hash = sha256_hex(token.as_bytes());
        return CallerIdentity {
            subject: format!("bearer:{}", &token_hash[..16.min(token_hash.len())]),
            auth_method: AuthMethod::Bearer { token_hash },
            verified: false,
        };
    }

    if let Some(principal) = source.and_then(|p| {
        if p.principal.is_empty() {
            None
        } else {
            Some(p.principal.clone())
        }
    }) {
        return CallerIdentity {
            subject: principal.clone(),
            auth_method: AuthMethod::Mtls { principal },
            verified: true,
        };
    }

    CallerIdentity {
        subject: "anonymous".to_string(),
        auth_method: AuthMethod::Anonymous,
        verified: false,
    }
}

fn bearer_token(headers: &std::collections::HashMap<String, String>) -> Option<String> {
    let raw = header_value(headers, "authorization")?;
    let trimmed = raw.trim();
    let prefix = "Bearer ";
    if trimmed.len() > prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix) {
        let token = trimmed[prefix.len()..].trim();
        if token.is_empty() {
            None
        } else {
            Some(token.to_string())
        }
    } else {
        None
    }
}

fn header_value(headers: &std::collections::HashMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Bind the request body to the evaluation. Envoy forwards the body in one of
/// two fields (`body` for UTF-8 text, `raw_body` for binary). We hash
/// whichever field is populated; if neither carries bytes we fall back to the
/// declared length so the call is recorded as body-bearing.
fn derive_body_binding(http: &ProtoHttpRequest) -> (Option<String>, u64) {
    let hash = if !http.raw_body.is_empty() {
        Some(sha256_hex(&http.raw_body))
    } else if !http.body.is_empty() {
        Some(sha256_hex(http.body.as_bytes()))
    } else {
        None
    };
    let length = if http.size >= 0 { http.size as u64 } else { 0 };
    (hash, length)
}

/// Construct a tool identity by lowercasing the method and compressing the
/// request path into dot segments. Leading and trailing slashes collapse to
/// a single dot so `/resource/` and `/resource` produce the same identity.
fn derive_tool_identity(method: &str, path: &str) -> String {
    let method = method.to_ascii_lowercase();
    let segments: Vec<String> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(escape_tool_identity_segment)
        .collect();
    if segments.is_empty() {
        format!("http.{method}")
    } else {
        format!("http.{method}.{}", segments.join("."))
    }
}

fn escape_tool_identity_segment(segment: &str) -> String {
    let mut escaped = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'~') {
            escaped.push(char::from(byte));
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

/// Prefer the `x-request-id` header (Envoy always populates it for
/// correlation) over the attribute context id.
fn choose_request_id(http: &ProtoHttpRequest, attrs: &AttributeContext) -> String {
    if let Some(id) = header_value(&http.headers, "x-request-id") {
        return id;
    }
    if !http.id.is_empty() {
        return http.id.clone();
    }
    // Best-effort fallback: an empty string signals "unknown". Downstream
    // wiring typically fills this in with a UUID before recording a receipt.
    let _ = attrs;
    String::new()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::proto::envoy::service::auth::v3::attribute_context::{HttpRequest, Peer, Request};

    fn mk_check(
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &str,
        source_principal: Option<&str>,
    ) -> CheckRequest {
        let mut header_map = std::collections::HashMap::new();
        for (k, v) in headers {
            header_map.insert((*k).to_string(), (*v).to_string());
        }
        let http = HttpRequest {
            id: "req-internal".to_string(),
            method: method.to_string(),
            headers: header_map,
            path: path.to_string(),
            host: "upstream.internal".to_string(),
            scheme: "https".to_string(),
            query: String::new(),
            fragment: String::new(),
            size: body.len() as i64,
            protocol: "HTTP/2".to_string(),
            body: body.to_string(),
            raw_body: Vec::new(),
        };
        let source = source_principal.map(|p| Peer {
            address: None,
            service: String::new(),
            labels: Default::default(),
            principal: p.to_string(),
            certificate: String::new(),
        });
        CheckRequest {
            attributes: Some(AttributeContext {
                source,
                destination: None,
                request: Some(Request {
                    time: None,
                    http: Some(http),
                }),
                context_extensions: Default::default(),
                metadata_context: None,
                route_metadata_context: None,
            }),
        }
    }

    #[test]
    fn translate_missing_attributes() {
        let check = CheckRequest { attributes: None };
        let err = check_request_to_tool_call(&check).unwrap_err();
        assert_eq!(err, TranslateError::MissingAttributes);
    }

    #[test]
    fn translate_get_derives_tool_identity() {
        let check = mk_check("GET", "/resource", &[], "", None);
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.tool, "http.get.resource");
        assert_eq!(call.method, "GET");
        assert_eq!(call.path, "/resource");
        assert_eq!(call.server_id, ENVOY_SERVER_ID);
        assert!(call.body_hash.is_none());
        assert_eq!(call.caller.auth_method, AuthMethod::Anonymous);
    }

    #[test]
    fn translate_nested_path_joins_segments() {
        let check = mk_check("GET", "/v1/agents/42/tools", &[], "", None);
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.tool, "http.get.v1.agents.42.tools");
    }

    #[test]
    fn translate_dotted_path_segment_is_escaped() {
        let dotted = mk_check("GET", "/admin.list", &[], "", None);
        let slash_delimited = mk_check("GET", "/admin/list", &[], "", None);
        let dotted_call = check_request_to_tool_call(&dotted).unwrap();
        let slash_delimited_call = check_request_to_tool_call(&slash_delimited).unwrap();

        assert_eq!(dotted_call.tool, "http.get.admin%2Elist");
        assert_eq!(slash_delimited_call.tool, "http.get.admin.list");
        assert_ne!(dotted_call.tool, slash_delimited_call.tool);
    }

    #[test]
    fn translate_root_path_omits_segment() {
        let check = mk_check("POST", "/", &[], "", None);
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.tool, "http.post");
    }

    #[test]
    fn translate_put_with_body_captures_hash() {
        let body = r#"{"k":"v"}"#;
        let check = mk_check(
            "PUT",
            "/objects/1",
            &[("content-type", "application/json")],
            body,
            None,
        );
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.method, "PUT");
        assert_eq!(call.path, "/objects/1");
        let expected = sha256_hex(body.as_bytes());
        assert_eq!(call.body_hash.as_deref(), Some(expected.as_str()));
        assert_eq!(call.body_length, body.len() as u64);
        assert_eq!(
            call.headers.get("content-type").map(String::as_str),
            Some("application/json"),
        );
    }

    #[test]
    fn translate_authorization_bearer_populates_identity() {
        let check = mk_check(
            "GET",
            "/ping",
            &[("authorization", "Bearer eyJhbGciOi.payload.signature")],
            "",
            None,
        );
        let call = check_request_to_tool_call(&check).unwrap();
        match call.caller.auth_method {
            AuthMethod::Bearer { ref token_hash } => {
                assert_eq!(token_hash.len(), 64);
            }
            other => panic!("expected bearer identity, got {other:?}"),
        }
        assert!(call.caller.subject.starts_with("bearer:"));
        // Authorization header must never appear in the forwarded header map.
        assert!(!call.headers.contains_key("authorization"));
    }

    #[test]
    fn translate_capability_header_takes_precedence_over_bearer() {
        let check = mk_check(
            "GET",
            "/ping",
            &[
                ("authorization", "Bearer abc.def.ghi"),
                ("x-chio-capability-token", "cap-123"),
            ],
            "",
            None,
        );
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(
            call.caller.auth_method,
            AuthMethod::Capability {
                capability_id: "cap-123".to_string(),
            }
        );
        assert_eq!(call.capability_id.as_deref(), Some("cap-123"));
        assert!(!call.headers.contains_key("x-chio-capability-token"));
    }

    #[test]
    fn translate_mtls_principal_when_no_http_auth() {
        let check = mk_check(
            "GET",
            "/ping",
            &[],
            "",
            Some("spiffe://cluster.local/ns/agents/sa/caller"),
        );
        let call = check_request_to_tool_call(&check).unwrap();
        assert!(call.caller.verified);
        match call.caller.auth_method {
            AuthMethod::Mtls { ref principal } => {
                assert_eq!(principal, "spiffe://cluster.local/ns/agents/sa/caller");
            }
            other => panic!("expected mTLS identity, got {other:?}"),
        }
    }

    #[test]
    fn translate_session_header_is_captured() {
        let check = mk_check(
            "POST",
            "/execute",
            &[("x-chio-session-id", "sess-42")],
            "{}",
            None,
        );
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.session_id.as_deref(), Some("sess-42"));
    }

    #[test]
    fn translate_strips_chio_internal_response_headers() {
        let check = mk_check(
            "GET",
            "/ping",
            &[
                ("x-chio-session-id", "sess-42"),
                ("x-chio-source", "istio-mesh"),
                ("x-chio-receipt-id", "rcpt-123"),
                ("x-chio-verdict", "allow"),
                ("x-chio-denial-reason", "nope"),
                ("x-chio-denial-guard", "ScopeGuard"),
            ],
            "",
            None,
        );
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(
            call.headers.get("x-chio-session-id").map(String::as_str),
            Some("sess-42")
        );
        assert_eq!(
            call.headers.get("x-chio-source").map(String::as_str),
            Some("istio-mesh")
        );
        assert!(!call.headers.contains_key("x-chio-receipt-id"));
        assert!(!call.headers.contains_key("x-chio-verdict"));
        assert!(!call.headers.contains_key("x-chio-denial-reason"));
        assert!(!call.headers.contains_key("x-chio-denial-guard"));
    }

    #[test]
    fn translate_invalid_method_rejected() {
        let check = mk_check("", "/foo", &[], "", None);
        let err = check_request_to_tool_call(&check).unwrap_err();
        assert_eq!(err, TranslateError::InvalidHttpMethod(String::new()));
    }

    #[test]
    fn translate_method_with_surrounding_whitespace_rejected() {
        let check = mk_check(" GET ", "/foo", &[], "", None);
        let err = check_request_to_tool_call(&check).unwrap_err();
        assert_eq!(err, TranslateError::InvalidHttpMethod(" GET ".to_string()));
    }

    #[test]
    fn translate_path_with_query() {
        let mut check = mk_check("GET", "/search?q=cats&page=2", &[], "", None);
        // Simulate Envoy leaving the query string embedded in the path.
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.path, "/search");
        assert_eq!(call.query, "q=cats&page=2");

        // When Envoy populates the explicit `query` field we still split the
        // path cleanly.
        if let Some(attrs) = check.attributes.as_mut() {
            if let Some(req) = attrs.request.as_mut() {
                if let Some(http) = req.http.as_mut() {
                    http.path = "/search".to_string();
                    http.query = "q=dogs".to_string();
                }
            }
        }
        let call = check_request_to_tool_call(&check).unwrap();
        assert_eq!(call.path, "/search");
        assert_eq!(call.query, "q=dogs");
    }
}
