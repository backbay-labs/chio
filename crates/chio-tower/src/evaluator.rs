//! Request evaluator for the Chio tower middleware.
//!
//! Contains the core evaluation logic: matching routes, checking capabilities,
//! and signing receipts.

use std::collections::HashMap;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::GuardEvidence;
use chio_http_core::{
    CallerIdentity, HttpAuthority, HttpAuthorityError, HttpAuthorityInput, HttpAuthorityPolicy,
    HttpMethod, HttpReceipt, PreparedHttpEvaluation, Verdict,
};

use crate::error::ChioTowerError;
use crate::identity::IdentityExtractor;

/// Result of evaluating an HTTP request.
pub struct EvaluationResult {
    /// The kernel's verdict.
    pub verdict: Verdict,
    /// Signed receipt for the evaluation.
    pub receipt: HttpReceipt,
    /// Per-guard evidence collected during evaluation.
    pub evidence: Vec<GuardEvidence>,
}

/// Input payload for evaluating a single HTTP request.
pub struct EvaluationInput<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a HashMap<String, String>,
    pub caller: CallerIdentity,
    pub headers: &'a http::HeaderMap,
    pub body_hash: Option<String>,
    pub body_length: u64,
}

pub(crate) type PreparedEvaluation = PreparedHttpEvaluation;

/// Route pattern resolver function type.
pub type RouteResolver = fn(&str, &str) -> String;

/// Default route resolver returns the raw path.
fn default_route_resolver(_method: &str, path: &str) -> String {
    path.to_string()
}

/// Chio request evaluator. Holds the shared HTTP authority and tower-specific hooks.
pub struct ChioEvaluator {
    authority: HttpAuthority,
    identity_extractor: IdentityExtractor,
    route_resolver: RouteResolver,
    /// When true, sidecar errors allow the request through (fail-open).
    /// Default is false (fail-closed).
    fail_open: bool,
}

impl ChioEvaluator {
    /// Create a new evaluator with the given keypair and policy hash.
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            authority: HttpAuthority::new(keypair, policy_hash),
            identity_extractor: crate::identity::extract_identity,
            route_resolver: default_route_resolver,
            fail_open: false,
        }
    }

    /// Set a custom identity extractor.
    #[must_use]
    pub fn with_identity_extractor(mut self, extractor: IdentityExtractor) -> Self {
        self.identity_extractor = extractor;
        self
    }

    /// Set a custom route resolver.
    #[must_use]
    pub fn with_route_resolver(mut self, resolver: RouteResolver) -> Self {
        self.route_resolver = resolver;
        self
    }

    /// Set fail-open mode (allow requests when evaluation fails).
    #[must_use]
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    /// Whether this evaluator is configured for fail-open.
    pub fn is_fail_open(&self) -> bool {
        self.fail_open
    }

    /// Get the identity extractor function.
    pub fn identity_extractor(&self) -> IdentityExtractor {
        self.identity_extractor
    }

    /// Get the route resolver function.
    pub fn route_resolver(&self) -> RouteResolver {
        self.route_resolver
    }

    /// Evaluate an HTTP request, producing a verdict and signed receipt.
    pub fn evaluate(&self, input: EvaluationInput<'_>) -> Result<EvaluationResult, ChioTowerError> {
        let prepared = self.prepare(input)?;
        let receipt = self.sign_decision_receipt(&prepared)?;
        Ok(EvaluationResult {
            verdict: prepared.verdict,
            receipt,
            evidence: prepared.evidence,
        })
    }

    pub(crate) fn prepare(
        &self,
        input: EvaluationInput<'_>,
    ) -> Result<PreparedEvaluation, ChioTowerError> {
        let EvaluationInput {
            method,
            path,
            query,
            caller,
            headers,
            body_hash,
            body_length,
        } = input;
        let http_method = parse_method(method)?;
        let route_pattern = (self.route_resolver)(method, path);
        self.authority
            .prepare(HttpAuthorityInput {
                request_id: uuid::Uuid::now_v7().to_string(),
                method: http_method,
                route_pattern,
                path,
                query,
                caller,
                body_hash,
                body_length,
                session_id: None,
                capability_id_hint: None,
                presented_capability: extract_presented_capability(headers, query),
                requested_tool_server: None,
                requested_tool_name: None,
                requested_arguments: None,
                model_metadata: None,
                policy: policy_mode(http_method),
            })
            .map_err(Into::into)
    }

    pub(crate) fn sign_decision_receipt(
        &self,
        prepared: &PreparedEvaluation,
    ) -> Result<HttpReceipt, ChioTowerError> {
        self.authority
            .sign_decision_receipt(prepared)
            .map_err(Into::into)
    }

    pub(crate) fn finalize_receipt(
        &self,
        prepared: &PreparedEvaluation,
        response_status: u16,
    ) -> Result<HttpReceipt, ChioTowerError> {
        self.authority
            .finalize_receipt(prepared, response_status, None)
            .map_err(Into::into)
    }
}

fn extract_presented_capability<'a>(
    headers: &'a http::HeaderMap,
    query: &'a HashMap<String, String>,
) -> Option<&'a str> {
    headers
        .get("x-chio-capability")
        .or_else(|| headers.get("X-Chio-Capability"))
        .and_then(|value| value.to_str().ok())
        .or_else(|| query.get("chio_capability").map(String::as_str))
}

fn policy_mode(method: HttpMethod) -> HttpAuthorityPolicy {
    if method.is_safe() {
        HttpAuthorityPolicy::SessionAllow
    } else {
        HttpAuthorityPolicy::DenyByDefault
    }
}

impl From<HttpAuthorityError> for ChioTowerError {
    fn from(value: HttpAuthorityError) -> Self {
        match value {
            HttpAuthorityError::CallerIdentity(message) => {
                Self::IdentityExtraction(format!("hash failed: {message}"))
            }
            HttpAuthorityError::ContentHash(message) => {
                Self::Evaluation(format!("content hash failed: {message}"))
            }
            HttpAuthorityError::Kernel(message) => Self::Evaluation(message),
            HttpAuthorityError::PendingApproval {
                approval_id,
                kernel_receipt_id,
            } => Self::Evaluation(match approval_id {
                Some(approval_id) => format!(
                    "request requires approval; approval_id={approval_id}; kernel_receipt_id={kernel_receipt_id}"
                ),
                None => format!(
                    "request requires approval; kernel_receipt_id={kernel_receipt_id}"
                ),
            }),
            HttpAuthorityError::ReceiptSign(message) => {
                Self::ReceiptSign(format!("signing failed: {message}"))
            }
        }
    }
}

impl Clone for ChioEvaluator {
    fn clone(&self) -> Self {
        Self {
            authority: self.authority.clone(),
            identity_extractor: self.identity_extractor,
            route_resolver: self.route_resolver,
            fail_open: self.fail_open,
        }
    }
}

/// Parse an HTTP method string into the chio-http-core HttpMethod enum.
fn parse_method(method: &str) -> Result<HttpMethod, ChioTowerError> {
    match method.to_uppercase().as_str() {
        "GET" => Ok(HttpMethod::Get),
        "POST" => Ok(HttpMethod::Post),
        "PUT" => Ok(HttpMethod::Put),
        "PATCH" => Ok(HttpMethod::Patch),
        "DELETE" => Ok(HttpMethod::Delete),
        "HEAD" => Ok(HttpMethod::Head),
        "OPTIONS" => Ok(HttpMethod::Options),
        other => Err(ChioTowerError::Evaluation(format!(
            "unsupported HTTP method: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::capability::{CapabilityToken, CapabilityTokenBody, ChioScope};
    use chio_http_core::{
        http_status_scope, CHIO_HTTP_STATUS_SCOPE_DECISION, CHIO_HTTP_STATUS_SCOPE_FINAL,
    };

    fn valid_capability_token_json(id: &str, issuer: &Keypair) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ChioScope::default(),
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
            },
            issuer,
        )
        .unwrap_or_else(|e| panic!("token sign failed: {e}"));
        serde_json::to_string(&token).unwrap_or_else(|e| panic!("token serialize failed: {e}"))
    }

    fn evaluate(
        evaluator: &ChioEvaluator,
        method: &str,
        path: &str,
        query: &HashMap<String, String>,
        caller: CallerIdentity,
        headers: &http::HeaderMap,
    ) -> Result<EvaluationResult, ChioTowerError> {
        evaluator.evaluate(EvaluationInput {
            method,
            path,
            query,
            caller,
            headers,
            body_hash: None,
            body_length: 0,
        })
    }

    #[test]
    fn evaluate_safe_method_allowed() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let result = evaluate(
            &evaluator,
            "GET",
            "/pets",
            &HashMap::new(),
            caller,
            &headers,
        )
        .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_allowed());
        assert!(result
            .receipt
            .verify_signature()
            .unwrap_or_else(|e| panic!("verify failed: {e}")));
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_unsafe_method_denied_without_capability() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let result = evaluate(
            &evaluator,
            "POST",
            "/pets",
            &HashMap::new(),
            caller,
            &headers,
        )
        .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
        assert!(result
            .receipt
            .verify_signature()
            .unwrap_or_else(|e| panic!("verify failed: {e}")));
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_unsafe_method_allowed_with_capability() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair.clone(), "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-chio-capability",
            http::HeaderValue::from_str(&valid_capability_token_json("cap-123", &keypair))
                .unwrap_or_else(|e| panic!("header build failed: {e}")),
        );

        let result = evaluate(
            &evaluator,
            "POST",
            "/pets",
            &HashMap::new(),
            caller,
            &headers,
        )
        .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_allowed());
        assert_eq!(result.receipt.capability_id.as_deref(), Some("cap-123"));
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_invalid_method() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let err = evaluate(
            &evaluator,
            "FOOBAR",
            "/pets",
            &HashMap::new(),
            caller,
            &headers,
        );
        assert!(err.is_err());
    }

    #[test]
    fn evaluate_all_safe_methods() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let headers = http::HeaderMap::new();

        for method in &["GET", "HEAD", "OPTIONS"] {
            let caller = CallerIdentity::anonymous();
            let result = evaluate(
                &evaluator,
                method,
                "/test",
                &HashMap::new(),
                caller,
                &headers,
            )
            .unwrap_or_else(|e| panic!("evaluation failed for {method}: {e}"));
            assert!(result.verdict.is_allowed(), "{method} should be allowed");
        }
    }

    #[test]
    fn evaluate_all_unsafe_methods_denied() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let headers = http::HeaderMap::new();

        for method in &["POST", "PUT", "PATCH", "DELETE"] {
            let caller = CallerIdentity::anonymous();
            let result = evaluate(
                &evaluator,
                method,
                "/test",
                &HashMap::new(),
                caller,
                &headers,
            )
            .unwrap_or_else(|e| panic!("evaluation failed for {method}: {e}"));
            assert!(
                result.verdict.is_denied(),
                "{method} should be denied without capability"
            );
        }
    }

    #[test]
    fn fail_open_mode() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string()).with_fail_open(true);
        assert!(evaluator.is_fail_open());
    }

    #[test]
    fn custom_route_resolver() {
        fn resolver(_method: &str, path: &str) -> String {
            // Normalize by stripping trailing slashes
            path.trim_end_matches('/').to_string()
        }
        let keypair = Keypair::generate();
        let evaluator =
            ChioEvaluator::new(keypair, "test-policy".to_string()).with_route_resolver(resolver);

        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();
        let result = evaluate(
            &evaluator,
            "GET",
            "/pets/",
            &HashMap::new(),
            caller,
            &headers,
        )
        .unwrap_or_else(|e| panic!("evaluation failed: {e}"));
        assert!(result.verdict.is_allowed());
        // Route pattern should have trailing slash stripped
        assert_eq!(result.receipt.route_pattern, "/pets");
    }

    #[test]
    fn parse_method_case_insensitive() {
        // parse_method uppercases internally
        assert!(parse_method("get").is_ok());
        assert!(parse_method("Get").is_ok());
        assert!(parse_method("GET").is_ok());
    }

    #[test]
    fn evaluator_clone() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let cloned = evaluator.clone();

        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();

        let r1 = evaluate(
            &evaluator,
            "GET",
            "/test",
            &HashMap::new(),
            caller.clone(),
            &headers,
        )
        .unwrap_or_else(|e| panic!("r1 failed: {e}"));
        let r2 = evaluate(&cloned, "GET", "/test", &HashMap::new(), caller, &headers)
            .unwrap_or_else(|e| panic!("r2 failed: {e}"));

        // Both should produce valid receipts with the same kernel key.
        assert!(r1.verdict.is_allowed());
        assert!(r2.verdict.is_allowed());
        assert_eq!(r1.receipt.kernel_key, r2.receipt.kernel_key);
    }

    #[test]
    fn evaluate_invalid_capability_is_denied() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-chio-capability",
            http::HeaderValue::from_static("not-json"),
        );

        let result = evaluate(
            &evaluator,
            "POST",
            "/pets",
            &HashMap::new(),
            caller,
            &headers,
        )
        .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.is_none());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_query_parameters_affect_content_hash() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();
        let mut query_a = HashMap::new();
        query_a.insert("q".to_string(), "cats".to_string());
        let mut query_b = HashMap::new();
        query_b.insert("q".to_string(), "dogs".to_string());

        let result_a = evaluate(
            &evaluator,
            "GET",
            "/search",
            &query_a,
            caller.clone(),
            &headers,
        )
        .unwrap_or_else(|e| panic!("evaluation failed: {e}"));
        let result_b = evaluate(&evaluator, "GET", "/search", &query_b, caller, &headers)
            .unwrap_or_else(|e| panic!("evaluation failed: {e}"));

        assert_ne!(result_a.receipt.content_hash, result_b.receipt.content_hash);
    }

    #[test]
    fn finalize_receipt_marks_final_scope() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new(keypair, "test-policy".to_string());
        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();
        let query = HashMap::new();

        let prepared = evaluator
            .prepare(EvaluationInput {
                method: "GET",
                path: "/pets",
                query: &query,
                caller,
                headers: &headers,
                body_hash: None,
                body_length: 0,
            })
            .unwrap_or_else(|e| panic!("prepare failed: {e}"));
        let receipt = evaluator
            .finalize_receipt(&prepared, 201)
            .unwrap_or_else(|e| panic!("finalize failed: {e}"));

        assert_eq!(receipt.response_status, 201);
        assert_eq!(
            http_status_scope(receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
        assert!(receipt
            .verify_signature()
            .unwrap_or_else(|e| panic!("verify failed: {e}")));
    }
}
