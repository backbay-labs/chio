//! Protocol-agnostic HTTP request model for Chio evaluation.

use std::collections::HashMap;

use chio_core_types::capability::scope::ModelMetadata;
use chio_kernel::SignedExecutionNonce;
use serde::{Deserialize, Serialize};

use crate::identity::CallerIdentity;
use crate::method::HttpMethod;

/// A protocol-agnostic HTTP request that Chio evaluates.
/// This is the shared input type for all HTTP substrate adapters --
/// reverse proxy, framework middleware, and sidecar alike.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChioHttpRequest {
    /// Unique request identifier (UUIDv7 recommended).
    pub request_id: String,

    /// HTTP method.
    pub method: HttpMethod,

    /// The matched route pattern (e.g., "/pets/{petId}"), not the raw path.
    /// Used for policy matching.
    pub route_pattern: String,

    /// The actual request path (e.g., "/pets/42").
    pub path: String,

    /// Query parameters.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub query: HashMap<String, String>,

    /// Selected request headers relevant to policy evaluation.
    /// Substrate adapters extract only the headers needed for guards
    /// (e.g., Content-Type, Content-Length) -- never raw auth headers.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,

    /// The extracted caller identity.
    pub caller: CallerIdentity,

    /// SHA-256 hash of the request body (for content binding in receipts).
    /// None for bodyless requests (GET, HEAD, OPTIONS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_hash: Option<String>,

    /// Content-Length of the request body in bytes.
    #[serde(default)]
    pub body_length: u64,

    /// Session ID this request belongs to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Capability token ID presented with this request, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,

    /// Optional sidecar tool server identity for synthetic tool-call evaluations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_server: Option<String>,

    /// Optional sidecar tool name for synthetic tool-call evaluations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// Optional structured tool-call arguments for synthetic sidecar evaluations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<serde_json::Value>,

    /// Optional model identity and safety tier for model-constrained grants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_metadata: Option<ModelMetadata>,

    /// Governed intent is not supported by the HTTP authority projection.
    /// It is retained here so the boundary can reject it instead of silently
    /// ignoring a security-sensitive field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governed_intent: Option<serde_json::Value>,

    /// Singular governed approval is unsupported on this projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<serde_json::Value>,

    /// Threshold governed approvals are unsupported on this projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_tokens: Option<serde_json::Value>,

    /// Threshold proposal is unsupported on this projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold_approval_proposal: Option<serde_json::Value>,

    /// Supplemental authorization is unsupported on this projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supplemental_authorization: Option<serde_json::Value>,

    /// Optional signed nonce presented to complete a strict nonce preflight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_nonce: Option<SignedExecutionNonce>,

    /// Unix timestamp (seconds) when the request was received.
    pub timestamp: u64,
}

impl ChioHttpRequest {
    /// Create a minimal request for testing or simple evaluations.
    #[must_use]
    pub fn new(
        request_id: String,
        method: HttpMethod,
        route_pattern: String,
        path: String,
        caller: CallerIdentity,
    ) -> Self {
        let now = chrono::Utc::now().timestamp() as u64;
        Self {
            request_id,
            method,
            route_pattern,
            path,
            query: HashMap::new(),
            headers: HashMap::new(),
            caller,
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id: None,
            tool_server: None,
            tool_name: None,
            arguments: None,
            model_metadata: None,
            governed_intent: None,
            approval_token: None,
            approval_tokens: None,
            threshold_approval_proposal: None,
            supplemental_authorization: None,
            execution_nonce: None,
            timestamp: now,
        }
    }

    /// Return the first authorization extension this HTTP projection cannot
    /// enforce. Callers use this to deny explicitly at the authority boundary.
    #[must_use]
    pub fn unsupported_authorization_extension(&self) -> Option<&'static str> {
        if self.governed_intent.is_some() {
            return Some("governed_intent");
        }
        if self.approval_token.is_some() {
            return Some("approval_token");
        }
        if self.approval_tokens.is_some() {
            return Some("approval_tokens");
        }
        if self.threshold_approval_proposal.is_some() {
            return Some("threshold_approval_proposal");
        }
        if self.supplemental_authorization.is_some() {
            return Some("supplemental_authorization");
        }
        None
    }

    /// Compute a content hash binding this request to a receipt.
    /// Hashes the canonical JSON of the route pattern, method, body hash,
    /// and query parameters.
    pub fn content_hash(&self) -> chio_core_types::Result<String> {
        let binding = RequestContentBinding {
            method: self.method,
            route_pattern: &self.route_pattern,
            path: &self.path,
            query: &self.query,
            body_hash: self.body_hash.as_deref(),
        };
        let bytes = chio_core_types::canonical_json_bytes(&binding)?;
        Ok(chio_core_types::sha256_hex(&bytes))
    }
}

/// Internal struct for deterministic content hashing.
#[derive(Serialize)]
struct RequestContentBinding<'a> {
    method: HttpMethod,
    route_pattern: &'a str,
    path: &'a str,
    query: &'a HashMap<String, String>,
    body_hash: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CallerIdentity;

    use chio_test_support::prelude::*;

    #[test]
    fn new_request_defaults() {
        let req = ChioHttpRequest::new(
            "req-001".to_string(),
            HttpMethod::Get,
            "/pets/{petId}".to_string(),
            "/pets/42".to_string(),
            CallerIdentity::anonymous(),
        );
        assert_eq!(req.method, HttpMethod::Get);
        assert!(req.body_hash.is_none());
        assert_eq!(req.body_length, 0);
        assert!(req.query.is_empty());
    }

    #[test]
    fn content_hash_deterministic() {
        let req = ChioHttpRequest::new(
            "req-002".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            CallerIdentity::anonymous(),
        );
        let h1 = req.content_hash().test_unwrap();
        let h2 = req.content_hash().test_unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn serde_roundtrip() {
        let mut req = ChioHttpRequest::new(
            "req-003".to_string(),
            HttpMethod::Put,
            "/pets/{petId}".to_string(),
            "/pets/7".to_string(),
            CallerIdentity::anonymous(),
        );
        req.query.insert("verbose".to_string(), "true".to_string());
        req.body_hash = Some("abc123".to_string());

        let json = serde_json::to_string(&req).test_unwrap();
        let back: ChioHttpRequest = serde_json::from_str(&json).test_unwrap();
        assert_eq!(back.method, HttpMethod::Put);
        assert_eq!(back.query.get("verbose").map(|s| s.as_str()), Some("true"));
        assert_eq!(back.body_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn serde_retains_unsupported_authorization_extensions_for_rejection() {
        let mut req = ChioHttpRequest::new(
            "req-auth-extension".to_string(),
            HttpMethod::Post,
            "/chio/evaluate".to_string(),
            "/chio/evaluate".to_string(),
            CallerIdentity::anonymous(),
        );
        req.approval_tokens = Some(serde_json::json!([
            { "id": "approval-a" },
            { "id": "approval-b" }
        ]));

        let json = serde_json::to_string(&req).test_unwrap();
        let back: ChioHttpRequest = serde_json::from_str(&json).test_unwrap();

        assert_eq!(
            back.unsupported_authorization_extension(),
            Some("approval_tokens")
        );
        assert_eq!(back.approval_tokens, req.approval_tokens);
    }

    #[test]
    fn content_hash_changes_with_query_params() {
        let mut req1 = ChioHttpRequest::new(
            "req-a".to_string(),
            HttpMethod::Get,
            "/search".to_string(),
            "/search".to_string(),
            CallerIdentity::anonymous(),
        );
        let mut req2 = req1.clone();

        req1.query.insert("q".to_string(), "cats".to_string());
        req2.query.insert("q".to_string(), "dogs".to_string());

        let h1 = req1.content_hash().test_unwrap();
        let h2 = req2.content_hash().test_unwrap();
        assert_ne!(
            h1, h2,
            "different query params should produce different hashes"
        );
    }

    #[test]
    fn content_hash_changes_with_body_hash() {
        let mut req1 = ChioHttpRequest::new(
            "req-b".to_string(),
            HttpMethod::Post,
            "/data".to_string(),
            "/data".to_string(),
            CallerIdentity::anonymous(),
        );
        let mut req2 = req1.clone();

        req1.body_hash = Some("bodyhash1".to_string());
        req2.body_hash = Some("bodyhash2".to_string());

        let h1 = req1.content_hash().test_unwrap();
        let h2 = req2.content_hash().test_unwrap();
        assert_ne!(
            h1, h2,
            "different body hashes should produce different content hashes"
        );
    }

    #[test]
    fn content_hash_differs_between_methods() {
        let req_get = ChioHttpRequest::new(
            "req-c".to_string(),
            HttpMethod::Get,
            "/resource".to_string(),
            "/resource".to_string(),
            CallerIdentity::anonymous(),
        );
        let req_post = ChioHttpRequest::new(
            "req-d".to_string(),
            HttpMethod::Post,
            "/resource".to_string(),
            "/resource".to_string(),
            CallerIdentity::anonymous(),
        );

        let h1 = req_get.content_hash().test_unwrap();
        let h2 = req_post.content_hash().test_unwrap();
        assert_ne!(
            h1, h2,
            "different methods should produce different content hashes"
        );
    }
}
