//! Request evaluator: matches routes, checks capabilities, signs receipts.

use std::collections::HashMap;
use std::sync::Arc;

use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::metadata::GuardEvidence;
use chio_http_core::{
    AuthMethod, CallerIdentity, ChioHttpRequest, HttpAuthority, HttpAuthorityError,
    HttpAuthorityEvaluation, HttpAuthorityInput, HttpAuthorityPolicy, HttpMethod, HttpReceipt,
    Verdict,
};
use chio_kernel::{ApprovalStore, ReceiptStore, RevocationStore, SignedExecutionNonce};
use chio_openapi::PolicyDecision;
use serde_json::Value;

/// Backend label reported through the sidecar health endpoint. A durable store
/// survives restart; an ephemeral one does not.
const BACKEND_DURABLE: &str = "durable";
const BACKEND_EPHEMERAL: &str = "ephemeral";

/// Evaluated result for a single HTTP request.
pub struct EvaluationResult {
    pub verdict: Verdict,
    pub receipt: HttpReceipt,
    pub evidence: Vec<GuardEvidence>,
    pub execution_nonce: Option<SignedExecutionNonce>,
}

/// Route information extracted from the OpenAPI spec.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub pattern: String,
    pub method: HttpMethod,
    pub operation_id: Option<String>,
    pub policy: PolicyDecision,
}

/// The request evaluator holds the loaded route table and shared HTTP authority.
pub struct RequestEvaluator {
    routes: Vec<RouteEntry>,
    authority: HttpAuthority,
    receipt_backend: &'static str,
    revocation_backend: &'static str,
}

#[derive(Clone)]
pub(crate) struct DurableAdmissionStores {
    pub(crate) store: Arc<dyn chio_kernel::QualifiedAdmissionProjectionStore>,
    pub(crate) outcome_store: Arc<dyn chio_kernel::tool_outcome::QualifiedToolOutcomeStore>,
    pub(crate) fence: chio_kernel::admission_operation::StoreMutationFence,
}

impl RequestEvaluator {
    /// Compatibility shim for the pre-rename constructor name. Renamed to
    /// [`RequestEvaluator::new_ephemeral`] so an embedder never gets in-memory
    /// audit state by mistake; kept so existing callers keep compiling.
    #[deprecated(
        note = "renamed to `new_ephemeral`: this keeps the receipt log and revocation state in memory, lost on restart"
    )]
    pub fn new(routes: Vec<RouteEntry>, keypair: Keypair, policy_hash: String) -> Self {
        Self::new_ephemeral(routes, keypair, policy_hash)
    }

    /// Compatibility shim for the pre-rename constructor name; see
    /// [`RequestEvaluator::new_ephemeral_with_trusted_capability_issuers`].
    #[deprecated(
        note = "renamed to `new_ephemeral_with_trusted_capability_issuers`: this keeps the receipt log and revocation state in memory, lost on restart"
    )]
    pub fn new_with_trusted_capability_issuers(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self::new_ephemeral_with_trusted_capability_issuers(
            routes,
            keypair,
            policy_hash,
            trusted_capability_issuers,
        )
    }

    /// Compatibility shim for the pre-rename constructor name; see
    /// [`RequestEvaluator::new_ephemeral_with_approval_store`].
    #[deprecated(
        note = "renamed to `new_ephemeral_with_approval_store`: this keeps the receipt log and revocation state in memory, lost on restart"
    )]
    pub fn new_with_approval_store(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
    ) -> Self {
        Self::new_ephemeral_with_approval_store(routes, keypair, policy_hash, approval_store)
    }

    /// Compatibility shim for the pre-rename constructor name; see
    /// [`RequestEvaluator::new_ephemeral_with_approval_store_and_trusted_capability_issuers`].
    #[deprecated(
        note = "renamed to `new_ephemeral_with_approval_store_and_trusted_capability_issuers`: this keeps the receipt log and revocation state in memory, lost on restart"
    )]
    pub fn new_with_approval_store_and_trusted_capability_issuers(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self::new_ephemeral_with_approval_store_and_trusted_capability_issuers(
            routes,
            keypair,
            policy_hash,
            approval_store,
            trusted_capability_issuers,
        )
    }

    /// Build an evaluator whose embedded kernel keeps its receipt log and
    /// revocation state in memory; both are lost on restart. Ephemerality is
    /// opted into through the constructor name so an embedder never gets
    /// in-memory audit state by mistake. Durable-by-default construction goes
    /// through [`RequestEvaluator::new_with_durable_stores`].
    pub fn new_ephemeral(routes: Vec<RouteEntry>, keypair: Keypair, policy_hash: String) -> Self {
        Self::new_ephemeral_with_trusted_capability_issuers(
            routes,
            keypair,
            policy_hash,
            Vec::new(),
        )
    }

    /// Ephemeral evaluator with additional trusted capability issuers; see
    /// [`RequestEvaluator::new_ephemeral`].
    pub fn new_ephemeral_with_trusted_capability_issuers(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self {
            routes,
            authority: HttpAuthority::new_ephemeral_with_approval_store_and_trusted_issuers(
                keypair,
                policy_hash,
                Arc::new(chio_kernel::InMemoryApprovalStore::new()),
                trusted_capability_issuers,
            ),
            receipt_backend: BACKEND_EPHEMERAL,
            revocation_backend: BACKEND_EPHEMERAL,
        }
    }

    /// Ephemeral evaluator with a caller-provided approval store; see
    /// [`RequestEvaluator::new_ephemeral`].
    pub fn new_ephemeral_with_approval_store(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
    ) -> Self {
        Self::new_ephemeral_with_approval_store_and_trusted_capability_issuers(
            routes,
            keypair,
            policy_hash,
            approval_store,
            Vec::new(),
        )
    }

    /// Ephemeral evaluator with a caller-provided approval store and additional
    /// trusted capability issuers; see [`RequestEvaluator::new_ephemeral`].
    pub fn new_ephemeral_with_approval_store_and_trusted_capability_issuers(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
    ) -> Self {
        Self {
            routes,
            authority: HttpAuthority::new_ephemeral_with_approval_store_and_trusted_issuers(
                keypair,
                policy_hash,
                approval_store,
                trusted_capability_issuers,
            ),
            receipt_backend: BACKEND_EPHEMERAL,
            revocation_backend: BACKEND_EPHEMERAL,
        }
    }

    /// Build an evaluator whose embedded kernel is backed by durable stores when
    /// provided. A `Some` store is attached and the kernel runs fail-closed
    /// against it. When a store is absent (or an attached one reports ephemeral),
    /// the kernel runs in-memory for that backend only when `allow_ephemeral` is
    /// set: durable-by-default, an operator must explicitly opt into losing
    /// receipts or revocation state on restart rather than getting it silently.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_durable_stores(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        receipt_store: Option<Arc<dyn ReceiptStore>>,
        revocation_store: Option<Arc<dyn RevocationStore>>,
        allow_ephemeral: bool,
    ) -> Result<Self, HttpAuthorityError> {
        Self::new_with_durable_stores_and_admission(
            routes,
            keypair,
            policy_hash,
            approval_store,
            trusted_capability_issuers,
            receipt_store,
            revocation_store,
            None,
            allow_ephemeral,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_with_durable_stores_and_admission(
        routes: Vec<RouteEntry>,
        keypair: Keypair,
        policy_hash: String,
        approval_store: Arc<dyn ApprovalStore>,
        trusted_capability_issuers: Vec<PublicKey>,
        receipt_store: Option<Arc<dyn ReceiptStore>>,
        revocation_store: Option<Arc<dyn RevocationStore>>,
        durable_admission: Option<DurableAdmissionStores>,
        allow_ephemeral: bool,
    ) -> Result<Self, HttpAuthorityError> {
        let receipt_backend = if receipt_store.is_some() {
            BACKEND_DURABLE
        } else {
            BACKEND_EPHEMERAL
        };
        // A revocation store counts as durable only if it survives a restart. An
        // in-memory store may be attached to share its handle with the sidecar's
        // release path in ephemeral mode; it must still report ephemeral so it
        // neither advertises a durable backend nor falsely satisfies the kernel's
        // revocation-durability gate.
        let revocation_is_ephemeral = revocation_store
            .as_ref()
            .is_none_or(|store| store.is_ephemeral());
        let revocation_backend = if revocation_is_ephemeral {
            BACKEND_EPHEMERAL
        } else {
            BACKEND_DURABLE
        };

        // The ephemeral allowances gate on the explicit opt-in, not on whether a
        // durable store happens to be absent. A durable revocation store keeps
        // the gate satisfied regardless (the kernel checks the store's own
        // durability); an absent or in-memory one requires `allow_ephemeral`, so
        // an embedder with durable receipts can never silently re-accept a
        // capability revoked before a restart from in-memory revocation state.
        let mut builder = HttpAuthority::builder()
            .approval_store(approval_store)
            .trusted_capability_issuers(trusted_capability_issuers)
            .allow_ephemeral_receipt_log(allow_ephemeral)
            .allow_ephemeral_revocation_store(allow_ephemeral);
        if let Some(store) = receipt_store {
            builder = builder.receipt_store(store);
        }
        if let Some(store) = revocation_store {
            builder = builder.revocation_store(store);
        }
        if let Some(durable) = durable_admission {
            builder = builder.durable_admission_stores(
                durable.store,
                durable.outcome_store,
                durable.fence,
            );
        }
        let authority = builder.build(keypair, policy_hash)?;

        Ok(Self {
            routes,
            authority,
            receipt_backend,
            revocation_backend,
        })
    }

    /// Health label for the embedded kernel's receipt backend.
    pub fn receipt_backend(&self) -> &'static str {
        self.receipt_backend
    }

    /// Health label for the embedded kernel's revocation backend.
    pub fn revocation_backend(&self) -> &'static str {
        self.revocation_backend
    }

    #[cfg(test)]
    #[must_use]
    pub fn approval_store(&self) -> Arc<dyn ApprovalStore> {
        self.authority.approval_store()
    }

    #[cfg(test)]
    pub fn enable_strict_execution_nonce_for_tests(&mut self) {
        let cfg = chio_kernel::ExecutionNonceConfig {
            nonce_ttl_secs: 30,
            nonce_store_capacity: 1024,
            require_nonce: true,
        };
        let store = Box::new(chio_kernel::InMemoryExecutionNonceStore::from_config(&cfg));
        if let Err(error) = self.authority.set_execution_nonce_store(cfg, store) {
            panic!("strict execution nonce test setup failed: {error}");
        }
    }

    /// Evaluate an incoming HTTP request against the route table.
    pub fn evaluate(
        &self,
        method: HttpMethod,
        path: &str,
        query: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        body_hash: Option<String>,
        body_length: u64,
    ) -> Result<EvaluationResult, crate::error::ProtectError> {
        self.evaluate_with_execution_nonce(
            method,
            path,
            query,
            headers,
            body_hash,
            body_length,
            None,
        )
    }

    /// Evaluate an incoming HTTP request with an optional direct-proxy nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn evaluate_with_execution_nonce(
        &self,
        method: HttpMethod,
        path: &str,
        query: &HashMap<String, String>,
        headers: &HashMap<String, String>,
        body_hash: Option<String>,
        body_length: u64,
        execution_nonce: Option<&SignedExecutionNonce>,
    ) -> Result<EvaluationResult, crate::error::ProtectError> {
        // A nonce retry is the same request; retain its signed idempotency identity.
        let request_id = execution_nonce.map_or_else(
            || uuid::Uuid::now_v7().to_string(),
            |nonce| nonce.nonce.bound_to.request_id.clone(),
        );
        let caller = caller_identity_from_headers(headers);
        let (route_pattern, matched_policy) = self.match_route(method, path);
        let result = self.authority.evaluate(HttpAuthorityInput {
            request_id,
            method,
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
            execution_nonce,
            model_metadata: None,
            unsupported_authorization_extension: None,
            policy: policy_mode(matched_policy),
        })?;
        Ok(result.into())
    }

    /// Evaluate a fully normalized sidecar request.
    pub fn evaluate_chio_request(
        &self,
        request: ChioHttpRequest,
        presented_capability: Option<&str>,
    ) -> Result<EvaluationResult, crate::error::ProtectError> {
        let unsupported_authorization_extension = request.unsupported_authorization_extension();
        let ChioHttpRequest {
            request_id,
            method,
            route_pattern: _client_route_pattern,
            path,
            query,
            headers,
            caller,
            body_hash,
            body_length,
            session_id,
            capability_id,
            tool_server,
            tool_name,
            arguments,
            model_metadata,
            execution_nonce,
            ..
        } = request;
        let (route_pattern, matched_policy, _) = self.match_route_with_status(method, &path);
        let raw_capability =
            presented_capability.or_else(|| extract_presented_capability(&headers, &query));
        let arguments = arguments.unwrap_or(Value::Null);
        let result = self.authority.evaluate(HttpAuthorityInput {
            request_id,
            method,
            route_pattern,
            path: &path,
            query: &query,
            caller,
            body_hash,
            body_length,
            session_id,
            capability_id_hint: capability_id.as_deref(),
            presented_capability: raw_capability,
            requested_tool_server: tool_server.as_deref(),
            requested_tool_name: tool_name.as_deref(),
            requested_arguments: Some(&arguments),
            execution_nonce: execution_nonce.as_ref(),
            model_metadata: model_metadata.as_ref(),
            unsupported_authorization_extension,
            policy: policy_mode(matched_policy),
        })?;
        Ok(result.into())
    }

    /// Match a request path against the route table.
    /// Returns (matched_pattern, policy). Falls back to a catch-all.
    fn match_route(&self, method: HttpMethod, path: &str) -> (String, PolicyDecision) {
        let (pattern, policy, _) = self.match_route_with_status(method, path);
        (pattern, policy)
    }

    fn match_route_with_status(
        &self,
        method: HttpMethod,
        path: &str,
    ) -> (String, PolicyDecision, bool) {
        // Try exact pattern match first, then prefix match.
        for route in &self.routes {
            if route.method == method && path_matches_pattern(path, &route.pattern) {
                return (route.pattern.clone(), route.policy, true);
            }
        }

        // Fallback: use method-based default policy.
        let pattern = path.to_string();
        let policy = if method.is_safe() {
            PolicyDecision::SessionAllow
        } else {
            PolicyDecision::DenyByDefault
        };
        (pattern, policy, false)
    }
}

fn extract_presented_capability<'a>(
    headers: &'a HashMap<String, String>,
    query: &'a HashMap<String, String>,
) -> Option<&'a str> {
    header_value(headers, "x-chio-capability")
        .or_else(|| query.get("chio_capability").map(String::as_str))
}

fn policy_mode(policy: PolicyDecision) -> HttpAuthorityPolicy {
    match policy {
        PolicyDecision::SessionAllow => HttpAuthorityPolicy::SessionAllow,
        PolicyDecision::DenyByDefault => HttpAuthorityPolicy::DenyByDefault,
    }
}

impl RequestEvaluator {
    pub fn finalize_receipt(
        &self,
        decision_receipt: &HttpReceipt,
        response_status: u16,
    ) -> Result<HttpReceipt, crate::error::ProtectError> {
        self.authority
            .finalize_decision_receipt(decision_receipt, response_status)
            .map_err(Into::into)
    }
}

impl From<HttpAuthorityEvaluation> for EvaluationResult {
    fn from(value: HttpAuthorityEvaluation) -> Self {
        Self {
            verdict: value.verdict,
            receipt: value.receipt,
            evidence: value.evidence,
            execution_nonce: value.execution_nonce,
        }
    }
}

impl From<HttpAuthorityError> for crate::error::ProtectError {
    fn from(value: HttpAuthorityError) -> Self {
        match value {
            HttpAuthorityError::CallerIdentity(message)
            | HttpAuthorityError::ContentHash(message)
            | HttpAuthorityError::Kernel(message) => Self::Evaluation(message),
            HttpAuthorityError::PendingApproval {
                approval_id,
                kernel_receipt_id,
            } => Self::PendingApproval {
                approval_id,
                kernel_receipt_id,
            },
            HttpAuthorityError::ReceiptSign(message) => Self::ReceiptSign(message),
        }
    }
}

/// Match OpenAPI-style path templates such as `/pets/{petId}`.
fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    let mut path_segments = path.split('/');
    let mut pattern_segments = pattern.split('/');

    loop {
        match (path_segments.next(), pattern_segments.next()) {
            (Some(path_segment), Some(pattern_segment))
                if path_segment_matches_pattern(path_segment, pattern_segment) => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn path_segment_matches_pattern(path_segment: &str, pattern_segment: &str) -> bool {
    pattern_segment.starts_with('{') && pattern_segment.ends_with('}')
        || path_segment == pattern_segment
}

/// Extract caller identity from HTTP headers.
pub(crate) fn caller_identity_from_headers(headers: &HashMap<String, String>) -> CallerIdentity {
    // Authorization headers become stable hashed caller identities.
    if let Some(auth) = header_value(headers, "authorization") {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if credential_value_is_well_formed(token) {
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
    }

    // API keys follow the same non-secret identity derivation.
    if let Some(key_value) = header_value(headers, "x-api-key") {
        if credential_value_is_well_formed(key_value) {
            let key_hash = chio_core_types::sha256_hex(key_value.as_bytes());
            return CallerIdentity {
                subject: format!("apikey:{}", &key_hash[..16]),
                auth_method: AuthMethod::ApiKey {
                    key_name: "x-api-key".to_string(),
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

pub(crate) fn header_value<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn credential_value_is_well_formed(value: &str) -> bool {
    !value.trim().is_empty()
        && value.trim() == value
        && !value.chars().any(|character| character.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chio_core_types::capability::{
        governance::ProvenanceEvidenceClass,
        scope::{ChioScope, Constraint, ModelMetadata, ModelSafetyTier, Operation, ToolGrant},
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_http_core::{
        http_status_scope, CHIO_DECISION_RECEIPT_ID_KEY, CHIO_HTTP_STATUS_SCOPE_DECISION,
        CHIO_HTTP_STATUS_SCOPE_FINAL,
    };

    use chio_test_support::prelude::*;

    #[test]
    fn durable_evaluator_reports_durable_backends() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
            chio_store_sqlite::SqliteReceiptStore::open(dir.path().join("receipts.db"))?,
        );
        let revocation_store: Arc<dyn chio_kernel::RevocationStore> = Arc::new(
            chio_store_sqlite::SqliteRevocationStore::open(dir.path().join("revocations.db"))?,
        );
        let authority_database = dir.path().join("authority.db");
        let authority_locks = dir.path().join("authority-locks");
        let mut lock_root_builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            lock_root_builder.mode(0o700);
        }
        lock_root_builder.create(&authority_locks)?;
        chio_store_sqlite::SqliteAuthorityStore::provision(&authority_database, &authority_locks)?;
        let authority = chio_store_sqlite::SqliteAuthorityStore::open_serving(
            &authority_database,
            &authority_locks,
        )?;
        let evaluator = RequestEvaluator::new_with_durable_stores_and_admission(
            Vec::new(),
            Keypair::generate(),
            chio_core_types::sha256_hex(b"test-policy"),
            Arc::new(chio_kernel::InMemoryApprovalStore::new()),
            Vec::new(),
            Some(receipt_store),
            Some(revocation_store),
            Some(DurableAdmissionStores {
                store: Arc::new(authority.admission_operation_store()),
                outcome_store: Arc::new(authority.tool_outcome_store()),
                fence: authority.mutation_fence(),
            }),
            false,
        )?;
        assert_eq!(evaluator.receipt_backend(), "durable");
        assert_eq!(evaluator.revocation_backend(), "durable");
        let evaluated = evaluator.evaluate(
            HttpMethod::Get,
            "/pets",
            &HashMap::new(),
            &HashMap::new(),
            None,
            0,
        )?;
        assert!(evaluated.verdict.is_allowed());
        Ok(())
    }

    /// Durable-by-default for revocation: an evaluator with durable receipts but
    /// no durable revocation store must fail closed on a mediated request unless
    /// the operator explicitly opts into ephemeral operation. Without the opt-in
    /// the kernel refuses pre-dispatch rather than serving a capability whose
    /// revocation state is lost on restart; with it, the same request serves,
    /// matching the explicit-ephemeral path.
    #[test]
    fn durable_evaluator_requires_explicit_opt_in_for_ephemeral_revocation(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let keypair = Keypair::generate();
        let mut headers = HashMap::new();
        headers.insert(
            "X-Chio-Capability".to_string(),
            signed_capability_token_json(&keypair, "cap-revocation-gate"),
        );

        let build = |file: &str,
                     allow_ephemeral: bool|
         -> Result<RequestEvaluator, Box<dyn std::error::Error>> {
            let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
                chio_store_sqlite::SqliteReceiptStore::open(dir.path().join(file))?,
            );
            Ok(RequestEvaluator::new_with_durable_stores(
                vec![],
                keypair.clone(),
                "test-policy".to_string(),
                Arc::new(chio_kernel::InMemoryApprovalStore::new()),
                Vec::new(),
                Some(receipt_store),
                None,
                allow_ephemeral,
            )?)
        };

        // No opt-in: durable receipts plus in-memory revocation fails closed.
        // The kernel refuses pre-dispatch, surfaced as an evaluation error.
        let denied = build("gated.db", false)?.evaluate(
            HttpMethod::Post,
            "/pets",
            &HashMap::new(),
            &headers,
            None,
            0,
        );
        let error = match denied {
            Ok(_) => panic!("in-memory revocation without an opt-in must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("revocation"),
            "the failure must name the missing revocation durability, got: {error}"
        );

        // Explicit opt-in: the same configuration serves the request.
        let allowed = build("opted.db", true)?.evaluate(
            HttpMethod::Post,
            "/pets",
            &HashMap::new(),
            &headers,
            None,
            0,
        )?;
        assert!(
            allowed.verdict.is_allowed(),
            "an explicit ephemeral opt-in restores in-memory revocation serving"
        );
        Ok(())
    }

    /// The pre-rename constructor names remain source-compatible for external
    /// embedders, delegating to the explicit-ephemeral path. Without the shims
    /// this test would not compile.
    #[test]
    #[allow(deprecated)]
    fn deprecated_constructor_shims_delegate_to_ephemeral() {
        let keypair = Keypair::generate();

        let evaluator = RequestEvaluator::new(vec![], keypair.clone(), "test-policy".to_string());
        assert_eq!(evaluator.receipt_backend(), "ephemeral");
        assert_eq!(evaluator.revocation_backend(), "ephemeral");

        let evaluator = RequestEvaluator::new_with_trusted_capability_issuers(
            vec![],
            keypair.clone(),
            "test-policy".to_string(),
            vec![],
        );
        assert_eq!(evaluator.receipt_backend(), "ephemeral");

        let evaluator = RequestEvaluator::new_with_approval_store(
            vec![],
            keypair.clone(),
            "test-policy".to_string(),
            Arc::new(chio_kernel::InMemoryApprovalStore::new()),
        );
        assert_eq!(evaluator.receipt_backend(), "ephemeral");

        let evaluator = RequestEvaluator::new_with_approval_store_and_trusted_capability_issuers(
            vec![],
            keypair,
            "test-policy".to_string(),
            Arc::new(chio_kernel::InMemoryApprovalStore::new()),
            vec![],
        );
        assert_eq!(evaluator.revocation_backend(), "ephemeral");
    }

    #[test]
    fn evaluator_without_durable_stores_reports_ephemeral_backends(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let evaluator = RequestEvaluator::new_with_durable_stores(
            Vec::new(),
            Keypair::generate(),
            "test-policy".to_string(),
            Arc::new(chio_kernel::InMemoryApprovalStore::new()),
            Vec::new(),
            None,
            None,
            true,
        )?;
        assert_eq!(evaluator.receipt_backend(), "ephemeral");
        assert_eq!(evaluator.revocation_backend(), "ephemeral");
        Ok(())
    }

    fn signed_capability_token_json(issuer: &Keypair, id: &str) -> String {
        signed_capability_token_json_with_scope(
            issuer,
            id,
            ChioScope {
                grants: vec![chio_http_core::http_authority_tool_grant()],
                ..ChioScope::default()
            },
        )
    }

    fn signed_capability_token_json_with_scope(
        issuer: &Keypair,
        id: &str,
        scope: ChioScope,
    ) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope,
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            issuer,
        )
        .test_unwrap();
        serde_json::to_string(&token).test_unwrap()
    }

    #[test]
    fn path_matching() {
        assert!(path_matches_pattern("/pets/42", "/pets/{petId}"));
        assert!(path_matches_pattern("/pets", "/pets"));
        assert!(!path_matches_pattern("/pets/42/toys", "/pets/{petId}"));
        assert!(!path_matches_pattern("/dogs/42", "/pets/{petId}"));
    }

    #[test]
    fn extract_bearer_caller() {
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "Bearer mytoken123".to_string());
        let caller = caller_identity_from_headers(&headers);
        assert!(caller.subject.starts_with("bearer:"));
        assert!(matches!(caller.auth_method, AuthMethod::Bearer { .. }));
    }

    #[test]
    fn extract_bearer_caller_accepts_case_insensitive_authorization_header() {
        let mut headers = HashMap::new();
        headers.insert("AUTHORIZATION".to_string(), "Bearer mytoken123".to_string());
        let caller = caller_identity_from_headers(&headers);
        assert!(caller.subject.starts_with("bearer:"));
        assert!(matches!(caller.auth_method, AuthMethod::Bearer { .. }));
    }

    #[test]
    fn extract_caller_ignores_blank_bearer_token() {
        let mut headers = HashMap::new();
        headers.insert("authorization".to_string(), "Bearer ".to_string());

        let caller = caller_identity_from_headers(&headers);

        assert!(matches!(caller.auth_method, AuthMethod::Anonymous));
        assert_eq!(caller.subject, "anonymous");
    }

    #[test]
    fn extract_anonymous_caller() {
        let headers = HashMap::new();
        let caller = caller_identity_from_headers(&headers);
        assert_eq!(caller.subject, "anonymous");
    }

    #[test]
    fn evaluate_get_allowed() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator =
            RequestEvaluator::new_ephemeral(routes, keypair.clone(), "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/pets",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();
        assert!(result.verdict.is_allowed());
        assert!(result.receipt.verify_signature().test_unwrap());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_chio_request_signed_denies_unsupported_approval_sets() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new_ephemeral(routes, keypair, "test-policy".to_string());
        let mut request = ChioHttpRequest::new(
            "req-unsupported-approvals".to_string(),
            HttpMethod::Get,
            "/pets".to_string(),
            "/pets".to_string(),
            CallerIdentity::anonymous(),
        );
        request.approval_tokens = Some(serde_json::json!([
            { "id": "approval-a" },
            { "id": "approval-b" }
        ]));

        let result = evaluator.evaluate_chio_request(request, None).test_unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.verify_signature().test_unwrap());
        assert!(result.receipt.evidence[0]
            .details
            .as_deref()
            .is_some_and(|details| details.contains(
                "HTTP authority projection does not support authorization field approval_tokens"
            )));
    }

    #[test]
    fn evaluate_chio_request_denies_spoofed_tool_identity_on_http_route() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator =
            RequestEvaluator::new_ephemeral(routes, keypair.clone(), "test-policy".to_string());
        let capability = signed_capability_token_json_with_scope(
            &keypair,
            "cap-math-only",
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "math".to_string(),
                    tool_name: "double".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
        );

        let mut request = ChioHttpRequest::new(
            "req-sidecar-spoofed-tool".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            CallerIdentity::anonymous(),
        );
        request.tool_server = Some("math".to_string());
        request.tool_name = Some("double".to_string());
        request.arguments = Some(serde_json::json!({ "value": 1 }));
        request.body_hash = Some("pet-body".to_string());
        request.body_length = 8;

        let result = evaluator
            .evaluate_chio_request(request, Some(&capability))
            .test_unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.is_none());
        assert!(result.receipt.evidence[0]
            .details
            .as_deref()
            .is_some_and(|details| {
                details.contains("capability does not authorize tool authorize_http_request")
            }));
    }

    #[test]
    fn evaluate_denies_get_reserved_tools_path_without_capability() {
        let keypair = Keypair::generate();
        let evaluator = RequestEvaluator::new_ephemeral(vec![], keypair, "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/chio/tools/billing/read",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.is_none());
        assert_eq!(
            result.receipt.evidence[0].details.as_deref(),
            Some("side-effect route requires a valid capability token")
        );
    }

    #[test]
    fn evaluate_chio_request_allows_reserved_tools_path_context() {
        let keypair = Keypair::generate();
        let evaluator =
            RequestEvaluator::new_ephemeral(vec![], keypair.clone(), "test-policy".to_string());
        let capability = signed_capability_token_json_with_scope(
            &keypair,
            "cap-matrix-read",
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "matrix".to_string(),
                    tool_name: "files.read".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
        );

        let mut request = ChioHttpRequest::new(
            "req-sidecar-matrix-tool".to_string(),
            HttpMethod::Post,
            "/chio/tools/matrix/files.read".to_string(),
            "/chio/tools/matrix/files.read".to_string(),
            CallerIdentity::anonymous(),
        );
        request.tool_server = Some("matrix".to_string());
        request.tool_name = Some("files.read".to_string());
        request.arguments = Some(serde_json::json!({ "path": "/tmp/a" }));
        request.body_hash = Some("tool-body".to_string());
        request.body_length = 8;

        let result = evaluator
            .evaluate_chio_request(request, Some(&capability))
            .test_unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(
            result.receipt.capability_id.as_deref(),
            Some("cap-matrix-read")
        );
    }

    #[test]
    fn evaluate_chio_request_denies_unmatched_http_path_with_spoofed_synthetic_pattern() {
        let keypair = Keypair::generate();
        let evaluator =
            RequestEvaluator::new_ephemeral(vec![], keypair.clone(), "test-policy".to_string());
        let capability = signed_capability_token_json_with_scope(
            &keypair,
            "cap-matrix-admin-delete",
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "matrix".to_string(),
                    tool_name: "admin.delete".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
        );

        let mut request = ChioHttpRequest::new(
            "req-unmatched-spoofed-synthetic-pattern".to_string(),
            HttpMethod::Post,
            "matrix:admin.delete".to_string(),
            "/admin/delete".to_string(),
            CallerIdentity::anonymous(),
        );
        request.tool_server = Some("matrix".to_string());
        request.tool_name = Some("admin.delete".to_string());
        request.arguments = Some(serde_json::json!({ "path": "/tmp/a" }));
        request.body_hash = Some("tool-body".to_string());
        request.body_length = 8;

        let result = evaluator
            .evaluate_chio_request(request, Some(&capability))
            .test_unwrap();

        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.route_pattern, "/admin/delete");
        assert!(result.receipt.capability_id.is_none());
        assert!(result.receipt.evidence[0]
            .details
            .as_deref()
            .is_some_and(|details| {
                details.contains("capability does not authorize tool authorize_http_request")
            }));
    }

    #[test]
    fn evaluate_chio_request_denies_capability_for_different_tool_identity() {
        let keypair = Keypair::generate();
        let evaluator =
            RequestEvaluator::new_ephemeral(vec![], keypair.clone(), "test-policy".to_string());
        let capability = signed_capability_token_json_with_scope(
            &keypair,
            "cap-tool-scope",
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "math".to_string(),
                    tool_name: "double".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
        );

        let mut request = ChioHttpRequest::new(
            "req-sidecar-tool-mismatch".to_string(),
            HttpMethod::Post,
            "/chio/tools/math/increment".to_string(),
            "/chio/tools/math/increment".to_string(),
            CallerIdentity::anonymous(),
        );
        request.tool_server = Some("math".to_string());
        request.tool_name = Some("increment".to_string());
        request.arguments = Some(serde_json::json!({ "value": 1 }));
        request.body_hash = Some("tool-body".to_string());
        request.body_length = 1;

        let result = evaluator
            .evaluate_chio_request(request, Some(&capability))
            .test_unwrap();

        assert!(result.verdict.is_denied());
        assert_eq!(
            result.receipt.evidence[0].details.as_deref(),
            Some("capability does not authorize tool increment on server math")
        );
    }

    #[test]
    fn evaluate_chio_request_allows_model_constrained_capability_when_metadata_matches() {
        let keypair = Keypair::generate();
        let evaluator =
            RequestEvaluator::new_ephemeral(vec![], keypair.clone(), "test-policy".to_string());
        let capability = signed_capability_token_json_with_scope(
            &keypair,
            "cap-model-scope",
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: "math".to_string(),
                    tool_name: "double".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![Constraint::ModelConstraint {
                        allowed_model_ids: vec!["gpt-5".to_string()],
                        min_safety_tier: Some(ModelSafetyTier::Standard),
                    }],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
        );

        let mut request = ChioHttpRequest::new(
            "req-model-scope".to_string(),
            HttpMethod::Post,
            "/chio/tools/math/double".to_string(),
            "/chio/tools/math/double".to_string(),
            CallerIdentity::anonymous(),
        );
        request.tool_server = Some("math".to_string());
        request.tool_name = Some("double".to_string());
        request.arguments = Some(serde_json::json!({ "value": 2 }));
        request.model_metadata = Some(ModelMetadata {
            model_id: "gpt-5".to_string(),
            safety_tier: Some(ModelSafetyTier::Standard),
            provider: Some("openai".to_string()),
            provenance_class: ProvenanceEvidenceClass::Asserted,
        });
        request.body_hash = Some("tool-body".to_string());
        request.body_length = 1;

        let result = evaluator
            .evaluate_chio_request(request, Some(&capability))
            .test_unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(
            result.receipt.capability_id.as_deref(),
            Some("cap-model-scope")
        );
    }

    #[test]
    fn evaluate_chio_request_allows_capability_from_configured_external_issuer() {
        let signer = Keypair::generate();
        let external_issuer = Keypair::generate();
        let evaluator = RequestEvaluator::new_ephemeral_with_trusted_capability_issuers(
            vec![],
            signer,
            "test-policy".to_string(),
            vec![external_issuer.public_key()],
        );
        let capability = signed_capability_token_json(&external_issuer, "cap-external");

        let mut request = ChioHttpRequest::new(
            "req-external-issuer".to_string(),
            HttpMethod::Post,
            "/pets".to_string(),
            "/pets".to_string(),
            CallerIdentity::anonymous(),
        );
        request.body_hash = Some("body".to_string());
        request.body_length = 1;

        let result = evaluator
            .evaluate_chio_request(request, Some(&capability))
            .test_unwrap();

        assert!(result.verdict.is_allowed());
        assert_eq!(
            result.receipt.capability_id.as_deref(),
            Some("cap-external")
        );
    }

    #[test]
    fn evaluate_post_denied_without_capability() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator =
            RequestEvaluator::new_ephemeral(routes, keypair.clone(), "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();
        assert!(result.verdict.is_denied());
        assert_eq!(result.receipt.response_status, 403);
        assert!(result.receipt.verify_signature().test_unwrap());
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_post_allowed_with_capability() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator =
            RequestEvaluator::new_ephemeral(routes, keypair.clone(), "test-policy".to_string());

        let mut headers = HashMap::new();
        headers.insert(
            "X-Chio-Capability".to_string(),
            signed_capability_token_json(&keypair, "cap-123"),
        );

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &headers,
                None,
                0,
            )
            .test_unwrap();
        assert!(result.verdict.is_allowed());
        assert_eq!(result.receipt.capability_id.as_deref(), Some("cap-123"));
        assert_eq!(
            http_status_scope(result.receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
        );
    }

    #[test]
    fn evaluate_post_accepts_case_insensitive_capability_header() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator =
            RequestEvaluator::new_ephemeral(routes, keypair.clone(), "test-policy".to_string());

        let mut headers = HashMap::new();
        headers.insert(
            "X-CHIO-CAPABILITY".to_string(),
            signed_capability_token_json(&keypair, "cap-uppercase"),
        );

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &headers,
                None,
                0,
            )
            .test_unwrap();
        assert!(result.verdict.is_allowed());
        assert_eq!(
            result.receipt.capability_id.as_deref(),
            Some("cap-uppercase")
        );
    }

    #[test]
    fn finalize_receipt_rebinds_status_and_links_decision_receipt() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("listPets".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new_ephemeral(routes, keypair, "test-policy".to_string());

        let decision = evaluator
            .evaluate(
                HttpMethod::Get,
                "/pets",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap()
            .receipt;
        let final_receipt = evaluator.finalize_receipt(&decision, 204).test_unwrap();

        assert_ne!(final_receipt.id, decision.id);
        assert_eq!(final_receipt.response_status, 204);
        assert_eq!(
            http_status_scope(final_receipt.metadata.as_ref()),
            Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
        );
        assert_eq!(
            final_receipt
                .metadata
                .as_ref()
                .and_then(|meta| meta.get(CHIO_DECISION_RECEIPT_ID_KEY))
                .and_then(|value| value.as_str()),
            Some(decision.id.as_str())
        );
        assert!(final_receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn path_matching_trailing_slash_mismatch() {
        // Trailing slash should NOT match if pattern has no trailing slash
        assert!(!path_matches_pattern("/pets/", "/pets"));
        assert!(!path_matches_pattern("/pets", "/pets/"));
    }

    #[test]
    fn path_matching_double_slashes() {
        // Double slashes produce empty segments, should not match normal paths
        assert!(!path_matches_pattern("//pets", "/pets"));
    }

    #[test]
    fn path_matching_case_sensitivity() {
        // Path matching should be case-sensitive
        assert!(!path_matches_pattern("/Pets", "/pets"));
        assert!(path_matches_pattern("/Pets", "/Pets"));
    }

    #[test]
    fn path_matching_multiple_params() {
        assert!(path_matches_pattern(
            "/orgs/123/members/456",
            "/orgs/{orgId}/members/{memberId}"
        ));
        assert!(!path_matches_pattern(
            "/orgs/123/members",
            "/orgs/{orgId}/members/{memberId}"
        ));
    }

    #[test]
    fn path_matching_root() {
        assert!(path_matches_pattern("/", "/"));
        assert!(!path_matches_pattern("/pets", "/"));
    }

    #[test]
    fn extract_api_key_caller() {
        let mut headers = HashMap::new();
        headers.insert("X-API-Key".to_string(), "my-api-key-value".to_string());
        let caller = caller_identity_from_headers(&headers);
        assert!(caller.subject.starts_with("apikey:"));
        assert!(matches!(caller.auth_method, AuthMethod::ApiKey { .. }));
    }

    #[test]
    fn evaluate_with_body_hash() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/data".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("getData".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new_ephemeral(routes, keypair, "test-policy".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/data",
                &HashMap::new(),
                &HashMap::new(),
                Some("bodyhash123".to_string()),
                1024,
            )
            .test_unwrap();
        assert!(result.verdict.is_allowed());
        assert!(result.receipt.verify_signature().test_unwrap());
    }

    #[test]
    fn fallback_policy_for_unmatched_route() {
        let keypair = Keypair::generate();
        let evaluator = RequestEvaluator::new_ephemeral(vec![], keypair, "test-policy".to_string());

        // GET to unknown route should still be allowed (safe method)
        let result = evaluator
            .evaluate(
                HttpMethod::Get,
                "/unknown",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();
        assert!(result.verdict.is_allowed());

        // DELETE to unknown route should be denied (side-effect method)
        let result = evaluator
            .evaluate(
                HttpMethod::Delete,
                "/unknown",
                &HashMap::new(),
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();
        assert!(result.verdict.is_denied());
    }

    #[test]
    fn evaluate_invalid_capability_denied_fail_closed() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/pets".to_string(),
            method: HttpMethod::Post,
            operation_id: Some("createPet".to_string()),
            policy: PolicyDecision::DenyByDefault,
        }];
        let evaluator = RequestEvaluator::new_ephemeral(routes, keypair, "test-policy".to_string());
        let mut headers = HashMap::new();
        headers.insert("X-Chio-Capability".to_string(), "not-json".to_string());

        let result = evaluator
            .evaluate(
                HttpMethod::Post,
                "/pets",
                &HashMap::new(),
                &headers,
                None,
                0,
            )
            .test_unwrap();

        assert!(result.verdict.is_denied());
        assert!(result.receipt.capability_id.as_deref().is_none());
    }

    #[test]
    fn evaluate_query_parameters_affect_content_hash() {
        let keypair = Keypair::generate();
        let routes = vec![RouteEntry {
            pattern: "/search".to_string(),
            method: HttpMethod::Get,
            operation_id: Some("search".to_string()),
            policy: PolicyDecision::SessionAllow,
        }];
        let evaluator = RequestEvaluator::new_ephemeral(routes, keypair, "test-policy".to_string());
        let mut query_a = HashMap::new();
        query_a.insert("q".to_string(), "cats".to_string());
        let mut query_b = HashMap::new();
        query_b.insert("q".to_string(), "dogs".to_string());

        let result_a = evaluator
            .evaluate(
                HttpMethod::Get,
                "/search",
                &query_a,
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();
        let result_b = evaluator
            .evaluate(
                HttpMethod::Get,
                "/search",
                &query_b,
                &HashMap::new(),
                None,
                0,
            )
            .test_unwrap();

        assert_ne!(result_a.receipt.content_hash, result_b.receipt.content_hash);
    }
}
