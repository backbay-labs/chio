//! Request evaluator for the Chio tower middleware.
//!
//! Contains the core evaluation logic: matching routes, checking capabilities,
//! and signing receipts.

use std::collections::HashMap;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::metadata::GuardEvidence;
use chio_http_core::{
    CallerIdentity, HttpAuthority, HttpAuthorityError, HttpAuthorityInput, HttpAuthorityPolicy,
    HttpMethod, HttpReceipt, PreparedHttpEvaluation, TransportDenyInput, Verdict,
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

/// Durable sink for the outer HTTP receipts that [`crate::ChioService`] signs.
///
/// The embedded authorization kernel already persists its own receipts to a
/// configured store, but the HTTP decision and final-response receipts are signed
/// at the tower edge and would otherwise live only in the response extensions.
/// When the evaluator is built with a durable receipt store, those HTTP receipts
/// are converted to core receipts (re-signed with the kernel keypair) and
/// appended here so the HTTP audit trail survives a restart.
#[derive(Clone)]
struct HttpReceiptSink {
    keypair: std::sync::Arc<Keypair>,
    store: std::sync::Arc<dyn chio_kernel::ReceiptStore>,
}

/// Chio request evaluator. Holds the shared HTTP authority and tower-specific hooks.
pub struct ChioEvaluator {
    authority: HttpAuthority,
    identity_extractor: IdentityExtractor,
    route_resolver: RouteResolver,
    /// When true, sidecar errors allow the request through (fail-open).
    /// Default is false (fail-closed).
    fail_open: bool,
    /// Durable sink for the HTTP receipts signed at the tower edge. `Some` only
    /// when the evaluator was built with a durable receipt store.
    receipt_sink: Option<HttpReceiptSink>,
    /// Whether the operator explicitly opted into ephemeral (in-memory)
    /// receipts. With no durable sink and no opt-in the evaluator is
    /// fail-closed, and every receipt-emitting path (including the transport
    /// deny path) must refuse rather than sign a receipt that cannot be
    /// durably recorded.
    allow_ephemeral: bool,
}

impl ChioEvaluator {
    /// Create a fail-closed evaluator with the given keypair and policy hash.
    ///
    /// No durable store is attached, so the first mediated call denies until a
    /// durable store is wired through [`ChioEvaluator::builder`]. Use
    /// [`ChioEvaluator::new_ephemeral`] for a local scaffold that intends
    /// in-memory persistence.
    pub fn new(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            authority: HttpAuthority::new(keypair, policy_hash),
            identity_extractor: crate::identity::extract_identity,
            route_resolver: default_route_resolver,
            fail_open: false,
            receipt_sink: None,
            allow_ephemeral: false,
        }
    }

    /// Create an explicitly ephemeral evaluator (in-memory receipt log and
    /// revocation store) for local scaffolds and tests.
    pub fn new_ephemeral(keypair: Keypair, policy_hash: String) -> Self {
        Self {
            authority: HttpAuthority::new_ephemeral(keypair, policy_hash),
            identity_extractor: crate::identity::extract_identity,
            route_resolver: default_route_resolver,
            fail_open: false,
            receipt_sink: None,
            allow_ephemeral: true,
        }
    }

    /// Start building an evaluator backed by durable receipt and revocation
    /// stores.
    #[must_use]
    pub fn builder(keypair: Keypair, policy_hash: String) -> ChioEvaluatorBuilder {
        ChioEvaluatorBuilder {
            keypair,
            policy_hash,
            receipt_store: None,
            revocation_store: None,
            durable_admission: None,
            allow_ephemeral: false,
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
        let presented_capability = extract_presented_capability(input.headers, input.query);
        self.prepare_with_presented_capability(input, presented_capability)
    }

    pub(crate) fn prepare_with_presented_capability(
        &self,
        input: EvaluationInput<'_>,
        presented_capability: Option<&str>,
    ) -> Result<PreparedEvaluation, ChioTowerError> {
        let EvaluationInput {
            method,
            path,
            query,
            caller,
            headers: _headers,
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
                presented_capability,
                requested_tool_server: None,
                requested_tool_name: None,
                requested_arguments: None,
                execution_nonce: None,
                model_metadata: None,
                unsupported_authorization_extension: None,
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

    /// Sign a deny receipt for a request that the transport layer rejected
    /// before kernel evaluation (for example, an oversized body that the
    /// middleware refused to buffer). Used by [`crate::ChioService`] to attach
    /// a verifiable verdict to its `413 Payload Too Large` response so an
    /// auditor cannot claim the rejection was a bare network error.
    pub(crate) fn sign_transport_deny_receipt(
        &self,
        input: TransportDenyInput<'_>,
    ) -> Result<HttpReceipt, ChioTowerError> {
        self.authority
            .sign_transport_deny_receipt(input)
            .map_err(Into::into)
    }

    /// Whether the receipts this evaluator signs can be recorded: either a
    /// durable receipt store is attached, or the operator explicitly opted into
    /// ephemeral (in-memory) receipts. When neither holds the evaluator is
    /// fail-closed - the embedded kernel denies normal requests for missing
    /// durable persistence - so a transport-level denial must refuse the same
    /// way instead of emitting a signed receipt whose audit record is silently
    /// dropped. Denial evidence must be as durable as allow evidence.
    pub(crate) fn receipts_are_audited(&self) -> bool {
        self.receipt_sink.is_some() || self.allow_ephemeral
    }

    /// Whether outer HTTP receipts are appended to a durable store. When this is
    /// false there is no durable audit trail to guarantee, so the service keeps
    /// its receipts best-effort in the response extensions and skips the
    /// pre-forward decision-receipt persist that would otherwise fail an allowed
    /// request closed on a store error.
    pub(crate) fn has_durable_receipt_sink(&self) -> bool {
        self.receipt_sink.is_some()
    }

    /// Append an outer HTTP receipt to the durable receipt store when one is
    /// configured. [`crate::ChioService`] signs decision, final-response, and
    /// transport-deny receipts at the HTTP edge; without this they would live
    /// only in the response extensions and vanish on restart, so a configured
    /// durable store must receive them.
    ///
    /// With no durable sink attached the append is a no-op: an ephemeral or
    /// store-less evaluator keeps its receipts best-effort.
    ///
    /// Only a receipt that converts into a verifiable core receipt may enter the
    /// durable audit log; the store rejects anything it cannot re-verify. An
    /// HTTP receipt that cannot be represented as a verifiable core receipt
    /// (for example one whose embedded kernel key does not match the durable sink
    /// keypair, so no well-formed signed receipt can be produced) is skipped
    /// rather than failing the request closed or writing a record the store could
    /// never verify. A record that IS verifiable but that the store then fails to
    /// persist still propagates the error so the caller can fail the request
    /// closed, matching durable-by-default: a protected effect must not complete
    /// while a valid audit record is silently dropped.
    pub(crate) fn persist_http_receipt(&self, receipt: &HttpReceipt) -> Result<(), ChioTowerError> {
        let Some(sink) = &self.receipt_sink else {
            return Ok(());
        };
        let chio_receipt = match receipt.to_chio_receipt_with_keypair(&sink.keypair) {
            Ok(chio_receipt) => chio_receipt,
            Err(error) => {
                tracing::warn!(
                    %error,
                    receipt_id = %receipt.id,
                    "skipping durable persistence of an HTTP receipt that cannot be converted into a verifiable core receipt"
                );
                return Ok(());
            }
        };
        sink.store
            .append_chio_receipt(&chio_receipt)
            .map_err(|error| {
                ChioTowerError::ReceiptPersist(format!(
                    "failed to append HTTP receipt to durable receipt store: {error}"
                ))
            })?;
        Ok(())
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

/// Builder for a [`ChioEvaluator`] backed by durable stores. `build` is
/// fallible because attaching a durable receipt store hydrates checkpoint
/// counters and can fail. `allow_ephemeral` defaults to `false` (fail-closed).
pub struct ChioEvaluatorBuilder {
    keypair: Keypair,
    policy_hash: String,
    receipt_store: Option<std::sync::Arc<dyn chio_kernel::ReceiptStore>>,
    revocation_store: Option<std::sync::Arc<dyn chio_kernel::RevocationStore>>,
    durable_admission: Option<DurableAdmissionStores>,
    allow_ephemeral: bool,
    identity_extractor: IdentityExtractor,
    route_resolver: RouteResolver,
    fail_open: bool,
}

struct DurableAdmissionStores {
    store: std::sync::Arc<dyn chio_kernel::QualifiedAdmissionProjectionStore>,
    outcome_store: std::sync::Arc<dyn chio_kernel::tool_outcome::QualifiedToolOutcomeStore>,
    fence: chio_kernel::admission_operation::StoreMutationFence,
}

impl ChioEvaluatorBuilder {
    #[must_use]
    pub fn receipt_store(mut self, store: std::sync::Arc<dyn chio_kernel::ReceiptStore>) -> Self {
        self.receipt_store = Some(store);
        self
    }

    #[must_use]
    pub fn revocation_store(
        mut self,
        store: std::sync::Arc<dyn chio_kernel::RevocationStore>,
    ) -> Self {
        self.revocation_store = Some(store);
        self
    }

    #[must_use]
    pub fn durable_admission_stores(
        mut self,
        store: std::sync::Arc<dyn chio_kernel::QualifiedAdmissionProjectionStore>,
        outcome_store: std::sync::Arc<dyn chio_kernel::tool_outcome::QualifiedToolOutcomeStore>,
        fence: chio_kernel::admission_operation::StoreMutationFence,
    ) -> Self {
        self.durable_admission = Some(DurableAdmissionStores {
            store,
            outcome_store,
            fence,
        });
        self
    }

    #[must_use]
    pub fn allow_ephemeral(mut self, allow: bool) -> Self {
        self.allow_ephemeral = allow;
        self
    }

    #[must_use]
    pub fn with_identity_extractor(mut self, extractor: IdentityExtractor) -> Self {
        self.identity_extractor = extractor;
        self
    }

    #[must_use]
    pub fn with_route_resolver(mut self, resolver: RouteResolver) -> Self {
        self.route_resolver = resolver;
        self
    }

    #[must_use]
    pub fn with_fail_open(mut self, fail_open: bool) -> Self {
        self.fail_open = fail_open;
        self
    }

    pub fn build(self) -> Result<ChioEvaluator, ChioTowerError> {
        let mut builder = HttpAuthority::builder()
            .allow_ephemeral_receipt_log(self.allow_ephemeral)
            .allow_ephemeral_revocation_store(self.allow_ephemeral);
        // A configured durable receipt store backs both the embedded kernel and
        // the tower edge: the store handle moves into the authority builder, and
        // a clone (with the kernel keypair) stays on the evaluator so the outer
        // HTTP receipts the service signs are appended to the same store.
        let receipt_sink = self.receipt_store.as_ref().map(|store| HttpReceiptSink {
            keypair: std::sync::Arc::new(self.keypair.clone()),
            store: std::sync::Arc::clone(store),
        });
        if let Some(store) = self.receipt_store {
            builder = builder.receipt_store(store);
        }
        if let Some(store) = self.revocation_store {
            builder = builder.revocation_store(store);
        }
        if let Some(durable) = self.durable_admission {
            builder = builder.durable_admission_stores(
                durable.store,
                durable.outcome_store,
                durable.fence,
            );
        }
        let authority = builder
            .build(self.keypair, self.policy_hash)
            .map_err(ChioTowerError::from)?;
        Ok(ChioEvaluator {
            authority,
            identity_extractor: self.identity_extractor,
            route_resolver: self.route_resolver,
            fail_open: self.fail_open,
            receipt_sink,
            allow_ephemeral: self.allow_ephemeral,
        })
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
            receipt_sink: self.receipt_sink.clone(),
            allow_ephemeral: self.allow_ephemeral,
        }
    }
}

/// Parse an HTTP method string into the chio-http-core HttpMethod enum.
pub(crate) fn parse_method(method: &str) -> Result<HttpMethod, ChioTowerError> {
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
    use chio_core_types::capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    };
    use chio_http_core::{
        http_authority_tool_grant, http_status_scope, CHIO_HTTP_STATUS_SCOPE_DECISION,
        CHIO_HTTP_STATUS_SCOPE_FINAL,
    };

    fn valid_capability_token_json(id: &str, issuer: &Keypair) -> String {
        let now = chrono::Utc::now().timestamp() as u64;
        let token = CapabilityToken::sign(
            CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope: ChioScope {
                    grants: vec![http_authority_tool_grant()],
                    ..ChioScope::default()
                },
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
    fn builder_with_durable_stores_allows_safe_method() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let receipt_store: std::sync::Arc<dyn chio_kernel::ReceiptStore> = std::sync::Arc::new(
            chio_store_sqlite::SqliteReceiptStore::open(dir.path().join("receipts.db"))?,
        );
        let revocation_store: std::sync::Arc<dyn chio_kernel::RevocationStore> =
            std::sync::Arc::new(chio_store_sqlite::SqliteRevocationStore::open(
                dir.path().join("revocations.db"),
            )?);
        let authority_database = dir.path().join("authority.db");
        let authority_locks = dir.path().join("authority-locks");
        std::fs::create_dir(&authority_locks)?;
        chio_store_sqlite::SqliteAuthorityStore::provision(&authority_database, &authority_locks)?;
        let authority_store = chio_store_sqlite::SqliteAuthorityStore::open_serving(
            &authority_database,
            &authority_locks,
        )?;
        let admission_store = std::sync::Arc::new(authority_store.admission_operation_store());
        let outcome_store = std::sync::Arc::new(authority_store.tool_outcome_store());
        let evaluator = ChioEvaluator::builder(
            Keypair::generate(),
            chio_core_types::crypto::sha256_hex(b"test-policy"),
        )
        .receipt_store(receipt_store)
        .revocation_store(revocation_store)
        .durable_admission_stores(
            admission_store,
            outcome_store,
            authority_store.mutation_fence(),
        )
        .build()?;
        assert!(!evaluator.is_fail_open());

        let caller = CallerIdentity::anonymous();
        let headers = http::HeaderMap::new();
        let result = evaluate(
            &evaluator,
            "GET",
            "/pets",
            &HashMap::new(),
            caller,
            &headers,
        )?;
        assert!(
            result.verdict.is_allowed(),
            "a durable-backed evaluator must allow a safe request"
        );
        Ok(())
    }

    /// A receipt store that counts appends without verifying, so a test can
    /// observe whether `persist_http_receipt` reached the append at all.
    #[derive(Default)]
    struct CountingReceiptStore {
        appended: std::sync::atomic::AtomicUsize,
    }

    impl CountingReceiptStore {
        fn append_count(&self) -> usize {
            self.appended.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl chio_kernel::ReceiptStore for CountingReceiptStore {
        fn append_chio_receipt(
            &self,
            _receipt: &chio_core_types::receipt::body::ChioReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            self.appended
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn append_child_receipt(
            &self,
            _receipt: &chio_core_types::receipt::lineage::ChildRequestReceipt,
        ) -> Result<(), chio_kernel::ReceiptStoreError> {
            Ok(())
        }
    }

    #[test]
    fn persists_a_well_formed_http_receipt_to_a_verifying_store(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A real durable store recomputes the action parameter hash and rejects a
        // receipt whose hash does not match its parameters. The outer HTTP receipt
        // must convert into a core receipt that this verification accepts, or a
        // durable deployment fails closed on every request instead of serving with
        // persistence.
        let dir = tempfile::tempdir()?;
        let keypair = Keypair::generate();
        let store: std::sync::Arc<dyn chio_kernel::ReceiptStore> = std::sync::Arc::new(
            chio_store_sqlite::SqliteReceiptStore::open(dir.path().join("receipts.db"))?,
        );
        let evaluator = ChioEvaluator::builder(keypair, "durable-policy".to_string())
            .receipt_store(store)
            .allow_ephemeral(true)
            .build()?;

        let result = evaluate(
            &evaluator,
            "GET",
            "/pets",
            &HashMap::new(),
            CallerIdentity::anonymous(),
            &http::HeaderMap::new(),
        )?;

        // The verifying durable store must accept the converted HTTP receipt.
        evaluator.persist_http_receipt(&result.receipt)?;
        Ok(())
    }

    #[test]
    fn skips_an_http_receipt_that_cannot_convert_to_a_verifiable_record(
    ) -> Result<(), Box<dyn std::error::Error>> {
        // A receipt whose embedded kernel key does not match the durable sink
        // keypair cannot be re-signed into a well-formed core receipt. It must be
        // skipped, never appended, and must not fail the request closed: the
        // durable audit log only ever receives verifiable records, and a record
        // that cannot be made verifiable is dropped rather than forcing a
        // fail-closed on every request.
        let store = std::sync::Arc::new(CountingReceiptStore::default());
        let sink_store: std::sync::Arc<dyn chio_kernel::ReceiptStore> = store.clone();
        let evaluator = ChioEvaluator::builder(Keypair::generate(), "durable-policy".to_string())
            .receipt_store(sink_store)
            .allow_ephemeral(true)
            .build()?;

        // A receipt signed by a different kernel keypair carries a foreign
        // kernel_key, so converting it under the sink keypair cannot produce a
        // signed core receipt.
        let foreign_evaluator =
            ChioEvaluator::new_ephemeral(Keypair::generate(), "foreign-policy".to_string());
        let foreign = evaluate(
            &foreign_evaluator,
            "GET",
            "/pets",
            &HashMap::new(),
            CallerIdentity::anonymous(),
            &http::HeaderMap::new(),
        )?;

        evaluator.persist_http_receipt(&foreign.receipt)?;
        assert_eq!(
            store.append_count(),
            0,
            "an HTTP receipt that cannot be converted into a verifiable core receipt must not be appended"
        );
        Ok(())
    }

    #[test]
    fn evaluate_unsafe_method_denied_without_capability() {
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair.clone(), "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator =
            ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string()).with_fail_open(true);
        assert!(evaluator.is_fail_open());
    }

    #[test]
    fn custom_route_resolver() {
        fn resolver(_method: &str, path: &str) -> String {
            // Normalize by stripping trailing slashes
            path.trim_end_matches('/').to_string()
        }
        let keypair = Keypair::generate();
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string())
            .with_route_resolver(resolver);

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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
        let evaluator = ChioEvaluator::new_ephemeral(keypair, "test-policy".to_string());
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
