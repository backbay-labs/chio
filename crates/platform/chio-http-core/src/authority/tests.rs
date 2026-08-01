use super::*;
use crate::{
    authority_projection::MALFORMED_CHIO_TOOLS_PATH_REASON, http_status_scope, AuthMethod,
    CHIO_DECISION_RECEIPT_ID_KEY, CHIO_HTTP_STATUS_SCOPE_DECISION, CHIO_HTTP_STATUS_SCOPE_FINAL,
};
use chio_core_types::capability::{
    attenuation::{compute_attenuation_witness, scope_hash, AttenuationProof},
    scope::{ChioScope, Operation, ToolGrant},
    token::{CapabilityTokenAttenuationBody, CapabilityTokenBody},
};
use chio_core_types::crypto::sha256_hex;

use chio_test_support::prelude::*;

fn signed_capability_token_json(issuer: &Keypair, id: &str) -> String {
    signed_capability_token_json_with_scope(
        issuer,
        id,
        ChioScope {
            grants: vec![http_authority_tool_grant()],
            ..ChioScope::default()
        },
    )
}

fn signed_capability_token_json_with_scope(issuer: &Keypair, id: &str, scope: ChioScope) -> String {
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

fn signed_direct_v2_capability_token_json(issuer: &Keypair, id: &str) -> String {
    let now = chrono::Utc::now().timestamp() as u64;
    let scope = ChioScope::default();
    let parent_hash = scope_hash(&scope).test_unwrap();
    let child_hash = scope_hash(&scope).test_unwrap();
    let witness = compute_attenuation_witness(&scope, &scope).test_unwrap();
    let token = CapabilityToken::sign_attenuated(
        CapabilityTokenAttenuationBody {
            body: CapabilityTokenBody {
                id: id.to_string(),
                issuer: issuer.public_key(),
                subject: issuer.public_key(),
                scope,
                issued_at: now.saturating_sub(60),
                expires_at: now + 3600,
                delegation_chain: Vec::new(),
                aggregate_invocation_budget: None,
            },
            caveats: Vec::new(),
            scope_attenuations: Vec::new(),
            attenuation_proof: AttenuationProof {
                parent_scope_hash: parent_hash,
                child_scope_hash: child_hash,
                normalized_subset_proof: witness,
            },
            budget_share_bps: None,
        },
        issuer,
    )
    .test_unwrap();
    serde_json::to_string(&token).test_unwrap()
}

fn caller() -> CallerIdentity {
    CallerIdentity {
        subject: "tester".to_string(),
        auth_method: AuthMethod::Anonymous,
        verified: false,
        tenant: None,
        agent_id: None,
    }
}

fn authority() -> HttpAuthority {
    HttpAuthority::new_ephemeral(Keypair::generate(), "policy-hash".to_string())
}

fn authority_with_issuer() -> (HttpAuthority, Keypair) {
    let issuer = Keypair::generate();
    (
        HttpAuthority::new_ephemeral(issuer.clone(), "policy-hash".to_string()),
        issuer,
    )
}

fn authority_with_trusted_issuer(trusted_issuer: PublicKey) -> HttpAuthority {
    HttpAuthority::new_ephemeral_with_approval_store_and_trusted_issuers(
        Keypair::generate(),
        "policy-hash".to_string(),
        Arc::new(InMemoryApprovalStore::new()),
        vec![trusted_issuer],
    )
}

fn authority_with_strict_execution_nonce() -> HttpAuthority {
    let mut authority = authority();
    let cfg = chio_kernel::ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 1024,
        require_nonce: true,
    };
    let store = Box::new(chio_kernel::InMemoryExecutionNonceStore::from_config(&cfg));
    Arc::get_mut(&mut authority.kernel)
        .test_unwrap()
        .set_execution_nonce_store(cfg, store);
    authority
}

#[test]
fn safe_policy_allows_without_capability() {
    let query = HashMap::new();
    let result = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-1".to_string(),
            method: HttpMethod::Get,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(
        http_status_scope(result.receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_DECISION)
    );
    assert!(
        metadata_string(result.receipt.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY).is_some()
    );
    assert_eq!(
        metadata_value(result.receipt.metadata.as_ref(), "route_selection")
            .and_then(|value| value.get("selectedTargetProtocol"))
            .and_then(Value::as_str),
        Some("native")
    );
}

fn safe_get_input<'a>(query: &'a HashMap<String, String>) -> HttpAuthorityInput<'a> {
    HttpAuthorityInput {
        request_id: "req-durability-probe".to_string(),
        method: HttpMethod::Get,
        route_pattern: "/pets".to_string(),
        path: "/pets",
        query,
        caller: caller(),
        body_hash: None,
        body_length: 0,
        session_id: None,
        capability_id_hint: None,
        presented_capability: None,
        requested_tool_server: None,
        requested_tool_name: None,
        requested_arguments: None,
        model_metadata: None,
        unsupported_authorization_extension: None,
        execution_nonce: None,
        policy: HttpAuthorityPolicy::SessionAllow,
    }
}

#[test]
fn new_is_failclosed_without_a_durable_store() {
    let authority = HttpAuthority::new(Keypair::generate(), "policy-hash".to_string());
    let query = HashMap::new();
    let error = authority.evaluate(safe_get_input(&query)).test_unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("durable receipt persistence unavailable")
            || message.contains("durable revocation state unavailable"),
        "fail-closed new must deny the first mediated call, got: {message}"
    );
}

#[test]
fn failclosed_authority_surfaces_durability_error_for_denied_projection() {
    // A request projected as denied (deny-by-default with no capability) must
    // still fail closed when no durable store is attached. The kernel's
    // durability gate runs before the projection guard, so without this the
    // authority would return a signed deny receipt and silently drop the denial
    // audit record until an allowed request happened to surface the error.
    let authority = HttpAuthority::new(Keypair::generate(), "policy-hash".to_string());
    let query = HashMap::new();
    let error = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-denied-durability".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("durable receipt persistence unavailable")
            || message.contains("durable revocation state unavailable"),
        "a denied projection must fail closed on missing durable persistence, got: {message}"
    );
}

#[test]
fn builder_with_durable_stores_evaluates_without_persistence_deny(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
        chio_store_sqlite::SqliteReceiptStore::open(dir.path().join("receipts.db"))?,
    );
    let revocation_store: Arc<dyn chio_kernel::RevocationStore> = Arc::new(
        chio_store_sqlite::SqliteRevocationStore::open(dir.path().join("revocations.db"))?,
    );
    let authority_database = dir.path().join("authority.db");
    let authority_locks = dir.path().join("authority-locks");
    std::fs::create_dir(&authority_locks)?;
    chio_store_sqlite::SqliteAuthorityStore::provision(&authority_database, &authority_locks)?;
    let authority_store = chio_store_sqlite::SqliteAuthorityStore::open_serving(
        &authority_database,
        &authority_locks,
    )?;
    let admission_store = Arc::new(authority_store.admission_operation_store());
    let outcome_store = Arc::new(authority_store.tool_outcome_store());
    let authority = HttpAuthority::builder()
        .receipt_store(receipt_store)
        .revocation_store(revocation_store)
        .durable_admission_stores(
            admission_store,
            outcome_store,
            authority_store.mutation_fence(),
        )
        .build(Keypair::generate(), sha256_hex(b"policy"))?;

    let query = HashMap::new();
    let result = authority.evaluate(safe_get_input(&query)).test_unwrap();
    assert!(
        result.verdict.is_allowed(),
        "a durable-backed authority must not deny an allowed request on persistence grounds"
    );
    Ok(())
}

#[test]
fn strict_execution_nonce_preflight_round_trips_before_authorizing_http() {
    let query = HashMap::new();
    let authority = authority_with_strict_execution_nonce();
    let preflight = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-strict-nonce-http-authority".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();

    assert!(matches!(preflight.verdict, Verdict::Incomplete { .. }));
    assert!(
        !preflight.receipt.is_allowed(),
        "nonce preflight must not authorize the HTTP side effect"
    );
    let nonce = preflight
        .execution_nonce
        .clone()
        .test_expect("strict HTTP preflight must return an execution nonce");

    let allowed = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-strict-nonce-http-authority".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: Some(&nonce),
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();
    assert!(allowed.verdict.is_allowed());
    assert!(allowed.execution_nonce.is_none());

    let replay = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-strict-nonce-http-authority".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: Some(&nonce),
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap_err();
    assert!(
        replay.to_string().contains("execution nonce"),
        "expected replayed nonce denial, got {replay}"
    );
}

#[test]
fn deny_by_default_requires_capability() {
    let query = HashMap::new();
    let result = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-2".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert_eq!(result.receipt.response_status, 403);
}

#[test]
fn invalid_presented_capability_denies_even_safe_route() {
    let query = HashMap::new();
    let result = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-invalid".to_string(),
            method: HttpMethod::Get,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some("{not-json"),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert_eq!(result.receipt.evidence.len(), 1);
    assert_eq!(result.receipt.evidence[0].guard_name, "CapabilityGuard");
}

#[test]
fn valid_capability_allows_deny_by_default() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json(&issuer, "cap-123");
    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-3".to_string(),
            method: HttpMethod::Patch,
            route_pattern: "/pets/{petId}".to_string(),
            path: "/pets/42",
            query: &query,
            caller: caller(),
            body_hash: Some("def".to_string()),
            body_length: 3,
            session_id: Some("session-1".to_string()),
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(result.receipt.capability_id.as_deref(), Some("cap-123"));
    assert_eq!(result.receipt.session_id.as_deref(), Some("session-1"));
    assert!(
        metadata_string(result.receipt.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY).is_some()
    );
}

#[test]
fn approval_store_constructor_fails_closed_without_durable_stores() {
    // Passing a caller-provided approval store must not silently opt the embedded
    // kernel out of durable persistence: with no receipt or revocation store
    // attached, a mediated side effect fails closed instead of running on
    // in-memory audit state. The same request is allowed only when ephemerality
    // is opted into explicitly.
    let query = HashMap::new();
    let issuer = Keypair::generate();
    let capability = signed_capability_token_json(&issuer, "cap-durable-gate");

    let fail_closed = HttpAuthority::new_with_approval_store_and_trusted_issuers(
        issuer.clone(),
        "policy-hash".to_string(),
        Arc::new(InMemoryApprovalStore::new()),
        Vec::new(),
    );
    let error = fail_closed
        .evaluate(HttpAuthorityInput {
            request_id: "req-fail-closed".to_string(),
            method: HttpMethod::Patch,
            route_pattern: "/pets/{petId}".to_string(),
            path: "/pets/42",
            query: &query,
            caller: caller(),
            body_hash: Some("def".to_string()),
            body_length: 3,
            session_id: Some("session-1".to_string()),
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap_err();
    assert!(
        error.to_string().contains("durable receipt persistence"),
        "fail-closed constructor must refuse a side effect for missing durable persistence, got {error}"
    );

    let ephemeral = HttpAuthority::new_ephemeral_with_approval_store_and_trusted_issuers(
        issuer.clone(),
        "policy-hash".to_string(),
        Arc::new(InMemoryApprovalStore::new()),
        Vec::new(),
    );
    let allowed = ephemeral
        .evaluate(HttpAuthorityInput {
            request_id: "req-ephemeral".to_string(),
            method: HttpMethod::Patch,
            route_pattern: "/pets/{petId}".to_string(),
            path: "/pets/42",
            query: &query,
            caller: caller(),
            body_hash: Some("def".to_string()),
            body_length: 3,
            session_id: Some("session-1".to_string()),
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();
    assert!(
        allowed.verdict.is_allowed(),
        "explicit ephemeral constructor still allows the same request"
    );
}

#[test]
fn direct_v2_capability_denies_without_http_trust_root_resolver() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_direct_v2_capability_token_json(&issuer, "cap-v2-direct");
    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-v2-direct".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("def".to_string()),
            body_length: 3,
            session_id: Some("session-1".to_string()),
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert!(result.receipt.evidence[0]
        .details
        .as_deref()
        .is_some_and(|details| details.contains("chain-binding requires")));
}

#[test]
fn capability_hint_mismatch_becomes_denial() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json(&issuer, "cap-123");
    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-4".to_string(),
            method: HttpMethod::Put,
            route_pattern: "/pets/42".to_string(),
            path: "/pets/42",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: Some("cap-other"),
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
}

#[test]
fn untrusted_capability_denies_deny_by_default() {
    let query = HashMap::new();
    let authority = authority();
    let capability = signed_capability_token_json(&Keypair::generate(), "cap-untrusted");
    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-untrusted".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("ghi".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert_eq!(result.receipt.capability_id, None);
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some("capability issuer is not trusted")
    );
}

#[test]
fn configured_external_issuer_allows_deny_by_default() {
    let query = HashMap::new();
    let external_issuer = Keypair::generate();
    let authority = authority_with_trusted_issuer(external_issuer.public_key());
    let capability = signed_capability_token_json(&external_issuer, "cap-external");
    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-external".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("issuer".to_string()),
            body_length: 6,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(
        result.receipt.capability_id.as_deref(),
        Some("cap-external")
    );
}

#[test]
fn revoked_presented_capability_denies_deny_by_default() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let receipt_store: Arc<dyn chio_kernel::ReceiptStore> = Arc::new(
        chio_store_sqlite::SqliteReceiptStore::open(dir.path().join("receipts.db"))?,
    );
    let revocation_store: Arc<dyn chio_kernel::RevocationStore> = Arc::new(
        chio_store_sqlite::SqliteRevocationStore::open(dir.path().join("revocations.db"))?,
    );
    // The caller presents a validly-signed capability whose id has since been
    // revoked in the durable store.
    revocation_store.revoke("cap-revoked")?;

    let external_issuer = Keypair::generate();
    let authority = HttpAuthority::builder()
        .receipt_store(receipt_store)
        .revocation_store(revocation_store)
        .trusted_capability_issuers(vec![external_issuer.public_key()])
        .build(Keypair::generate(), "policy-hash".to_string())?;

    let capability = signed_capability_token_json(&external_issuer, "cap-revoked");
    let query = HashMap::new();
    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-revoked".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("revoked".to_string()),
            body_length: 7,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(
        result.verdict.is_denied(),
        "a revoked presented capability must be denied"
    );
    assert!(result.receipt.capability_id.is_none());
    assert!(
        result.receipt.evidence[0]
            .details
            .as_deref()
            .is_some_and(|details| details.contains("revoked")),
        "evidence should record the revocation, got {:?}",
        result.receipt.evidence
    );

    Ok(())
}

#[test]
fn finalized_receipt_links_decision_receipt_and_kernel_receipt() {
    let query = HashMap::new();
    let shared = authority();
    let decision = shared
        .evaluate(HttpAuthorityInput {
            request_id: "req-5".to_string(),
            method: HttpMethod::Get,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap()
        .receipt;
    let kernel_receipt_id = metadata_string(decision.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY)
        .map(ToOwned::to_owned)
        .test_unwrap();
    let final_receipt = shared
        .finalize_decision_receipt(&decision, 204)
        .test_unwrap();

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
            .and_then(|metadata| metadata.get(CHIO_DECISION_RECEIPT_ID_KEY))
            .and_then(serde_json::Value::as_str),
        Some(decision.id.as_str())
    );
    assert_eq!(
        metadata_string(final_receipt.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY),
        Some(kernel_receipt_id.as_str())
    );
    assert_eq!(
        metadata_value(final_receipt.metadata.as_ref(), "route_selection")
            .and_then(|value| value.get("selectedTargetProtocol"))
            .and_then(Value::as_str),
        Some("native")
    );
}

#[test]
fn extract_approval_id_parses_resume_path() {
    assert_eq!(
        extract_approval_id(Some(
            "kernel returned PendingApproval; resume via /approvals/ap-123/respond"
        ))
        .as_deref(),
        Some("ap-123")
    );
    assert_eq!(
        extract_approval_id(Some("kernel returned PendingApproval; approval_id=ap-456")).as_deref(),
        Some("ap-456")
    );
    assert_eq!(
        extract_approval_id(Some("kernel returned PendingApproval; approval_id: ap-789"))
            .as_deref(),
        Some("ap-789")
    );
    assert!(extract_approval_id(Some("kernel returned PendingApproval")).is_none());
}

#[test]
fn pending_approval_id_reads_nested_metadata() {
    let metadata = serde_json::json!({
        "pending_approval": {
            "approval_id": "ap-structured"
        }
    });
    assert_eq!(
        pending_approval_id(Some(&metadata), Some("kernel returned PendingApproval")).as_deref(),
        Some("ap-structured")
    );
}

#[test]
fn pending_approval_is_not_a_dispatch_failure() {
    // A HITL PendingApproval is the normal approval-required flow (a 409), not a
    // mediation-edge dispatch failure. The `evaluate` error arm gates the
    // dispatch-failure counter and the error latency/guard-eval series on this
    // predicate, so a governed approval prompt cannot page the P0
    // fail-open/dispatch-failure alert or skew the error metrics.
    assert!(
        !is_dispatch_failure(&HttpAuthorityError::PendingApproval {
            approval_id: Some("ap-1".to_string()),
            kernel_receipt_id: "rcpt-1".to_string(),
        }),
        "a pending approval must not count as a dispatch failure"
    );
    // A genuine kernel evaluation error is still a dispatch failure and must
    // continue to feed the paging metric.
    assert!(
        is_dispatch_failure(&HttpAuthorityError::Kernel("boom".to_string())),
        "a real evaluation error is a dispatch failure"
    );
    assert!(is_dispatch_failure(&HttpAuthorityError::ContentHash(
        "bad".to_string()
    )));
}

#[test]
fn deny_by_default_proxy_path_requires_http_authority_grant() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-proxy-scope".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
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
fn deny_by_default_proxy_path_ignores_spoofed_tool_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-proxy-spoofed-tool".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("math"),
            requested_tool_name: Some("double"),
            requested_arguments: Some(&serde_json::json!({ "value": 1 })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
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
fn deny_by_default_tools_path_honors_path_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-sidecar-tool-context".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/matrix/files.read".to_string(),
            path: "/chio/tools/matrix/files.read",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("matrix"),
            requested_tool_name: Some("files.read"),
            requested_arguments: Some(&serde_json::json!({ "path": "/tmp/a" })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(
        result.receipt.capability_id.as_deref(),
        Some("cap-matrix-read")
    );
}

#[test]
fn deny_by_default_tools_path_without_sidecar_fields_binds_to_path_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
        "cap-billing-charge",
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "billing".to_string(),
                tool_name: "charge".to_string(),
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tools-path-no-sidecar-fields".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/billing/charge".to_string(),
            path: "/chio/tools/billing/charge",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(
        result.receipt.capability_id.as_deref(),
        Some("cap-billing-charge")
    );
}

#[test]
fn deny_by_default_tools_path_with_arguments_only_binds_to_path_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
        "cap-billing-charge",
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "billing".to_string(),
                tool_name: "charge".to_string(),
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tools-path-arguments-only".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/billing/charge".to_string(),
            path: "/chio/tools/billing/charge",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: Some(&serde_json::json!({ "amount": 100 })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(
        result.receipt.capability_id.as_deref(),
        Some("cap-billing-charge")
    );
}

#[test]
fn reserved_tools_path_safe_policy_binds_to_path_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-safe-tools-path-spoofed-fields".to_string(),
            method: HttpMethod::Get,
            route_pattern: "/chio/tools/billing/charge".to_string(),
            path: "/chio/tools/billing/charge",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("math"),
            requested_tool_name: Some("double"),
            requested_arguments: Some(&serde_json::json!({ "amount": 100 })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some("capability does not authorize tool charge on server billing")
    );
}

#[test]
fn reserved_tools_path_safe_policy_requires_capability() {
    let query = HashMap::new();
    let result = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-safe-tools-path-no-capability".to_string(),
            method: HttpMethod::Get,
            route_pattern: "/chio/tools/billing/read".to_string(),
            path: "/chio/tools/billing/read",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: Some("billing"),
            requested_tool_name: Some("read"),
            requested_arguments: Some(&Value::Null),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some("side-effect route requires a valid capability token")
    );
}

#[test]
fn reserved_tools_path_safe_policy_requires_capability_without_sidecar_fields() {
    let query = HashMap::new();
    let result = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-safe-tools-path-no-sidecar-fields".to_string(),
            method: HttpMethod::Get,
            route_pattern: "/chio/tools/billing/read".to_string(),
            path: "/chio/tools/billing/read",
            query: &query,
            caller: caller(),
            body_hash: None,
            body_length: 0,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::SessionAllow,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some("side-effect route requires a valid capability token")
    );
}

#[test]
fn deny_by_default_unmatched_http_path_does_not_trust_synthetic_pattern() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-unmatched-spoofed-synthetic-pattern".to_string(),
            method: HttpMethod::Post,
            route_pattern: "matrix:admin.delete".to_string(),
            path: "/admin/delete",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("matrix"),
            requested_tool_name: Some("admin.delete"),
            requested_arguments: Some(&serde_json::json!({ "path": "/tmp/a" })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
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
fn deny_by_default_tools_path_binds_to_path_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tools-path-spoofed-fields".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/billing/charge".to_string(),
            path: "/chio/tools/billing/charge",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("math"),
            requested_tool_name: Some("double"),
            requested_arguments: Some(&serde_json::json!({ "amount": 100 })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some("capability does not authorize tool charge on server billing")
    );
}

#[test]
fn deny_by_default_tools_path_decodes_percent_encoded_identity() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
        "cap-acp-terminal-create",
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "acp".to_string(),
                tool_name: "terminal/create".to_string(),
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tools-path-encoded-tool".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/acp/terminal%2Fcreate".to_string(),
            path: "/chio/tools/acp/terminal%2Fcreate",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("acp"),
            requested_tool_name: Some("terminal/create"),
            requested_arguments: Some(&serde_json::json!({ "command": "ls" })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_allowed());
    assert_eq!(
        result.receipt.capability_id.as_deref(),
        Some("cap-acp-terminal-create")
    );
}

#[test]
fn deny_by_default_tools_path_rejects_malformed_percent_encoding() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
        "cap-http-authority",
        ChioScope {
            grants: vec![http_authority_tool_grant()],
            ..ChioScope::default()
        },
    );

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tools-path-malformed-tool".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/acp/terminal%ZZcreate".to_string(),
            path: "/chio/tools/acp/terminal%ZZcreate",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("acp"),
            requested_tool_name: Some("terminal/create"),
            requested_arguments: Some(&serde_json::json!({ "command": "ls" })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some(MALFORMED_CHIO_TOOLS_PATH_REASON)
    );
}

#[test]
fn deny_by_default_tools_path_rejects_malformed_percent_encoding_before_wildcard_grant() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
        "cap-wildcard",
        ChioScope {
            grants: vec![ToolGrant {
                server_id: "*".to_string(),
                tool_name: "*".to_string(),
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tools-path-malformed-wildcard".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/acp/terminal%ZZcreate".to_string(),
            path: "/chio/tools/acp/terminal%ZZcreate",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("acp"),
            requested_tool_name: Some("terminal/create"),
            requested_arguments: Some(&serde_json::json!({ "command": "ls" })),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some(MALFORMED_CHIO_TOOLS_PATH_REASON)
    );
}

#[test]
fn deny_by_default_requires_matching_tool_grant() {
    let query = HashMap::new();
    let (authority, issuer) = authority_with_issuer();
    let capability = signed_capability_token_json_with_scope(
        &issuer,
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

    let result = authority
        .evaluate(HttpAuthorityInput {
            request_id: "req-tool-mismatch".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/chio/tools/math/increment".to_string(),
            path: "/chio/tools/math/increment",
            query: &query,
            caller: caller(),
            body_hash: Some("toolhash".to_string()),
            body_length: 8,
            session_id: None,
            capability_id_hint: None,
            presented_capability: Some(&capability),
            requested_tool_server: Some("math"),
            requested_tool_name: Some("increment"),
            requested_arguments: Some(&Value::Null),
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();

    assert!(result.verdict.is_denied());
    assert!(result.receipt.capability_id.is_none());
    assert_eq!(
        result.receipt.evidence[0].details.as_deref(),
        Some("capability does not authorize tool increment on server math")
    );
}
#[test]
fn sign_transport_deny_receipt_signs_final_scope_deny() {
    let authority = authority();
    let verdict = Verdict::deny_with_status(
        "request body exceeds limit",
        "chio_tower_request_body_limit_guard",
        413,
    );
    let receipt = authority
        .sign_transport_deny_receipt(TransportDenyInput {
            request_id: "req-transport-deny",
            route_pattern: "/upload",
            method: HttpMethod::Post,
            caller_identity_hash: "caller-hash",
            content_hash: None,
            verdict,
        })
        .test_unwrap();

    assert!(receipt.verify_signature().test_unwrap());
    assert!(receipt.is_denied());
    assert_eq!(receipt.response_status, 413);
    assert_eq!(receipt.request_id, "req-transport-deny");
    assert_eq!(receipt.route_pattern, "/upload");
    assert_eq!(receipt.caller_identity_hash, "caller-hash");
    assert!(receipt.capability_id.is_none());
    assert!(receipt.evidence.is_empty());
    assert_eq!(receipt.content_hash, "");
    assert_eq!(
        http_status_scope(receipt.metadata.as_ref()),
        Some(CHIO_HTTP_STATUS_SCOPE_FINAL)
    );
    assert!(
        metadata_string(receipt.metadata.as_ref(), CHIO_KERNEL_RECEIPT_ID_KEY).is_none(),
        "transport deny must not claim a kernel receipt id"
    );
}

#[test]
fn policy_deny_is_not_recorded_as_a_dispatch_failure() {
    // A normal policy/capability deny is an expected fail-closed decision. It is
    // tracked by the guard-verdict metrics and must NOT increment
    // chio_dispatch_failure_total, or one ordinary rejected request would page
    // the P0 fail-open/dispatch-failure alert.
    let query = HashMap::new();
    let denied = authority()
        .evaluate(HttpAuthorityInput {
            request_id: "req-deny-no-page".to_string(),
            method: HttpMethod::Post,
            route_pattern: "/pets".to_string(),
            path: "/pets",
            query: &query,
            caller: caller(),
            body_hash: Some("abc".to_string()),
            body_length: 3,
            session_id: None,
            capability_id_hint: None,
            presented_capability: None,
            requested_tool_server: None,
            requested_tool_name: None,
            requested_arguments: None,
            model_metadata: None,
            unsupported_authorization_extension: None,
            execution_nonce: None,
            policy: HttpAuthorityPolicy::DenyByDefault,
        })
        .test_unwrap();
    assert!(denied.verdict.is_denied());

    // No code path produces the "denied" outcome, so the paging counter never
    // carries a deny series regardless of how many requests are rejected.
    let mut body = String::new();
    chio_metrics_spec::runtime::families::DISPATCH_FAILURE.render(&mut body);
    assert!(
        !body.contains("outcome=\"denied\""),
        "a policy deny must not appear on the dispatch-failure paging metric: {body}"
    );

    // The deny is still observable via the guard-verdict metric.
    assert!(
        crate::metrics::guard_evaluations_total(crate::metrics::GUARD_OUTCOME_DENY) >= 1,
        "a deny must be tracked by the guard-verdict metric"
    );
}

#[test]
fn sign_transport_deny_receipt_rejects_non_deny_verdict() {
    let authority = authority();
    let err = authority
        .sign_transport_deny_receipt(TransportDenyInput {
            request_id: "req-transport-allow",
            route_pattern: "/pets",
            method: HttpMethod::Get,
            caller_identity_hash: "caller-hash",
            content_hash: Some("abc"),
            verdict: Verdict::Allow,
        })
        .test_unwrap_err();
    assert!(matches!(err, HttpAuthorityError::Kernel(_)));
    assert!(err
        .to_string()
        .contains("sign_transport_deny_receipt requires a Deny verdict"));
}
