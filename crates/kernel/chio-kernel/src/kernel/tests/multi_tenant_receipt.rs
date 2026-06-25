// Multi-tenant receipt isolation tests.
//
// Included by `src/kernel/tests.rs`. Shares helper items from
// `tests/all.rs` via the surrounding `tests.rs` `include!`s.
//
// These tests anchor the core kernel behaviour:
//   * a session whose auth_context carries an enterprise_identity with
//     tenant_id stamps that tenant on every receipt signed during its
//     tool-call evaluation;
//   * a session without a tenant claim produces receipts whose
//     tenant_id is `None`;
//   * the tenant tag is never read from the `ToolCallRequest` itself.

use chio_core_types::session::{
    EnterpriseFederationMethod, EnterpriseIdentityContext, OAuthBearerFederatedClaims,
    OAuthBearerSessionAuthInput,
};
use std::collections::BTreeMap;

fn oauth_auth_with_enterprise_tenant(tenant: &str) -> SessionAuthContext {
    SessionAuthContext::streamable_http_oauth_bearer_with_claims(OAuthBearerSessionAuthInput {
        principal: Some(format!("oidc:https://issuer.example#sub:user-{tenant}")),
        issuer: Some("https://issuer.example".to_string()),
        subject: Some(format!("user-{tenant}")),
        audience: Some("chio-mcp".to_string()),
        scopes: vec!["mcp:invoke".to_string()],
        federated_claims: OAuthBearerFederatedClaims::default(),
        enterprise_identity: Some(EnterpriseIdentityContext {
            provider_id: "provider-tenant-test".to_string(),
            provider_record_id: None,
            provider_kind: "oidc_jwks".to_string(),
            federation_method: EnterpriseFederationMethod::Jwt,
            principal: format!("oidc:https://issuer.example#sub:user-{tenant}"),
            subject_key: format!("subject-key-{tenant}"),
            client_id: Some("client-abc".to_string()),
            object_id: None,
            tenant_id: Some(tenant.to_string()),
            organization_id: None,
            groups: Vec::new(),
            roles: Vec::new(),
            source_subject: None,
            attribute_sources: BTreeMap::new(),
            trust_material_ref: None,
        }),
        token_fingerprint: Some(format!("fp-{tenant}")),
        origin: Some("https://app.example".to_string()),
    })
}

#[test]
fn session_tenant_id_is_stamped_on_tool_call_receipt() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel
        .set_session_auth_context(&session_id, oauth_auth_with_enterprise_tenant("tenant-A"))
        .unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(&session_id, "req-tenant", &agent_kp.public_key().to_hex());
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        execution_nonce: None,
        model_metadata: None,
    });

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected tool call response");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(
        response.receipt.tenant_id.as_deref(),
        Some("tenant-A"),
        "receipt must carry the session-derived tenant tag"
    );
    // Signature must still verify with the tenant tag included in the body.
    assert!(response.receipt.verify_signature().unwrap());
}

#[test]
fn request_keyed_tenant_scope_survives_missing_thread_local_scope() {
    let kernel = make_kernel(make_config());
    let _request_scope =
        kernel.scope_receipt_tenant_id_for_request("req-tenant-map", Some("tenant-map".to_string()));
    let _thread_scope = scope_receipt_tenant_id(None);

    let receipt = kernel
        .build_and_sign_receipt(ReceiptParams {
            request_id: Some("req-tenant-map"),
            capability_id: "cap-tenant-map",
            tool_name: "read_file",
            server_id: "srv-a",
            decision: Decision::Allow,
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/app/src/main.rs",
            }))
            .unwrap(),
            content_hash: chio_core::crypto::sha256_hex(b"tenant-map-content"),
            canonical_content: b"tenant-map-content".to_vec(),
            metadata: None,
            timestamp: 1_700_000_100,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })
        .unwrap();

    assert_eq!(receipt.tenant_id.as_deref(), Some("tenant-map"));
    assert!(receipt.verify_signature().unwrap());
}

#[test]
fn session_without_tenant_id_produces_untagged_receipt() {
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    // Default session auth context is in-process anonymous; no tenant.
    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(&session_id, "req-notenant", &agent_kp.public_key().to_hex());
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        execution_nonce: None,
        model_metadata: None,
    });

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected tool call response");

    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.receipt.tenant_id.is_none(),
        "single-tenant session must produce receipts without a tenant tag"
    );
}

#[test]
fn blocking_evaluate_without_session_leaves_tenant_id_none() {
    // `evaluate_tool_call_blocking` has no session handle; it MUST leave
    // tenant_id unset regardless of any thread-local residue.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let request = make_request("req-blocking", &cap, "read_file", "srv-a");
    let response = kernel.evaluate_tool_call_blocking(&request).unwrap();

    assert_eq!(response.verdict, Verdict::Allow);
    assert!(
        response.receipt.tenant_id.is_none(),
        "sessionless blocking evaluate must produce receipts without a tenant tag"
    );
}

#[test]
fn tenant_id_falls_back_to_oauth_federated_claims() {
    // A minimal OAuth token without full EnterpriseIdentityContext but with
    // `federated_claims.tenant_id` should still tag receipts with the
    // tenant -- the resolver's second fallback path.
    let mut kernel = make_kernel(make_config());
    kernel.register_tool_server(Box::new(EchoServer::new("srv-a", vec!["read_file"])));

    let agent_kp = make_keypair();
    let scope = make_scope(vec![make_grant("srv-a", "read_file")]);
    let cap = make_capability(&kernel, &agent_kp, scope, 300);

    let auth = SessionAuthContext::streamable_http_oauth_bearer_with_claims(
        OAuthBearerSessionAuthInput {
            principal: Some("oidc:https://issuer.example#sub:user-Z".to_string()),
            issuer: Some("https://issuer.example".to_string()),
            subject: Some("user-Z".to_string()),
            audience: Some("chio-mcp".to_string()),
            scopes: vec!["mcp:invoke".to_string()],
            federated_claims: OAuthBearerFederatedClaims {
                tenant_id: Some("tenant-fed".to_string()),
                ..OAuthBearerFederatedClaims::default()
            },
            enterprise_identity: None,
            token_fingerprint: Some("fp-Z".to_string()),
            origin: Some("https://app.example".to_string()),
        },
    );

    let session_id = kernel.open_session(agent_kp.public_key().to_hex(), vec![cap.clone()]).unwrap();
    kernel.set_session_auth_context(&session_id, auth).unwrap();
    kernel.activate_session(&session_id).unwrap();

    let context = make_operation_context(&session_id, "req-fed", &agent_kp.public_key().to_hex());
    let operation = SessionOperation::ToolCall(ToolCallOperation {
        capability: cap,
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/main.rs"}),
        execution_nonce: None,
        model_metadata: None,
    });

    let response = session_tool_call(
        kernel
            .evaluate_session_operation(&context, &operation)
            .unwrap(),
    )
    .expect("expected tool call response");

    assert_eq!(response.verdict, Verdict::Allow);
    assert_eq!(response.receipt.tenant_id.as_deref(), Some("tenant-fed"));
}

// --- WYSIWYS on the PRODUCTION signing path (BAC-539) ---------------------
//
// These tests exercise the live `ChioKernel::build_and_sign_receipt` path --
// the choke point EVERY production receipt (allow/deny, inline and session)
// flows through -- not the opt-in `sign_with_handle` API directly. They prove
// the recompute-and-refuse gate is now wired into production, closing the
// render-A / sign-B hole end-to-end on the path real signers use.

#[test]
fn production_build_and_sign_refuses_render_a_sign_b() {
    let kernel = make_kernel(make_config());

    // The producer renders/evaluates content A but submits a body claiming the
    // hash of a *different* content B. canonical_content is the bytes the
    // kernel actually hashed (A); content_hash is the forged claim (hash of B).
    let content_a = b"content-A-shown-to-the-human".to_vec();
    let forged_hash_b = chio_core::crypto::sha256_hex(b"content-B-secretly-signed");

    let result = kernel.build_and_sign_receipt(ReceiptParams {
        request_id: None,
        capability_id: "cap-wysiwys",
        tool_name: "read_file",
        server_id: "srv-a",
        decision: Decision::Allow,
        action: ToolCallAction::from_parameters(serde_json::json!({
            "path": "/app/src/main.rs",
        }))
        .unwrap(),
        content_hash: forged_hash_b,
        canonical_content: content_a,
        metadata: None,
        timestamp: 1_700_000_200,
        trust_level: chio_core::receipt::kinds::TrustLevel::default(),
        tenant_id: None,
    });

    let error = result.expect_err(
        "production build_and_sign_receipt MUST refuse a content_hash that was not \
         recomputed from the bound canonical content (render-A/sign-B)",
    );
    let message = error.to_string();
    assert!(
        message.contains("content_hash mismatch") && message.contains("WYSIWYS"),
        "unexpected error surfaced for production WYSIWYS refusal: {message}"
    );
}

#[test]
fn production_build_and_sign_accepts_matching_content_hash() {
    let kernel = make_kernel(make_config());

    // Honest producer: content_hash is sha256_hex of the exact canonical
    // content the kernel signs over.
    let content = b"honest-canonical-content".to_vec();
    let content_hash = chio_core::crypto::sha256_hex(&content);

    let receipt = kernel
        .build_and_sign_receipt(ReceiptParams {
            request_id: None,
            capability_id: "cap-wysiwys-ok",
            tool_name: "read_file",
            server_id: "srv-a",
            decision: Decision::Allow,
            action: ToolCallAction::from_parameters(serde_json::json!({
                "path": "/app/src/main.rs",
            }))
            .unwrap(),
            content_hash: content_hash.clone(),
            canonical_content: content,
            metadata: None,
            timestamp: 1_700_000_201,
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
        })
        .expect("honest content_hash must sign on the production path");

    assert_eq!(receipt.content_hash, content_hash);
    assert!(
        receipt.verify_signature().unwrap(),
        "production WYSIWYS-signed receipt must verify"
    );
}
