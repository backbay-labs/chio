#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::{
    CallChainContinuationToken, CallChainContinuationTokenBody, CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
};
use chio_core_types::receipt::{
    ReceiptLineageEndpoints, ReceiptLineageRelationKind, ReceiptLineageStatement,
    ReceiptLineageStatementBody,
};
use chio_core_types::session::{
    RequestLineageMode, RequestLineageRecord, SessionAnchor, SessionAnchorBody,
    SessionAnchorContext, SessionAnchorReference,
};
use chio_core_types::{
    sha256_hex, Keypair, OperationKind, RequestId, SessionAuthContext, SessionId, Signature,
};

const UNSUPPORTED_SCHEMA: &str = "chio.unsupported_future_schema.v999";

fn session_anchor_body(kernel: &Keypair) -> SessionAnchorBody {
    let auth = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("https://app.example".to_string()),
    );
    SessionAnchorBody::new(
        "anchor-schema",
        SessionAnchorContext::new(
            SessionId::new("sess-schema"),
            "agent-schema".to_string(),
            auth,
            None,
        ),
        1,
        1_710_000_000,
        kernel.public_key(),
    )
    .expect("session anchor body builds")
}

fn receipt_lineage_body(kernel: &Keypair) -> ReceiptLineageStatementBody {
    let endpoints = ReceiptLineageEndpoints::new(
        "parent-receipt-schema",
        "child-receipt-schema",
        RequestId::new("parent-req-schema"),
        RequestId::new("child-req-schema"),
        SessionAnchorReference::new("parent-anchor", sha256_hex(b"parent-anchor")),
        SessionAnchorReference::new("child-anchor", sha256_hex(b"child-anchor")),
    );
    ReceiptLineageStatementBody::new(
        "lineage-schema",
        endpoints,
        ReceiptLineageRelationKind::LocalChild,
        1_710_000_000,
        kernel.public_key(),
    )
}

fn continuation_body(signer: &Keypair) -> CallChainContinuationTokenBody {
    CallChainContinuationTokenBody {
        schema: CHIO_CALL_CHAIN_CONTINUATION_SCHEMA.to_string(),
        token_id: "continuation-schema".to_string(),
        signer: signer.public_key(),
        subject: Keypair::generate().public_key(),
        chain_id: "chain-schema".to_string(),
        parent_request_id: "parent-req-schema".to_string(),
        parent_receipt_id: Some("parent-receipt-schema".to_string()),
        parent_receipt_hash: Some(sha256_hex(b"parent-receipt")),
        parent_session_anchor: None,
        current_subject: "current-subject".to_string(),
        delegator_subject: "delegator-subject".to_string(),
        origin_subject: "origin-subject".to_string(),
        parent_capability_id: Some("cap-parent".to_string()),
        delegation_link_hash: Some(sha256_hex(b"delegation-link")),
        governed_intent_hash: Some(sha256_hex(b"governed-intent")),
        audience: None,
        nonce: Some("nonce-schema".to_string()),
        issued_at: 1_710_000_000,
        expires_at: 1_710_003_600,
    }
}

fn request_lineage_record() -> RequestLineageRecord {
    RequestLineageRecord::new(
        RequestId::new("request-lineage-schema"),
        SessionAnchorReference::new("anchor-schema", sha256_hex(b"anchor-schema")),
        OperationKind::ToolCall,
        RequestLineageMode::LocalChild,
        1_710_000_000,
    )
}

fn sign_body<T: serde::Serialize>(body: &T, keypair: &Keypair) -> Signature {
    keypair.sign_canonical(body).expect("body signs").0
}

fn session_anchor_from_body(body: SessionAnchorBody, signature: Signature) -> SessionAnchor {
    SessionAnchor {
        schema: body.schema,
        id: body.id,
        session_id: body.session_id,
        agent_id: body.agent_id,
        auth_context: body.auth_context,
        auth_context_hash: body.auth_context_hash,
        auth_method_hash: body.auth_method_hash,
        proof_binding: body.proof_binding,
        auth_epoch: body.auth_epoch,
        issued_at: body.issued_at,
        kernel_key: body.kernel_key,
        signature,
    }
}

fn receipt_lineage_from_body(
    body: ReceiptLineageStatementBody,
    signature: Signature,
) -> ReceiptLineageStatement {
    ReceiptLineageStatement {
        schema: body.schema,
        id: body.id,
        parent_receipt_id: body.parent_receipt_id,
        child_receipt_id: body.child_receipt_id,
        parent_request_id: body.parent_request_id,
        child_request_id: body.child_request_id,
        parent_session_anchor: body.parent_session_anchor,
        child_session_anchor: body.child_session_anchor,
        relation_kind: body.relation_kind,
        evidence_class: body.evidence_class,
        continuation_token_id: body.continuation_token_id,
        issued_at: body.issued_at,
        kernel_key: body.kernel_key,
        signature,
    }
}

fn continuation_from_body(
    body: CallChainContinuationTokenBody,
    signature: Signature,
) -> CallChainContinuationToken {
    CallChainContinuationToken {
        schema: body.schema,
        token_id: body.token_id,
        signer: body.signer,
        subject: body.subject,
        chain_id: body.chain_id,
        parent_request_id: body.parent_request_id,
        parent_receipt_id: body.parent_receipt_id,
        parent_receipt_hash: body.parent_receipt_hash,
        parent_session_anchor: body.parent_session_anchor,
        current_subject: body.current_subject,
        delegator_subject: body.delegator_subject,
        origin_subject: body.origin_subject,
        parent_capability_id: body.parent_capability_id,
        delegation_link_hash: body.delegation_link_hash,
        governed_intent_hash: body.governed_intent_hash,
        audience: body.audience,
        nonce: body.nonce,
        issued_at: body.issued_at,
        expires_at: body.expires_at,
        signature,
    }
}

#[test]
fn schema_tagged_signers_reject_unsupported_schema_ids() {
    let keypair = Keypair::generate();

    let mut anchor_body = session_anchor_body(&keypair);
    anchor_body.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(SessionAnchor::sign(anchor_body, &keypair).is_err());

    let mut lineage_body = receipt_lineage_body(&keypair);
    lineage_body.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(ReceiptLineageStatement::sign(lineage_body, &keypair).is_err());

    let mut continuation_body = continuation_body(&keypair);
    continuation_body.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(CallChainContinuationToken::sign(continuation_body, &keypair).is_err());
}

#[test]
fn schema_tagged_verifiers_reject_supported_key_with_unsupported_schema() {
    let keypair = Keypair::generate();

    let mut anchor_body = session_anchor_body(&keypair);
    anchor_body.schema = UNSUPPORTED_SCHEMA.to_string();
    let anchor_signature = sign_body(&anchor_body, &keypair);
    let anchor = session_anchor_from_body(anchor_body, anchor_signature);
    assert!(anchor.verify_signature().is_err());

    let mut lineage_body = receipt_lineage_body(&keypair);
    lineage_body.schema = UNSUPPORTED_SCHEMA.to_string();
    let lineage_signature = sign_body(&lineage_body, &keypair);
    let lineage = receipt_lineage_from_body(lineage_body, lineage_signature);
    assert!(lineage.verify_signature().is_err());

    let mut continuation_body = continuation_body(&keypair);
    continuation_body.schema = UNSUPPORTED_SCHEMA.to_string();
    let continuation_signature = sign_body(&continuation_body, &keypair);
    let continuation = continuation_from_body(continuation_body, continuation_signature);
    assert!(continuation.verify_signature().is_err());
}

#[test]
fn schema_tagged_request_lineage_record_rejects_unsupported_schema_id() {
    let mut record = request_lineage_record();
    assert!(record.validate_schema().is_ok());

    record.schema = UNSUPPORTED_SCHEMA.to_string();
    assert!(record.validate_schema().is_err());
}
