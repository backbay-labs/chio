#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};

use chio_core_types::capability::governance::{
    CallChainContinuationToken, CallChainContinuationTokenBody, CHIO_CALL_CHAIN_CONTINUATION_SCHEMA,
};
use chio_core_types::receipt::lineage::{
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
const BBS_PROJECTION_MANIFEST_V2_SCHEMA: &str = "chio.bbs-projection.manifest.v2";
const PROOF_ROOM_FIXTURE_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-catalog.v1";
const PROOF_ROOM_FIXTURE_ROOT_CATALOG_SCHEMA: &str = "chio.proof-room.fixture-root-catalog.v1";

#[test]
fn known_signed_artifact_schemas_are_supported() {
    for schema in chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "schema should be supported: {schema}"
        );
    }
}

#[test]
fn known_signed_artifact_schemas_match_public_registry_or_internal_exemption() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let registered_schemas: BTreeSet<&str> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter_map(|entry| entry.get("schema").and_then(serde_json::Value::as_str))
        .collect();
    let internal_only_schemas: BTreeSet<&str> = [
        "chio.session_anchor.v1",
        "chio.request_lineage_record.v1",
        "chio.runtime-attestation.azure-maa.jwt.v1",
        "chio.runtime-attestation.aws-nitro-attestation.v1",
        "chio.runtime-attestation.google-confidential-vm.jwt.v1",
        "chio.runtime-attestation.enterprise-verifier.json.v1",
    ]
    .into_iter()
    .collect();
    let missing_schemas: Vec<&str> = chio_core_types::KNOWN_SIGNED_ARTIFACT_SCHEMAS
        .iter()
        .copied()
        .filter(|schema| {
            !registered_schemas.contains(schema) && !internal_only_schemas.contains(schema)
        })
        .collect();

    assert!(
        missing_schemas.is_empty(),
        "known signed-artifact schemas missing from registry.json or internal exemption list: {missing_schemas:?}"
    );
}

#[test]
fn built_in_signed_artifact_registry_matches_public_metadata() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let registered_metadata: BTreeMap<&str, (&str, &str)> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .map(|entry| {
            let schema = entry
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has schema");
            let artifact_kind = entry
                .get("artifactKind")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has artifactKind");
            let introduced_by = entry
                .get("introducedBy")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has introducedBy");
            (schema, (artifact_kind, introduced_by))
        })
        .collect();
    let internal_only_schemas: BTreeSet<&str> = [
        "chio.session_anchor.v1",
        "chio.request_lineage_record.v1",
        "chio.runtime-attestation.azure-maa.jwt.v1",
        "chio.runtime-attestation.aws-nitro-attestation.v1",
        "chio.runtime-attestation.google-confidential-vm.jwt.v1",
        "chio.runtime-attestation.enterprise-verifier.json.v1",
    ]
    .into_iter()
    .collect();

    for entry in chio_core_types::built_in_signed_artifact_registry() {
        let Some((artifact_kind, introduced_by)) = registered_metadata.get(entry.schema.as_str())
        else {
            assert!(
                internal_only_schemas.contains(entry.schema.as_str()),
                "built-in signed-artifact registry row missing from registry.json or internal exemption list: {}",
                entry.schema
            );
            continue;
        };
        assert_eq!(
            entry.artifact_kind, *artifact_kind,
            "built-in artifact kind must match registry.json for {}",
            entry.schema
        );
        assert_eq!(
            entry.introduced_by, *introduced_by,
            "built-in introducedBy must match registry.json for {}",
            entry.schema
        );
    }
}

#[test]
fn public_settlement_dispatch_and_receipt_schemas_are_supported() {
    let registry: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../spec/schemas/registry.json"
    )))
    .expect("schema registry parses");
    let settlement_schemas: Vec<&str> = registry
        .get("artifacts")
        .and_then(serde_json::Value::as_array)
        .expect("registry artifacts are present")
        .iter()
        .filter(|entry| {
            matches!(
                entry
                    .get("artifactKind")
                    .and_then(serde_json::Value::as_str),
                Some("web3_settlement_dispatch" | "web3_settlement_execution_receipt")
            )
        })
        .map(|entry| {
            entry
                .get("schema")
                .and_then(serde_json::Value::as_str)
                .expect("registry artifact has schema")
        })
        .collect();

    assert_eq!(settlement_schemas.len(), 4);
    for schema in settlement_schemas {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "public settlement schema should be supported by the core signed-artifact gate: {schema}"
        );
    }
}

#[test]
fn governed_action_evidence_schemas_are_registered() {
    for (schema, artifact_kind) in [
        ("chio.capability.proof.v1", "capability_proof"),
        ("chio.guard.decision.v1", "guard_decision"),
        ("chio.policy.bundle.v1", "policy_bundle"),
        ("chio.trust.root.v1", "trust_root"),
    ] {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "governed-action evidence schema should be supported: {schema}"
        );
        assert!(
            chio_core_types::built_in_signed_artifact_registry()
                .iter()
                .any(|entry| entry.schema == schema
                    && entry.artifact_kind == artifact_kind
                    && entry.introduced_by == "transaction-passport-v1"),
            "governed-action evidence schema should have a built-in registry row: {schema}"
        );
    }
}

#[test]
fn proof_room_fixture_catalog_schema_is_registered() {
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        PROOF_ROOM_FIXTURE_CATALOG_SCHEMA
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(|entry| entry.schema == PROOF_ROOM_FIXTURE_CATALOG_SCHEMA
            && entry.artifact_kind == "proof_room_fixture_catalog"
            && entry.introduced_by == "proof-room-v1"));
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        PROOF_ROOM_FIXTURE_ROOT_CATALOG_SCHEMA
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(
            |entry| entry.schema == PROOF_ROOM_FIXTURE_ROOT_CATALOG_SCHEMA
                && entry.artifact_kind == "proof_room_fixture_root_catalog"
                && entry.introduced_by == "proof-room-v1"
        ));
}

#[test]
fn public_settlement_anchor_evidence_schemas_are_registered() {
    for (schema, artifact_kind) in [
        ("chio.anchor-inclusion-proof.v1", "anchor_inclusion_proof"),
        ("chio.anchor-proof-bundle.v1", "anchor_proof_bundle"),
    ] {
        assert!(
            chio_core_types::is_supported_signed_artifact_schema(schema),
            "anchor evidence schema should be supported: {schema}"
        );
        assert!(
            chio_core_types::built_in_signed_artifact_registry()
                .iter()
                .any(|entry| entry.schema == schema
                    && entry.artifact_kind == artifact_kind
                    && entry.introduced_by == "public-settlement-v1"),
            "anchor evidence schema should have a built-in registry row: {schema}"
        );
    }
}

#[test]
fn bbs_projection_manifest_v2_schema_is_registered() {
    assert!(chio_core_types::is_supported_signed_artifact_schema(
        BBS_PROJECTION_MANIFEST_V2_SCHEMA
    ));
    assert!(chio_core_types::built_in_signed_artifact_registry()
        .iter()
        .any(|entry| entry.schema == BBS_PROJECTION_MANIFEST_V2_SCHEMA
            && entry.artifact_kind == "bbs_projection_manifest"
            && entry.introduced_by == "crypto-context-v1"));
}

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
