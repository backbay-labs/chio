use std::collections::BTreeMap;

use super::*;
use crate::capability::{
    scope::{ChioScope, Operation, ToolGrant},
    token::CapabilityTokenBody,
};
use crate::crypto::Keypair;

fn make_token(kp: &Keypair) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "cap-session-001".to_string(),
            issuer: kp.public_key(),
            subject: kp.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "srv-a".to_string(),
                    tool_name: "read_file".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: 100,
            expires_at: 200,
            delegation_chain: vec![],
        },
        kp,
    )
    .unwrap()
}

#[test]
fn session_id_roundtrip() {
    let id = SessionId::new("sess-001");
    let encoded = serde_json::to_string(&id).unwrap();
    let decoded: SessionId = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, id);
    assert_eq!(decoded.to_string(), "sess-001");
}

#[test]
fn operation_context_new_sets_default_lineage_fields() {
    let context = OperationContext::new(
        SessionId::new("sess-001"),
        RequestId::new("req-001"),
        "agent-123".to_string(),
    );
    assert_eq!(context.session_id.as_str(), "sess-001");
    assert_eq!(context.request_id.as_str(), "req-001");
    assert_eq!(context.agent_id, "agent-123");
    assert_eq!(context.parent_request_id, None);
    assert_eq!(context.progress_token, None);
}

#[test]
fn operation_context_roundtrip_preserves_lineage() {
    let context = OperationContext {
        session_id: SessionId::new("sess-001"),
        request_id: RequestId::new("req-002"),
        agent_id: "agent-123".to_string(),
        parent_request_id: Some(RequestId::new("req-001")),
        progress_token: Some(ProgressToken::String("progress-7".to_string())),
    };

    let encoded = serde_json::to_string(&context).unwrap();
    let decoded: OperationContext = serde_json::from_str(&encoded).unwrap();

    assert_eq!(decoded, context);
}

#[test]
fn progress_token_accepts_integer_or_string() {
    let numeric = serde_json::json!(7);
    let stringy = serde_json::json!("progress-7");

    let numeric_token: ProgressToken = serde_json::from_value(numeric).unwrap();
    let string_token: ProgressToken = serde_json::from_value(stringy).unwrap();

    assert_eq!(numeric_token, ProgressToken::Integer(7));
    assert_eq!(
        string_token,
        ProgressToken::String("progress-7".to_string())
    );
}

#[test]
fn session_operation_roundtrip_preserves_tool_call_payload() {
    let kp = Keypair::generate();
    let op = SessionOperation::ToolCall(Box::new(ToolCallOperation {
        capability: make_token(&kp),
        server_id: "srv-a".to_string(),
        tool_name: "read_file".to_string(),
        arguments: serde_json::json!({"path": "/app/src/lib.rs"}),
        governed_intent: None,
        execution_nonce: None,
        model_metadata: Some(ModelMetadata {
            model_id: "gpt-5".to_string(),
            safety_tier: None,
            provider: Some("openai".to_string()),
            provenance_class: ProvenanceEvidenceClass::Observed,
        }),
        extra_metadata: Some(serde_json::json!({
            "route_selection": {
                "selectedRouteId": "mcp:task-child-a"
            }
        })),
    }));

    let encoded = serde_json::to_string(&op).unwrap();
    let decoded: SessionOperation = serde_json::from_str(&encoded).unwrap();

    match decoded {
        SessionOperation::ToolCall(payload) => {
            assert_eq!(payload.server_id, "srv-a");
            assert_eq!(payload.tool_name, "read_file");
            assert_eq!(payload.arguments["path"], "/app/src/lib.rs");
            assert_eq!(
                payload
                    .model_metadata
                    .as_ref()
                    .map(|metadata| metadata.model_id.as_str()),
                Some("gpt-5")
            );
            assert_eq!(
                payload
                    .model_metadata
                    .as_ref()
                    .map(|metadata| metadata.provenance_class),
                Some(ProvenanceEvidenceClass::Observed)
            );
            assert_eq!(
                payload
                    .extra_metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("route_selection"))
                    .and_then(|route| route.get("selectedRouteId"))
                    .and_then(serde_json::Value::as_str),
                Some("mcp:task-child-a")
            );
        }
        _ => panic!("expected tool call"),
    }
}

#[test]
fn session_operation_reports_kind() {
    assert_eq!(SessionOperation::Heartbeat.kind(), OperationKind::Heartbeat);
    assert_eq!(
        SessionOperation::ListCapabilities.kind(),
        OperationKind::ListCapabilities
    );
    assert_eq!(
        SessionOperation::CreateMessage(CreateMessageOperation {
            messages: vec![],
            model_preferences: None,
            system_prompt: None,
            include_context: None,
            temperature: None,
            max_tokens: 1,
            stop_sequences: vec![],
            metadata: None,
            tools: vec![],
            tool_choice: None,
        })
        .kind(),
        OperationKind::CreateMessage
    );
    assert_eq!(
        SessionOperation::CreateElicitation(CreateElicitationOperation::Form {
            meta: None,
            message: "Confirm this action".to_string(),
            requested_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "approved": { "type": "boolean" }
                },
                "required": ["approved"]
            }),
        })
        .kind(),
        OperationKind::CreateElicitation
    );
    assert_eq!(
        SessionOperation::ListResources.kind(),
        OperationKind::ListResources
    );
    assert_eq!(SessionOperation::ListRoots.kind(), OperationKind::ListRoots);
}

#[test]
fn root_definition_roundtrip() {
    let root = RootDefinition {
        uri: "file:///workspace/project".to_string(),
        name: Some("Project".to_string()),
    };

    let encoded = serde_json::to_string(&root).unwrap();
    let decoded: RootDefinition = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, root);
}

#[test]
fn normalizes_enforceable_file_roots_for_runtime() {
    let root = RootDefinition {
        uri: "file:///workspace/project/../project/src".to_string(),
        name: Some("Project".to_string()),
    };

    let normalized = root.normalize_for_runtime();
    assert!(normalized.is_enforceable_filesystem());
    assert_eq!(
        normalized.normalized_filesystem_path(),
        Some("/workspace/project/src")
    );
}

#[test]
fn normalizes_windows_style_file_roots_for_runtime() {
    let root = RootDefinition {
        uri: "file:///C:/Workspace/Chio/../project".to_string(),
        name: None,
    };

    let normalized = root.normalize_for_runtime();
    assert_eq!(
        normalized.normalized_filesystem_path(),
        Some("C:/Workspace/project")
    );
}

#[test]
fn classifies_non_file_roots_as_metadata_only() {
    let root = RootDefinition {
        uri: "repo://docs/roadmap".to_string(),
        name: Some("Roadmap".to_string()),
    };

    let normalized = root.normalize_for_runtime();
    assert!(matches!(
        normalized,
        NormalizedRoot::NonFileSystem { ref scheme, .. } if scheme == "repo"
    ));
}

#[test]
fn root_and_resource_normalization_cover_remaining_helper_edges() {
    let localhost_root = RootDefinition {
        uri: "file://localhost/workspace/project/docs".to_string(),
        name: None,
    };
    let normalized = localhost_root.normalize_for_runtime();
    assert!(normalized.is_enforceable_filesystem());
    assert_eq!(normalized.uri(), "file://localhost/workspace/project/docs");

    let invalid_file_root = RootDefinition {
        uri: "file:relative/path".to_string(),
        name: None,
    };
    let normalized = invalid_file_root.normalize_for_runtime();
    assert!(matches!(
        normalized,
        NormalizedRoot::EnforceableFileSystem { ref normalized_path, .. }
            if normalized_path == "/relative/path"
    ));

    let invalid_utf8_root = RootDefinition {
        uri: "file:///workspace/%FF".to_string(),
        name: None,
    };
    assert!(matches!(
        invalid_utf8_root.normalize_for_runtime(),
        NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
            if reason == "invalid_utf8_path"
    ));

    let read = ReadResourceOperation {
        capability: make_token(&Keypair::generate()),
        uri: "file:///workspace/project/docs/../docs/spec.md".to_string(),
    };
    let classified = read.classify_uri_for_runtime();
    assert!(classified.is_enforceable_filesystem());
    assert_eq!(
        classified.normalized_filesystem_path(),
        Some("/workspace/project/docs/spec.md")
    );

    assert_eq!(
        normalize_absolute_filesystem_path("/workspace/project/../docs"),
        Some("/workspace/docs".to_string())
    );
    assert_eq!(
        normalize_absolute_filesystem_path("C:\\Workspace\\Chio\\..\\project"),
        Some("C:/Workspace/project".to_string())
    );
    assert_eq!(normalize_absolute_filesystem_path("relative/path"), None);
    assert_eq!(
        split_windows_drive("c:/Workspace/project"),
        Some(('C', "Workspace/project"))
    );
    assert_eq!(split_windows_drive("D:"), Some(('D', "")));
    assert_eq!(split_windows_drive("1:/not-a-drive"), None);
    assert_eq!(
        extract_uri_scheme("repo+docs://roadmap"),
        Some("repo+docs".to_string())
    );
    assert_eq!(extract_uri_scheme("1repo://roadmap"), None);
    assert_eq!(extract_uri_scheme("repo^docs://roadmap"), None);
}

#[test]
fn marks_non_local_file_roots_as_unenforceable() {
    let root = RootDefinition {
        uri: "file://remote-host/workspace/project".to_string(),
        name: None,
    };

    let normalized = root.normalize_for_runtime();
    assert!(matches!(
        normalized,
        NormalizedRoot::UnenforceableFileSystem { ref reason, .. }
            if reason == "non_local_file_authority"
    ));
    assert_eq!(normalized.normalized_filesystem_path(), None);
}

#[test]
fn classifies_filesystem_resource_uris_for_runtime() {
    let classified =
        ResourceUriClassification::from_uri("file:///workspace/project/docs/../docs/roadmap.md");

    assert!(classified.is_enforceable_filesystem());
    assert_eq!(
        classified.normalized_filesystem_path(),
        Some("/workspace/project/docs/roadmap.md")
    );
}

#[test]
fn classifies_non_filesystem_resource_uris_without_forcing_root_checks() {
    let classified = ResourceUriClassification::from_uri("repo://docs/roadmap");

    assert!(matches!(
        classified,
        ResourceUriClassification::NonFileSystem { ref scheme, .. } if scheme == "repo"
    ));
    assert_eq!(classified.normalized_filesystem_path(), None);
}

#[test]
fn marks_unenforceable_filesystem_resource_uris_as_fail_closed() {
    let classified = ResourceUriClassification::from_uri("file://remote-host/workspace/ops");

    assert!(matches!(
        classified,
        ResourceUriClassification::UnenforceableFileSystem { ref reason, .. }
            if reason == "non_local_file_authority"
    ));
    assert_eq!(classified.normalized_filesystem_path(), None);
}

#[test]
fn create_message_operation_roundtrip() {
    let operation = CreateMessageOperation {
        messages: vec![SamplingMessage {
            role: "user".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "Summarize this change"
            }),
            meta: Some(serde_json::json!({ "source": "tool-call" })),
        }],
        model_preferences: Some(serde_json::json!({
            "speedPriority": 0.8
        })),
        system_prompt: Some("You are careful.".to_string()),
        include_context: Some("none".to_string()),
        temperature: Some(0.2),
        max_tokens: 512,
        stop_sequences: vec!["END".to_string()],
        metadata: Some(serde_json::json!({ "trace": "abc123" })),
        tools: vec![SamplingTool {
            name: "search_docs".to_string(),
            description: Some("Search docs".to_string()),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" }
                },
                "required": ["query"]
            }),
        }],
        tool_choice: Some(SamplingToolChoice {
            mode: "auto".to_string(),
        }),
    };

    let encoded = serde_json::to_string(&operation).unwrap();
    let decoded: CreateMessageOperation = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, operation);
}

#[test]
fn create_elicitation_operation_roundtrip() {
    let operation = CreateElicitationOperation::Form {
        meta: Some(serde_json::json!({ "trace": "abc123" })),
        message: "Please confirm the deploy target".to_string(),
        requested_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "environment": {
                    "type": "string",
                    "enum": ["staging", "production"]
                }
            },
            "required": ["environment"]
        }),
    };

    let encoded = serde_json::to_string(&operation).unwrap();
    let decoded: CreateElicitationOperation = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, operation);
}

#[test]
fn create_elicitation_result_roundtrip() {
    let result = CreateElicitationResult {
        action: ElicitationAction::Accept,
        content: Some(serde_json::json!({
            "environment": "staging"
        })),
    };

    let encoded = serde_json::to_string(&result).unwrap();
    let decoded: CreateElicitationResult = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, result);
}

#[test]
fn prompt_result_roundtrip() {
    let prompt = PromptResult {
        description: Some("Example prompt".to_string()),
        messages: vec![PromptMessage {
            role: "user".to_string(),
            content: serde_json::json!({
                "type": "text",
                "text": "hello"
            }),
        }],
    };

    let encoded = serde_json::to_string(&prompt).unwrap();
    let decoded: PromptResult = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, prompt);
}

#[test]
fn completion_result_roundtrip() {
    let completion = CompletionResult {
        values: vec!["python".to_string(), "pytorch".to_string()],
        total: Some(10),
        has_more: true,
    };

    let encoded = serde_json::to_string(&completion).unwrap();
    let decoded: CompletionResult = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, completion);
}

#[test]
fn session_auth_context_roundtrip_and_principal_helpers() {
    let auth = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("http://localhost:3000".to_string()),
    );

    assert!(auth.is_authenticated());
    assert_eq!(auth.principal(), Some("static-bearer:abcd1234"));

    let encoded = serde_json::to_string(&auth).unwrap();
    let decoded: SessionAuthContext = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, auth);
}

#[test]
fn anonymous_session_auth_context_has_no_principal() {
    let auth = SessionAuthContext::stdio_anonymous();
    assert!(!auth.is_authenticated());
    assert_eq!(auth.principal(), None);
}

#[test]
fn session_auth_context_helpers_cover_in_process_and_oauth_without_principal() {
    let in_process = SessionAuthContext::in_process_anonymous();
    assert_eq!(in_process.transport, SessionTransport::InProcess);
    assert!(!in_process.is_authenticated());
    assert_eq!(in_process.principal(), None);

    let oauth = SessionAuthContext::streamable_http_oauth_bearer(
        None,
        Some("https://issuer.example".to_string()),
        Some("user-123".to_string()),
        Some("chio-mcp".to_string()),
        vec!["mcp:invoke".to_string()],
        Some("cafebabe".to_string()),
        Some("https://app.example".to_string()),
    );
    assert!(oauth.is_authenticated());
    assert_eq!(oauth.principal(), None);
}

#[test]
fn oauth_session_auth_context_roundtrips_with_federated_claims() {
    let auth =
        SessionAuthContext::streamable_http_oauth_bearer_with_claims(OAuthBearerSessionAuthInput {
            principal: Some("oidc:https://issuer.example#sub:user-123".to_string()),
            issuer: Some("https://issuer.example".to_string()),
            subject: Some("user-123".to_string()),
            audience: Some("chio-mcp".to_string()),
            scopes: vec!["mcp:invoke".to_string()],
            federated_claims: OAuthBearerFederatedClaims {
                client_id: Some("client-abc".to_string()),
                object_id: Some("object-123".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-789".to_string()),
                groups: vec!["eng".to_string(), "ops".to_string()],
                roles: vec!["operator".to_string()],
            },
            enterprise_identity: Some(EnterpriseIdentityContext {
                provider_id: "provider-1".to_string(),
                provider_record_id: Some("provider-1".to_string()),
                provider_kind: "oidc_jwks".to_string(),
                federation_method: EnterpriseFederationMethod::Jwt,
                principal: "oidc:https://issuer.example#sub:user-123".to_string(),
                subject_key: "subject-key-123".to_string(),
                client_id: Some("client-abc".to_string()),
                object_id: Some("object-123".to_string()),
                tenant_id: Some("tenant-123".to_string()),
                organization_id: Some("org-789".to_string()),
                groups: vec!["eng".to_string(), "ops".to_string()],
                roles: vec!["operator".to_string()],
                source_subject: Some("user-123".to_string()),
                attribute_sources: BTreeMap::from([
                    ("principal".to_string(), "sub".to_string()),
                    ("groups".to_string(), "groups".to_string()),
                ]),
                trust_material_ref: Some("jwks:primary".to_string()),
            }),
            token_fingerprint: Some("cafebabe".to_string()),
            origin: Some("http://localhost:3000".to_string()),
        });

    assert!(auth.is_authenticated());
    assert_eq!(
        auth.principal(),
        Some("oidc:https://issuer.example#sub:user-123")
    );

    let encoded = serde_json::to_string(&auth).unwrap();
    let decoded: SessionAuthContext = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, auth);
}

#[test]
fn session_anchor_signing_binds_auth_context_and_reference() {
    let kp = Keypair::generate();
    let auth = SessionAuthContext::streamable_http_static_bearer(
        "static-bearer:abcd1234",
        "cafebabe",
        Some("https://app.example".to_string()),
    );
    let proof_binding = SessionProofBinding {
        token_fingerprint: Some("cafebabe".to_string()),
        dpop_public_key_thumbprint: Some("dpop-thumbprint".to_string()),
        mtls_thumbprint_sha256: None,
        runtime_attestation_sha256: None,
    };

    let body = SessionAnchorBody::new(
        "anchor-1",
        SessionAnchorContext::new(
            SessionId::new("sess-001"),
            "agent-123".to_string(),
            auth.clone(),
            Some(proof_binding.clone()),
        ),
        4,
        1_710_000_000,
        kp.public_key(),
    )
    .unwrap();
    let anchor = SessionAnchor::sign(body, &kp).unwrap();
    let reference = anchor.reference().unwrap();

    assert!(anchor.verify_signature().unwrap());
    assert!(anchor.matches_context(&auth, Some(&proof_binding)).unwrap());
    assert_eq!(reference.session_anchor_id, "anchor-1");
    assert!(!reference.session_anchor_hash.is_empty());
    assert_eq!(anchor.auth_context_hash, auth.canonical_hash().unwrap());
    assert_eq!(anchor.auth_method_hash, auth.auth_method_hash().unwrap());
}

#[test]
fn session_anchor_detects_material_auth_context_drift() {
    let kp = Keypair::generate();
    let auth = SessionAuthContext::streamable_http_oauth_bearer(
        Some("oidc:https://issuer.example#sub:user-123".to_string()),
        Some("https://issuer.example".to_string()),
        Some("user-123".to_string()),
        Some("chio-mcp".to_string()),
        vec!["mcp:invoke".to_string()],
        Some("cafebabe".to_string()),
        Some("https://app.example".to_string()),
    );
    let body = SessionAnchorBody::new(
        "anchor-2",
        SessionAnchorContext::new(
            SessionId::new("sess-002"),
            "agent-456".to_string(),
            auth.clone(),
            SessionProofBinding::from_auth_context(&auth),
        ),
        1,
        1_710_000_010,
        kp.public_key(),
    )
    .unwrap();
    let anchor = SessionAnchor::sign(body, &kp).unwrap();
    let changed_auth = SessionAuthContext::streamable_http_oauth_bearer(
        Some("oidc:https://issuer.example#sub:user-123".to_string()),
        Some("https://issuer.example".to_string()),
        Some("user-123".to_string()),
        Some("chio-mcp".to_string()),
        vec!["mcp:invoke".to_string(), "mcp:admin".to_string()],
        Some("cafebabe".to_string()),
        Some("https://app.example".to_string()),
    );
    let changed_binding = SessionProofBinding::from_auth_context(&changed_auth);

    assert!(!anchor
        .matches_context(&changed_auth, changed_binding.as_ref())
        .unwrap());
}

#[test]
fn request_lineage_record_tracks_continuation_and_capability_binding() {
    let record = RequestLineageRecord::new(
        RequestId::new("req-child-1"),
        SessionAnchorReference::new("anchor-1", "anchor-hash-1"),
        OperationKind::ToolCall,
        RequestLineageMode::Continued,
        1_710_000_020,
    )
    .with_parent_request_id(RequestId::new("req-parent-1"))
    .with_capability_attribution("cap-1", "subject-key-1", "issuer-key-1")
    .with_intent_hash("intent-hash-1")
    .with_continuation_token_id("continuation-1");

    let encoded = serde_json::to_string(&record).unwrap();
    let decoded: RequestLineageRecord = serde_json::from_str(&encoded).unwrap();

    assert!(decoded.is_continued());
    assert!(!decoded.is_root());
    assert_eq!(decoded.evidence_class, ProvenanceEvidenceClass::Verified);
    assert_eq!(
        decoded.parent_request_id,
        Some(RequestId::new("req-parent-1"))
    );
    assert_eq!(decoded.capability_id.as_deref(), Some("cap-1"));
    assert_eq!(
        decoded.continuation_token_id.as_deref(),
        Some("continuation-1")
    );
    assert!(decoded.validate_schema().is_ok());
}

#[test]
fn request_lineage_record_rejects_unknown_schema() {
    let mut record = RequestLineageRecord::new(
        RequestId::new("req-schema"),
        SessionAnchorReference::new("anchor-1", "anchor-hash-1"),
        OperationKind::ToolCall,
        RequestLineageMode::LocalChild,
        1_710_000_030,
    );
    record.schema = "chio.request_lineage_record.v999".to_string();

    assert!(record.validate_schema().is_err());
}

#[test]
fn ownership_snapshots_roundtrip_with_expected_defaults() {
    let request = RequestOwnershipSnapshot::request_owned();
    let task = TaskOwnershipSnapshot::task_owned();

    let request_encoded = serde_json::to_string(&request).unwrap();
    let task_encoded = serde_json::to_string(&task).unwrap();

    let request_decoded: RequestOwnershipSnapshot = serde_json::from_str(&request_encoded).unwrap();
    let task_decoded: TaskOwnershipSnapshot = serde_json::from_str(&task_encoded).unwrap();

    assert_eq!(request_decoded, request);
    assert_eq!(task_decoded, task);
    assert_eq!(request_decoded.work_owner, WorkOwner::Request);
    assert_eq!(
        request_decoded.result_stream_owner,
        StreamOwner::RequestStream
    );
    assert_eq!(request_decoded.terminal_state_owner, WorkOwner::Request);
    assert_eq!(task_decoded.work_owner, WorkOwner::Task);
    assert_eq!(task_decoded.result_stream_owner, StreamOwner::RequestStream);
    assert_eq!(
        task_decoded.status_notification_owner,
        StreamOwner::SessionNotificationStream
    );
    assert_eq!(task_decoded.terminal_state_owner, WorkOwner::Task);
}

#[test]
fn operation_terminal_state_and_kind_helpers_cover_all_variants() {
    let completed = OperationTerminalState::Completed;
    let cancelled = OperationTerminalState::Cancelled {
        reason: "operator_cancelled".to_string(),
    };
    let incomplete = OperationTerminalState::Incomplete {
        reason: "stream_closed".to_string(),
    };
    assert!(completed.is_completed());
    assert!(!completed.is_cancelled());
    assert!(cancelled.is_cancelled());
    assert!(!cancelled.is_incomplete());
    assert!(incomplete.is_incomplete());

    assert_eq!(OperationKind::ToolCall.as_str(), "tool_call");
    assert_eq!(OperationKind::ReadResource.as_str(), "read_resource");
    assert_eq!(
        OperationKind::ListResourceTemplates.as_str(),
        "list_resource_templates"
    );
    assert_eq!(OperationKind::ListPrompts.as_str(), "list_prompts");
    assert_eq!(OperationKind::GetPrompt.as_str(), "get_prompt");
    assert_eq!(OperationKind::Complete.as_str(), "complete");
}

#[test]
fn chio_identity_assertion_roundtrips_and_validates() {
    let assertion = ChioIdentityAssertion {
        verifier_id: "https://verifier.example.com".to_string(),
        subject: "alice@example.com".to_string(),
        continuity_id: "session-123".to_string(),
        issued_at: 100,
        expires_at: 200,
        provider: Some("oidc".to_string()),
        session_hint: Some("resume".to_string()),
        bound_request_id: Some("req-123".to_string()),
    };

    assertion.validate_at(150).unwrap();

    let encoded = serde_json::to_string(&assertion).unwrap();
    let decoded: ChioIdentityAssertion = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, assertion);
}

#[test]
fn chio_identity_assertion_rejects_stale_or_empty_fields() {
    let stale = ChioIdentityAssertion {
        verifier_id: "https://verifier.example.com".to_string(),
        subject: "alice@example.com".to_string(),
        continuity_id: "session-123".to_string(),
        issued_at: 100,
        expires_at: 110,
        provider: None,
        session_hint: None,
        bound_request_id: None,
    };
    assert!(stale.validate_at(111).unwrap_err().contains("stale"));
    assert!(stale.validate_at(110).unwrap_err().contains("stale"));

    let empty = ChioIdentityAssertion {
        verifier_id: "https://verifier.example.com".to_string(),
        subject: "".to_string(),
        continuity_id: "session-123".to_string(),
        issued_at: 100,
        expires_at: 110,
        provider: None,
        session_hint: None,
        bound_request_id: None,
    };
    assert!(empty
        .validate()
        .unwrap_err()
        .contains("identityAssertion.subject"));
}

#[test]
fn chio_identity_assertion_rejects_remaining_invalid_fields() {
    let mut assertion = ChioIdentityAssertion {
        verifier_id: "https://verifier.example.com".to_string(),
        subject: "alice@example.com".to_string(),
        continuity_id: "session-123".to_string(),
        issued_at: 200,
        expires_at: 100,
        provider: Some("oidc".to_string()),
        session_hint: Some("resume".to_string()),
        bound_request_id: Some("req-123".to_string()),
    };
    assert!(assertion.validate().unwrap_err().contains("issuedAt"));

    assertion = ChioIdentityAssertion {
        verifier_id: "".to_string(),
        subject: "alice@example.com".to_string(),
        continuity_id: "session-123".to_string(),
        issued_at: 100,
        expires_at: 200,
        provider: None,
        session_hint: None,
        bound_request_id: None,
    };
    assert!(assertion.validate().unwrap_err().contains("verifierId"));

    assertion = ChioIdentityAssertion {
        verifier_id: "https://verifier.example.com".to_string(),
        subject: "alice@example.com".to_string(),
        continuity_id: "".to_string(),
        issued_at: 100,
        expires_at: 200,
        provider: None,
        session_hint: None,
        bound_request_id: None,
    };
    assert!(assertion.validate().unwrap_err().contains("continuityId"));

    let mut assertion = ChioIdentityAssertion {
        verifier_id: "https://verifier.example.com".to_string(),
        subject: "alice@example.com".to_string(),
        continuity_id: "session-123".to_string(),
        issued_at: 100,
        expires_at: 200,
        provider: Some(" ".to_string()),
        session_hint: Some("resume".to_string()),
        bound_request_id: Some("req-123".to_string()),
    };
    assert!(assertion.validate().unwrap_err().contains("provider"));
    assertion.provider = Some("oidc".to_string());
    assertion.session_hint = Some(" ".to_string());
    assert!(assertion.validate().unwrap_err().contains("sessionHint"));
    assertion.session_hint = Some("resume".to_string());
    assertion.bound_request_id = Some(" ".to_string());
    assert!(assertion.validate().unwrap_err().contains("boundRequestId"));
}
