use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use chio_test_support::prelude::*;
use serde_json::{json, Value};

use chio_agent_web_interop::{verify_agent_web_interop, AgentWebInteropBundle};
use chio_core_types::{
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    },
    Keypair,
};
use chio_transaction_passport::TransactionPassport;

const CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND: &str = "claim.agent_web.external_subject_digest_bound";
const CLAIM_PROJECTION_MANIFEST_BOUND: &str = "claim.agent_web.projection_manifest_bound";
const CLAIM_UNSUPPORTED_CLAIMS_LIMITED: &str = "claim.agent_web.unsupported_claims_limited";
const CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY: &str = "claim.agent_web.sidecar_not_native_authority";
const UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM: &str =
    "claim.external.webhook_signature_is_chio_authority";
const UNSUPPORTED_CLOUDEVENTS_AUTHORITY_CLAIM: &str =
    "claim.external.cloudevents_event_is_chio_authority";
const UNSUPPORTED_GRAPHQL_SUBSCRIPTION_CLAIM: &str =
    "claim.external.graphql_http_subscription_coverage";
const UNSUPPORTED_GRAPHQL_AUTHORITY_CLAIM: &str =
    "claim.external.graphql_http_operation_is_chio_authority";
const UNSUPPORTED_MCP_AUTHORITY_CLAIM: &str = "claim.external.mcp_tool_call_is_chio_authority";
const UNSUPPORTED_A2A_AUTHORITY_CLAIM: &str = "claim.external.a2a_task_is_chio_authority";
const UNSUPPORTED_ACP_CLIENT_AUTHORITY_CLAIM: &str =
    "claim.external.acp_client_permission_is_chio_authority";
const UNSUPPORTED_ACP_COMMERCE_AUTHORITY_CLAIM: &str =
    "claim.external.acp_commerce_payment_is_chio_authority";
const UNSUPPORTED_AG_UI_AUTHORITY_CLAIM: &str = "claim.external.ag_ui_event_is_chio_authority";
const UNSUPPORTED_BROWSER_AUTHORITY_CLAIM: &str =
    "claim.external.browser_automation_is_chio_authority";
const UNSUPPORTED_RPA_AUTHORITY_CLAIM: &str = "claim.external.rpa_transcript_is_chio_authority";
const UNSUPPORTED_EMAIL_AUTHORITY_CLAIM: &str = "claim.external.email_action_is_chio_authority";
const UNSUPPORTED_CALENDAR_AUTHORITY_CLAIM: &str =
    "claim.external.calendar_action_is_chio_authority";
const UNSUPPORTED_SLACK_AUTHORITY_CLAIM: &str = "claim.external.slack_action_is_chio_authority";
const UNSUPPORTED_OAUTH2_AUTHORITY_CLAIM: &str = "claim.external.oauth2_token_is_chio_authority";
const UNSUPPORTED_OPENID_CONNECT_AUTHORITY_CLAIM: &str =
    "claim.external.openid_connect_identity_is_chio_authority";
const UNSUPPORTED_SCIM_AUTHORITY_CLAIM: &str = "claim.external.scim_lifecycle_is_chio_authority";
const UNSUPPORTED_SPIFFE_AUTHORITY_CLAIM: &str =
    "claim.external.spiffe_workload_identity_is_chio_authority";
const UNSUPPORTED_KUBERNETES_ADMISSION_AUTHORITY_CLAIM: &str =
    "claim.external.kubernetes_admission_is_chio_authority";
const UNSUPPORTED_OCI_REF_AUTHORITY_CLAIM: &str = "claim.external.oci_ref_is_chio_authority";
const UNSUPPORTED_VC_AUTHORITY_CLAIM: &str = "claim.external.vc_is_chio_authority";
const UNSUPPORTED_SD_JWT_VC_AUTHORITY_CLAIM: &str = "claim.external.sd_jwt_vc_is_chio_authority";
const UNSUPPORTED_SIGSTORE_AUTHORITY_CLAIM: &str =
    "claim.external.sigstore_bundle_is_chio_authority";
const UNSUPPORTED_IN_TOTO_AUTHORITY_CLAIM: &str =
    "claim.external.in_toto_statement_is_chio_authority";
const UNSUPPORTED_DSSE_AUTHORITY_CLAIM: &str = "claim.external.dsse_envelope_is_chio_authority";
const UNSUPPORTED_SLSA_AUTHORITY_CLAIM: &str = "claim.external.slsa_provenance_is_chio_authority";
const UNSUPPORTED_BBS_AUTHORITY_CLAIM: &str = "claim.external.bbs_proof_is_chio_authority";
const UNSUPPORTED_VC_DI_BBS_INTEROP_CLAIM: &str = "claim.external.vc_di_bbs_interop_verified";
const UNSUPPORTED_OPENAPI_AUTHORITY_CLAIM: &str =
    "claim.external.openapi_operation_is_chio_authority";
const UNSUPPORTED_ASYNCAPI_AUTHORITY_CLAIM: &str =
    "claim.external.asyncapi_message_is_chio_authority";
const UNSUPPORTED_AP2_AUTHORITY_CLAIM: &str = "claim.external.ap2_mandate_is_chio_authority";
const UNSUPPORTED_X402_AUTHORITY_CLAIM: &str = "claim.external.x402_payment_is_chio_authority";

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|platform_dir| platform_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/platform/chio-agent-web-interop")
        .to_path_buf()
}

fn read_workspace_json(relative_path: &str) -> Value {
    let bytes = std::fs::read(workspace_root().join(relative_path)).test_expect("json file reads");
    serde_json::from_slice(&bytes).test_expect("json file parses")
}

fn assert_schema_accepts_fixture(schema: &Value, relative_path: &str) {
    let value = read_workspace_json(relative_path);
    assert_schema_accepts_value(schema, &value, relative_path);
}

fn assert_schema_accepts_value(schema: &Value, value: &Value, label: &str) {
    let validator = jsonschema::validator_for(schema).test_expect("schema compiles");
    let errors = validator
        .iter_errors(value)
        .map(|error| error.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        errors.is_empty(),
        "schema rejected Agent Web artifact {label}:\n{errors}"
    );
}

fn agent_web_envelope_or_manifest_paths(relative_dir: &str) -> Vec<String> {
    let fixture_dir = workspace_root().join(relative_dir);
    let mut artifacts = std::fs::read_dir(&fixture_dir)
        .test_expect("Agent Web fixture directory reads")
        .map(|entry| {
            entry
                .test_expect("Agent Web fixture entry reads")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|file_name| {
            file_name.ends_with("-envelope.json") || file_name.ends_with("-manifest.json")
        })
        .map(|file_name| {
            Path::new(relative_dir)
                .join(file_name)
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    artifacts.sort();
    artifacts
}

#[derive(Debug, Clone, Copy)]
enum AgentWebCase {
    Valid,
    ExternalDigestMismatch,
    UnsupportedClaimNotLimited,
    RequiredExternalAuthorityClaim,
    SidecarClaimMarkedNative,
    MissingRequiredSignature,
    MalformedWebhookSignature,
    MissingWebhookTimestamp,
    CloudEventsAuthorityClaimNotLimited,
    CloudEventsSpecVersionMismatch,
    GraphqlHttpDraftVersionMissing,
    GraphqlErrorsProjectedAsSuccess,
    ExternalSubjectSchemaMismatch,
    McpAuthorityClaimNotLimited,
    A2aAuthorityClaimNotLimited,
    MissingReceiptRef,
    BoundReceiptDenied,
    BoundReceiptUnsigned,
    BoundReceiptPolicyHashMismatch,
    MissingRequiredSidecarClaim,
    MissingManifestEdge,
    MissingExternalSubjectEdge,
    MissingReceiptEdge,
    UnboundRiskRef,
    RequiredSignatureAlgorithmNone,
    UnusedSignatureAlgorithmPresent,
    OpenApiProjection,
    OpenApiUnsupportedVersion,
    OpenApiReceiptRefMismatch,
    AcpClientProjection,
    AcpCommerceProjection,
    AcpCommerceOrderContextDigestMismatch,
    AcpCommerceReceiptRefMismatch,
    AgUiProjection,
    BrowserAutomationProjection,
    RpaProjection,
    EmailProjection,
    EmailMissingMessageDigest,
    CalendarProjection,
    CalendarTimeRangeMismatch,
    SlackProjection,
    SlackOkFalse,
    OAuth2Projection,
    OAuth2WrongObjectKind,
    OAuth2ReceiptRefMismatch,
    OpenIdConnectProjection,
    OpenIdConnectWrongObjectKind,
    OpenIdConnectReceiptRefMismatch,
    ScimProjection,
    ScimActiveLifecycleMissingReceiptRef,
    SpiffeProjection,
    SpiffeReceiptRefMissing,
    SpiffeTrustDomainContainsPath,
    KubernetesAdmissionProjection,
    KubernetesAdmissionUidMismatch,
    OciRefProjection,
    OciTagOnly,
    VcProjection,
    VcReceiptRefMissing,
    SdJwtVcProjection,
    SdJwtVcReceiptRefMissing,
    SigstoreProjection,
    SigstoreReceiptRefMissing,
    InTotoProjection,
    InTotoReceiptRefMissing,
    DsseProjection,
    SlsaProjection,
    SlsaUnverified,
    BbsProjection,
    BbsReceiptRefMissing,
    AsyncApiProjection,
    AsyncApiUnsupportedVersion,
    AsyncApiReceiptRefMismatch,
    Ap2Projection,
    Ap2TransactionContextDigestMismatch,
    Ap2DetachedOrder,
    Ap2ReceiptRefMismatch,
    X402Projection,
    X402AmountMismatch,
    X402DetachedOrder,
    X402ReceiptRefMismatch,
}

fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).test_expect("test json serializes")
}

fn push_artifact(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut Vec<Value>,
    graph_role: &str,
    node_id: &str,
    schema: &str,
    path: &str,
    bytes: Vec<u8>,
) {
    let sha256 = chio_core_types::sha256_hex(&bytes);
    graph_nodes.push(json!({
        "id": node_id,
        "schema": schema,
        "path": path,
        "sha256": sha256,
        "role": graph_role
    }));
    artifacts.insert(path.to_string(), bytes);
}

fn sign_agent_web_receipts(
    case: AgentWebCase,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut [Value],
    policy_hash: &str,
) {
    for node in graph_nodes {
        if node.get("role").and_then(Value::as_str) != Some("receipt") {
            continue;
        }
        let Some(receipt_id) = node.get("id").and_then(Value::as_str) else {
            continue;
        };
        if matches!(case, AgentWebCase::BoundReceiptUnsigned)
            && receipt_id == "receipt-agent-web-webhook-allow"
        {
            continue;
        }
        let Some(path) = node.get("path").and_then(Value::as_str) else {
            continue;
        };
        let Some(subject_path) = agent_web_receipt_subject_path(receipt_id) else {
            continue;
        };
        let subject_bytes = artifacts
            .get(subject_path)
            .test_expect("Agent Web receipt subject artifact exists");
        let current_receipt: Value = serde_json::from_slice(
            artifacts
                .get(path)
                .test_expect("Agent Web receipt artifact exists"),
        )
        .test_expect("Agent Web receipt placeholder parses");
        let terminal_status = current_receipt
            .get("terminal_status")
            .and_then(Value::as_str)
            .test_expect("Agent Web receipt placeholder has terminal status");
        let receipt_policy_hash = if matches!(case, AgentWebCase::BoundReceiptPolicyHashMismatch)
            && receipt_id == "receipt-agent-web-webhook-allow"
        {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            policy_hash
        };
        let receipt_bytes = signed_agent_web_receipt_bytes(
            receipt_id,
            &chio_core_types::sha256_hex(subject_bytes),
            receipt_policy_hash,
            terminal_status == "allowed_executed",
        );
        let sha256 = chio_core_types::sha256_hex(&receipt_bytes);
        artifacts.insert(path.to_string(), receipt_bytes);
        node["sha256"] = Value::String(sha256);
    }
}

fn agent_web_receipt_subject_path(receipt_id: &str) -> Option<&'static str> {
    Some(match receipt_id {
        "receipt-agent-web-webhook-allow" => "external/webhook-delivery.json",
        "receipt-agent-web-cloudevents-allow" => "external/cloudevent.json",
        "receipt-agent-web-graphql-mutation-allow" => "external/graphql-operation.json",
        "receipt-agent-web-mcp-tool-call-allow" => "external/mcp-tool-call.json",
        "receipt-agent-web-a2a-task-allow" => "external/a2a-task.json",
        "receipt-agent-web-openapi-operation-allow" => "external/openapi-operation.json",
        "receipt-agent-web-acp-client-permission-allow" => "external/acp-client-permission.json",
        "receipt-agent-web-acp-commerce-checkout-allow" => "external/acp-commerce-checkout.json",
        "receipt-agent-web-ag-ui-event-allow" => "external/ag-ui-event.json",
        "receipt-agent-web-browser-command-allow" => "external/browser-command.json",
        "receipt-agent-web-rpa-transcript-allow" => "external/rpa-transcript.json",
        "receipt-agent-web-email-message-allow" => "external/email-message.json",
        "receipt-agent-web-calendar-event-allow" => "external/calendar-event.json",
        "receipt-agent-web-slack-message-allow" => "external/slack-message.json",
        "receipt-agent-web-oauth2-authorization-allow" => "external/oauth2-authorization.json",
        "receipt-agent-web-openid-connect-identity-allow" => {
            "external/openid-connect-identity.json"
        }
        "receipt-agent-web-scim-lifecycle-allow" => "external/scim-lifecycle.json",
        "receipt-agent-web-spiffe-workload-allow" => "external/spiffe-workload-identity.json",
        "receipt-agent-web-kubernetes-admission-allow" => {
            "external/kubernetes-admission-review.json"
        }
        "receipt-agent-web-oci-ref-allow" => "external/oci-ref.json",
        "receipt-agent-web-vc-allow" => "external/verifiable-credential.json",
        "receipt-agent-web-sd-jwt-vc-presentation-allow" => "external/sd-jwt-vc-presentation.json",
        "receipt-agent-web-bbs-disclosure-allow" => "external/bbs-receipt-disclosure.json",
        "receipt-agent-web-sigstore-bundle-allow" => "external/sigstore-bundle.json",
        "receipt-agent-web-in-toto-statement-allow" => "external/in-toto-statement.json",
        "receipt-agent-web-dsse-envelope-allow" => "external/dsse-envelope.json",
        "receipt-agent-web-slsa-provenance-allow" => "external/slsa-provenance.json",
        "receipt-agent-web-asyncapi-message-allow" => "external/asyncapi-message.json",
        "receipt-agent-web-ap2-mandate-allow" => "external/ap2-mandate-chain.json",
        "receipt-agent-web-x402-payment-allow" => "external/x402-payment.json",
        _ => return None,
    })
}

fn signed_agent_web_receipt_bytes(
    receipt_ref: &str,
    content_hash: &str,
    policy_hash: &str,
    allowed: bool,
) -> Vec<u8> {
    let keypair = Keypair::from_seed(&[17u8; 32]);
    let decision = if allowed {
        Some(Decision::Allow)
    } else {
        Some(Decision::Deny {
            reason: "Agent Web projection denied".to_string(),
            guard: "agent-web-test-guard".to_string(),
        })
    };
    let action = ToolCallAction::from_parameters(json!({
        "agent_web_receipt_ref": receipt_ref,
        "content_hash": content_hash
    }))
    .test_expect("Agent Web receipt action hashes");
    let body = ChioReceiptBody {
        id: receipt_ref.to_string(),
        timestamp: 1_770_508_800,
        capability_id: "cap-agent-web-test".to_string(),
        tool_server: "agent-web-sidecar".to_string(),
        tool_name: "project-external-evidence".to_string(),
        action,
        decision,
        receipt_kind: ReceiptKind::MediatedDecision,
        boundary_class: BoundaryClass::Prevent,
        observation_outcome: None,
        tool_origin: ToolOrigin::CallerExecuted,
        redaction_mode: RedactionMode::Summary,
        actor_chain: Vec::new(),
        content_hash: content_hash.to_string(),
        policy_hash: policy_hash.to_string(),
        evidence: Vec::new(),
        metadata: Some(json!({ "agent_web_receipt_ref": receipt_ref })),
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        bbs_projection_version: None,
        kernel_key: keypair.public_key(),
    };
    let receipt = ChioReceipt::sign(body, &keypair).test_expect("Agent Web receipt signs");
    serde_json::to_vec(&receipt).test_expect("Agent Web receipt serializes")
}

fn agent_web_bundle(case: AgentWebCase) -> AgentWebInteropBundle {
    let passport = TransactionPassport {
        schema: "chio.transaction-passport.v1".to_string(),
        id: "passport-agent-web-valid".to_string(),
        issued_at: "2026-06-10T00:00:00Z".to_string(),
        evidence_graph_sha256: String::new(),
        evidence_graph_path: "evidence-graph.json".to_string(),
        verifier_policy_sha256: String::new(),
        verifier_policy_path: "verifier-policy.json".to_string(),
    };

    let mut artifacts = BTreeMap::new();
    let mut graph_nodes = Vec::new();

    let webhook_timestamp = match case {
        AgentWebCase::MissingWebhookTimestamp => "",
        _ => "1770508800",
    };
    let webhook_signature = match case {
        AgentWebCase::MalformedWebhookSignature => "standard-webhooks-signature",
        _ => "v1,standard-webhooks-signature",
    };
    let webhook_delivery = json_bytes(json!({
        "object_kind": "standard_webhooks_delivery",
        "id": "webhook-delivery-agent-web-valid",
        "webhook_id": "msg_agent_web_001",
        "webhook_timestamp": webhook_timestamp,
        "webhook_signature": webhook_signature,
        "event_type": "order.created",
        "tenant_id": "tenant-backbay",
        "endpoint_url_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "method": "POST",
        "body_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "signature_ref": "sig-standard-webhooks-valid"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-subject",
        "webhook-delivery",
        "external.standard-webhooks.delivery.v1",
        "external/webhook-delivery.json",
        webhook_delivery.clone(),
    );

    let cloud_events_specversion = match case {
        AgentWebCase::CloudEventsSpecVersionMismatch => "0.3",
        _ => "1.0",
    };
    let cloudevent = json_bytes(json!({
        "specversion": cloud_events_specversion,
        "id": "event-agent-web-001",
        "source": "urn:chio:test:agent-web",
        "type": "dev.chio.agent.allowed",
        "subject": "order-commerce-001",
        "time": "2026-06-10T00:00:00Z",
        "datacontenttype": "application/json",
        "data_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-subject",
        "cloudevents-event",
        "external.cloudevents.event.v1",
        "external/cloudevent.json",
        cloudevent.clone(),
    );

    let mut graphql_operation_value = json!({
        "object_kind": "graphql_http_operation",
        "id": "graphql-operation-agent-web-valid",
        "endpoint_url_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "method": "POST",
        "media_type": "application/json",
        "schema_digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "operation_type": "mutation",
        "operation_name": "CreateAgentOrder",
        "document_digest": "abababababababababababababababababababababababababababababababab",
        "variables_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "response_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "status_code": 200
    });
    if matches!(case, AgentWebCase::GraphqlErrorsProjectedAsSuccess) {
        graphql_operation_value["response_has_errors"] = serde_json::Value::Bool(true);
        graphql_operation_value["response_error_digest"] = serde_json::Value::String(
            "4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e".to_string(),
        );
    }
    let graphql_operation = json_bytes(graphql_operation_value);
    let graphql_graph_schema = match case {
        AgentWebCase::ExternalSubjectSchemaMismatch => "external.mcp.tool-call.v1",
        _ => "external.graphql-http.operation.v1",
    };
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-subject",
        "graphql-operation",
        graphql_graph_schema,
        "external/graphql-operation.json",
        graphql_operation.clone(),
    );

    let mcp_tool_call = json_bytes(json!({
        "object_kind": "mcp_tool_call",
        "id": "mcp-tool-call-agent-web-valid",
        "protocol_version": "2025-11-25",
        "transport": "streamable-http",
        "server_identity_digest": "1212121212121212121212121212121212121212121212121212121212121212",
        "session_id_digest": "3434343434343434343434343434343434343434343434343434343434343434",
        "tool_name": "create_order",
        "arguments_digest": "5656565656565656565656565656565656565656565656565656565656565656",
        "result_digest": "7878787878787878787878787878787878787878787878787878787878787878",
        "authorization_context_digest": "9090909090909090909090909090909090909090909090909090909090909090"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-subject",
        "mcp-tool-call",
        "external.mcp.tool-call.v1",
        "external/mcp-tool-call.json",
        mcp_tool_call.clone(),
    );

    let a2a_task = json_bytes(json!({
        "object_kind": "a2a_task",
        "id": "a2a-task-agent-web-valid",
        "protocol_version": "0.3.0",
        "task_id": "task-a2a-agent-web-001",
        "message_id": "message-a2a-agent-web-001",
        "agent_card_digest": "1313131313131313131313131313131313131313131313131313131313131313",
        "task_input_digest": "2424242424242424242424242424242424242424242424242424242424242424",
        "task_state": "completed",
        "task_state_digest": "3535353535353535353535353535353535353535353535353535353535353535",
        "result_digest": "4646464646464646464646464646464646464646464646464646464646464646",
        "authorization_context_digest": "5757575757575757575757575757575757575757575757575757575757575757"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-subject",
        "a2a-task",
        "external.a2a.task.v1",
        "external/a2a-task.json",
        a2a_task.clone(),
    );

    let openapi_receipt_ref = match case {
        AgentWebCase::OpenApiReceiptRefMismatch => "receipt-agent-web-openapi-other-allow",
        _ => "receipt-agent-web-openapi-operation-allow",
    };
    let openapi_operation = json_bytes(json!({
        "object_kind": "openapi_operation",
        "id": "openapi-operation-agent-web-valid",
        "spec_digest": "6868686868686868686868686868686868686868686868686868686868686868",
        "operation_id": "createAgentOrder",
        "method": "POST",
        "path_template": "/orders",
        "request_digest": "7979797979797979797979797979797979797979797979797979797979797979",
        "response_digest": "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
        "status_code": 201,
        "authorization_context_digest": "9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b",
        "chio_operation_receipt_ref": openapi_receipt_ref
    }));
    if matches!(
        case,
        AgentWebCase::OpenApiProjection
            | AgentWebCase::OpenApiUnsupportedVersion
            | AgentWebCase::OpenApiReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "openapi-operation",
            "external.openapi.operation.v1",
            "external/openapi-operation.json",
            openapi_operation.clone(),
        );
    }

    let acp_client_permission = json_bytes(json!({
        "object_kind": "acp_client_permission_request",
        "id": "acp-client-permission-agent-web-valid",
        "protocol_version": "v1",
        "capability_id": "write_file",
        "category": "filesystem",
        "requires_permission": true,
        "permission_decision": "allow",
        "bridge_fidelity": "lossless",
        "source_envelope_digest": "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac",
        "arguments_digest": "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc",
        "client_session_digest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "agent_id_digest": "dededededededededededededededededededededededededededededededede",
        "authorization_context_digest": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
    }));
    if matches!(case, AgentWebCase::AcpClientProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "acp-client-permission",
            "external.acp-client.permission.v1",
            "external/acp-client-permission.json",
            acp_client_permission.clone(),
        );
    }

    let order_context = json_bytes(json!({
        "schema": "chio.commerce.order-context.v1",
        "id": "order-context-commerce-001",
        "issued_at": "2026-06-10T00:00:00Z",
        "order_id": "order-commerce-001",
        "buyer_subject": "did:chio:buyer-acme",
        "agent_subject": "did:chio:agent-shopping",
        "merchant_subject": "did:chio:merchant-store",
        "quote_id": "quote-commerce-001",
        "quote_amount_minor": 1250,
        "quote_currency": "USD",
        "event_log_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "event_log_path": "commerce/event-log.json",
        "payment_lifecycle_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "payment_lifecycle_path": "commerce/payment-lifecycle.json",
        "mandate_ledger_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
        "mandate_ledger_path": "commerce/mandate-allowance-ledger.json",
        "current_state": "settled"
    }));
    let acp_commerce_order_context_digest =
        if matches!(case, AgentWebCase::AcpCommerceOrderContextDigestMismatch) {
            "cacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacaca".to_string()
        } else {
            chio_core_types::sha256_hex(&order_context)
        };

    let acp_commerce_receipt_ref = match case {
        AgentWebCase::AcpCommerceReceiptRefMismatch => "receipt-agent-web-acp-commerce-other-allow",
        _ => "receipt-agent-web-acp-commerce-checkout-allow",
    };

    let acp_commerce_checkout = json_bytes(json!({
        "object_kind": "acp_commerce_checkout",
        "id": "acp-commerce-checkout-agent-web-valid",
        "transaction_passport_ref": passport.id,
        "order_id": "order-commerce-001",
        "delegated_payment_token_digest": "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
        "checkout_context_digest": "b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9",
        "order_context_digest": acp_commerce_order_context_digest,
        "payment_instruction_digest": "dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb",
        "merchant_identity_digest": "ecececececececececececececececececececececececececececececececec",
        "buyer_identity_digest": "fdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfd",
        "amount_units": 1250,
        "currency": "USD",
        "status": "authorized",
        "chio_checkout_receipt_ref": acp_commerce_receipt_ref
    }));

    let ag_ui_event = json_bytes(json!({
        "object_kind": "ag_ui_event",
        "id": "ag-ui-event-agent-web-valid",
        "protocol_version": "events-v1",
        "event_id": "evt-agent-web-checkout-001",
        "agent_id_digest": "1111111111111111111111111111111111111111111111111111111111111111",
        "session_id_digest": "2222222222222222222222222222222222222222222222222222222222222222",
        "capability_id": "ui.checkout.submit",
        "event_type": "state_update",
        "target_component_type": "checkout-panel",
        "target_component_id_digest": "3333333333333333333333333333333333333333333333333333333333333333",
        "classification": "mutate",
        "transport": "websocket",
        "allowed": true,
        "payload_digest": "4444444444444444444444444444444444444444444444444444444444444444",
        "receipt_digest": "5555555555555555555555555555555555555555555555555555555555555555",
        "authorization_context_digest": "6666666666666666666666666666666666666666666666666666666666666666"
    }));
    if matches!(case, AgentWebCase::AgUiProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "ag-ui-event",
            "external.ag-ui.event.v1",
            "external/ag-ui-event.json",
            ag_ui_event.clone(),
        );
    }

    let browser_automation_command = json_bytes(json!({
        "object_kind": "browser_automation_command",
        "id": "browser-command-agent-web-valid",
        "protocol": "webdriver-bidi",
        "protocol_version": "2026-06",
        "browser_session_id_digest": "7171717171717171717171717171717171717171717171717171717171717171",
        "user_context_digest": "7272727272727272727272727272727272727272727272727272727272727272",
        "target_url_digest": "7373737373737373737373737373737373737373737373737373737373737373",
        "command_name": "submit_form",
        "command_parameters_digest": "7474747474747474747474747474747474747474747474747474747474747474",
        "locator_digest": "7575757575757575757575757575757575757575757575757575757575757575",
        "navigation_result_digest": "7676767676767676767676767676767676767676767676767676767676767676",
        "screenshot_digest": "7777777777777777777777777777777777777777777777777777777777777777",
        "storage_access": "read-write",
        "storage_scope_digest": "7878787878787878787878787878787878787878787878787878787878787878",
        "network_egress_digest": "7979797979797979797979797979797979797979797979797979797979797979",
        "authorization_context_digest": "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a",
        "mediated_by_chio_receipt": true
    }));
    if matches!(case, AgentWebCase::BrowserAutomationProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "browser-command",
            "external.browser-automation.command.v1",
            "external/browser-command.json",
            browser_automation_command.clone(),
        );
    }

    let rpa_transcript = json_bytes(json!({
        "object_kind": "rpa_transcript",
        "id": "rpa-transcript-agent-web-valid",
        "runner": "uia",
        "runner_version": "2026-06",
        "transcript_digest": "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "desktop_session_digest": "8080808080808080808080808080808080808080808080808080808080808080",
        "user_context_digest": "8181818181818181818181818181818181818181818181818181818181818181",
        "application_identity_digest": "8282828282828282828282828282828282828282828282828282828282828282",
        "window_identity_digest": "8383838383838383838383838383838383838383838383838383838383838383",
        "control_locator_digest": "8484848484848484848484848484848484848484848484848484848484848484",
        "action_name": "submit_invoice",
        "action_parameters_digest": "8585858585858585858585858585858585858585858585858585858585858585",
        "pre_state_digest": "8686868686868686868686868686868686868686868686868686868686868686",
        "post_state_digest": "8787878787878787878787878787878787878787878787878787878787878787",
        "screenshot_digest": "8888888888888888888888888888888888888888888888888888888888888888",
        "authorization_context_digest": "8989898989898989898989898989898989898989898989898989898989898989",
        "mutation_classification": "ui-write",
        "mediated_by_chio_receipt": true
    }));
    if matches!(case, AgentWebCase::RpaProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "rpa-transcript",
            "external.rpa.transcript.v1",
            "external/rpa-transcript.json",
            rpa_transcript.clone(),
        );
    }

    let email_message_digest = match case {
        AgentWebCase::EmailMissingMessageDigest => "",
        _ => "8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f",
    };
    let email_connector_action = json_bytes(json!({
        "object_kind": "email_connector_action",
        "id": "email-message-agent-web-valid",
        "provider_protocol": "gmail-api",
        "mailbox_account_digest": "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
        "message_id": "msg-agent-web-gmail-001",
        "rfc5322_message_digest": email_message_digest,
        "thread_id": "thread-agent-web-gmail-001",
        "recipient_digest_list": [
            "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b"
        ],
        "subject_digest": "8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c",
        "attachment_digest_list": [
            "8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d"
        ],
        "method": "send",
        "oauth_scope_set_digest": "8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
        "provider_response_digest": "8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e8f8e",
        "receipt_refs": ["receipt-agent-web-email-message-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::EmailProjection | AgentWebCase::EmailMissingMessageDigest
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "email-message",
            "external.email.connector-action.v1",
            "external/email-message.json",
            email_connector_action.clone(),
        );
    }

    let calendar_time_range_digest = match case {
        AgentWebCase::CalendarTimeRangeMismatch => {
            "8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b"
        }
        _ => "8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c",
    };
    let calendar_connector_action = json_bytes(json!({
        "object_kind": "calendar_connector_action",
        "id": "calendar-event-agent-web-valid",
        "provider_protocol": "google-calendar-api",
        "calendar_id_digest": "8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a",
        "event_id": "event-agent-web-calendar-001",
        "organizer_digest": "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b",
        "attendee_digest_list": [
            "8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c8b8c"
        ],
        "time_range_digest": calendar_time_range_digest,
        "approved_time_range_digest": "8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c",
        "recurrence_digest": "8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d8b8d",
        "conferencing_link_digest": "8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e8b8e",
        "write_method": "update",
        "oauth_scope_set_digest": "8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f",
        "receipt_refs": ["receipt-agent-web-calendar-event-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::CalendarProjection | AgentWebCase::CalendarTimeRangeMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "calendar-event",
            "external.calendar.connector-action.v1",
            "external/calendar-event.json",
            calendar_connector_action.clone(),
        );
    }

    let slack_response_ok = !matches!(case, AgentWebCase::SlackOkFalse);
    let slack_connector_action = json_bytes(json!({
        "object_kind": "slack_connector_action",
        "id": "slack-message-agent-web-valid",
        "workspace_id_digest": "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
        "channel_id_digest": "8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b",
        "method_name": "chat.postMessage",
        "message_id": "1717986918.000100",
        "request_body_digest": "8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c8c",
        "response_ok": slack_response_ok,
        "response_error_digest": "8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d8d",
        "oauth_scope_set_digest": "8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
        "event_id": "evt-slack-agent-web-001",
        "receipt_refs": ["receipt-agent-web-slack-message-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::SlackProjection | AgentWebCase::SlackOkFalse
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "slack-message",
            "external.slack.connector-action.v1",
            "external/slack-message.json",
            slack_connector_action.clone(),
        );
    }

    let oauth2_object_kind = match case {
        AgentWebCase::OAuth2WrongObjectKind => "openid_connect_identity",
        _ => "oauth2_authorization",
    };
    let oauth2_receipt_ref = match case {
        AgentWebCase::OAuth2ReceiptRefMismatch => "receipt-agent-web-oauth2-other-allow",
        _ => "receipt-agent-web-oauth2-authorization-allow",
    };
    let oauth2_authorization = json_bytes(json!({
        "object_kind": oauth2_object_kind,
        "id": "oauth2-authorization-agent-web-valid",
        "issuer": "https://issuer.enterprise.example",
        "resource": "https://api.enterprise.example/mcp",
        "grant_type": "token_exchange",
        "subject_digest": "9090909090909090909090909090909090909090909090909090909090909090",
        "audience_digest": "9191919191919191919191919191919191919191919191919191919191919191",
        "client_id_digest": "9292929292929292929292929292929292929292929292929292929292929292",
        "scope_set_digest": "9393939393939393939393939393939393939393939393939393939393939393",
        "authorization_details_digest": "9494949494949494949494949494949494949494949494949494949494949494",
        "sender_constraint": "dpop",
        "sender_constraint_digest": "9595959595959595959595959595959595959595959595959595959595959595",
        "token_verification_report_digest": "9696969696969696969696969696969696969696969696969696969696969696",
        "chio_caller_identity_digest": "9797979797979797979797979797979797979797979797979797979797979797",
        "token_status": "active",
        "authorized_scope_subset": true,
        "chio_authorization_receipt_ref": oauth2_receipt_ref,
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::OAuth2Projection
            | AgentWebCase::OAuth2WrongObjectKind
            | AgentWebCase::OAuth2ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "oauth2-authorization",
            "external.oauth2.authorization.v1",
            "external/oauth2-authorization.json",
            oauth2_authorization.clone(),
        );
    }

    let openid_connect_object_kind = match case {
        AgentWebCase::OpenIdConnectWrongObjectKind => "oauth2_authorization",
        _ => "openid_connect_identity",
    };
    let openid_connect_receipt_ref = match case {
        AgentWebCase::OpenIdConnectReceiptRefMismatch => {
            "receipt-agent-web-openid-connect-other-allow"
        }
        _ => "receipt-agent-web-openid-connect-identity-allow",
    };
    let openid_connect_identity = json_bytes(json!({
        "object_kind": openid_connect_object_kind,
        "id": "openid-connect-identity-agent-web-valid",
        "issuer": "https://issuer.enterprise.example",
        "subject_digest": "9898989898989898989898989898989898989898989898989898989898989898",
        "audience_digest": "9999999999999999999999999999999999999999999999999999999999999999",
        "nonce_digest": "9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e9e",
        "authentication_time": "2026-06-10T00:00:00Z",
        "acr": "urn:enterprise:assurance:phishing-resistant",
        "amr_digest": "9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f",
        "id_token_verification_report_digest": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
        "token_status": "verified",
        "chio_identity_receipt_ref": openid_connect_receipt_ref,
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::OpenIdConnectProjection
            | AgentWebCase::OpenIdConnectWrongObjectKind
            | AgentWebCase::OpenIdConnectReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "openid-connect-identity",
            "external.openid-connect.identity.v1",
            "external/openid-connect-identity.json",
            openid_connect_identity.clone(),
        );
    }

    let (scim_operation, scim_active_state) =
        if matches!(case, AgentWebCase::ScimActiveLifecycleMissingReceiptRef) {
            ("update", "active")
        } else {
            ("delete", "inactive")
        };
    let mut scim_lifecycle_event_value = json!({
        "object_kind": "scim_lifecycle_event",
        "id": "scim-lifecycle-agent-web-valid",
        "provider_id": "scim-provider-enterprise",
        "resource_type": "User",
        "resource_id_digest": "9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a",
        "subject_digest": "9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b",
        "group_digest": "9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c",
        "operation": scim_operation,
        "active_state": scim_active_state,
        "resource_version_digest": "9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d9d",
        "deprovisioning_receipt_ref": "receipt-agent-web-scim-lifecycle-allow",
        "capability_revocation_refs": [
            "revocation-agent-web-user-capability-001"
        ],
        "mediated_by_chio_receipt": true
    });
    if matches!(case, AgentWebCase::ScimActiveLifecycleMissingReceiptRef) {
        let scim_lifecycle_event = scim_lifecycle_event_value
            .as_object_mut()
            .test_expect("SCIM event is object");
        scim_lifecycle_event.remove("deprovisioning_receipt_ref");
        scim_lifecycle_event.remove("capability_revocation_refs");
    }
    let scim_lifecycle_event = json_bytes(scim_lifecycle_event_value);
    if matches!(
        case,
        AgentWebCase::ScimProjection | AgentWebCase::ScimActiveLifecycleMissingReceiptRef
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "scim-lifecycle",
            "external.scim.lifecycle.v1",
            "external/scim-lifecycle.json",
            scim_lifecycle_event.clone(),
        );
    }

    let spiffe_trust_domain = match case {
        AgentWebCase::SpiffeTrustDomainContainsPath => "enterprise.example/ns/prod",
        _ => "enterprise.example",
    };
    let mut spiffe_workload_identity_value = json!({
        "object_kind": "spiffe_workload_identity",
        "id": "spiffe-workload-agent-web-valid",
        "trust_domain": spiffe_trust_domain,
        "spiffe_id": "spiffe://enterprise.example/ns/prod/sa/agent-web",
        "svid_type": "x509_svid",
        "bundle_digest": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "workload_attestation_ref": "attestation-agent-web-spiffe-workload",
        "expiry": "2026-06-10T01:00:00Z",
        "chio_workload_identity_mapping_ref": "mapping-agent-web-toolserver",
        "chio_workload_receipt_ref": "receipt-agent-web-spiffe-workload-allow",
        "mediated_by_chio_receipt": true
    });
    if matches!(case, AgentWebCase::SpiffeReceiptRefMissing) {
        spiffe_workload_identity_value
            .as_object_mut()
            .test_expect("SPIFFE workload identity is object")
            .remove("chio_workload_receipt_ref");
    }
    let spiffe_workload_identity = json_bytes(spiffe_workload_identity_value);
    if matches!(
        case,
        AgentWebCase::SpiffeProjection
            | AgentWebCase::SpiffeReceiptRefMissing
            | AgentWebCase::SpiffeTrustDomainContainsPath
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "spiffe-workload-identity",
            "external.spiffe.workload-identity.v1",
            "external/spiffe-workload-identity.json",
            spiffe_workload_identity.clone(),
        );
    }

    let kubernetes_response_uid = match case {
        AgentWebCase::KubernetesAdmissionUidMismatch => "admission-review-response-mismatch",
        _ => "admission-review-request-001",
    };
    let kubernetes_admission_review = json_bytes(json!({
        "object_kind": "kubernetes_admission_review",
        "id": "kubernetes-admission-agent-web-valid",
        "cluster_id_digest": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
        "api_group": "apps",
        "api_version": "v1",
        "resource": "deployments",
        "kind": "Deployment",
        "namespace": "agent-tools",
        "operation": "CREATE",
        "request_uid": "admission-review-request-001",
        "response_uid": kubernetes_response_uid,
        "user_info_digest": "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        "object_digest": "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
        "admission_webhook_configuration_digest": "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "allowed": true,
        "patch_digest": "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
        "warning_digests": [
            "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"
        ],
        "chio_capability_token_digest": "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
        "chio_admission_receipt_ref": "receipt-agent-web-kubernetes-admission-allow",
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::KubernetesAdmissionProjection | AgentWebCase::KubernetesAdmissionUidMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "kubernetes-admission-review",
            "external.kubernetes.admission-review.v1",
            "external/kubernetes-admission-review.json",
            kubernetes_admission_review.clone(),
        );
    }

    let oci_digest = match case {
        AgentWebCase::OciTagOnly => "latest",
        _ => "sha256:b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    };
    let oci_artifact_ref = json_bytes(json!({
        "object_kind": "oci_artifact_ref",
        "id": "oci-ref-agent-web-valid",
        "registry": "registry.enterprise.example",
        "repository": "agent-tools/guard-runner",
        "digest": oci_digest,
        "media_type": "application/vnd.oci.image.manifest.v1+json",
        "descriptor_digest": "sha256:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "descriptor_size": 4096,
        "artifact_type": "application/vnd.chio.guard-runner.v1",
        "subject_digest": "sha256:b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3",
        "sigstore_bundle_digest": "b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4",
        "rekor_inclusion_status": "verified",
        "cache_admission_report_digest": "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
        "receipt_refs": ["receipt-agent-web-oci-ref-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::OciRefProjection | AgentWebCase::OciTagOnly
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "oci-ref",
            "external.oci.ref.v1",
            "external/oci-ref.json",
            oci_artifact_ref.clone(),
        );
    }

    let vc_receipt_refs = if matches!(case, AgentWebCase::VcReceiptRefMissing) {
        vec!["receipt-agent-web-vc-unbound"]
    } else {
        vec!["receipt-agent-web-vc-allow"]
    };
    let verifiable_credential = json_bytes(json!({
        "object_kind": "verifiable_credential",
        "id": "vc-agent-web-valid",
        "media_type": "application/vc+ld+json",
        "credential_digest": "61".repeat(32),
        "issuer_digest": "62".repeat(32),
        "subject_digest": "63".repeat(32),
        "credential_schema_digest": "64".repeat(32),
        "credential_status_digest": "65".repeat(32),
        "proof_digest": "66".repeat(32),
        "proof_type": "DataIntegrityProof",
        "proof_purpose": "assertionMethod",
        "credential_status": "valid",
        "verifier_policy_digest": "67".repeat(32),
        "authorization_context_digest": "68".repeat(32),
        "receipt_refs": vc_receipt_refs,
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::VcProjection | AgentWebCase::VcReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "vc",
            "external.vc.verifiable-credential.v1",
            "external/verifiable-credential.json",
            verifiable_credential.clone(),
        );
    }

    let sd_jwt_vc_receipt_refs = if matches!(case, AgentWebCase::SdJwtVcReceiptRefMissing) {
        vec!["receipt-agent-web-sd-jwt-vc-presentation-unbound"]
    } else {
        vec!["receipt-agent-web-sd-jwt-vc-presentation-allow"]
    };
    let sd_jwt_vc_presentation = json_bytes(json!({
        "object_kind": "sd_jwt_vc_presentation",
        "id": "sd-jwt-vc-presentation-agent-web-valid",
        "media_type": "application/dc+sd-jwt",
        "credential_digest": "1717171717171717171717171717171717171717171717171717171717171717",
        "disclosed_claims_digest": "2828282828282828282828282828282828282828282828282828282828282828",
        "holder_binding_digest": "3939393939393939393939393939393939393939393939393939393939393939",
        "issuer_key_digest": "4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a",
        "verifier_policy_digest": "5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b",
        "presentation_nonce_digest": "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c",
        "audience_digest": "7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d7d",
        "authorization_context_digest": "8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e8e",
        "credential_status": "valid",
        "key_binding_alg": "ES256",
        "receipt_refs": sd_jwt_vc_receipt_refs,
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::SdJwtVcProjection | AgentWebCase::SdJwtVcReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "sd-jwt-vc-presentation",
            "external.sd-jwt-vc.presentation.v1",
            "external/sd-jwt-vc-presentation.json",
            sd_jwt_vc_presentation.clone(),
        );
    }

    let mut bbs_receipt_disclosure_value = json!({
        "object_kind": "bbs_receipt_disclosure",
        "id": "bbs-receipt-disclosure-agent-web-valid",
        "projection_profile": "chio-receipt-bbs-v1",
        "proof_digest": "81".repeat(32),
        "revealed_messages_digest": "82".repeat(32),
        "hidden_messages_digest": "83".repeat(32),
        "issuer_key_digest": "84".repeat(32),
        "nonce_digest": "85".repeat(32),
        "verifier_policy_digest": "86".repeat(32),
        "receipt_digest": "87".repeat(32),
        "authorization_context_digest": "88".repeat(32),
        "disclosure_count": 4,
        "hidden_count": 3,
        "verification_status": "verified",
        "receipt_refs": ["receipt-agent-web-bbs-disclosure-allow"],
        "mediated_by_chio_receipt": true
    });
    if matches!(case, AgentWebCase::BbsReceiptRefMissing) {
        bbs_receipt_disclosure_value
            .as_object_mut()
            .test_expect("BBS receipt disclosure is object")
            .remove("receipt_refs");
    }
    let bbs_receipt_disclosure = json_bytes(bbs_receipt_disclosure_value);
    if matches!(
        case,
        AgentWebCase::BbsProjection | AgentWebCase::BbsReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "bbs-receipt-disclosure",
            "external.bbs.receipt-disclosure.v1",
            "external/bbs-receipt-disclosure.json",
            bbs_receipt_disclosure.clone(),
        );
    }

    let mut sigstore_bundle_value = json!({
        "object_kind": "sigstore_bundle",
        "id": "sigstore-bundle-agent-web-valid",
        "media_type": "application/vnd.dev.sigstore.bundle+json",
        "bundle_digest": "91".repeat(32),
        "artifact_digest": "92".repeat(32),
        "certificate_identity_digest": "93".repeat(32),
        "certificate_issuer_digest": "94".repeat(32),
        "transparency_log_digest": "95".repeat(32),
        "rekor_entry_digest": "96".repeat(32),
        "signature_digest": "97".repeat(32),
        "verification_material_digest": "98".repeat(32),
        "slsa_provenance_digest": "99".repeat(32),
        "authorization_context_digest": "9a".repeat(32),
        "predicate_type": "https://slsa.dev/provenance/v1",
        "transparency_included": true,
        "verification_status": "verified",
        "receipt_refs": ["receipt-agent-web-sigstore-bundle-allow"],
        "mediated_by_chio_receipt": true
    });
    if matches!(case, AgentWebCase::SigstoreReceiptRefMissing) {
        sigstore_bundle_value
            .as_object_mut()
            .test_expect("Sigstore bundle is object")
            .remove("receipt_refs");
    }
    let sigstore_bundle = json_bytes(sigstore_bundle_value);
    if matches!(
        case,
        AgentWebCase::SigstoreProjection | AgentWebCase::SigstoreReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "sigstore-bundle",
            "external.sigstore.bundle.v1",
            "external/sigstore-bundle.json",
            sigstore_bundle.clone(),
        );
    }

    let mut in_toto_statement_value = json!({
        "object_kind": "in_toto_statement",
        "id": "in-toto-statement-agent-web-valid",
        "statement_type": "https://in-toto.io/Statement/v1",
        "payload_type": "application/vnd.in-toto+json",
        "predicate_type": "https://chio.dev/predicates/agent-web-invocation/v1",
        "dsse_envelope_digest": "a0".repeat(32),
        "payload_digest": "a1".repeat(32),
        "subject_digest": "a2".repeat(32),
        "predicate_digest": "a3".repeat(32),
        "builder_identity_digest": "a4".repeat(32),
        "signer_identity_digest": "a5".repeat(32),
        "verification_material_digest": "a6".repeat(32),
        "authorization_context_digest": "a7".repeat(32),
        "signature_count": 1,
        "receipt_refs": ["receipt-agent-web-in-toto-statement-allow"],
        "mediated_by_chio_receipt": true
    });
    if matches!(case, AgentWebCase::InTotoReceiptRefMissing) {
        in_toto_statement_value
            .as_object_mut()
            .test_expect("in-toto statement is object")
            .remove("receipt_refs");
    }
    let in_toto_statement = json_bytes(in_toto_statement_value);
    if matches!(
        case,
        AgentWebCase::InTotoProjection | AgentWebCase::InTotoReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "in-toto-statement",
            "external.in-toto.statement.v1",
            "external/in-toto-statement.json",
            in_toto_statement.clone(),
        );
    }

    let dsse_envelope_subject = json_bytes(json!({
        "object_kind": "dsse_envelope",
        "id": "dsse-envelope-agent-web-valid",
        "payload_type": "application/vnd.in-toto+json",
        "payload_digest": "c0".repeat(32),
        "subject_digest": "c1".repeat(32),
        "signature_digest": "c2".repeat(32),
        "signer_identity_digest": "c3".repeat(32),
        "verification_material_digest": "c4".repeat(32),
        "authorization_context_digest": "c5".repeat(32),
        "signature_count": 1,
        "verification_status": "verified",
        "receipt_refs": ["receipt-agent-web-dsse-envelope-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(case, AgentWebCase::DsseProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "dsse-envelope-subject",
            "external.dsse.envelope.v1",
            "external/dsse-envelope.json",
            dsse_envelope_subject.clone(),
        );
    }

    let slsa_verification_status = match case {
        AgentWebCase::SlsaUnverified => "unverified",
        _ => "verified",
    };
    let slsa_provenance = json_bytes(json!({
        "object_kind": "slsa_provenance",
        "id": "slsa-provenance-agent-web-valid",
        "predicate_type": "https://slsa.dev/provenance/v1",
        "build_type": "https://slsa.dev/container-based-build/v1",
        "builder_id_digest": "b0".repeat(32),
        "build_invocation_digest": "b1".repeat(32),
        "resolved_dependencies_digest": "b2".repeat(32),
        "materials_digest": "b3".repeat(32),
        "artifact_digest": "b4".repeat(32),
        "provenance_digest": "b5".repeat(32),
        "verification_material_digest": "b6".repeat(32),
        "authorization_context_digest": "b7".repeat(32),
        "build_started_on": "2026-06-10T00:00:00Z",
        "build_finished_on": "2026-06-10T00:02:00Z",
        "verification_status": slsa_verification_status,
        "receipt_refs": ["receipt-agent-web-slsa-provenance-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::SlsaProjection | AgentWebCase::SlsaUnverified
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "slsa-provenance",
            "external.slsa.provenance.v1",
            "external/slsa-provenance.json",
            slsa_provenance.clone(),
        );
    }

    let asyncapi_receipt_ref = match case {
        AgentWebCase::AsyncApiReceiptRefMismatch => "receipt-agent-web-asyncapi-other-allow",
        _ => "receipt-agent-web-asyncapi-message-allow",
    };
    let asyncapi_message = json_bytes(json!({
        "object_kind": "asyncapi_message",
        "id": "asyncapi-message-agent-web-valid",
        "spec_digest": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "channel_digest": "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2",
        "message_digest": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
        "payload_digest": "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
        "headers_digest": "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
        "broker_identity_digest": "f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6",
        "authorization_context_digest": "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
        "operation_id": "PublishOrderCreated",
        "channel": "orders.created",
        "direction": "publish",
        "protocol": "kafka",
        "chio_message_receipt_ref": asyncapi_receipt_ref
    }));
    if matches!(
        case,
        AgentWebCase::AsyncApiProjection
            | AgentWebCase::AsyncApiUnsupportedVersion
            | AgentWebCase::AsyncApiReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "asyncapi-message",
            "external.asyncapi.message.v1",
            "external/asyncapi-message.json",
            asyncapi_message.clone(),
        );
    }

    let ap2_transaction_context_digest =
        if matches!(case, AgentWebCase::Ap2TransactionContextDigestMismatch) {
            "dfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdf".to_string()
        } else {
            chio_core_types::sha256_hex(&order_context)
        };
    let ap2_receipt_ref = match case {
        AgentWebCase::Ap2ReceiptRefMismatch => "receipt-agent-web-ap2-other-allow",
        _ => "receipt-agent-web-ap2-mandate-allow",
    };
    let ap2_mandate_chain = json_bytes(json!({
        "object_kind": "ap2_mandate_chain",
        "id": "ap2-mandate-chain-agent-web-valid",
        "transaction_passport_ref": passport.id,
        "order_id": "order-commerce-001",
        "credential_format": "vdc",
        "checkout_mandate_digest": "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac",
        "payment_mandate_digest": "bdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbd",
        "payment_instrument_digest": "cececececececececececececececececececececececececececececececece",
        "transaction_context_digest": ap2_transaction_context_digest,
        "agent_mode": "human-not-present",
        "status": "authorized",
        "chio_mandate_receipt_ref": ap2_receipt_ref
    }));
    if matches!(
        case,
        AgentWebCase::Ap2Projection
            | AgentWebCase::Ap2TransactionContextDigestMismatch
            | AgentWebCase::Ap2DetachedOrder
            | AgentWebCase::Ap2ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "ap2-mandate-chain",
            "external.ap2.mandate-chain.v1",
            "external/ap2-mandate-chain.json",
            ap2_mandate_chain.clone(),
        );
    }

    let x402_amount_units = match case {
        AgentWebCase::X402AmountMismatch => 1300,
        _ => 1250,
    };
    let x402_receipt_ref = match case {
        AgentWebCase::X402ReceiptRefMismatch => "receipt-agent-web-x402-other-allow",
        _ => "receipt-agent-web-x402-payment-allow",
    };
    let x402_payment = json_bytes(json!({
        "object_kind": "x402_payment",
        "id": "x402-payment-agent-web-valid",
        "transaction_passport_ref": passport.id,
        "order_id": "order-commerce-001",
        "resource_digest": "abababababababababababababababababababababababababababababababab",
        "payment_requirements_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "payment_proof_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "settlement_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "network": "base-sepolia",
        "asset": "USDC",
        "amount_units": x402_amount_units,
        "status": "settled",
        "chio_payment_receipt_ref": x402_receipt_ref
    }));
    if matches!(
        case,
        AgentWebCase::AcpCommerceProjection
            | AgentWebCase::AcpCommerceOrderContextDigestMismatch
            | AgentWebCase::AcpCommerceReceiptRefMismatch
            | AgentWebCase::Ap2Projection
            | AgentWebCase::Ap2TransactionContextDigestMismatch
            | AgentWebCase::Ap2DetachedOrder
            | AgentWebCase::Ap2ReceiptRefMismatch
            | AgentWebCase::X402Projection
            | AgentWebCase::X402AmountMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "commerce-order-context",
            "chio.commerce.order-context.v1",
            "external/order-context.json",
            order_context.clone(),
        );
    }
    if matches!(
        case,
        AgentWebCase::AcpCommerceProjection
            | AgentWebCase::AcpCommerceOrderContextDigestMismatch
            | AgentWebCase::AcpCommerceReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "acp-commerce-checkout",
            "external.acp-commerce.checkout.v1",
            "external/acp-commerce-checkout.json",
            acp_commerce_checkout.clone(),
        );
    }
    if matches!(
        case,
        AgentWebCase::X402Projection
            | AgentWebCase::X402AmountMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-subject",
            "x402-payment",
            "external.x402.payment.v1",
            "external/x402-payment.json",
            x402_payment.clone(),
        );
    }

    let webhook_evidence_class = match case {
        AgentWebCase::SidecarClaimMarkedNative => "native-external-proof",
        _ => "chio-sidecar-proof",
    };
    let webhook_unsupported_claims = match case {
        AgentWebCase::UnsupportedClaimNotLimited => Vec::<&str>::new(),
        _ => vec![UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM],
    };
    let webhook_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-standard-webhooks-valid",
        "source_protocol": "standard-webhooks",
        "source_version": "2026-06-09",
        "external_fields_used": [
            "webhook_id",
            "webhook_timestamp",
            "event_type",
            "tenant_id",
            "endpoint_url_digest",
            "body_digest",
            "webhook_signature"
        ],
        "external_fields_not_used": [],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": if matches!(case, AgentWebCase::RequiredSignatureAlgorithmNone) {
            "none"
        } else {
            "standard-webhooks"
        },
        "requires_external_signature": true,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": webhook_evidence_class
            }
        ],
        "unsupported_claims": webhook_unsupported_claims,
        "copy_limitations": [
            "Standard Webhooks signatures are external evidence and do not authorize Chio tool execution."
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-projection-manifest",
        "standard-webhooks-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "standard-webhooks-manifest.json",
        webhook_manifest,
    );

    let webhook_digest = match case {
        AgentWebCase::ExternalDigestMismatch => "f".repeat(64),
        _ => chio_core_types::sha256_hex(&webhook_delivery),
    };
    let webhook_signature_ref = match case {
        AgentWebCase::MissingRequiredSignature => "",
        AgentWebCase::MalformedWebhookSignature => "standard-webhooks-signature",
        _ => "v1,standard-webhooks-signature",
    };
    let webhook_claim_refs = match case {
        AgentWebCase::MissingRequiredSidecarClaim => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
        ],
        AgentWebCase::UnsupportedClaimNotLimited => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
            UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM,
        ],
        _ => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
        ],
    };
    let webhook_risk_refs = match case {
        AgentWebCase::UnboundRiskRef => vec!["risk-report-unloaded"],
        _ => Vec::<&str>::new(),
    };
    let webhook_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-standard-webhooks-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "standard-webhooks",
        "source_protocol_version": "2026-06-09",
        "external_subject": "webhook-delivery-agent-web-valid",
        "external_subject_path": "external/webhook-delivery.json",
        "external_subject_digest": webhook_digest,
        "external_subject_signature_ref": webhook_signature_ref,
        "projection_manifest_ref": "projection-standard-webhooks-valid",
        "chio_claim_refs": webhook_claim_refs,
        "receipt_refs": ["receipt-agent-web-webhook-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": webhook_risk_refs,
        "limitations": [
            "Webhook signature evidence is not Chio capability authority."
        ],
        "signature": "sig-agent-web-webhook-envelope"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "agent-web-proof-envelope",
        "standard-webhooks-envelope",
        "chio.agent-web-proof-envelope.v1",
        "standard-webhooks-envelope.json",
        webhook_envelope,
    );

    for receipt_id in [
        "receipt-agent-web-webhook-allow",
        "receipt-agent-web-cloudevents-allow",
        "receipt-agent-web-graphql-mutation-allow",
        "receipt-agent-web-mcp-tool-call-allow",
        "receipt-agent-web-a2a-task-allow",
    ] {
        if matches!(case, AgentWebCase::MissingReceiptRef)
            && receipt_id == "receipt-agent-web-webhook-allow"
        {
            continue;
        }
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            receipt_id,
            "chio.receipt.v1",
            &format!("receipts/{receipt_id}.json"),
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": receipt_id,
                "terminal_status": if matches!(case, AgentWebCase::BoundReceiptDenied)
                    && receipt_id == "receipt-agent-web-webhook-allow"
                {
                    "denied_guard_request"
                } else {
                    "allowed_executed"
                }
            })),
        );
    }

    let cloudevents_unsupported_claims = match case {
        AgentWebCase::CloudEventsAuthorityClaimNotLimited => Vec::<&str>::new(),
        _ => vec![UNSUPPORTED_CLOUDEVENTS_AUTHORITY_CLAIM],
    };
    let cloudevents_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-cloudevents-valid",
        "source_protocol": "cloudevents",
        "source_version": "1.0.2",
        "external_fields_used": [
            "specversion",
            "id",
            "source",
            "type",
            "subject",
            "time",
            "datacontenttype",
            "data_digest"
        ],
        "external_fields_not_used": [],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": if matches!(case, AgentWebCase::UnusedSignatureAlgorithmPresent) {
            "standard-webhooks"
        } else {
            "none"
        },
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": cloudevents_unsupported_claims,
        "copy_limitations": [
            "CloudEvents identity fields are event evidence and do not authorize Chio tool execution."
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-projection-manifest",
        "cloudevents-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "cloudevents-manifest.json",
        cloudevents_manifest,
    );

    let graphql_source_version = match case {
        AgentWebCase::GraphqlHttpDraftVersionMissing => "1.0.0",
        _ => "draft-2026-06-04",
    };
    let mut graphql_external_fields_used = vec![
        "endpoint_url_digest",
        "method",
        "media_type",
        "schema_digest",
        "operation_type",
        "operation_name",
        "document_digest",
        "variables_digest",
        "response_digest",
        "status_code",
    ];
    if matches!(case, AgentWebCase::GraphqlErrorsProjectedAsSuccess) {
        graphql_external_fields_used.insert(9, "response_has_errors");
        graphql_external_fields_used.insert(10, "response_error_digest");
    }
    let graphql_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-graphql-http-valid",
        "source_protocol": "graphql-http",
        "source_version": graphql_source_version,
        "external_fields_used": graphql_external_fields_used,
        "external_fields_not_used": ["subscription_stream"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [
            UNSUPPORTED_GRAPHQL_AUTHORITY_CLAIM,
            UNSUPPORTED_GRAPHQL_SUBSCRIPTION_CLAIM
        ],
        "copy_limitations": [
            "GraphQL over HTTP projection covers digest-bound query and mutation request-response evidence, not subscription streams."
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-projection-manifest",
        "graphql-http-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "graphql-http-manifest.json",
        graphql_manifest,
    );

    let mcp_unsupported_claims = match case {
        AgentWebCase::McpAuthorityClaimNotLimited => Vec::<&str>::new(),
        _ => vec![UNSUPPORTED_MCP_AUTHORITY_CLAIM],
    };
    let mcp_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-mcp-valid",
        "source_protocol": "mcp",
        "source_version": "2025-11-25",
        "external_fields_used": [
            "protocol_version",
            "transport",
            "server_identity_digest",
            "session_id_digest",
            "tool_name",
            "arguments_digest",
            "result_digest",
            "authorization_context_digest"
        ],
        "external_fields_not_used": ["tool_annotations_as_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": mcp_unsupported_claims,
        "copy_limitations": [
            "MCP tool-call evidence is digest-bound external protocol evidence, not Chio capability authority."
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-projection-manifest",
        "mcp-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "mcp-manifest.json",
        mcp_manifest,
    );

    let a2a_unsupported_claims = match case {
        AgentWebCase::A2aAuthorityClaimNotLimited => Vec::<&str>::new(),
        _ => vec![UNSUPPORTED_A2A_AUTHORITY_CLAIM],
    };
    let a2a_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-a2a-valid",
        "source_protocol": "a2a",
        "source_version": "0.3.0",
        "external_fields_used": [
            "protocol_version",
            "task_id",
            "message_id",
            "agent_card_digest",
            "task_input_digest",
            "task_state",
            "task_state_digest",
            "result_digest",
            "authorization_context_digest"
        ],
        "external_fields_not_used": ["task_state_as_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": a2a_unsupported_claims,
        "copy_limitations": [
            "A2A task lifecycle evidence is digest-bound external task state, not Chio capability authority."
        ]
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "external-projection-manifest",
        "a2a-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "a2a-manifest.json",
        a2a_manifest,
    );

    let openapi_source_version = match case {
        AgentWebCase::OpenApiUnsupportedVersion => "2.0",
        _ => "3.1.0",
    };
    let openapi_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-openapi-valid",
        "source_protocol": "openapi",
        "source_version": openapi_source_version,
        "external_fields_used": [
            "spec_digest",
            "operation_id",
            "method",
            "path_template",
            "request_digest",
            "response_digest",
            "status_code",
            "chio_operation_receipt_ref"
        ],
        "external_fields_not_used": ["security_scheme_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_OPENAPI_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OpenAPI operation evidence is digest-bound HTTP contract evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::OpenApiProjection
            | AgentWebCase::OpenApiUnsupportedVersion
            | AgentWebCase::OpenApiReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "openapi-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "openapi-manifest.json",
            openapi_manifest,
        );
    }

    let acp_client_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-acp-client-valid",
        "source_protocol": "acp-client",
        "source_version": "v1",
        "external_fields_used": [
            "protocol_version",
            "capability_id",
            "category",
            "requires_permission",
            "permission_decision",
            "bridge_fidelity",
            "source_envelope_digest",
            "arguments_digest",
            "client_session_digest",
            "agent_id_digest",
            "authorization_context_digest"
        ],
        "external_fields_not_used": ["host_permission_prompt_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_ACP_CLIENT_AUTHORITY_CLAIM],
        "copy_limitations": [
            "ACP-Client permission evidence is digest-bound client protocol evidence, not Chio capability authority."
        ]
    }));
    if matches!(case, AgentWebCase::AcpClientProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "acp-client-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "acp-client-manifest.json",
            acp_client_manifest,
        );
    }

    let acp_commerce_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-acp-commerce-valid",
        "source_protocol": "acp-commerce",
        "source_version": "2026-06",
        "external_fields_used": [
            "transaction_passport_ref",
            "order_id",
            "delegated_payment_token_digest",
            "checkout_context_digest",
            "order_context_digest",
            "payment_instruction_digest",
            "merchant_identity_digest",
            "buyer_identity_digest",
            "amount_units",
            "currency",
            "status",
            "chio_checkout_receipt_ref"
        ],
        "external_fields_not_used": ["delegated_payment_token_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_ACP_COMMERCE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "ACP-Commerce checkout evidence is digest-bound payment protocol evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::AcpCommerceProjection
            | AgentWebCase::AcpCommerceOrderContextDigestMismatch
            | AgentWebCase::AcpCommerceReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "acp-commerce-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "acp-commerce-manifest.json",
            acp_commerce_manifest,
        );
    }

    let ag_ui_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-ag-ui-valid",
        "source_protocol": "ag-ui",
        "source_version": "events-v1",
        "external_fields_used": [
            "protocol_version",
            "event_id",
            "agent_id_digest",
            "session_id_digest",
            "capability_id",
            "event_type",
            "target_component_type",
            "target_component_id_digest",
            "classification",
            "transport",
            "allowed",
            "payload_digest",
            "receipt_digest",
            "authorization_context_digest"
        ],
        "external_fields_not_used": ["ui_event_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_AG_UI_AUTHORITY_CLAIM],
        "copy_limitations": [
            "AG-UI event evidence is digest-bound UI stream evidence, not Chio capability authority."
        ]
    }));
    if matches!(case, AgentWebCase::AgUiProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "ag-ui-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "ag-ui-manifest.json",
            ag_ui_manifest,
        );
    }

    let browser_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-browser-automation-valid",
        "source_protocol": "browser-automation",
        "source_version": "webdriver-bidi-2026-06",
        "external_fields_used": [
            "protocol",
            "protocol_version",
            "browser_session_id_digest",
            "user_context_digest",
            "target_url_digest",
            "command_name",
            "command_parameters_digest",
            "locator_digest",
            "navigation_result_digest",
            "screenshot_digest",
            "storage_access",
            "storage_scope_digest",
            "network_egress_digest",
            "authorization_context_digest",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "screenshot_as_dom_authority",
            "browser_command_as_chio_authority"
        ],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_BROWSER_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Browser automation command evidence is digest-bound browser transcript evidence, not Chio capability authority."
        ]
    }));
    if matches!(case, AgentWebCase::BrowserAutomationProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "browser-automation-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "browser-automation-manifest.json",
            browser_manifest,
        );
    }

    let rpa_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-rpa-valid",
        "source_protocol": "rpa",
        "source_version": "uia-2026-06",
        "external_fields_used": [
            "runner",
            "runner_version",
            "transcript_digest",
            "desktop_session_digest",
            "user_context_digest",
            "application_identity_digest",
            "window_identity_digest",
            "control_locator_digest",
            "action_name",
            "action_parameters_digest",
            "pre_state_digest",
            "post_state_digest",
            "screenshot_digest",
            "authorization_context_digest",
            "mutation_classification",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["rpa_transcript_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_RPA_AUTHORITY_CLAIM],
        "copy_limitations": [
            "RPA transcript evidence is digest-bound desktop automation evidence, not Chio capability authority."
        ]
    }));
    if matches!(case, AgentWebCase::RpaProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "rpa-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "rpa-manifest.json",
            rpa_manifest,
        );
    }

    let email_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-gmail-api-valid",
        "source_protocol": "gmail-api",
        "source_version": "v1",
        "external_fields_used": [
            "provider_protocol",
            "mailbox_account_digest",
            "message_id",
            "rfc5322_message_digest",
            "thread_id",
            "recipient_digest_list",
            "subject_digest",
            "attachment_digest_list",
            "method",
            "oauth_scope_set_digest",
            "provider_response_digest",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["email_action_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_EMAIL_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Email connector evidence is digest-bound provider action evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::EmailProjection | AgentWebCase::EmailMissingMessageDigest
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "email-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "email-manifest.json",
            email_manifest,
        );
    }

    let calendar_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-google-calendar-api-valid",
        "source_protocol": "google-calendar-api",
        "source_version": "v1",
        "external_fields_used": [
            "provider_protocol",
            "calendar_id_digest",
            "event_id",
            "organizer_digest",
            "attendee_digest_list",
            "time_range_digest",
            "approved_time_range_digest",
            "recurrence_digest",
            "conferencing_link_digest",
            "write_method",
            "oauth_scope_set_digest",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["calendar_action_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_CALENDAR_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Calendar connector evidence is digest-bound provider action evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::CalendarProjection | AgentWebCase::CalendarTimeRangeMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "calendar-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "calendar-manifest.json",
            calendar_manifest,
        );
    }

    let slack_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-slack-valid",
        "source_protocol": "slack",
        "source_version": "web-api-2026-06",
        "external_fields_used": [
            "workspace_id_digest",
            "channel_id_digest",
            "method_name",
            "message_id",
            "request_body_digest",
            "response_ok",
            "response_error_digest",
            "oauth_scope_set_digest",
            "event_id",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["slack_action_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_SLACK_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Slack connector evidence is digest-bound provider action evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SlackProjection | AgentWebCase::SlackOkFalse
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "slack-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "slack-manifest.json",
            slack_manifest,
        );
    }

    let oauth2_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-oauth2-valid",
        "source_protocol": "oauth2",
        "source_version": "rfc6749",
        "external_fields_used": [
            "issuer",
            "resource",
            "grant_type",
            "subject_digest",
            "audience_digest",
            "client_id_digest",
            "scope_set_digest",
            "authorization_details_digest",
            "sender_constraint",
            "sender_constraint_digest",
            "token_verification_report_digest",
            "chio_caller_identity_digest",
            "token_status",
            "authorized_scope_subset",
            "chio_authorization_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["oauth2_token_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_OAUTH2_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OAuth2 authorization evidence is digest-bound bearer admission evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::OAuth2Projection
            | AgentWebCase::OAuth2WrongObjectKind
            | AgentWebCase::OAuth2ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "oauth2-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "oauth2-manifest.json",
            oauth2_manifest,
        );
    }

    let openid_connect_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-openid-connect-valid",
        "source_protocol": "openid-connect",
        "source_version": "core-1.0",
        "external_fields_used": [
            "issuer",
            "subject_digest",
            "audience_digest",
            "nonce_digest",
            "authentication_time",
            "acr",
            "amr_digest",
            "id_token_verification_report_digest",
            "token_status",
            "chio_identity_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["openid_connect_identity_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_OPENID_CONNECT_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OpenID Connect identity evidence is digest-bound identity evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::OpenIdConnectProjection
            | AgentWebCase::OpenIdConnectWrongObjectKind
            | AgentWebCase::OpenIdConnectReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "openid-connect-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "openid-connect-manifest.json",
            openid_connect_manifest,
        );
    }

    let scim_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-scim-valid",
        "source_protocol": "scim",
        "source_version": "rfc7644",
        "external_fields_used": [
            "provider_id",
            "resource_type",
            "resource_id_digest",
            "subject_digest",
            "group_digest",
            "operation",
            "active_state",
            "resource_version_digest",
            "deprovisioning_receipt_ref",
            "capability_revocation_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["scim_lifecycle_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_SCIM_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SCIM lifecycle evidence is digest-bound identity lifecycle evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::ScimProjection | AgentWebCase::ScimActiveLifecycleMissingReceiptRef
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "scim-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "scim-manifest.json",
            scim_manifest,
        );
    }

    let spiffe_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-spiffe-valid",
        "source_protocol": "spiffe",
        "source_version": "workload-api-v1",
        "external_fields_used": [
            "trust_domain",
            "spiffe_id",
            "svid_type",
            "bundle_digest",
            "workload_attestation_ref",
            "expiry",
            "chio_workload_identity_mapping_ref",
            "chio_workload_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["spiffe_workload_identity_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_SPIFFE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SPIFFE workload identity evidence is digest-bound workload identity evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SpiffeProjection
            | AgentWebCase::SpiffeReceiptRefMissing
            | AgentWebCase::SpiffeTrustDomainContainsPath
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "spiffe-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "spiffe-manifest.json",
            spiffe_manifest,
        );
    }

    let kubernetes_admission_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-kubernetes-admission-valid",
        "source_protocol": "kubernetes-admission",
        "source_version": "admissionreview-v1",
        "external_fields_used": [
            "cluster_id_digest",
            "api_group",
            "api_version",
            "resource",
            "kind",
            "namespace",
            "operation",
            "request_uid",
            "response_uid",
            "user_info_digest",
            "object_digest",
            "admission_webhook_configuration_digest",
            "allowed",
            "patch_digest",
            "warning_digests",
            "chio_capability_token_digest",
            "chio_admission_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["kubernetes_admission_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_KUBERNETES_ADMISSION_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Kubernetes admission evidence is digest-bound cluster admission evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::KubernetesAdmissionProjection | AgentWebCase::KubernetesAdmissionUidMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "kubernetes-admission-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "kubernetes-admission-manifest.json",
            kubernetes_admission_manifest,
        );
    }

    let oci_ref_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-oci-ref-valid",
        "source_protocol": "oci",
        "source_version": "image-spec-v1",
        "external_fields_used": [
            "registry",
            "repository",
            "digest",
            "media_type",
            "descriptor_digest",
            "descriptor_size",
            "artifact_type",
            "subject_digest",
            "sigstore_bundle_digest",
            "rekor_inclusion_status",
            "cache_admission_report_digest",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["oci_ref_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_OCI_REF_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OCI artifact evidence is digest-bound supply-chain evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::OciRefProjection | AgentWebCase::OciTagOnly
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "oci-ref-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "oci-ref-manifest.json",
            oci_ref_manifest,
        );
    }

    let vc_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-vc-valid",
        "source_protocol": "vc",
        "source_version": "vc-data-model-2.0",
        "external_fields_used": [
            "media_type",
            "credential_digest",
            "issuer_digest",
            "subject_digest",
            "credential_schema_digest",
            "credential_status_digest",
            "proof_digest",
            "proof_type",
            "proof_purpose",
            "credential_status",
            "verifier_policy_digest",
            "authorization_context_digest",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "credential_signature_as_chio_authority",
            "issuer_as_chio_authority"
        ],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_VC_AUTHORITY_CLAIM],
        "copy_limitations": [
            "VC evidence is digest-bound credential evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::VcProjection | AgentWebCase::VcReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "vc-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "vc-manifest.json",
            vc_manifest,
        );
    }

    let sd_jwt_vc_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-sd-jwt-vc-valid",
        "source_protocol": "sd-jwt-vc",
        "source_version": "v1",
        "external_fields_used": [
            "media_type",
            "credential_digest",
            "disclosed_claims_digest",
            "holder_binding_digest",
            "issuer_key_digest",
            "verifier_policy_digest",
            "presentation_nonce_digest",
            "audience_digest",
            "authorization_context_digest",
            "credential_status",
            "key_binding_alg",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["credential_presentation_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_SD_JWT_VC_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SD-JWT VC presentation evidence is digest-bound credential evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SdJwtVcProjection | AgentWebCase::SdJwtVcReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "sd-jwt-vc-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "sd-jwt-vc-manifest.json",
            sd_jwt_vc_manifest,
        );
    }

    let bbs_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-bbs-valid",
        "source_protocol": "bbs",
        "source_version": "chio-receipt-bbs-v1",
        "external_fields_used": [
            "projection_profile",
            "proof_digest",
            "revealed_messages_digest",
            "hidden_messages_digest",
            "issuer_key_digest",
            "nonce_digest",
            "verifier_policy_digest",
            "receipt_digest",
            "authorization_context_digest",
            "disclosure_count",
            "hidden_count",
            "verification_status",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "bbs_proof_as_chio_authority",
            "vc_di_bbs_interop"
        ],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [
            UNSUPPORTED_BBS_AUTHORITY_CLAIM,
            UNSUPPORTED_VC_DI_BBS_INTEROP_CLAIM
        ],
        "copy_limitations": [
            "BBS receipt disclosure evidence is digest-bound Chio receipt evidence, not generic VC Data Integrity BBS interoperability or Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::BbsProjection | AgentWebCase::BbsReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "bbs-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "bbs-manifest.json",
            bbs_manifest,
        );
    }

    let sigstore_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-sigstore-valid",
        "source_protocol": "sigstore",
        "source_version": "bundle-v1",
        "external_fields_used": [
            "media_type",
            "bundle_digest",
            "artifact_digest",
            "certificate_identity_digest",
            "certificate_issuer_digest",
            "transparency_log_digest",
            "rekor_entry_digest",
            "signature_digest",
            "verification_material_digest",
            "slsa_provenance_digest",
            "authorization_context_digest",
            "predicate_type",
            "transparency_included",
            "verification_status",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["sigstore_bundle_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_SIGSTORE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Sigstore bundle evidence is digest-bound supply-chain evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SigstoreProjection | AgentWebCase::SigstoreReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "sigstore-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "sigstore-manifest.json",
            sigstore_manifest,
        );
    }

    let in_toto_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-in-toto-valid",
        "source_protocol": "in-toto",
        "source_version": "statement-v1-dsse",
        "external_fields_used": [
            "statement_type",
            "payload_type",
            "predicate_type",
            "dsse_envelope_digest",
            "payload_digest",
            "subject_digest",
            "predicate_digest",
            "builder_identity_digest",
            "signer_identity_digest",
            "verification_material_digest",
            "authorization_context_digest",
            "signature_count",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "in_toto_statement_as_chio_authority",
            "dsse_envelope_as_chio_authority"
        ],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [
            UNSUPPORTED_IN_TOTO_AUTHORITY_CLAIM,
            UNSUPPORTED_DSSE_AUTHORITY_CLAIM
        ],
        "copy_limitations": [
            "in-toto Statement and DSSE envelope evidence are digest-bound supply-chain evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::InTotoProjection | AgentWebCase::InTotoReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "in-toto-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "in-toto-manifest.json",
            in_toto_manifest,
        );
    }

    let dsse_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-dsse-valid",
        "source_protocol": "dsse",
        "source_version": "v1",
        "external_fields_used": [
            "payload_type",
            "payload_digest",
            "subject_digest",
            "signature_digest",
            "signer_identity_digest",
            "verification_material_digest",
            "authorization_context_digest",
            "signature_count",
            "verification_status"
        ],
        "external_fields_not_used": ["dsse_envelope_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_DSSE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "DSSE envelope evidence is digest-bound supply-chain envelope evidence, not Chio capability authority."
        ]
    }));
    if matches!(case, AgentWebCase::DsseProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "dsse-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "dsse-manifest.json",
            dsse_manifest,
        );
    }

    let slsa_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-slsa-valid",
        "source_protocol": "slsa-provenance",
        "source_version": "v1",
        "external_fields_used": [
            "predicate_type",
            "build_type",
            "builder_id_digest",
            "build_invocation_digest",
            "resolved_dependencies_digest",
            "materials_digest",
            "artifact_digest",
            "provenance_digest",
            "verification_material_digest",
            "authorization_context_digest",
            "build_started_on",
            "build_finished_on",
            "verification_status",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["slsa_provenance_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_SLSA_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SLSA provenance evidence is digest-bound build evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SlsaProjection | AgentWebCase::SlsaUnverified
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "slsa-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "slsa-manifest.json",
            slsa_manifest,
        );
    }

    let asyncapi_source_version = if matches!(case, AgentWebCase::AsyncApiUnsupportedVersion) {
        "2.6.0"
    } else {
        "3.0.0"
    };
    let asyncapi_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-asyncapi-valid",
        "source_protocol": "asyncapi",
        "source_version": asyncapi_source_version,
        "external_fields_used": [
            "spec_digest",
            "channel_digest",
            "message_digest",
            "payload_digest",
            "headers_digest",
            "broker_identity_digest",
            "authorization_context_digest",
            "operation_id",
            "channel",
            "direction",
            "protocol",
            "chio_message_receipt_ref"
        ],
        "external_fields_not_used": ["broker_acl_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_ASYNCAPI_AUTHORITY_CLAIM],
        "copy_limitations": [
            "AsyncAPI message evidence is digest-bound event contract evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::AsyncApiProjection
            | AgentWebCase::AsyncApiUnsupportedVersion
            | AgentWebCase::AsyncApiReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "asyncapi-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "asyncapi-manifest.json",
            asyncapi_manifest,
        );
    }

    let ap2_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-ap2-valid",
        "source_protocol": "ap2",
        "source_version": "0.2",
        "external_fields_used": [
            "transaction_passport_ref",
            "order_id",
            "credential_format",
            "checkout_mandate_digest",
            "payment_mandate_digest",
            "payment_instrument_digest",
            "transaction_context_digest",
            "agent_mode",
            "status",
            "chio_mandate_receipt_ref"
        ],
        "external_fields_not_used": ["mandate_signature_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_AP2_AUTHORITY_CLAIM],
        "copy_limitations": [
            "AP2 mandate evidence is digest-bound payment authorization evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::Ap2Projection
            | AgentWebCase::Ap2TransactionContextDigestMismatch
            | AgentWebCase::Ap2DetachedOrder
            | AgentWebCase::Ap2ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "ap2-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "ap2-manifest.json",
            ap2_manifest,
        );
    }

    let x402_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-x402-valid",
        "source_protocol": "x402",
        "source_version": "0.5",
        "external_fields_used": [
            "transaction_passport_ref",
            "order_id",
            "resource_digest",
            "payment_requirements_digest",
            "payment_proof_digest",
            "settlement_digest",
            "network",
            "asset",
            "amount_units",
            "status",
            "chio_payment_receipt_ref"
        ],
        "external_fields_not_used": ["payment_header_as_chio_authority"],
        "sidecar_fields": [
            "transaction_passport_ref",
            "receipt_refs",
            "chio_claim_refs"
        ],
        "digest_algorithm": "sha256",
        "signature_algorithm": "none",
        "requires_external_signature": false,
        "claim_mapping": [
            {
                "claim_ref": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "evidence_class": "digest-bound-reference"
            },
            {
                "claim_ref": CLAIM_PROJECTION_MANIFEST_BOUND,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "evidence_class": "chio-sidecar-proof"
            },
            {
                "claim_ref": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "evidence_class": "chio-sidecar-proof"
            }
        ],
        "unsupported_claims": [UNSUPPORTED_X402_AUTHORITY_CLAIM],
        "copy_limitations": [
            "x402 payment evidence is digest-bound payment protocol evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::X402Projection
            | AgentWebCase::X402AmountMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "external-projection-manifest",
            "x402-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "x402-manifest.json",
            x402_manifest,
        );
    }

    let cloudevents_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-cloudevents-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "cloudevents",
        "source_protocol_version": "1.0.2",
        "external_subject": "event-agent-web-001",
        "external_subject_path": "external/cloudevent.json",
        "external_subject_digest": chio_core_types::sha256_hex(&cloudevent),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-cloudevents-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-cloudevents-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "CloudEvents projection is digest-bound event evidence, not Chio capability authority."
        ],
        "signature": "sig-agent-web-cloudevents-envelope"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "agent-web-proof-envelope",
        "cloudevents-envelope",
        "chio.agent-web-proof-envelope.v1",
        "cloudevents-envelope.json",
        cloudevents_envelope,
    );

    let graphql_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-graphql-http-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "graphql-http",
        "source_protocol_version": graphql_source_version,
        "external_subject": "graphql-operation-agent-web-valid",
        "external_subject_path": "external/graphql-operation.json",
        "external_subject_digest": chio_core_types::sha256_hex(&graphql_operation),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-graphql-http-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-graphql-mutation-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "GraphQL over HTTP projection is digest-bound HTTP evidence, not Chio capability authority."
        ],
        "signature": "sig-agent-web-graphql-http-envelope"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "agent-web-proof-envelope",
        "graphql-http-envelope",
        "chio.agent-web-proof-envelope.v1",
        "graphql-http-envelope.json",
        graphql_envelope,
    );

    let mcp_claim_refs = match case {
        AgentWebCase::McpAuthorityClaimNotLimited => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
            UNSUPPORTED_MCP_AUTHORITY_CLAIM,
        ],
        _ => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
        ],
    };
    let mcp_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-mcp-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "mcp",
        "source_protocol_version": "2025-11-25",
        "external_subject": "mcp-tool-call-agent-web-valid",
        "external_subject_path": "external/mcp-tool-call.json",
        "external_subject_digest": chio_core_types::sha256_hex(&mcp_tool_call),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-mcp-valid",
        "chio_claim_refs": mcp_claim_refs,
        "receipt_refs": ["receipt-agent-web-mcp-tool-call-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "MCP tool-call projection does not make MCP authority equivalent to Chio receipts."
        ],
        "signature": "sig-agent-web-mcp-envelope"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "agent-web-proof-envelope",
        "mcp-envelope",
        "chio.agent-web-proof-envelope.v1",
        "mcp-envelope.json",
        mcp_envelope,
    );

    let a2a_claim_refs = match case {
        AgentWebCase::A2aAuthorityClaimNotLimited => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
            UNSUPPORTED_A2A_AUTHORITY_CLAIM,
        ],
        _ => vec![
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
        ],
    };
    let a2a_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-a2a-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "a2a",
        "source_protocol_version": "0.3.0",
        "external_subject": "a2a-task-agent-web-valid",
        "external_subject_path": "external/a2a-task.json",
        "external_subject_digest": chio_core_types::sha256_hex(&a2a_task),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-a2a-valid",
        "chio_claim_refs": a2a_claim_refs,
        "receipt_refs": ["receipt-agent-web-a2a-task-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "A2A task projection does not make task state equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-a2a-envelope"
    }));
    push_artifact(
        &mut artifacts,
        &mut graph_nodes,
        "agent-web-proof-envelope",
        "a2a-envelope",
        "chio.agent-web-proof-envelope.v1",
        "a2a-envelope.json",
        a2a_envelope,
    );

    let openapi_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-openapi-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "openapi",
        "source_protocol_version": openapi_source_version,
        "external_subject": "openapi-operation-agent-web-valid",
        "external_subject_path": "external/openapi-operation.json",
        "external_subject_digest": chio_core_types::sha256_hex(&openapi_operation),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-openapi-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-openapi-operation-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "OpenAPI projection does not make the HTTP operation equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-openapi-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::OpenApiProjection
            | AgentWebCase::OpenApiUnsupportedVersion
            | AgentWebCase::OpenApiReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "openapi-envelope",
            "chio.agent-web-proof-envelope.v1",
            "openapi-envelope.json",
            openapi_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-openapi-operation-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-openapi-operation-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-openapi-operation-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let acp_client_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-acp-client-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "acp-client",
        "source_protocol_version": "v1",
        "external_subject": "acp-client-permission-agent-web-valid",
        "external_subject_path": "external/acp-client-permission.json",
        "external_subject_digest": chio_core_types::sha256_hex(&acp_client_permission),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-acp-client-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-acp-client-permission-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "ACP-Client projection does not make client permission prompts equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-acp-client-envelope"
    }));
    if matches!(case, AgentWebCase::AcpClientProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "acp-client-envelope",
            "chio.agent-web-proof-envelope.v1",
            "acp-client-envelope.json",
            acp_client_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-acp-client-permission-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-acp-client-permission-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-acp-client-permission-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let acp_commerce_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-acp-commerce-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "acp-commerce",
        "source_protocol_version": "2026-06",
        "external_subject": "acp-commerce-checkout-agent-web-valid",
        "external_subject_path": "external/acp-commerce-checkout.json",
        "external_subject_digest": chio_core_types::sha256_hex(&acp_commerce_checkout),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-acp-commerce-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-acp-commerce-checkout-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "ACP-Commerce projection does not make payment protocol evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-acp-commerce-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::AcpCommerceProjection
            | AgentWebCase::AcpCommerceOrderContextDigestMismatch
            | AgentWebCase::AcpCommerceReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "acp-commerce-envelope",
            "chio.agent-web-proof-envelope.v1",
            "acp-commerce-envelope.json",
            acp_commerce_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-acp-commerce-checkout-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-acp-commerce-checkout-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-acp-commerce-checkout-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let ag_ui_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-ag-ui-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "ag-ui",
        "source_protocol_version": "events-v1",
        "external_subject": "ag-ui-event-agent-web-valid",
        "external_subject_path": "external/ag-ui-event.json",
        "external_subject_digest": chio_core_types::sha256_hex(&ag_ui_event),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-ag-ui-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-ag-ui-event-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "AG-UI projection does not make UI event evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-ag-ui-envelope"
    }));
    if matches!(case, AgentWebCase::AgUiProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "ag-ui-envelope",
            "chio.agent-web-proof-envelope.v1",
            "ag-ui-envelope.json",
            ag_ui_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-ag-ui-event-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-ag-ui-event-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-ag-ui-event-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let browser_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-browser-automation-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "browser-automation",
        "source_protocol_version": "webdriver-bidi-2026-06",
        "external_subject": "browser-command-agent-web-valid",
        "external_subject_path": "external/browser-command.json",
        "external_subject_digest": chio_core_types::sha256_hex(&browser_automation_command),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-browser-automation-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-browser-command-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "Browser automation projection does not make browser command evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-browser-automation-envelope"
    }));
    if matches!(case, AgentWebCase::BrowserAutomationProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "browser-automation-envelope",
            "chio.agent-web-proof-envelope.v1",
            "browser-automation-envelope.json",
            browser_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-browser-command-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-browser-command-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-browser-command-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let rpa_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-rpa-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "rpa",
        "source_protocol_version": "uia-2026-06",
        "external_subject": "rpa-transcript-agent-web-valid",
        "external_subject_path": "external/rpa-transcript.json",
        "external_subject_digest": chio_core_types::sha256_hex(&rpa_transcript),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-rpa-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-rpa-transcript-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "RPA projection does not make desktop automation evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-rpa-envelope"
    }));
    if matches!(case, AgentWebCase::RpaProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "rpa-envelope",
            "chio.agent-web-proof-envelope.v1",
            "rpa-envelope.json",
            rpa_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-rpa-transcript-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-rpa-transcript-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-rpa-transcript-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let email_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-gmail-api-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "gmail-api",
        "source_protocol_version": "v1",
        "external_subject": "email-message-agent-web-valid",
        "external_subject_path": "external/email-message.json",
        "external_subject_digest": chio_core_types::sha256_hex(&email_connector_action),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-gmail-api-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-email-message-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "Gmail projection does not make provider email evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-gmail-api-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::EmailProjection | AgentWebCase::EmailMissingMessageDigest
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "email-envelope",
            "chio.agent-web-proof-envelope.v1",
            "email-envelope.json",
            email_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-email-message-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-email-message-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-email-message-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let calendar_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-google-calendar-api-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "google-calendar-api",
        "source_protocol_version": "v1",
        "external_subject": "calendar-event-agent-web-valid",
        "external_subject_path": "external/calendar-event.json",
        "external_subject_digest": chio_core_types::sha256_hex(&calendar_connector_action),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-google-calendar-api-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-calendar-event-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "Google Calendar projection does not make provider calendar evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-google-calendar-api-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::CalendarProjection | AgentWebCase::CalendarTimeRangeMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "calendar-envelope",
            "chio.agent-web-proof-envelope.v1",
            "calendar-envelope.json",
            calendar_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-calendar-event-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-calendar-event-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-calendar-event-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let slack_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-slack-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "slack",
        "source_protocol_version": "web-api-2026-06",
        "external_subject": "slack-message-agent-web-valid",
        "external_subject_path": "external/slack-message.json",
        "external_subject_digest": chio_core_types::sha256_hex(&slack_connector_action),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-slack-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-slack-message-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "Slack projection does not make provider action evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-slack-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::SlackProjection | AgentWebCase::SlackOkFalse
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "slack-envelope",
            "chio.agent-web-proof-envelope.v1",
            "slack-envelope.json",
            slack_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-slack-message-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-slack-message-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-slack-message-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let oauth2_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-oauth2-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "oauth2",
        "source_protocol_version": "rfc6749",
        "external_subject": "oauth2-authorization-agent-web-valid",
        "external_subject_path": "external/oauth2-authorization.json",
        "external_subject_digest": chio_core_types::sha256_hex(&oauth2_authorization),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-oauth2-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-oauth2-authorization-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "OAuth2 projection does not make bearer admission evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-oauth2-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::OAuth2Projection
            | AgentWebCase::OAuth2WrongObjectKind
            | AgentWebCase::OAuth2ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "oauth2-envelope",
            "chio.agent-web-proof-envelope.v1",
            "oauth2-envelope.json",
            oauth2_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-oauth2-authorization-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-oauth2-authorization-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-oauth2-authorization-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let openid_connect_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-openid-connect-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "openid-connect",
        "source_protocol_version": "core-1.0",
        "external_subject": "openid-connect-identity-agent-web-valid",
        "external_subject_path": "external/openid-connect-identity.json",
        "external_subject_digest": chio_core_types::sha256_hex(&openid_connect_identity),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-openid-connect-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-openid-connect-identity-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "OpenID Connect projection does not make identity evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-openid-connect-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::OpenIdConnectProjection
            | AgentWebCase::OpenIdConnectWrongObjectKind
            | AgentWebCase::OpenIdConnectReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "openid-connect-envelope",
            "chio.agent-web-proof-envelope.v1",
            "openid-connect-envelope.json",
            openid_connect_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-openid-connect-identity-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-openid-connect-identity-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-openid-connect-identity-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let scim_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-scim-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "scim",
        "source_protocol_version": "rfc7644",
        "external_subject": "scim-lifecycle-agent-web-valid",
        "external_subject_path": "external/scim-lifecycle.json",
        "external_subject_digest": chio_core_types::sha256_hex(&scim_lifecycle_event),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-scim-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-scim-lifecycle-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "SCIM projection does not make lifecycle evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-scim-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::ScimProjection | AgentWebCase::ScimActiveLifecycleMissingReceiptRef
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "scim-envelope",
            "chio.agent-web-proof-envelope.v1",
            "scim-envelope.json",
            scim_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-scim-lifecycle-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-scim-lifecycle-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-scim-lifecycle-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let spiffe_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-spiffe-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "spiffe",
        "source_protocol_version": "workload-api-v1",
        "external_subject": "spiffe-workload-agent-web-valid",
        "external_subject_path": "external/spiffe-workload-identity.json",
        "external_subject_digest": chio_core_types::sha256_hex(&spiffe_workload_identity),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-spiffe-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-spiffe-workload-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "SPIFFE projection does not make workload identity evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-spiffe-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::SpiffeProjection
            | AgentWebCase::SpiffeReceiptRefMissing
            | AgentWebCase::SpiffeTrustDomainContainsPath
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "spiffe-envelope",
            "chio.agent-web-proof-envelope.v1",
            "spiffe-envelope.json",
            spiffe_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-spiffe-workload-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-spiffe-workload-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-spiffe-workload-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let kubernetes_admission_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-kubernetes-admission-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "kubernetes-admission",
        "source_protocol_version": "admissionreview-v1",
        "external_subject": "kubernetes-admission-agent-web-valid",
        "external_subject_path": "external/kubernetes-admission-review.json",
        "external_subject_digest": chio_core_types::sha256_hex(&kubernetes_admission_review),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-kubernetes-admission-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-kubernetes-admission-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "Kubernetes admission projection does not make cluster admission evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-kubernetes-admission-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::KubernetesAdmissionProjection | AgentWebCase::KubernetesAdmissionUidMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "kubernetes-admission-envelope",
            "chio.agent-web-proof-envelope.v1",
            "kubernetes-admission-envelope.json",
            kubernetes_admission_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-kubernetes-admission-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-kubernetes-admission-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-kubernetes-admission-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let oci_ref_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-oci-ref-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "oci",
        "source_protocol_version": "image-spec-v1",
        "external_subject": "oci-ref-agent-web-valid",
        "external_subject_path": "external/oci-ref.json",
        "external_subject_digest": chio_core_types::sha256_hex(&oci_artifact_ref),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-oci-ref-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-oci-ref-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "OCI projection does not make artifact reference evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-oci-ref-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::OciRefProjection | AgentWebCase::OciTagOnly
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "oci-ref-envelope",
            "chio.agent-web-proof-envelope.v1",
            "oci-ref-envelope.json",
            oci_ref_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-oci-ref-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-oci-ref-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-oci-ref-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let vc_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-vc-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "vc",
        "source_protocol_version": "vc-data-model-2.0",
        "external_subject": "vc-agent-web-valid",
        "external_subject_path": "external/verifiable-credential.json",
        "external_subject_digest": chio_core_types::sha256_hex(&verifiable_credential),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-vc-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-vc-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "VC projection does not make credential signature evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-vc-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::VcProjection | AgentWebCase::VcReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "vc-envelope",
            "chio.agent-web-proof-envelope.v1",
            "vc-envelope.json",
            vc_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-vc-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-vc-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-vc-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let sd_jwt_vc_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-sd-jwt-vc-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "sd-jwt-vc",
        "source_protocol_version": "v1",
        "external_subject": "sd-jwt-vc-presentation-agent-web-valid",
        "external_subject_path": "external/sd-jwt-vc-presentation.json",
        "external_subject_digest": chio_core_types::sha256_hex(&sd_jwt_vc_presentation),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-sd-jwt-vc-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-sd-jwt-vc-presentation-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "SD-JWT VC projection does not make credential presentation evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-sd-jwt-vc-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::SdJwtVcProjection | AgentWebCase::SdJwtVcReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "sd-jwt-vc-envelope",
            "chio.agent-web-proof-envelope.v1",
            "sd-jwt-vc-envelope.json",
            sd_jwt_vc_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-sd-jwt-vc-presentation-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-sd-jwt-vc-presentation-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-sd-jwt-vc-presentation-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let bbs_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-bbs-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "bbs",
        "source_protocol_version": "chio-receipt-bbs-v1",
        "external_subject": "bbs-receipt-disclosure-agent-web-valid",
        "external_subject_path": "external/bbs-receipt-disclosure.json",
        "external_subject_digest": chio_core_types::sha256_hex(&bbs_receipt_disclosure),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-bbs-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-bbs-disclosure-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "BBS projection does not make disclosure proof evidence equivalent to Chio authority or generic VC-DI-BBS interoperability."
        ],
        "signature": "sig-agent-web-bbs-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::BbsProjection | AgentWebCase::BbsReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "bbs-envelope",
            "chio.agent-web-proof-envelope.v1",
            "bbs-envelope.json",
            bbs_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-bbs-disclosure-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-bbs-disclosure-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-bbs-disclosure-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let sigstore_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-sigstore-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "sigstore",
        "source_protocol_version": "bundle-v1",
        "external_subject": "sigstore-bundle-agent-web-valid",
        "external_subject_path": "external/sigstore-bundle.json",
        "external_subject_digest": chio_core_types::sha256_hex(&sigstore_bundle),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-sigstore-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-sigstore-bundle-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "Sigstore projection does not make supply-chain signature evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-sigstore-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::SigstoreProjection | AgentWebCase::SigstoreReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "sigstore-envelope",
            "chio.agent-web-proof-envelope.v1",
            "sigstore-envelope.json",
            sigstore_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-sigstore-bundle-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-sigstore-bundle-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-sigstore-bundle-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let in_toto_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-in-toto-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "in-toto",
        "source_protocol_version": "statement-v1-dsse",
        "external_subject": "in-toto-statement-agent-web-valid",
        "external_subject_path": "external/in-toto-statement.json",
        "external_subject_digest": chio_core_types::sha256_hex(&in_toto_statement),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-in-toto-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-in-toto-statement-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "in-toto and DSSE projection does not make supply-chain statement evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-in-toto-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::InTotoProjection | AgentWebCase::InTotoReceiptRefMissing
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "in-toto-envelope",
            "chio.agent-web-proof-envelope.v1",
            "in-toto-envelope.json",
            in_toto_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-in-toto-statement-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-in-toto-statement-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-in-toto-statement-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let dsse_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-dsse-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "dsse",
        "source_protocol_version": "v1",
        "external_subject": "dsse-envelope-agent-web-valid",
        "external_subject_path": "external/dsse-envelope.json",
        "external_subject_digest": chio_core_types::sha256_hex(&dsse_envelope_subject),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-dsse-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-dsse-envelope-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "DSSE projection does not make signed envelope evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-dsse-envelope"
    }));
    if matches!(case, AgentWebCase::DsseProjection) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "dsse-envelope",
            "chio.agent-web-proof-envelope.v1",
            "dsse-envelope.json",
            dsse_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-dsse-envelope-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-dsse-envelope-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-dsse-envelope-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let slsa_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-slsa-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "slsa-provenance",
        "source_protocol_version": "v1",
        "external_subject": "slsa-provenance-agent-web-valid",
        "external_subject_path": "external/slsa-provenance.json",
        "external_subject_digest": chio_core_types::sha256_hex(&slsa_provenance),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-slsa-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-slsa-provenance-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "SLSA provenance projection does not make build provenance evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-slsa-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::SlsaProjection | AgentWebCase::SlsaUnverified
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "slsa-envelope",
            "chio.agent-web-proof-envelope.v1",
            "slsa-envelope.json",
            slsa_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-slsa-provenance-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-slsa-provenance-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-slsa-provenance-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let asyncapi_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-asyncapi-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "asyncapi",
        "source_protocol_version": asyncapi_source_version,
        "external_subject": "asyncapi-message-agent-web-valid",
        "external_subject_path": "external/asyncapi-message.json",
        "external_subject_digest": chio_core_types::sha256_hex(&asyncapi_message),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-asyncapi-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-asyncapi-message-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "AsyncAPI projection does not make message broker evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-asyncapi-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::AsyncApiProjection
            | AgentWebCase::AsyncApiUnsupportedVersion
            | AgentWebCase::AsyncApiReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "asyncapi-envelope",
            "chio.agent-web-proof-envelope.v1",
            "asyncapi-envelope.json",
            asyncapi_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-asyncapi-message-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-asyncapi-message-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-asyncapi-message-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let ap2_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-ap2-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "ap2",
        "source_protocol_version": "0.2",
        "external_subject": "ap2-mandate-chain-agent-web-valid",
        "external_subject_path": "external/ap2-mandate-chain.json",
        "external_subject_digest": chio_core_types::sha256_hex(&ap2_mandate_chain),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-ap2-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-ap2-mandate-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "AP2 projection does not make mandate evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-ap2-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::Ap2Projection
            | AgentWebCase::Ap2TransactionContextDigestMismatch
            | AgentWebCase::Ap2DetachedOrder
            | AgentWebCase::Ap2ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "ap2-envelope",
            "chio.agent-web-proof-envelope.v1",
            "ap2-envelope.json",
            ap2_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-ap2-mandate-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-ap2-mandate-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-ap2-mandate-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let x402_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v1",
        "envelope_id": "agent-web-envelope-x402-valid",
        "transaction_passport_ref": passport.id,
        "source_protocol": "x402",
        "source_protocol_version": "0.5",
        "external_subject": "x402-payment-agent-web-valid",
        "external_subject_path": "external/x402-payment.json",
        "external_subject_digest": chio_core_types::sha256_hex(&x402_payment),
        "external_subject_signature_ref": "",
        "projection_manifest_ref": "projection-x402-valid",
        "chio_claim_refs": [
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ],
        "receipt_refs": ["receipt-agent-web-x402-payment-allow"],
        "disclosure_capsule_refs": [],
        "settlement_refs": [],
        "risk_refs": [],
        "limitations": [
            "x402 projection does not make payment protocol evidence equivalent to Chio authority."
        ],
        "signature": "sig-agent-web-x402-envelope"
    }));
    if matches!(
        case,
        AgentWebCase::X402Projection
            | AgentWebCase::X402AmountMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
    ) {
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "agent-web-proof-envelope",
            "x402-envelope",
            "chio.agent-web-proof-envelope.v1",
            "x402-envelope.json",
            x402_envelope,
        );
        push_artifact(
            &mut artifacts,
            &mut graph_nodes,
            "receipt",
            "receipt-agent-web-x402-payment-allow",
            "chio.receipt.v1",
            "receipts/receipt-agent-web-x402-payment-allow.json",
            json_bytes(json!({
                "schema": "chio.receipt.v1",
                "receipt_id": "receipt-agent-web-x402-payment-allow",
                "terminal_status": "allowed_executed"
            })),
        );
    }

    let required_claims = match case {
        AgentWebCase::RequiredExternalAuthorityClaim => json!([
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
            UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM
        ]),
        _ => json!([
            CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
            CLAIM_PROJECTION_MANIFEST_BOUND,
            CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
            CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY
        ]),
    };
    let verifier_policy = json_bytes(json!({
        "schema": "chio.transaction.verifier-policy.v1",
        "id": "agent-web-policy-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "required_claims": required_claims,
        "omitted_claims": []
    }));
    let verifier_policy_sha256 = chio_core_types::sha256_hex(&verifier_policy);
    sign_agent_web_receipts(
        case,
        &mut artifacts,
        &mut graph_nodes,
        &verifier_policy_sha256,
    );

    let mut graph_edges = vec![
        json!({
            "from": "standard-webhooks-envelope",
            "to": "standard-webhooks-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "standard-webhooks-envelope",
            "to": "webhook-delivery",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "standard-webhooks-envelope",
            "to": "receipt-agent-web-webhook-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "cloudevents-envelope",
            "to": "cloudevents-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "cloudevents-envelope",
            "to": "cloudevents-event",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "cloudevents-envelope",
            "to": "receipt-agent-web-cloudevents-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "graphql-http-envelope",
            "to": "graphql-http-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "graphql-http-envelope",
            "to": "graphql-operation",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "graphql-http-envelope",
            "to": "receipt-agent-web-graphql-mutation-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "mcp-envelope",
            "to": "mcp-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "mcp-envelope",
            "to": "mcp-tool-call",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "mcp-envelope",
            "to": "receipt-agent-web-mcp-tool-call-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "a2a-envelope",
            "to": "a2a-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }),
        json!({
            "from": "a2a-envelope",
            "to": "a2a-task",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
        json!({
            "from": "a2a-envelope",
            "to": "receipt-agent-web-a2a-task-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
    ];
    if matches!(
        case,
        AgentWebCase::OpenApiProjection
            | AgentWebCase::OpenApiUnsupportedVersion
            | AgentWebCase::OpenApiReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "openapi-envelope",
            "to": "openapi-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "openapi-envelope",
            "to": "openapi-operation",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "openapi-envelope",
            "to": "receipt-agent-web-openapi-operation-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(case, AgentWebCase::AcpClientProjection) {
        graph_edges.push(json!({
            "from": "acp-client-envelope",
            "to": "acp-client-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "acp-client-envelope",
            "to": "acp-client-permission",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "acp-client-envelope",
            "to": "receipt-agent-web-acp-client-permission-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::AcpCommerceProjection
            | AgentWebCase::AcpCommerceOrderContextDigestMismatch
            | AgentWebCase::AcpCommerceReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "acp-commerce-envelope",
            "to": "acp-commerce-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "acp-commerce-envelope",
            "to": "acp-commerce-checkout",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "acp-commerce-envelope",
            "to": "receipt-agent-web-acp-commerce-checkout-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "acp-commerce-checkout",
            "to": "commerce-order-context",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(case, AgentWebCase::AgUiProjection) {
        graph_edges.push(json!({
            "from": "ag-ui-envelope",
            "to": "ag-ui-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "ag-ui-envelope",
            "to": "ag-ui-event",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "ag-ui-envelope",
            "to": "receipt-agent-web-ag-ui-event-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(case, AgentWebCase::BrowserAutomationProjection) {
        graph_edges.push(json!({
            "from": "browser-automation-envelope",
            "to": "browser-automation-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "browser-automation-envelope",
            "to": "browser-command",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "browser-automation-envelope",
            "to": "receipt-agent-web-browser-command-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(case, AgentWebCase::RpaProjection) {
        graph_edges.push(json!({
            "from": "rpa-envelope",
            "to": "rpa-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "rpa-envelope",
            "to": "rpa-transcript",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "rpa-envelope",
            "to": "receipt-agent-web-rpa-transcript-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::EmailProjection | AgentWebCase::EmailMissingMessageDigest
    ) {
        graph_edges.push(json!({
            "from": "email-envelope",
            "to": "email-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "email-envelope",
            "to": "email-message",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "email-envelope",
            "to": "receipt-agent-web-email-message-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::CalendarProjection | AgentWebCase::CalendarTimeRangeMismatch
    ) {
        graph_edges.push(json!({
            "from": "calendar-envelope",
            "to": "calendar-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "calendar-envelope",
            "to": "calendar-event",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "calendar-envelope",
            "to": "receipt-agent-web-calendar-event-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::SlackProjection | AgentWebCase::SlackOkFalse
    ) {
        graph_edges.push(json!({
            "from": "slack-envelope",
            "to": "slack-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "slack-envelope",
            "to": "slack-message",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "slack-envelope",
            "to": "receipt-agent-web-slack-message-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::OAuth2Projection
            | AgentWebCase::OAuth2WrongObjectKind
            | AgentWebCase::OAuth2ReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "oauth2-envelope",
            "to": "oauth2-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "oauth2-envelope",
            "to": "oauth2-authorization",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "oauth2-envelope",
            "to": "receipt-agent-web-oauth2-authorization-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::OpenIdConnectProjection
            | AgentWebCase::OpenIdConnectWrongObjectKind
            | AgentWebCase::OpenIdConnectReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "openid-connect-envelope",
            "to": "openid-connect-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "openid-connect-envelope",
            "to": "openid-connect-identity",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "openid-connect-envelope",
            "to": "receipt-agent-web-openid-connect-identity-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::ScimProjection | AgentWebCase::ScimActiveLifecycleMissingReceiptRef
    ) {
        graph_edges.push(json!({
            "from": "scim-envelope",
            "to": "scim-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "scim-envelope",
            "to": "scim-lifecycle",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "scim-envelope",
            "to": "receipt-agent-web-scim-lifecycle-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::SpiffeProjection
            | AgentWebCase::SpiffeReceiptRefMissing
            | AgentWebCase::SpiffeTrustDomainContainsPath
    ) {
        graph_edges.push(json!({
            "from": "spiffe-envelope",
            "to": "spiffe-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "spiffe-envelope",
            "to": "spiffe-workload-identity",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "spiffe-envelope",
            "to": "receipt-agent-web-spiffe-workload-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::KubernetesAdmissionProjection | AgentWebCase::KubernetesAdmissionUidMismatch
    ) {
        graph_edges.push(json!({
            "from": "kubernetes-admission-envelope",
            "to": "kubernetes-admission-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "kubernetes-admission-envelope",
            "to": "kubernetes-admission-review",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "kubernetes-admission-envelope",
            "to": "receipt-agent-web-kubernetes-admission-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::OciRefProjection | AgentWebCase::OciTagOnly
    ) {
        graph_edges.push(json!({
            "from": "oci-ref-envelope",
            "to": "oci-ref-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "oci-ref-envelope",
            "to": "oci-ref",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "oci-ref-envelope",
            "to": "receipt-agent-web-oci-ref-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::VcProjection | AgentWebCase::VcReceiptRefMissing
    ) {
        graph_edges.push(json!({
            "from": "vc-envelope",
            "to": "vc-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "vc-envelope",
            "to": "vc",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "vc-envelope",
            "to": "receipt-agent-web-vc-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::SdJwtVcProjection | AgentWebCase::SdJwtVcReceiptRefMissing
    ) {
        graph_edges.push(json!({
            "from": "sd-jwt-vc-envelope",
            "to": "sd-jwt-vc-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "sd-jwt-vc-envelope",
            "to": "sd-jwt-vc-presentation",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "sd-jwt-vc-envelope",
            "to": "receipt-agent-web-sd-jwt-vc-presentation-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::BbsProjection | AgentWebCase::BbsReceiptRefMissing
    ) {
        graph_edges.push(json!({
            "from": "bbs-envelope",
            "to": "bbs-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "bbs-envelope",
            "to": "bbs-receipt-disclosure",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "bbs-envelope",
            "to": "receipt-agent-web-bbs-disclosure-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::SigstoreProjection | AgentWebCase::SigstoreReceiptRefMissing
    ) {
        graph_edges.push(json!({
            "from": "sigstore-envelope",
            "to": "sigstore-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "sigstore-envelope",
            "to": "sigstore-bundle",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "sigstore-envelope",
            "to": "receipt-agent-web-sigstore-bundle-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::InTotoProjection | AgentWebCase::InTotoReceiptRefMissing
    ) {
        graph_edges.push(json!({
            "from": "in-toto-envelope",
            "to": "in-toto-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "in-toto-envelope",
            "to": "in-toto-statement",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "in-toto-envelope",
            "to": "receipt-agent-web-in-toto-statement-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(case, AgentWebCase::DsseProjection) {
        graph_edges.push(json!({
            "from": "dsse-envelope",
            "to": "dsse-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "dsse-envelope",
            "to": "dsse-envelope-subject",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "dsse-envelope",
            "to": "receipt-agent-web-dsse-envelope-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::SlsaProjection | AgentWebCase::SlsaUnverified
    ) {
        graph_edges.push(json!({
            "from": "slsa-envelope",
            "to": "slsa-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "slsa-envelope",
            "to": "slsa-provenance",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "slsa-envelope",
            "to": "receipt-agent-web-slsa-provenance-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::AsyncApiProjection
            | AgentWebCase::AsyncApiUnsupportedVersion
            | AgentWebCase::AsyncApiReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "asyncapi-envelope",
            "to": "asyncapi-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "asyncapi-envelope",
            "to": "asyncapi-message",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "asyncapi-envelope",
            "to": "receipt-agent-web-asyncapi-message-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
    }
    if matches!(
        case,
        AgentWebCase::Ap2Projection
            | AgentWebCase::Ap2TransactionContextDigestMismatch
            | AgentWebCase::Ap2DetachedOrder
            | AgentWebCase::Ap2ReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "ap2-envelope",
            "to": "ap2-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "ap2-envelope",
            "to": "ap2-mandate-chain",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "ap2-envelope",
            "to": "receipt-agent-web-ap2-mandate-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        if !matches!(case, AgentWebCase::Ap2DetachedOrder) {
            graph_edges.push(json!({
                "from": "ap2-mandate-chain",
                "to": "commerce-order-context",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            }));
        }
    }
    if matches!(
        case,
        AgentWebCase::X402Projection
            | AgentWebCase::X402AmountMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
    ) {
        graph_edges.push(json!({
            "from": "x402-envelope",
            "to": "x402-manifest",
            "predicate": "projects-to",
            "evidence_class": "chio-sidecar-proof"
        }));
        graph_edges.push(json!({
            "from": "x402-envelope",
            "to": "x402-payment",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        graph_edges.push(json!({
            "from": "x402-envelope",
            "to": "receipt-agent-web-x402-payment-allow",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }));
        if !matches!(case, AgentWebCase::X402DetachedOrder) {
            graph_edges.push(json!({
                "from": "x402-payment",
                "to": "commerce-order-context",
                "predicate": "binds",
                "evidence_class": "digest-bound-reference"
            }));
        }
    }
    match case {
        AgentWebCase::MissingManifestEdge => graph_edges.retain(|edge| {
            edge.get("from").and_then(Value::as_str) != Some("standard-webhooks-envelope")
                || edge.get("to").and_then(Value::as_str) != Some("standard-webhooks-manifest")
        }),
        AgentWebCase::MissingExternalSubjectEdge => graph_edges.retain(|edge| {
            edge.get("from").and_then(Value::as_str) != Some("standard-webhooks-envelope")
                || edge.get("to").and_then(Value::as_str) != Some("webhook-delivery")
        }),
        AgentWebCase::MissingReceiptRef | AgentWebCase::MissingReceiptEdge => {
            graph_edges.retain(|edge| {
                edge.get("from").and_then(Value::as_str) != Some("standard-webhooks-envelope")
                    || edge.get("to").and_then(Value::as_str)
                        != Some("receipt-agent-web-webhook-allow")
            })
        }
        _ => {}
    }
    let evidence_graph = json_bytes(json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "agent-web-evidence-graph-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "nodes": graph_nodes,
        "edges": graph_edges
    }));

    let mut passport = passport;
    passport.evidence_graph_sha256 = chio_core_types::sha256_hex(&evidence_graph);
    passport.verifier_policy_sha256 = verifier_policy_sha256;

    AgentWebInteropBundle {
        passport,
        evidence_graph_bytes: evidence_graph,
        verifier_policy_bytes: verifier_policy,
        artifacts,
    }
}

#[test]
fn published_agent_web_schemas_accept_supported_projection_fixtures() {
    let envelope_schema =
        read_workspace_json("spec/schemas/chio-agent-web/v1/proof-envelope.schema.json");
    let manifest_schema = read_workspace_json(
        "spec/schemas/chio-agent-web/v1/external-projection-manifest.schema.json",
    );

    for relative_path in agent_web_envelope_or_manifest_paths(
        "fixtures/proof-room/agent-web/valid-webhook-cloudevents",
    ) {
        if relative_path.ends_with("-envelope.json") {
            assert_schema_accepts_fixture(&envelope_schema, &relative_path);
        } else {
            assert_schema_accepts_fixture(&manifest_schema, &relative_path);
        }
    }
}

#[test]
fn published_agent_web_report_schema_accepts_verifier_output() {
    let report_schema =
        read_workspace_json("spec/schemas/chio-agent-web/v1/interop-verifier-report.schema.json");

    for case in [
        AgentWebCase::Valid,
        AgentWebCase::VcProjection,
        AgentWebCase::DsseProjection,
    ] {
        let bundle = agent_web_bundle(case);
        let report = verify_agent_web_interop(&bundle)
            .test_expect("valid Agent Web interop bundle should verify");
        let report_value =
            serde_json::to_value(report).test_expect("Agent Web verifier report serializes");

        assert_schema_accepts_value(&report_schema, &report_value, "Agent Web verifier report");
    }
}

#[test]
fn agent_web_interop_accepts_webhook_and_cloudevents_fixture() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);

    let report = verify_agent_web_interop(&bundle)
        .test_expect("valid Agent Web interop bundle should verify");

    assert_eq!(report.schema, "chio.agent-web.interop-verifier-report.v1");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.passport_id, "passport-agent-web-valid");
    assert_eq!(report.projections.len(), 5);
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "graphql-http"));
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "mcp"));
    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "a2a"));
    let graphql_projection = report
        .projections
        .iter()
        .find(|projection| projection.source_protocol == "graphql-http")
        .test_expect("GraphQL projection report is present");
    assert!(graphql_projection.claim_evidence.iter().any(|entry| {
        entry.claim_ref == CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND
            && entry.evidence_class == "digest-bound-reference"
    }));
    assert!(graphql_projection.claim_evidence.iter().any(|entry| {
        entry.claim_ref == CLAIM_PROJECTION_MANIFEST_BOUND
            && entry.evidence_class == "chio-sidecar-proof"
    }));
    assert!(report
        .verified_claims
        .contains(&CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_PROJECTION_MANIFEST_BOUND.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_UNSUPPORTED_CLAIMS_LIMITED.to_string()));
    assert!(report
        .verified_claims
        .contains(&CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_GRAPHQL_SUBSCRIPTION_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_GRAPHQL_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_MCP_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_A2A_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_external_digest_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::ExternalDigestMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external subject digest mismatch must fail");

    assert!(error
        .to_string()
        .contains("external subject digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_unresolved_receipt_ref() {
    let bundle = agent_web_bundle(AgentWebCase::MissingReceiptRef);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web receipt refs must resolve to evidence artifacts");

    assert!(error
        .to_string()
        .contains("missing Agent Web receipt ref: receipt-agent-web-webhook-allow"));
}

#[test]
fn agent_web_interop_rejects_bound_receipt_that_did_not_execute() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptDenied);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection must bind an executed Chio receipt");

    assert!(error
        .to_string()
        .contains("Agent Web receipt did not execute"));
}

#[test]
fn agent_web_interop_rejects_unsigned_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptUnsigned);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection must bind a signed Chio receipt");

    assert!(error
        .to_string()
        .contains("Agent Web receipt signature invalid"));
}

#[test]
fn agent_web_interop_rejects_bound_receipt_for_different_policy() {
    let bundle = agent_web_bundle(AgentWebCase::BoundReceiptPolicyHashMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external projection receipt must bind the verifier policy");

    assert!(error
        .to_string()
        .contains("Agent Web receipt policy digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_envelope_missing_required_sidecar_claim() {
    let bundle = agent_web_bundle(AgentWebCase::MissingRequiredSidecarClaim);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("required sidecar claims must be present in the envelope");

    assert!(error.to_string().contains(
        "Agent Web envelope missing required claim: claim.agent_web.sidecar_not_native_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_missing_manifest_binding_edge() {
    let bundle = agent_web_bundle(AgentWebCase::MissingManifestEdge);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("projection manifest must be bound by the evidence graph");

    assert!(error
        .to_string()
        .contains("missing Agent Web manifest binding edge"));
}

#[test]
fn agent_web_interop_rejects_missing_external_subject_binding_edge() {
    let bundle = agent_web_bundle(AgentWebCase::MissingExternalSubjectEdge);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external subject must be bound by the evidence graph");

    assert!(error
        .to_string()
        .contains("missing Agent Web external subject binding edge"));
}

#[test]
fn agent_web_interop_rejects_missing_receipt_binding_edge() {
    let bundle = agent_web_bundle(AgentWebCase::MissingReceiptEdge);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("receipt refs must be bound by the evidence graph");

    assert!(error
        .to_string()
        .contains("missing Agent Web receipt binding edge"));
}

#[test]
fn agent_web_interop_rejects_unbound_risk_refs() {
    let bundle = agent_web_bundle(AgentWebCase::UnboundRiskRef);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("risk refs must not pass unless verifier loads them");

    assert!(error
        .to_string()
        .contains("Agent Web risk refs are not verifier-bound"));
}

#[test]
fn agent_web_interop_rejects_required_signature_with_none_algorithm() {
    let bundle = agent_web_bundle(AgentWebCase::RequiredSignatureAlgorithmNone);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("required external signature must name a signature algorithm");

    assert!(error
        .to_string()
        .contains("Agent Web required signature cannot use none algorithm"));
}

#[test]
fn agent_web_interop_rejects_unused_signature_algorithm() {
    let bundle = agent_web_bundle(AgentWebCase::UnusedSignatureAlgorithmPresent);

    let error = verify_agent_web_interop(&bundle).test_expect_err(
        "signature algorithm must not be present when no external signature is required",
    );

    assert!(error
        .to_string()
        .contains("Agent Web signature algorithm present without external signature requirement"));
}

#[test]
fn agent_web_interop_rejects_unsupported_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::UnsupportedClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("unsupported external claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.webhook_signature_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_policy_required_external_authority_claim() {
    let bundle = agent_web_bundle(AgentWebCase::RequiredExternalAuthorityClaim);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("external authority claims cannot be required by policy");

    assert!(error.to_string().contains(
        "Agent Web policy requires unsupported external claim: claim.external.webhook_signature_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_sidecar_claim_marked_native() {
    let bundle = agent_web_bundle(AgentWebCase::SidecarClaimMarkedNative);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("sidecar Chio proof cannot be native external authority");

    assert!(error
        .to_string()
        .contains("sidecar claim presented as native external proof"));
}

#[test]
fn agent_web_interop_rejects_missing_required_signature() {
    let bundle = agent_web_bundle(AgentWebCase::MissingRequiredSignature);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("manifest-required external signature must be present");

    assert!(error.to_string().contains("missing external signature"));
}

#[test]
fn agent_web_interop_rejects_malformed_webhook_signature() {
    let bundle = agent_web_bundle(AgentWebCase::MalformedWebhookSignature);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks signature must use the v1 signature format");

    assert!(error
        .to_string()
        .contains("invalid Standard Webhooks signature"));
}

#[test]
fn agent_web_interop_rejects_missing_webhook_timestamp() {
    let bundle = agent_web_bundle(AgentWebCase::MissingWebhookTimestamp);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks timestamp is required");

    assert!(error
        .to_string()
        .contains("missing Standard Webhooks timestamp"));
}

#[test]
fn agent_web_interop_rejects_cloudevents_specversion_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::CloudEventsSpecVersionMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("CloudEvents specversion must match the projection version");

    assert!(error
        .to_string()
        .contains("CloudEvents specversion mismatch"));
}

#[test]
fn agent_web_interop_rejects_cloudevents_authority_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::CloudEventsAuthorityClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("CloudEvents authority claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.cloudevents_event_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_graphql_http_draft_version_missing() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlHttpDraftVersionMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL over HTTP projection must keep draft status visible");

    assert!(error
        .to_string()
        .contains("GraphQL over HTTP version must be draft-labeled"));
}

#[test]
fn agent_web_interop_rejects_graphql_errors_projected_as_success() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlErrorsProjectedAsSuccess);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL response errors must not verify as success");

    assert!(error
        .to_string()
        .contains("GraphQL response contains errors"));
}

#[test]
fn agent_web_interop_rejects_external_subject_schema_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::ExternalSubjectSchemaMismatch);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("external subject schema must match");

    assert!(error
        .to_string()
        .contains("external subject schema mismatch"));
}

#[test]
fn agent_web_interop_rejects_mcp_authority_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::McpAuthorityClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("MCP authority claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.mcp_tool_call_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_rejects_a2a_authority_claim_without_limitation() {
    let bundle = agent_web_bundle(AgentWebCase::A2aAuthorityClaimNotLimited);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("A2A authority claim must be explicitly limited");

    assert!(error.to_string().contains(
        "missing Agent Web unsupported authority limitation: claim.external.a2a_task_is_chio_authority"
    ));
}

#[test]
fn agent_web_interop_accepts_openapi_projection() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("OpenAPI projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "openapi"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_OPENAPI_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_unsupported_openapi_version() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiUnsupportedVersion);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("OpenAPI projection version is bounded");

    assert!(
        error
            .to_string()
            .contains("unsupported OpenAPI source version"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_unbound_operation_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI operation receipt ref must be bound");

    assert!(
        error
            .to_string()
            .contains("OpenAPI operation receipt ref is not bound"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_accepts_acp_client_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AcpClientProjection);

    let report =
        verify_agent_web_interop(&bundle).test_expect("ACP-Client projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "acp-client"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_ACP_CLIENT_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_acp_commerce_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceProjection);

    let report =
        verify_agent_web_interop(&bundle).test_expect("ACP-Commerce projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "acp-commerce"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_ACP_COMMERCE_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_acp_commerce_order_context_digest_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceOrderContextDigestMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("ACP-Commerce checkout must bind the order context digest");

    assert!(error
        .to_string()
        .contains("acp-commerce order context digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_acp_commerce_unbound_checkout_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("ACP-Commerce checkout receipt ref must be bound");

    assert!(
        error
            .to_string()
            .contains("ACP-Commerce checkout receipt ref is not bound"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_accepts_ag_ui_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AgUiProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("AG-UI projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "ag-ui"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_AG_UI_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_browser_automation_projection() {
    let bundle = agent_web_bundle(AgentWebCase::BrowserAutomationProjection);

    let report = verify_agent_web_interop(&bundle)
        .test_expect("browser automation projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "browser-automation"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_BROWSER_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_rpa_projection() {
    let bundle = agent_web_bundle(AgentWebCase::RpaProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("RPA projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "rpa"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_RPA_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_email_projection() {
    let bundle = agent_web_bundle(AgentWebCase::EmailProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("Email projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "gmail-api"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_EMAIL_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_email_send_without_message_digest() {
    let bundle = agent_web_bundle(AgentWebCase::EmailMissingMessageDigest);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Gmail send projection must bind the RFC 5322 message digest");

    assert!(error.to_string().contains("missing email message digest"));
}

#[test]
fn agent_web_interop_accepts_calendar_projection() {
    let bundle = agent_web_bundle(AgentWebCase::CalendarProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("Calendar projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "google-calendar-api"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_CALENDAR_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_calendar_time_range_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::CalendarTimeRangeMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Calendar update must match approved time range");

    assert!(error
        .to_string()
        .contains("Calendar time range changed after approval"));
}

#[test]
fn agent_web_interop_accepts_slack_projection() {
    let bundle = agent_web_bundle(AgentWebCase::SlackProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("Slack projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "slack"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_SLACK_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_slack_failed_provider_response() {
    let bundle = agent_web_bundle(AgentWebCase::SlackOkFalse);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Slack failed provider response must not verify");

    assert!(error
        .to_string()
        .contains("Slack response was not successful"));
}

#[test]
fn agent_web_interop_accepts_oauth2_projection() {
    let bundle = agent_web_bundle(AgentWebCase::OAuth2Projection);

    let report = verify_agent_web_interop(&bundle).test_expect("OAuth2 projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "oauth2"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_OAUTH2_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_oauth2_wrong_object_kind() {
    let bundle = agent_web_bundle(AgentWebCase::OAuth2WrongObjectKind);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OAuth2 projection must reject a wrong external object kind");

    assert!(error
        .to_string()
        .contains("OAuth2 external subject kind mismatch"));
}

#[test]
fn agent_web_interop_rejects_oauth2_unbound_authorization_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::OAuth2ReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OAuth2 authorization receipt must be bound to the envelope");

    assert!(error
        .to_string()
        .contains("OAuth2 authorization receipt ref is not bound"));
}

#[test]
fn agent_web_interop_accepts_openid_connect_projection() {
    let bundle = agent_web_bundle(AgentWebCase::OpenIdConnectProjection);

    let report =
        verify_agent_web_interop(&bundle).test_expect("OpenID Connect projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "openid-connect"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_OPENID_CONNECT_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_openid_connect_wrong_object_kind() {
    let bundle = agent_web_bundle(AgentWebCase::OpenIdConnectWrongObjectKind);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenID Connect projection must reject a wrong external object kind");

    assert!(error
        .to_string()
        .contains("OpenID Connect external subject kind mismatch"));
}

#[test]
fn agent_web_interop_rejects_openid_connect_unbound_identity_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::OpenIdConnectReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenID Connect identity receipt must be bound to the envelope");

    assert!(error
        .to_string()
        .contains("OpenID Connect identity receipt ref is not bound"));
}

#[test]
fn agent_web_interop_accepts_scim_projection() {
    let bundle = agent_web_bundle(AgentWebCase::ScimProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("SCIM projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "scim"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_SCIM_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_scim_active_lifecycle_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::ScimActiveLifecycleMissingReceiptRef);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("SCIM active lifecycle events must name a bound Chio receipt");

    assert!(error
        .to_string()
        .contains("missing SCIM lifecycle receipt ref"));
}

#[test]
fn agent_web_interop_accepts_spiffe_projection() {
    let bundle = agent_web_bundle(AgentWebCase::SpiffeProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("SPIFFE projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "spiffe"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_SPIFFE_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_spiffe_workload_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::SpiffeReceiptRefMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("SPIFFE workload identities must name a bound Chio receipt");

    assert!(
        error
            .to_string()
            .contains("missing SPIFFE workload receipt ref"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_spiffe_trust_domain_with_path() {
    let bundle = agent_web_bundle(AgentWebCase::SpiffeTrustDomainContainsPath);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("SPIFFE trust domain must not contain path segments");

    assert!(error
        .to_string()
        .contains("SPIFFE trust domain must not contain path"));
}

#[test]
fn agent_web_interop_accepts_kubernetes_admission_projection() {
    let bundle = agent_web_bundle(AgentWebCase::KubernetesAdmissionProjection);

    let report = verify_agent_web_interop(&bundle)
        .test_expect("Kubernetes admission projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "kubernetes-admission"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_KUBERNETES_ADMISSION_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_kubernetes_admission_uid_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::KubernetesAdmissionUidMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Kubernetes admission response UID must match request UID");

    assert!(error
        .to_string()
        .contains("Kubernetes admission response UID mismatch"));
}

#[test]
fn agent_web_interop_accepts_oci_ref_projection() {
    let bundle = agent_web_bundle(AgentWebCase::OciRefProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("OCI ref projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "oci"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_OCI_REF_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_oci_tag_only_ref() {
    let bundle = agent_web_bundle(AgentWebCase::OciTagOnly);

    let error = verify_agent_web_interop(&bundle).test_expect_err("OCI refs must be digest-pinned");

    assert!(error
        .to_string()
        .contains("OCI reference must be digest-pinned"));
}

#[test]
fn agent_web_interop_accepts_vc_projection() {
    let bundle = agent_web_bundle(AgentWebCase::VcProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("VC projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "vc"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_VC_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_sd_jwt_vc_projection() {
    let bundle = agent_web_bundle(AgentWebCase::SdJwtVcProjection);

    let report =
        verify_agent_web_interop(&bundle).test_expect("SD-JWT VC projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "sd-jwt-vc"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_SD_JWT_VC_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_vc_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::VcReceiptRefMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("VC projection must bind the credential receipt");

    assert!(error.to_string().contains("VC receipt ref is not bound"));
}

#[test]
fn agent_web_interop_rejects_sd_jwt_vc_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::SdJwtVcReceiptRefMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("SD-JWT VC projection must bind the presentation receipt");

    assert!(error
        .to_string()
        .contains("SD-JWT VC receipt ref is not bound"));
}

#[test]
fn agent_web_interop_accepts_bbs_projection() {
    let bundle = agent_web_bundle(AgentWebCase::BbsProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("BBS projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "bbs"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_BBS_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_VC_DI_BBS_INTEROP_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_bbs_receipt_disclosure_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::BbsReceiptRefMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("BBS receipt disclosures must name a bound Chio receipt");

    assert!(error.to_string().contains("missing BBS receipt refs"));
}

#[test]
fn agent_web_interop_accepts_sigstore_projection() {
    let bundle = agent_web_bundle(AgentWebCase::SigstoreProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("Sigstore projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "sigstore"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_SIGSTORE_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_sigstore_bundle_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::SigstoreReceiptRefMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Sigstore bundles must name a bound Chio receipt");

    assert!(
        error.to_string().contains("missing Sigstore receipt refs"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_accepts_in_toto_dsse_projection() {
    let bundle = agent_web_bundle(AgentWebCase::InTotoProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("in-toto projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "in-toto"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_IN_TOTO_AUTHORITY_CLAIM.to_string()));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_DSSE_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_in_toto_statement_without_bound_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::InTotoReceiptRefMissing);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("in-toto statements must name a bound Chio receipt");

    assert!(error.to_string().contains("missing in-toto receipt refs"));
}

#[test]
fn agent_web_interop_accepts_dsse_projection() {
    let bundle = agent_web_bundle(AgentWebCase::DsseProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("DSSE projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "dsse"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_DSSE_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_slsa_projection() {
    let bundle = agent_web_bundle(AgentWebCase::SlsaProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("SLSA projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "slsa-provenance"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_SLSA_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_unverified_slsa_provenance() {
    let bundle = agent_web_bundle(AgentWebCase::SlsaUnverified);

    let error = verify_agent_web_interop(&bundle).test_expect_err("SLSA provenance should fail");

    assert!(error
        .to_string()
        .contains("unsupported SLSA verification status"));
}

#[test]
fn agent_web_interop_accepts_asyncapi_projection() {
    let bundle = agent_web_bundle(AgentWebCase::AsyncApiProjection);

    let report = verify_agent_web_interop(&bundle).test_expect("AsyncAPI projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "asyncapi"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_ASYNCAPI_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_unsupported_asyncapi_version() {
    let bundle = agent_web_bundle(AgentWebCase::AsyncApiUnsupportedVersion);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("AsyncAPI projection version is bounded");

    assert!(error
        .to_string()
        .contains("unsupported AsyncAPI source version"));
}

#[test]
fn agent_web_interop_rejects_asyncapi_unbound_message_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::AsyncApiReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("AsyncAPI message receipt ref must be bound");

    assert!(error
        .to_string()
        .contains("AsyncAPI message receipt ref is not bound"));
}

#[test]
fn agent_web_interop_accepts_x402_projection() {
    let bundle = agent_web_bundle(AgentWebCase::X402Projection);

    let report = verify_agent_web_interop(&bundle).test_expect("x402 projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "x402"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_X402_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_accepts_ap2_projection() {
    let bundle = agent_web_bundle(AgentWebCase::Ap2Projection);

    let report = verify_agent_web_interop(&bundle).test_expect("AP2 projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "ap2"));
    assert!(report
        .unsupported_claims
        .contains(&UNSUPPORTED_AP2_AUTHORITY_CLAIM.to_string()));
}

#[test]
fn agent_web_interop_rejects_ap2_transaction_context_digest_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::Ap2TransactionContextDigestMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("AP2 mandate transaction context digest must match the bound order");

    assert!(error
        .to_string()
        .contains("ap2 transaction context digest mismatch"));
}

#[test]
fn agent_web_interop_rejects_ap2_mandate_detached_from_order() {
    let bundle = agent_web_bundle(AgentWebCase::Ap2DetachedOrder);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("AP2 mandate must bind to an order");

    assert!(error.to_string().contains("missing ap2 order binding"));
}

#[test]
fn agent_web_interop_rejects_ap2_unbound_mandate_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::Ap2ReceiptRefMismatch);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("AP2 mandate receipt ref must be bound");

    assert!(error
        .to_string()
        .contains("AP2 mandate receipt ref is not bound"));
}

#[test]
fn agent_web_interop_rejects_x402_payment_detached_from_order() {
    let bundle = agent_web_bundle(AgentWebCase::X402DetachedOrder);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("x402 payment must bind to an order");

    assert!(error.to_string().contains("missing x402 order binding"));
}

#[test]
fn agent_web_interop_rejects_x402_unbound_payment_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::X402ReceiptRefMismatch);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("x402 payment receipt ref must be bound");

    assert!(error
        .to_string()
        .contains("x402 payment receipt ref is not bound"));
}

#[test]
fn agent_web_interop_rejects_x402_payment_amount_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::X402AmountMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("x402 payment amount must match the bound order");

    assert!(error.to_string().contains("x402 payment amount mismatch"));
}
