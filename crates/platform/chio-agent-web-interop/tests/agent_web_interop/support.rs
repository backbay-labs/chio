use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_test_support::prelude::*;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use chio_agent_web_interop::{AgentWebInteropBundle, AgentWebInteropReport, AgentWebVerifierTrust};
use chio_core_types::{
    receipt::{
        body::{ChioReceipt, ChioReceiptBody},
        decision::{Decision, ToolCallAction},
        kinds::{BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel},
    },
    Keypair,
};
use chio_transaction_passport::TransactionPassport;

pub(crate) const CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND: &str =
    "claim.agent_web.external_subject_digest_bound";
pub(crate) const CLAIM_PROJECTION_MANIFEST_BOUND: &str =
    "claim.agent_web.projection_manifest_bound";
pub(crate) const CLAIM_UNSUPPORTED_CLAIMS_LIMITED: &str =
    "claim.agent_web.unsupported_claims_limited";
pub(crate) const CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY: &str =
    "claim.agent_web.sidecar_not_native_authority";
pub(crate) const UNSUPPORTED_WEBHOOK_AUTHORITY_CLAIM: &str =
    "claim.external.webhook_signature_is_chio_authority";
pub(crate) const UNSUPPORTED_CLOUDEVENTS_AUTHORITY_CLAIM: &str =
    "claim.external.cloudevents_event_is_chio_authority";
pub(crate) const UNSUPPORTED_GRAPHQL_SUBSCRIPTION_CLAIM: &str =
    "claim.external.graphql_http_subscription_coverage";
pub(crate) const UNSUPPORTED_GRAPHQL_AUTHORITY_CLAIM: &str =
    "claim.external.graphql_http_operation_is_chio_authority";
pub(crate) const UNSUPPORTED_MCP_AUTHORITY_CLAIM: &str =
    "claim.external.mcp_tool_call_is_chio_authority";
pub(crate) const UNSUPPORTED_A2A_AUTHORITY_CLAIM: &str =
    "claim.external.a2a_task_is_chio_authority";
pub(crate) const UNSUPPORTED_ACP_CLIENT_AUTHORITY_CLAIM: &str =
    "claim.external.acp_client_permission_is_chio_authority";
pub(crate) const UNSUPPORTED_ACP_COMMERCE_AUTHORITY_CLAIM: &str =
    "claim.external.acp_commerce_payment_is_chio_authority";
pub(crate) const UNSUPPORTED_AG_UI_AUTHORITY_CLAIM: &str =
    "claim.external.ag_ui_event_is_chio_authority";
pub(crate) const UNSUPPORTED_BROWSER_AUTHORITY_CLAIM: &str =
    "claim.external.browser_automation_is_chio_authority";
pub(crate) const UNSUPPORTED_RPA_AUTHORITY_CLAIM: &str =
    "claim.external.rpa_transcript_is_chio_authority";
pub(crate) const UNSUPPORTED_EMAIL_AUTHORITY_CLAIM: &str =
    "claim.external.email_action_is_chio_authority";
pub(crate) const UNSUPPORTED_CALENDAR_AUTHORITY_CLAIM: &str =
    "claim.external.calendar_action_is_chio_authority";
pub(crate) const UNSUPPORTED_SLACK_AUTHORITY_CLAIM: &str =
    "claim.external.slack_action_is_chio_authority";
pub(crate) const UNSUPPORTED_OAUTH2_AUTHORITY_CLAIM: &str =
    "claim.external.oauth2_token_is_chio_authority";
pub(crate) const UNSUPPORTED_OPENID_CONNECT_AUTHORITY_CLAIM: &str =
    "claim.external.openid_connect_identity_is_chio_authority";
pub(crate) const UNSUPPORTED_SCIM_AUTHORITY_CLAIM: &str =
    "claim.external.scim_lifecycle_is_chio_authority";
pub(crate) const UNSUPPORTED_SPIFFE_AUTHORITY_CLAIM: &str =
    "claim.external.spiffe_workload_identity_is_chio_authority";
pub(crate) const UNSUPPORTED_KUBERNETES_ADMISSION_AUTHORITY_CLAIM: &str =
    "claim.external.kubernetes_admission_is_chio_authority";
pub(crate) const UNSUPPORTED_OCI_REF_AUTHORITY_CLAIM: &str =
    "claim.external.oci_ref_is_chio_authority";
pub(crate) const UNSUPPORTED_VC_AUTHORITY_CLAIM: &str = "claim.external.vc_is_chio_authority";
pub(crate) const UNSUPPORTED_SD_JWT_VC_AUTHORITY_CLAIM: &str =
    "claim.external.sd_jwt_vc_is_chio_authority";
pub(crate) const UNSUPPORTED_SIGSTORE_AUTHORITY_CLAIM: &str =
    "claim.external.sigstore_bundle_is_chio_authority";
pub(crate) const UNSUPPORTED_IN_TOTO_AUTHORITY_CLAIM: &str =
    "claim.external.in_toto_statement_is_chio_authority";
pub(crate) const UNSUPPORTED_DSSE_AUTHORITY_CLAIM: &str =
    "claim.external.dsse_envelope_is_chio_authority";
pub(crate) const UNSUPPORTED_SLSA_AUTHORITY_CLAIM: &str =
    "claim.external.slsa_provenance_is_chio_authority";
pub(crate) const UNSUPPORTED_BBS_AUTHORITY_CLAIM: &str =
    "claim.external.bbs_proof_is_chio_authority";
pub(crate) const UNSUPPORTED_VC_DI_BBS_INTEROP_CLAIM: &str =
    "claim.external.vc_di_bbs_interop_verified";
pub(crate) const UNSUPPORTED_OPENAPI_AUTHORITY_CLAIM: &str =
    "claim.external.openapi_operation_is_chio_authority";
pub(crate) const UNSUPPORTED_ASYNCAPI_AUTHORITY_CLAIM: &str =
    "claim.external.asyncapi_message_is_chio_authority";
pub(crate) const UNSUPPORTED_AP2_AUTHORITY_CLAIM: &str =
    "claim.external.ap2_mandate_is_chio_authority";
pub(crate) const UNSUPPORTED_X402_AUTHORITY_CLAIM: &str =
    "claim.external.x402_payment_is_chio_authority";
pub(crate) const STANDARD_WEBHOOKS_WEBHOOK_ID: &str = "msg_agent_web_001";
pub(crate) const STANDARD_WEBHOOKS_TIMESTAMP: &str = "1770508800";
pub(crate) const STANDARD_WEBHOOKS_ENDPOINT_URL_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) const STANDARD_WEBHOOKS_BODY_DIGEST: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

type HmacSha256 = Hmac<Sha256>;

pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &[u8] =
    b"chio-agent-web-standard-webhooks-fixture-secret-v1";
const FORGED_STANDARD_WEBHOOKS_SIGNATURE_REF: &str =
    "v1,Zm9yZ2VkLXN0YW5kYXJkLXdlYmhvb2tzLXNpZ25hdHVyZQ==";

pub(crate) fn agent_web_fixture_trust() -> AgentWebVerifierTrust {
    AgentWebVerifierTrust::new().with_standard_webhooks_secret_for(
        STANDARD_WEBHOOKS_WEBHOOK_ID,
        STANDARD_WEBHOOKS_VERIFIER_SECRET.to_vec(),
    )
}

pub(crate) fn verify_agent_web_interop(
    bundle: &AgentWebInteropBundle,
) -> Result<AgentWebInteropReport, chio_transaction_passport::TransactionPassportError> {
    chio_agent_web_interop::verify_agent_web_interop_with_trust(bundle, &agent_web_fixture_trust())
}

pub(crate) fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|platform_dir| platform_dir.parent())
        .and_then(|crates_dir| crates_dir.parent())
        .test_expect("workspace root is parent of crates/platform/chio-agent-web-interop")
        .to_path_buf()
}

pub(crate) fn standard_webhooks_timestamp_for_case(case: AgentWebCase) -> &'static str {
    match case {
        AgentWebCase::MissingWebhookTimestamp => "",
        _ => STANDARD_WEBHOOKS_TIMESTAMP,
    }
}

pub(crate) fn standard_webhooks_signature_ref_for_case(case: AgentWebCase) -> String {
    match case {
        AgentWebCase::MalformedWebhookSignature => "standard-webhooks-signature".to_string(),
        AgentWebCase::ForgedWebhookSignature => FORGED_STANDARD_WEBHOOKS_SIGNATURE_REF.to_string(),
        _ => standard_webhooks_signature_ref(standard_webhooks_timestamp_for_case(case)),
    }
}

fn standard_webhooks_signature_ref(webhook_timestamp: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(STANDARD_WEBHOOKS_VERIFIER_SECRET)
        .test_expect("Standard Webhooks test secret initializes HMAC");
    mac.update(STANDARD_WEBHOOKS_WEBHOOK_ID.as_bytes());
    mac.update(b".");
    mac.update(webhook_timestamp.as_bytes());
    mac.update(b".");
    mac.update(STANDARD_WEBHOOKS_BODY_DIGEST.as_bytes());
    mac.update(b".");
    mac.update(STANDARD_WEBHOOKS_ENDPOINT_URL_DIGEST.as_bytes());
    format!("v1,{}", STANDARD.encode(mac.finalize().into_bytes()))
}

pub(crate) fn read_workspace_json(relative_path: &str) -> Value {
    let bytes = std::fs::read(workspace_root().join(relative_path)).test_expect("json file reads");
    serde_json::from_slice(&bytes).test_expect("json file parses")
}

pub(crate) fn assert_schema_accepts_fixture(schema: &Value, relative_path: &str) {
    let value = read_workspace_json(relative_path);
    assert_schema_accepts_value(schema, &value, relative_path);
}

pub(crate) fn assert_schema_accepts_value(schema: &Value, value: &Value, label: &str) {
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

pub(crate) fn agent_web_envelope_or_manifest_paths(relative_dir: &str) -> Vec<String> {
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
pub(crate) enum AgentWebCase {
    Valid,
    ExternalDigestMismatch,
    UnsupportedClaimNotLimited,
    RequiredExternalAuthorityClaim,
    SidecarClaimMarkedNative,
    MissingRequiredSignature,
    MalformedWebhookSignature,
    ForgedWebhookSignature,
    MissingWebhookTimestamp,
    CloudEventsAuthorityClaimNotLimited,
    CloudEventsSpecVersionMismatch,
    GraphqlHttpDraftVersionMissing,
    GraphqlErrorsProjectedAsSuccess,
    GraphqlHttpFailedStatus,
    ExternalSubjectSchemaMismatch,
    McpAuthorityClaimNotLimited,
    A2aAuthorityClaimNotLimited,
    A2aFailedTaskState,
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
    OpenApiFailedStatus,
    AcpClientProjection,
    AcpClientDenied,
    AcpCommerceProjection,
    AcpCommerceOrderContextDigestMismatch,
    AcpCommerceReceiptRefMismatch,
    AcpCommerceRefunded,
    AgUiProjection,
    AgUiDenied,
    BrowserAutomationProjection,
    RpaProjection,
    EmailProjection,
    EmailMissingMessageDigest,
    CalendarProjection,
    CalendarTimeRangeMismatch,
    CalendarCreateTimeRangeMismatch,
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
    X402AssetMismatch,
    X402DetachedOrder,
    X402ReceiptRefMismatch,
    X402Refunded,
}

pub(crate) fn json_bytes(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).test_expect("test json serializes")
}

pub(crate) fn graphql_source_version(case: AgentWebCase) -> &'static str {
    match case {
        AgentWebCase::GraphqlHttpDraftVersionMissing => "1.0.0",
        _ => "draft-2026-06-04",
    }
}

pub(crate) fn openapi_source_version(case: AgentWebCase) -> &'static str {
    match case {
        AgentWebCase::OpenApiUnsupportedVersion => "2.0",
        _ => "3.1.0",
    }
}

pub(crate) fn asyncapi_source_version(case: AgentWebCase) -> &'static str {
    match case {
        AgentWebCase::AsyncApiUnsupportedVersion => "2.6.0",
        _ => "3.0.0",
    }
}

pub(crate) fn push_artifact(
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

pub(crate) fn sign_agent_web_receipts(
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

pub(crate) fn agent_web_receipt_subject_path(receipt_id: &str) -> Option<&'static str> {
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

pub(crate) fn signed_agent_web_receipt_bytes(
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

pub(crate) struct AgentWebBundleBuilder {
    pub(crate) case: AgentWebCase,
    pub(crate) passport: TransactionPassport,
    pub(crate) artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) raw_artifacts: BTreeMap<String, Vec<u8>>,
    pub(crate) graph_nodes: Vec<Value>,
}

impl AgentWebBundleBuilder {
    pub(crate) fn new(case: AgentWebCase) -> Self {
        Self {
            case,
            passport: TransactionPassport {
                schema: "chio.transaction-passport.v1".to_string(),
                id: "passport-agent-web-valid".to_string(),
                issued_at: "2026-06-10T00:00:00Z".to_string(),
                evidence_graph_sha256: String::new(),
                evidence_graph_path: "evidence-graph.json".to_string(),
                verifier_policy_sha256: String::new(),
                verifier_policy_path: "verifier-policy.json".to_string(),
            },
            artifacts: BTreeMap::new(),
            raw_artifacts: BTreeMap::new(),
            graph_nodes: Vec::new(),
        }
    }

    pub(crate) fn artifact_bytes(&self, path: &str) -> Vec<u8> {
        self.artifacts
            .get(path)
            .or_else(|| self.raw_artifacts.get(path))
            .unwrap_or_else(|| panic!("test fixture artifact missing: {path}"))
            .clone()
    }
}

pub(crate) fn agent_web_bundle(case: AgentWebCase) -> AgentWebInteropBundle {
    let mut builder = AgentWebBundleBuilder::new(case);
    super::subjects::add_external_subject_artifacts(&mut builder);
    super::manifests_core::add_core_projection_manifests(&mut builder);
    super::manifests_extended::add_extended_projection_manifests(&mut builder);
    super::envelopes::add_projection_envelopes(&mut builder);
    super::policy_graph::finish_agent_web_bundle(builder)
}
