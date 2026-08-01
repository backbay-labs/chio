use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chio_test_support::prelude::*;
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;

use chio_agent_web_interop::{
    AgentWebInteropBundle, AgentWebInteropReport, AgentWebVerifierTrust,
    InMemoryAgentWebReplayStore,
};
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
pub(crate) const STALE_STANDARD_WEBHOOKS_TIMESTAMP: &str = "1770508200";
pub(crate) const STANDARD_WEBHOOKS_VERIFIER_NOW: u64 = 1_770_508_860;
pub(crate) const STANDARD_WEBHOOKS_MAX_AGE_SECONDS: u64 = 300;
pub(crate) const STANDARD_WEBHOOKS_ENDPOINT_URL_DIGEST: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub(crate) const STANDARD_WEBHOOKS_BODY_DIGEST: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

type HmacSha256 = Hmac<Sha256>;

pub(crate) const STANDARD_WEBHOOKS_VERIFIER_SECRET: &[u8] =
    b"chio-agent-web-standard-webhooks-fixture-secret-v1";
const TRANSACTION_PASSPORT_SIGNATURE_SEED: [u8; 32] = [7; 32];
pub(crate) const AGENT_WEB_FIXTURE_SIDECAR_SIGNATURE_SEED: [u8; 32] = [17; 32];
pub(crate) const AGENT_WEB_FIXTURE_KERNEL_SIGNATURE_SEED: [u8; 32] = [18; 32];
const FORGED_STANDARD_WEBHOOKS_SIGNATURE_REF: &str =
    "v1,Zm9yZ2VkLXN0YW5kYXJkLXdlYmhvb2tzLXNpZ25hdHVyZQ==";

pub(crate) fn agent_web_fixture_trust() -> AgentWebVerifierTrust {
    AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys([transaction_passport_keypair().public_key()])
        .with_standard_webhooks_secret_for(
            STANDARD_WEBHOOKS_WEBHOOK_ID,
            STANDARD_WEBHOOKS_VERIFIER_SECRET.to_vec(),
        )
        .with_standard_webhooks_replay_window(
            STANDARD_WEBHOOKS_VERIFIER_NOW,
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
        )
        .with_standard_webhooks_replay_store(Arc::new(InMemoryAgentWebReplayStore::new()))
        .with_trusted_receipt_kernel_keys([agent_web_fixture_kernel_keypair().public_key()])
        .with_trusted_envelope_sidecar_keys([agent_web_fixture_sidecar_keypair().public_key()])
}

pub(crate) fn transaction_passport_keypair() -> Keypair {
    Keypair::from_seed(&TRANSACTION_PASSPORT_SIGNATURE_SEED)
}

pub(crate) fn sign_transaction_passport(passport: &mut TransactionPassport) {
    let keypair = transaction_passport_keypair();
    passport.issuer = format!("did:chio:{}", keypair.public_key().to_hex());
    passport.signature = String::new();
    passport.signature = chio_transaction_passport::sign_transaction_passport(passport, &keypair)
        .test_expect("transaction passport signs");
}

pub(crate) fn agent_web_fixture_sidecar_keypair() -> Keypair {
    Keypair::from_seed(&AGENT_WEB_FIXTURE_SIDECAR_SIGNATURE_SEED)
}

pub(crate) fn agent_web_fixture_kernel_keypair() -> Keypair {
    Keypair::from_seed(&AGENT_WEB_FIXTURE_KERNEL_SIGNATURE_SEED)
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
        AgentWebCase::StaleWebhookTimestamp => STALE_STANDARD_WEBHOOKS_TIMESTAMP,
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

pub(crate) fn assert_schema_rejects_value(schema: &Value, value: &Value, label: &str) {
    let validator = jsonschema::validator_for(schema).test_expect("schema compiles");
    assert!(
        !validator.is_valid(value),
        "schema unexpectedly accepted Agent Web artifact {label}"
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
    StaleWebhookTimestamp,
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
    BoundReceiptProducerServerMismatch,
    BoundReceiptProducerToolMismatch,
    BoundReceiptActionRefMismatch,
    BoundReceiptActionContentHashMismatch,
    BoundReceiptActionPassportIdMismatch,
    BoundReceiptActionPassportIssuerMismatch,
    BoundReceiptActionEnvelopeIdMismatch,
    BoundReceiptActionProjectionManifestMismatch,
    BoundReceiptActionSourceProtocolMismatch,
    BoundReceiptActionSourceProtocolVersionMismatch,
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
    BrowserAutomationReceiptRefMismatch,
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
    BbsSelfAssertedVerified,
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

pub(crate) fn content_address_graph_nodes(graph_nodes: &mut [Value], graph_edges: &mut [Value]) {
    let rewrites = graph_nodes
        .iter()
        .filter_map(|node| {
            let semantic_id = node.get("id").and_then(Value::as_str)?;
            let sha256 = node.get("sha256").and_then(Value::as_str)?;
            Some((semantic_id.to_string(), sha256.to_string()))
        })
        .collect::<BTreeMap<_, _>>();

    for node in graph_nodes {
        let sha256 = node
            .get("sha256")
            .and_then(Value::as_str)
            .test_expect("Agent Web graph node has digest")
            .to_string();
        node["id"] = Value::String(sha256);
    }

    for edge in graph_edges {
        for endpoint in ["from", "to"] {
            let Some(current) = edge.get(endpoint).and_then(Value::as_str) else {
                continue;
            };
            let Some(rewritten) = rewrites.get(current) else {
                continue;
            };
            edge[endpoint] = Value::String(rewritten.clone());
        }
    }
}

pub(crate) fn sign_agent_web_receipts(
    case: AgentWebCase,
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut [Value],
    policy_hash: &str,
    passport_id: &str,
    passport_issuer: &str,
    passport_scope_sha256: &str,
) {
    let receipt_intents = agent_web_receipt_intents(
        artifacts,
        graph_nodes,
        passport_id,
        passport_issuer,
        passport_scope_sha256,
    );
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
            case,
            receipt_id,
            &chio_core_types::sha256_hex(subject_bytes),
            receipt_policy_hash,
            terminal_status == "allowed_executed",
            receipt_intents
                .get(receipt_id)
                .test_expect("Agent Web receipt resolves to one envelope"),
        );
        let sha256 = chio_core_types::sha256_hex(&receipt_bytes);
        artifacts.insert(path.to_string(), receipt_bytes);
        node["sha256"] = Value::String(sha256);
    }
}

#[derive(Clone)]
pub(crate) struct AgentWebReceiptIntent {
    pub(crate) passport_id: String,
    pub(crate) passport_issuer: String,
    pub(crate) passport_scope_sha256: String,
    pub(crate) envelope_id: String,
    pub(crate) projection_manifest_sha256: String,
    pub(crate) source_protocol: String,
    pub(crate) source_protocol_version: String,
}

fn agent_web_receipt_intents(
    artifacts: &BTreeMap<String, Vec<u8>>,
    graph_nodes: &[Value],
    passport_id: &str,
    passport_issuer: &str,
    passport_scope_sha256: &str,
) -> BTreeMap<String, AgentWebReceiptIntent> {
    let mut intents = BTreeMap::new();
    for node in graph_nodes {
        if node.get("role").and_then(Value::as_str) != Some("agent-web-proof-envelope") {
            continue;
        }
        let path = node
            .get("path")
            .and_then(Value::as_str)
            .test_expect("Agent Web envelope node has path");
        let envelope: Value = serde_json::from_slice(
            artifacts
                .get(path)
                .test_expect("Agent Web envelope artifact exists"),
        )
        .test_expect("Agent Web envelope parses");
        let intent = AgentWebReceiptIntent {
            passport_id: passport_id.to_string(),
            passport_issuer: passport_issuer.to_string(),
            passport_scope_sha256: passport_scope_sha256.to_string(),
            envelope_id: envelope
                .get("envelope_id")
                .and_then(Value::as_str)
                .test_expect("Agent Web envelope has id")
                .to_string(),
            projection_manifest_sha256: envelope
                .get("projection_manifest_sha256")
                .and_then(Value::as_str)
                .test_expect("Agent Web envelope has projection manifest digest")
                .to_string(),
            source_protocol: envelope
                .get("source_protocol")
                .and_then(Value::as_str)
                .test_expect("Agent Web envelope has source protocol")
                .to_string(),
            source_protocol_version: envelope
                .get("source_protocol_version")
                .and_then(Value::as_str)
                .test_expect("Agent Web envelope has source protocol version")
                .to_string(),
        };
        let receipt_refs = envelope
            .get("receipt_refs")
            .and_then(Value::as_array)
            .test_expect("Agent Web envelope has receipt refs");
        for receipt_ref in receipt_refs {
            let receipt_ref = receipt_ref
                .as_str()
                .test_expect("Agent Web envelope receipt ref is a string");
            assert!(
                intents
                    .insert(receipt_ref.to_string(), intent.clone())
                    .is_none(),
                "Agent Web receipt ref must resolve to one envelope: {receipt_ref}"
            );
        }
    }
    intents
}

pub(crate) fn sign_agent_web_envelopes(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut [Value],
    passport_scope_sha256: &str,
) {
    let keypair = agent_web_fixture_sidecar_keypair();
    let public_key = keypair.public_key().to_hex();
    for node in graph_nodes {
        if node.get("role").and_then(Value::as_str) != Some("agent-web-proof-envelope") {
            continue;
        }
        let path = node
            .get("path")
            .and_then(Value::as_str)
            .test_expect("Agent Web envelope node has path")
            .to_string();
        let mut envelope: Value = serde_json::from_slice(
            artifacts
                .get(&path)
                .test_expect("Agent Web envelope artifact exists"),
        )
        .test_expect("Agent Web envelope parses");
        envelope["agent_web_passport_scope_sha256"] =
            Value::String(passport_scope_sha256.to_string());
        sign_agent_web_envelope_value(&mut envelope, &keypair, &public_key);
        let envelope_bytes = json_bytes(envelope);
        node["sha256"] = Value::String(chio_core_types::sha256_hex(&envelope_bytes));
        artifacts.insert(path, envelope_bytes);
    }
}

pub(crate) fn bind_agent_web_envelope_manifest_digests(
    artifacts: &mut BTreeMap<String, Vec<u8>>,
    graph_nodes: &mut [Value],
) {
    let mut manifest_digests = BTreeMap::new();
    for node in graph_nodes.iter() {
        if node.get("role").and_then(Value::as_str) != Some("external-projection-manifest") {
            continue;
        }
        let path = node
            .get("path")
            .and_then(Value::as_str)
            .test_expect("Agent Web manifest node has path");
        let manifest: Value = serde_json::from_slice(
            artifacts
                .get(path)
                .test_expect("Agent Web manifest artifact exists"),
        )
        .test_expect("Agent Web manifest parses");
        let projection_id = manifest
            .get("projection_id")
            .and_then(Value::as_str)
            .test_expect("Agent Web manifest has projection id");
        let digest = node
            .get("sha256")
            .and_then(Value::as_str)
            .test_expect("Agent Web manifest node has digest");
        manifest_digests.insert(projection_id.to_string(), digest.to_string());
    }

    for node in graph_nodes {
        if node.get("role").and_then(Value::as_str) != Some("agent-web-proof-envelope") {
            continue;
        }
        let path = node
            .get("path")
            .and_then(Value::as_str)
            .test_expect("Agent Web envelope node has path")
            .to_string();
        let mut envelope: Value = serde_json::from_slice(
            artifacts
                .get(&path)
                .test_expect("Agent Web envelope artifact exists"),
        )
        .test_expect("Agent Web envelope parses");
        let manifest_ref = envelope
            .get("projection_manifest_ref")
            .and_then(Value::as_str)
            .test_expect("Agent Web envelope has manifest ref");
        let manifest_digest = manifest_digests
            .get(manifest_ref)
            .test_expect("Agent Web envelope manifest ref resolves");
        envelope["projection_manifest_sha256"] = Value::String(manifest_digest.clone());
        let envelope_bytes = json_bytes(envelope);
        node["sha256"] = Value::String(chio_core_types::sha256_hex(&envelope_bytes));
        artifacts.insert(path, envelope_bytes);
    }
}

fn agent_web_envelope_signature_payload(envelope: &Value) -> Value {
    let mut fields = vec![
        "schema",
        "envelope_id",
        "transaction_passport_ref",
        "source_protocol",
        "source_protocol_version",
        "external_subject",
        "external_subject_path",
        "external_subject_digest",
        "external_subject_signature_ref",
        "projection_manifest_ref",
        "projection_manifest_sha256",
        "chio_claim_refs",
        "receipt_refs",
        "disclosure_capsule_refs",
        "settlement_refs",
        "risk_refs",
        "limitations",
    ];
    if envelope.get("schema").and_then(Value::as_str) == Some("chio.agent-web-proof-envelope.v2") {
        fields.insert(3, "agent_web_passport_scope_sha256");
    }
    agent_web_envelope_payload(envelope, &fields)
}

fn agent_web_envelope_id(envelope: &Value) -> String {
    let mut fields = vec![
        "schema",
        "transaction_passport_ref",
        "source_protocol",
        "source_protocol_version",
        "external_subject",
        "external_subject_path",
        "external_subject_digest",
        "external_subject_signature_ref",
        "projection_manifest_ref",
        "projection_manifest_sha256",
        "chio_claim_refs",
        "receipt_refs",
        "disclosure_capsule_refs",
        "settlement_refs",
        "risk_refs",
        "limitations",
    ];
    if envelope.get("schema").and_then(Value::as_str) == Some("chio.agent-web-proof-envelope.v2") {
        fields.insert(2, "agent_web_passport_scope_sha256");
    }
    let payload = agent_web_envelope_payload(envelope, &fields);
    let canonical = chio_core_types::canonical_json_bytes(&payload)
        .test_expect("Agent Web envelope canonicalizes");
    chio_core_types::sha256_hex(&canonical)
}

fn agent_web_envelope_payload(envelope: &Value, fields: &[&str]) -> Value {
    let object = envelope
        .as_object()
        .test_expect("Agent Web envelope is an object");
    let mut payload = serde_json::Map::new();
    for field in fields {
        payload.insert(
            (*field).to_string(),
            object
                .get(*field)
                .unwrap_or_else(|| panic!("Agent Web envelope missing field: {field}"))
                .clone(),
        );
    }
    Value::Object(payload)
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
    case: AgentWebCase,
    receipt_ref: &str,
    content_hash: &str,
    policy_hash: &str,
    allowed: bool,
    intent: &AgentWebReceiptIntent,
) -> Vec<u8> {
    let keypair = agent_web_fixture_kernel_keypair();
    let decision = if allowed {
        Some(Decision::Allow)
    } else {
        Some(Decision::Deny {
            reason: "Agent Web projection denied".to_string(),
            guard: "agent-web-test-guard".to_string(),
        })
    };
    let action_receipt_ref = if matches!(case, AgentWebCase::BoundReceiptActionRefMismatch)
        && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "receipt-agent-web-other-allow"
    } else {
        receipt_ref
    };
    let action_content_hash = if matches!(case, AgentWebCase::BoundReceiptActionContentHashMismatch)
        && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    } else {
        content_hash
    };
    let action_passport_id = if matches!(case, AgentWebCase::BoundReceiptActionPassportIdMismatch)
        && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "passport-agent-web-other"
    } else {
        &intent.passport_id
    };
    let action_passport_issuer =
        if matches!(case, AgentWebCase::BoundReceiptActionPassportIssuerMismatch)
            && receipt_ref == "receipt-agent-web-webhook-allow"
        {
            "did:chio:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        } else {
            &intent.passport_issuer
        };
    let action_envelope_id = if matches!(case, AgentWebCase::BoundReceiptActionEnvelopeIdMismatch)
        && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    } else {
        &intent.envelope_id
    };
    let action_projection_manifest_sha256 = if matches!(
        case,
        AgentWebCase::BoundReceiptActionProjectionManifestMismatch
    ) && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    } else {
        &intent.projection_manifest_sha256
    };
    let action_source_protocol =
        if matches!(case, AgentWebCase::BoundReceiptActionSourceProtocolMismatch)
            && receipt_ref == "receipt-agent-web-webhook-allow"
        {
            "cloudevents"
        } else {
            &intent.source_protocol
        };
    let action_source_protocol_version = if matches!(
        case,
        AgentWebCase::BoundReceiptActionSourceProtocolVersionMismatch
    ) && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "9.9.9"
    } else {
        &intent.source_protocol_version
    };
    let action = ToolCallAction::from_parameters(json!({
        "agent_web_receipt_ref": action_receipt_ref,
        "content_hash": action_content_hash,
        "transaction_passport_id": action_passport_id,
        "transaction_passport_issuer": action_passport_issuer,
        "agent_web_passport_scope_sha256": intent.passport_scope_sha256,
        "agent_web_envelope_id": action_envelope_id,
        "projection_manifest_sha256": action_projection_manifest_sha256,
        "source_protocol": action_source_protocol,
        "source_protocol_version": action_source_protocol_version
    }))
    .test_expect("Agent Web receipt action hashes");
    let tool_server = if matches!(case, AgentWebCase::BoundReceiptProducerServerMismatch)
        && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "caller-controlled-sidecar"
    } else {
        "agent-web-sidecar"
    };
    let tool_name = if matches!(case, AgentWebCase::BoundReceiptProducerToolMismatch)
        && receipt_ref == "receipt-agent-web-webhook-allow"
    {
        "caller-controlled-tool"
    } else {
        "project-external-evidence"
    };
    let body = ChioReceiptBody {
        id: receipt_ref.to_string(),
        timestamp: 1_770_508_800,
        capability_id: "cap-agent-web-test".to_string(),
        tool_server: tool_server.to_string(),
        tool_name: tool_name.to_string(),
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
        metadata: None,
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
                not_before: None,
                expires_at: None,
                issuer: format!(
                    "did:chio:{}",
                    transaction_passport_keypair().public_key().to_hex()
                ),
                evidence_graph_sha256: String::new(),
                evidence_graph_path: "evidence-graph.json".to_string(),
                claim_set_sha256: String::new(),
                claim_set_path: "claim-set.json".to_string(),
                verifier_policy_sha256: String::new(),
                verifier_policy_path: "verifier-policy.json".to_string(),
                omission_policy: Vec::new(),
                signature: "0".repeat(128),
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

pub(crate) fn replace_agent_web_json_artifact(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    mutate: impl FnOnce(&mut Value),
) {
    let artifact = bundle
        .artifacts
        .get(relative_path)
        .test_expect("Agent Web artifact exists");
    let mut value: Value =
        serde_json::from_slice(artifact).test_expect("Agent Web JSON artifact parses");
    mutate(&mut value);
    replace_agent_web_json_value(bundle, relative_path, value);
}

pub(crate) fn replace_agent_web_envelope_artifact(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    mutate: impl FnOnce(&mut Value),
) {
    let artifact = bundle
        .artifacts
        .get(relative_path)
        .test_expect("Agent Web envelope artifact exists");
    let mut value: Value =
        serde_json::from_slice(artifact).test_expect("Agent Web envelope artifact parses");
    mutate(&mut value);
    let keypair = agent_web_fixture_sidecar_keypair();
    let public_key = keypair.public_key().to_hex();
    sign_agent_web_envelope_value(&mut value, &keypair, &public_key);
    replace_agent_web_json_value(bundle, relative_path, value);
}

pub(crate) fn sign_agent_web_envelope_with_key(envelope: &mut Value, keypair: &Keypair) {
    let public_key = keypair.public_key().to_hex();
    sign_agent_web_envelope_value(envelope, keypair, &public_key);
}

pub(crate) fn downgrade_agent_web_bundle_to_signed_v1(bundle: &mut AgentWebInteropBundle) {
    let sidecar_keypair = agent_web_fixture_sidecar_keypair();
    let sidecar_public_key = sidecar_keypair.public_key().to_hex();
    let kernel_keypair = agent_web_fixture_kernel_keypair();
    let mut graph: Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
        .test_expect("Agent Web evidence graph parses");
    if let Some(openapi_subject) = bundle.artifacts.get_mut("external/openapi-operation.json") {
        let mut subject: Value =
            serde_json::from_slice(openapi_subject).test_expect("Agent Web OpenAPI subject parses");
        subject["x_chio_proof_envelope_profile"] =
            Value::String("chio.agent-web-proof-envelope.v1".to_string());
        *openapi_subject = json_bytes(subject);
    }
    let mut node_id_replacements = Vec::new();
    let nodes = graph["nodes"]
        .as_array_mut()
        .test_expect("Agent Web evidence graph has nodes");

    for node in nodes {
        let previous_id = node["id"]
            .as_str()
            .test_expect("Agent Web evidence node has id")
            .to_string();
        let previous_sha256 = node["sha256"]
            .as_str()
            .test_expect("Agent Web evidence node has digest")
            .to_string();
        let role = node["role"]
            .as_str()
            .test_expect("Agent Web evidence node has role");
        let path = node["path"]
            .as_str()
            .test_expect("Agent Web evidence node has path")
            .to_string();
        if role == "agent-web-proof-envelope" {
            let mut envelope: Value = serde_json::from_slice(
                bundle
                    .artifacts
                    .get(&path)
                    .test_expect("Agent Web envelope exists"),
            )
            .test_expect("Agent Web envelope parses");
            envelope["schema"] = Value::String("chio.agent-web-proof-envelope.v1".to_string());
            envelope
                .as_object_mut()
                .test_expect("Agent Web envelope is an object")
                .remove("agent_web_passport_scope_sha256");
            if path == "standard-webhooks-envelope.json" {
                let receipt_ref = envelope["receipt_refs"][0].clone();
                envelope["receipt_refs"] = json!([receipt_ref.clone(), receipt_ref]);
            }
            if envelope.get("source_protocol").and_then(Value::as_str) == Some("openapi") {
                envelope["external_subject_digest"] = Value::String(chio_core_types::sha256_hex(
                    bundle
                        .artifacts
                        .get("external/openapi-operation.json")
                        .test_expect("Agent Web OpenAPI subject exists"),
                ));
            }
            sign_agent_web_envelope_value(&mut envelope, &sidecar_keypair, &sidecar_public_key);
            let bytes = json_bytes(envelope);
            node["schema"] = Value::String("chio.agent-web-proof-envelope.v1".to_string());
            node["sha256"] = Value::String(chio_core_types::sha256_hex(&bytes));
            bundle.artifacts.insert(path, bytes);
        } else if role == "external-subject" && path == "external/openapi-operation.json" {
            node["sha256"] = Value::String(chio_core_types::sha256_hex(
                bundle
                    .artifacts
                    .get(&path)
                    .test_expect("Agent Web OpenAPI subject exists"),
            ));
        } else if role == "receipt" {
            let receipt: ChioReceipt = serde_json::from_slice(
                bundle
                    .artifacts
                    .get(&path)
                    .test_expect("Agent Web receipt exists"),
            )
            .test_expect("Agent Web receipt parses");
            let mut body = receipt.body();
            let receipt_ref = body
                .action
                .parameters
                .get("agent_web_receipt_ref")
                .and_then(Value::as_str)
                .test_expect("Agent Web receipt action has receipt ref")
                .to_string();
            body.action = ToolCallAction::from_parameters(json!({
                "legacy_projection": true,
            }))
            .test_expect("legacy Agent Web receipt action hashes");
            body.metadata = Some(json!({ "agent_web_receipt_ref": receipt_ref }));
            body.kernel_key = kernel_keypair.public_key();
            let receipt = ChioReceipt::sign(body, &kernel_keypair)
                .test_expect("legacy Agent Web receipt signs");
            let bytes = json_bytes(
                serde_json::to_value(receipt).test_expect("legacy Agent Web receipt serializes"),
            );
            node["sha256"] = Value::String(chio_core_types::sha256_hex(&bytes));
            bundle.artifacts.insert(path, bytes);
        }
        let updated_sha256 = node["sha256"]
            .as_str()
            .test_expect("Agent Web evidence node has updated digest")
            .to_string();
        if previous_id == previous_sha256 && previous_id != updated_sha256 {
            node["id"] = Value::String(updated_sha256.clone());
            node_id_replacements.push((previous_id, updated_sha256));
        }
    }
    for edge in graph["edges"]
        .as_array_mut()
        .test_expect("Agent Web evidence graph has edges")
    {
        for endpoint in ["from", "to"] {
            let Some(current) = edge[endpoint].as_str() else {
                continue;
            };
            if let Some((_, replacement)) = node_id_replacements
                .iter()
                .find(|(previous, _)| previous == current)
            {
                edge[endpoint] = Value::String(replacement.clone());
            }
        }
    }

    bundle.evidence_graph_bytes = json_bytes(graph);
    bundle.passport.evidence_graph_sha256 =
        chio_core_types::sha256_hex(&bundle.evidence_graph_bytes);
    sign_transaction_passport(&mut bundle.passport);
}

pub(crate) fn append_agent_web_json_artifact(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    role: &str,
    schema: &str,
    value: Value,
) -> String {
    let bytes = json_bytes(value);
    let digest = chio_core_types::sha256_hex(&bytes);
    bundle.artifacts.insert(relative_path.to_string(), bytes);

    let mut graph: Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
        .test_expect("Agent Web evidence graph parses");
    graph["nodes"]
        .as_array_mut()
        .test_expect("Agent Web evidence graph has nodes")
        .push(json!({
            "id": digest,
            "schema": schema,
            "path": relative_path,
            "sha256": digest,
            "role": role
        }));
    bundle.evidence_graph_bytes = json_bytes(graph);
    bundle.passport.evidence_graph_sha256 =
        chio_core_types::sha256_hex(&bundle.evidence_graph_bytes);
    sign_transaction_passport(&mut bundle.passport);
    digest
}

pub(crate) fn replace_agent_web_receipt_for_subject(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    receipt_ref: &str,
    subject_digest: &str,
) {
    let policy_hash = bundle.passport.verifier_policy_sha256.clone();
    let graph: Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
        .test_expect("Agent Web evidence graph parses");
    let graph_nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .test_expect("Agent Web evidence graph has nodes");
    let passport_scope_sha256 =
        chio_agent_web_interop::agent_web_passport_scope_sha256(&bundle.passport)
            .test_expect("Agent Web passport scope hashes");
    let intent = agent_web_receipt_intents(
        &bundle.artifacts,
        graph_nodes,
        &bundle.passport.id,
        &bundle.passport.issuer,
        &passport_scope_sha256,
    )
    .remove(receipt_ref)
    .test_expect("Agent Web receipt resolves to one envelope");
    let bytes = signed_agent_web_receipt_bytes(
        AgentWebCase::Valid,
        receipt_ref,
        subject_digest,
        &policy_hash,
        true,
        &intent,
    );
    let value: Value =
        serde_json::from_slice(&bytes).test_expect("Agent Web receipt artifact parses");
    replace_agent_web_json_value(bundle, relative_path, value);
}

fn replace_agent_web_json_value(
    bundle: &mut AgentWebInteropBundle,
    relative_path: &str,
    value: Value,
) {
    let updated = json_bytes(value);
    let updated_digest = chio_core_types::sha256_hex(&updated);
    bundle.artifacts.insert(relative_path.to_string(), updated);

    let mut graph: Value = serde_json::from_slice(&bundle.evidence_graph_bytes)
        .test_expect("Agent Web evidence graph parses");
    let nodes = graph
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .test_expect("Agent Web evidence graph has nodes");
    let node = nodes
        .iter_mut()
        .find(|node| node.get("path").and_then(Value::as_str) == Some(relative_path))
        .test_expect("Agent Web evidence graph contains artifact");
    let previous_id = node
        .get("id")
        .and_then(Value::as_str)
        .test_expect("Agent Web evidence graph node has id")
        .to_string();
    node["sha256"] = Value::String(updated_digest.clone());
    node["id"] = Value::String(updated_digest.clone());

    let edges = graph
        .get_mut("edges")
        .and_then(Value::as_array_mut)
        .test_expect("Agent Web evidence graph has edges");
    for edge in edges {
        for endpoint in ["from", "to"] {
            if edge.get(endpoint).and_then(Value::as_str) == Some(previous_id.as_str()) {
                edge[endpoint] = Value::String(updated_digest.clone());
            }
        }
    }

    bundle.evidence_graph_bytes = json_bytes(graph);
    bundle.passport.evidence_graph_sha256 =
        chio_core_types::sha256_hex(&bundle.evidence_graph_bytes);
    sign_transaction_passport(&mut bundle.passport);
}

fn sign_agent_web_envelope_value(envelope: &mut Value, keypair: &Keypair, public_key: &str) {
    envelope["envelope_id"] = Value::String(agent_web_envelope_id(envelope));
    let payload = agent_web_envelope_signature_payload(envelope);
    let canonical = chio_core_types::canonical_json_bytes(&payload)
        .test_expect("Agent Web envelope canonicalizes");
    let signature = keypair.sign(&canonical).to_hex();
    envelope["signature"] = Value::String(format!("sig-ed25519:{public_key}:{signature}"));
}
