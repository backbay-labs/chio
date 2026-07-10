use super::claims::{
    CLAIM_EXTERNAL_A2A_TASK_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_ACP_CLIENT_PERMISSION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_ACP_COMMERCE_PAYMENT_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_AG_UI_EVENT_IS_CHIO_AUTHORITY, CLAIM_EXTERNAL_AP2_MANDATE_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_ASYNCAPI_MESSAGE_IS_CHIO_AUTHORITY, CLAIM_EXTERNAL_BBS_PROOF_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_BROWSER_AUTOMATION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_CALENDAR_ACTION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_CLOUDEVENTS_EVENT_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_DSSE_ENVELOPE_IS_CHIO_AUTHORITY, CLAIM_EXTERNAL_EMAIL_ACTION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_GRAPHQL_HTTP_OPERATION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_IN_TOTO_STATEMENT_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_KUBERNETES_ADMISSION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_MCP_TOOL_CALL_IS_CHIO_AUTHORITY, CLAIM_EXTERNAL_OAUTH2_TOKEN_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_OCI_REF_IS_CHIO_AUTHORITY, CLAIM_EXTERNAL_OPENAPI_OPERATION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_OPENID_CONNECT_IDENTITY_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_RPA_TRANSCRIPT_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_SCIM_LIFECYCLE_IS_CHIO_AUTHORITY, CLAIM_EXTERNAL_SD_JWT_VC_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_SIGSTORE_BUNDLE_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_SLACK_ACTION_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_SLSA_PROVENANCE_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_SPIFFE_WORKLOAD_IDENTITY_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_VC_DI_BBS_INTEROP_VERIFIED, CLAIM_EXTERNAL_VC_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_WEBHOOK_SIGNATURE_IS_CHIO_AUTHORITY,
    CLAIM_EXTERNAL_X402_PAYMENT_IS_CHIO_AUTHORITY,
};

struct SourceProtocolSpec {
    id: &'static str,
    external_subject_schema: &'static str,
    required_unsupported_claims: &'static [&'static str],
    supported_source_versions: &'static [&'static str],
    unsupported_source_version_message: &'static str,
}

const SOURCE_PROTOCOLS: &[SourceProtocolSpec] = &[
    SourceProtocolSpec {
        id: "standard-webhooks",
        external_subject_schema: "external.standard-webhooks.delivery.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_WEBHOOK_SIGNATURE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["2026-06-09"],
        unsupported_source_version_message: "unsupported Standard Webhooks source version",
    },
    SourceProtocolSpec {
        id: "cloudevents",
        external_subject_schema: "external.cloudevents.event.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_CLOUDEVENTS_EVENT_IS_CHIO_AUTHORITY],
        supported_source_versions: &["1.0.2"],
        unsupported_source_version_message: "unsupported CloudEvents source version",
    },
    SourceProtocolSpec {
        id: "graphql-http",
        external_subject_schema: "external.graphql-http.operation.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_GRAPHQL_HTTP_OPERATION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["draft-2026-06-04"],
        unsupported_source_version_message: "unsupported GraphQL over HTTP source version",
    },
    SourceProtocolSpec {
        id: "mcp",
        external_subject_schema: "external.mcp.tool-call.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_MCP_TOOL_CALL_IS_CHIO_AUTHORITY],
        supported_source_versions: &["2025-11-25"],
        unsupported_source_version_message: "unsupported MCP source version",
    },
    SourceProtocolSpec {
        id: "a2a",
        external_subject_schema: "external.a2a.task.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_A2A_TASK_IS_CHIO_AUTHORITY],
        supported_source_versions: &["0.3.0"],
        unsupported_source_version_message: "unsupported A2A source version",
    },
    SourceProtocolSpec {
        id: "acp-client",
        external_subject_schema: "external.acp-client.permission.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_ACP_CLIENT_PERMISSION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["v1"],
        unsupported_source_version_message: "unsupported ACP-Client source version",
    },
    SourceProtocolSpec {
        id: "acp-commerce",
        external_subject_schema: "external.acp-commerce.checkout.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_ACP_COMMERCE_PAYMENT_IS_CHIO_AUTHORITY],
        supported_source_versions: &["2026-06"],
        unsupported_source_version_message: "unsupported ACP-Commerce source version",
    },
    SourceProtocolSpec {
        id: "ag-ui",
        external_subject_schema: "external.ag-ui.event.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_AG_UI_EVENT_IS_CHIO_AUTHORITY],
        supported_source_versions: &["events-v1"],
        unsupported_source_version_message: "unsupported AG-UI source version",
    },
    SourceProtocolSpec {
        id: "browser-automation",
        external_subject_schema: "external.browser-automation.command.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_BROWSER_AUTOMATION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["webdriver-bidi-2026-06"],
        unsupported_source_version_message: "unsupported browser automation source version",
    },
    SourceProtocolSpec {
        id: "rpa",
        external_subject_schema: "external.rpa.transcript.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_RPA_TRANSCRIPT_IS_CHIO_AUTHORITY],
        supported_source_versions: &["uia-2026-06"],
        unsupported_source_version_message: "unsupported RPA source version",
    },
    SourceProtocolSpec {
        id: "gmail-api",
        external_subject_schema: "external.email.connector-action.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_EMAIL_ACTION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["v1"],
        unsupported_source_version_message: "unsupported email source version",
    },
    SourceProtocolSpec {
        id: "google-calendar-api",
        external_subject_schema: "external.calendar.connector-action.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_CALENDAR_ACTION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["v1"],
        unsupported_source_version_message: "unsupported Calendar source version",
    },
    SourceProtocolSpec {
        id: "slack",
        external_subject_schema: "external.slack.connector-action.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_SLACK_ACTION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["web-api-2026-06"],
        unsupported_source_version_message: "unsupported Slack source version",
    },
    SourceProtocolSpec {
        id: "oauth2",
        external_subject_schema: "external.oauth2.authorization.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_OAUTH2_TOKEN_IS_CHIO_AUTHORITY],
        supported_source_versions: &["rfc6749"],
        unsupported_source_version_message: "unsupported OAuth2 source version",
    },
    SourceProtocolSpec {
        id: "openid-connect",
        external_subject_schema: "external.openid-connect.identity.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_OPENID_CONNECT_IDENTITY_IS_CHIO_AUTHORITY],
        supported_source_versions: &["core-1.0"],
        unsupported_source_version_message: "unsupported OpenID Connect source version",
    },
    SourceProtocolSpec {
        id: "scim",
        external_subject_schema: "external.scim.lifecycle.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_SCIM_LIFECYCLE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["rfc7644"],
        unsupported_source_version_message: "unsupported SCIM source version",
    },
    SourceProtocolSpec {
        id: "spiffe",
        external_subject_schema: "external.spiffe.workload-identity.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_SPIFFE_WORKLOAD_IDENTITY_IS_CHIO_AUTHORITY],
        supported_source_versions: &["workload-api-v1"],
        unsupported_source_version_message: "unsupported SPIFFE source version",
    },
    SourceProtocolSpec {
        id: "kubernetes-admission",
        external_subject_schema: "external.kubernetes.admission-review.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_KUBERNETES_ADMISSION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["admissionreview-v1"],
        unsupported_source_version_message: "unsupported Kubernetes admission source version",
    },
    SourceProtocolSpec {
        id: "oci",
        external_subject_schema: "external.oci.ref.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_OCI_REF_IS_CHIO_AUTHORITY],
        supported_source_versions: &["image-spec-v1"],
        unsupported_source_version_message: "unsupported OCI source version",
    },
    SourceProtocolSpec {
        id: "vc",
        external_subject_schema: "external.vc.verifiable-credential.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_VC_IS_CHIO_AUTHORITY],
        supported_source_versions: &["vc-data-model-2.0"],
        unsupported_source_version_message: "unsupported VC source version",
    },
    SourceProtocolSpec {
        id: "sd-jwt-vc",
        external_subject_schema: "external.sd-jwt-vc.presentation.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_SD_JWT_VC_IS_CHIO_AUTHORITY],
        supported_source_versions: &["v1"],
        unsupported_source_version_message: "unsupported SD-JWT VC source version",
    },
    SourceProtocolSpec {
        id: "bbs",
        external_subject_schema: "external.bbs.receipt-disclosure.v1",
        required_unsupported_claims: &[
            CLAIM_EXTERNAL_BBS_PROOF_IS_CHIO_AUTHORITY,
            CLAIM_EXTERNAL_VC_DI_BBS_INTEROP_VERIFIED,
        ],
        supported_source_versions: &["chio-receipt-bbs-v1"],
        unsupported_source_version_message: "unsupported BBS source version",
    },
    SourceProtocolSpec {
        id: "sigstore",
        external_subject_schema: "external.sigstore.bundle.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_SIGSTORE_BUNDLE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["bundle-v1"],
        unsupported_source_version_message: "unsupported Sigstore source version",
    },
    SourceProtocolSpec {
        id: "in-toto",
        external_subject_schema: "external.in-toto.statement.v1",
        required_unsupported_claims: &[
            CLAIM_EXTERNAL_IN_TOTO_STATEMENT_IS_CHIO_AUTHORITY,
            CLAIM_EXTERNAL_DSSE_ENVELOPE_IS_CHIO_AUTHORITY,
        ],
        supported_source_versions: &["statement-v1-dsse"],
        unsupported_source_version_message: "unsupported in-toto source version",
    },
    SourceProtocolSpec {
        id: "dsse",
        external_subject_schema: "external.dsse.envelope.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_DSSE_ENVELOPE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["v1"],
        unsupported_source_version_message: "unsupported DSSE source version",
    },
    SourceProtocolSpec {
        id: "slsa-provenance",
        external_subject_schema: "external.slsa.provenance.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_SLSA_PROVENANCE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["v1"],
        unsupported_source_version_message: "unsupported SLSA source version",
    },
    SourceProtocolSpec {
        id: "openapi",
        external_subject_schema: "external.openapi.operation.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_OPENAPI_OPERATION_IS_CHIO_AUTHORITY],
        supported_source_versions: &["3.1.0"],
        unsupported_source_version_message: "unsupported OpenAPI source version",
    },
    SourceProtocolSpec {
        id: "asyncapi",
        external_subject_schema: "external.asyncapi.message.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_ASYNCAPI_MESSAGE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["3.0.0"],
        unsupported_source_version_message: "unsupported AsyncAPI source version",
    },
    SourceProtocolSpec {
        id: "ap2",
        external_subject_schema: "external.ap2.mandate-chain.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_AP2_MANDATE_IS_CHIO_AUTHORITY],
        supported_source_versions: &["0.2"],
        unsupported_source_version_message: "unsupported AP2 source version",
    },
    SourceProtocolSpec {
        id: "x402",
        external_subject_schema: "external.x402.payment.v1",
        required_unsupported_claims: &[CLAIM_EXTERNAL_X402_PAYMENT_IS_CHIO_AUTHORITY],
        supported_source_versions: &["0.5"],
        unsupported_source_version_message: "unsupported x402 source version",
    },
];

pub(super) fn is_supported_source_protocol(source_protocol: &str) -> bool {
    source_protocol_spec(source_protocol).is_some()
}

pub(super) fn external_subject_schema(source_protocol: &str) -> Option<&'static str> {
    source_protocol_spec(source_protocol).map(|spec| spec.external_subject_schema)
}

pub(super) fn required_unsupported_claims(source_protocol: &str) -> &'static [&'static str] {
    source_protocol_spec(source_protocol)
        .map(|spec| spec.required_unsupported_claims)
        .unwrap_or(&[])
}

pub(super) fn is_supported_source_version(source_protocol: &str, source_version: &str) -> bool {
    if source_protocol == "openapi" {
        return source_version.starts_with("3.0.") || source_version.starts_with("3.1.");
    }
    source_protocol_spec(source_protocol)
        .map(|spec| spec.supported_source_versions.contains(&source_version))
        .unwrap_or(false)
}

pub(super) fn unsupported_source_version_message(source_protocol: &str) -> &'static str {
    source_protocol_spec(source_protocol)
        .map(|spec| spec.unsupported_source_version_message)
        .unwrap_or("unsupported Agent Web source version")
}

fn source_protocol_spec(source_protocol: &str) -> Option<&'static SourceProtocolSpec> {
    SOURCE_PROTOCOLS
        .iter()
        .find(|spec| spec.id == source_protocol)
}
