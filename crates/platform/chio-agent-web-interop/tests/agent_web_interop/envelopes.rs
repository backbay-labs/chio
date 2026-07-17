use super::support::*;
use serde_json::json;

pub(crate) fn add_projection_envelopes(builder: &mut AgentWebBundleBuilder) {
    let case = builder.case;
    let graphql_source_version = graphql_source_version(case);
    let openapi_source_version = openapi_source_version(case);
    let asyncapi_source_version = asyncapi_source_version(case);
    let cloudevent = builder.artifact_bytes("external/cloudevent.json");
    let graphql_operation = builder.artifact_bytes("external/graphql-operation.json");
    let mcp_tool_call = builder.artifact_bytes("external/mcp-tool-call.json");
    let a2a_task = builder.artifact_bytes("external/a2a-task.json");
    let openapi_operation = builder.artifact_bytes("external/openapi-operation.json");
    let acp_client_permission = builder.artifact_bytes("external/acp-client-permission.json");
    let acp_commerce_checkout = builder.artifact_bytes("external/acp-commerce-checkout.json");
    let ag_ui_event = builder.artifact_bytes("external/ag-ui-event.json");
    let browser_automation_command = builder.artifact_bytes("external/browser-command.json");
    let rpa_transcript = builder.artifact_bytes("external/rpa-transcript.json");
    let email_connector_action = builder.artifact_bytes("external/email-message.json");
    let calendar_connector_action = builder.artifact_bytes("external/calendar-event.json");
    let slack_connector_action = builder.artifact_bytes("external/slack-message.json");
    let oauth2_authorization = builder.artifact_bytes("external/oauth2-authorization.json");
    let openid_connect_identity = builder.artifact_bytes("external/openid-connect-identity.json");
    let scim_lifecycle_event = builder.artifact_bytes("external/scim-lifecycle.json");
    let spiffe_workload_identity = builder.artifact_bytes("external/spiffe-workload-identity.json");
    let kubernetes_admission_review =
        builder.artifact_bytes("external/kubernetes-admission-review.json");
    let oci_artifact_ref = builder.artifact_bytes("external/oci-ref.json");
    let verifiable_credential = builder.artifact_bytes("external/verifiable-credential.json");
    let sd_jwt_vc_presentation = builder.artifact_bytes("external/sd-jwt-vc-presentation.json");
    let bbs_receipt_disclosure = builder.artifact_bytes("external/bbs-receipt-disclosure.json");
    let sigstore_bundle = builder.artifact_bytes("external/sigstore-bundle.json");
    let in_toto_statement = builder.artifact_bytes("external/in-toto-statement.json");
    let dsse_envelope_subject = builder.artifact_bytes("external/dsse-envelope.json");
    let slsa_provenance = builder.artifact_bytes("external/slsa-provenance.json");
    let asyncapi_message = builder.artifact_bytes("external/asyncapi-message.json");
    let ap2_mandate_chain = builder.artifact_bytes("external/ap2-mandate-chain.json");
    let x402_payment = builder.artifact_bytes("external/x402-payment.json");
    let cloudevents_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-cloudevents-valid",
        "transaction_passport_ref": builder.passport.id,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "agent-web-proof-envelope",
        "cloudevents-envelope",
        "chio.agent-web-proof-envelope.v2",
        "cloudevents-envelope.json",
        cloudevents_envelope,
    );

    let graphql_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-graphql-http-valid",
        "transaction_passport_ref": builder.passport.id,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "agent-web-proof-envelope",
        "graphql-http-envelope",
        "chio.agent-web-proof-envelope.v2",
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-mcp-valid",
        "transaction_passport_ref": builder.passport.id,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "agent-web-proof-envelope",
        "mcp-envelope",
        "chio.agent-web-proof-envelope.v2",
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-a2a-valid",
        "transaction_passport_ref": builder.passport.id,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "agent-web-proof-envelope",
        "a2a-envelope",
        "chio.agent-web-proof-envelope.v2",
        "a2a-envelope.json",
        a2a_envelope,
    );

    let openapi_envelope = json_bytes(json!({
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-openapi-valid",
        "transaction_passport_ref": builder.passport.id,
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
            | AgentWebCase::OpenApiFailedStatus
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "openapi-envelope",
            "chio.agent-web-proof-envelope.v2",
            "openapi-envelope.json",
            openapi_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-acp-client-valid",
        "transaction_passport_ref": builder.passport.id,
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
    if matches!(
        case,
        AgentWebCase::AcpClientProjection | AgentWebCase::AcpClientDenied
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "acp-client-envelope",
            "chio.agent-web-proof-envelope.v2",
            "acp-client-envelope.json",
            acp_client_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-acp-commerce-valid",
        "transaction_passport_ref": builder.passport.id,
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
            | AgentWebCase::AcpCommerceRefunded
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "acp-commerce-envelope",
            "chio.agent-web-proof-envelope.v2",
            "acp-commerce-envelope.json",
            acp_commerce_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-ag-ui-valid",
        "transaction_passport_ref": builder.passport.id,
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
    if matches!(
        case,
        AgentWebCase::AgUiProjection | AgentWebCase::AgUiDenied
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "ag-ui-envelope",
            "chio.agent-web-proof-envelope.v2",
            "ag-ui-envelope.json",
            ag_ui_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-browser-automation-valid",
        "transaction_passport_ref": builder.passport.id,
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
    if matches!(
        case,
        AgentWebCase::BrowserAutomationProjection
            | AgentWebCase::BrowserAutomationReceiptRefMismatch
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "browser-automation-envelope",
            "chio.agent-web-proof-envelope.v2",
            "browser-automation-envelope.json",
            browser_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-rpa-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "rpa-envelope",
            "chio.agent-web-proof-envelope.v2",
            "rpa-envelope.json",
            rpa_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-gmail-api-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "email-envelope",
            "chio.agent-web-proof-envelope.v2",
            "email-envelope.json",
            email_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-google-calendar-api-valid",
        "transaction_passport_ref": builder.passport.id,
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
        AgentWebCase::CalendarProjection
            | AgentWebCase::CalendarTimeRangeMismatch
            | AgentWebCase::CalendarCreateTimeRangeMismatch
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "calendar-envelope",
            "chio.agent-web-proof-envelope.v2",
            "calendar-envelope.json",
            calendar_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-slack-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "slack-envelope",
            "chio.agent-web-proof-envelope.v2",
            "slack-envelope.json",
            slack_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-oauth2-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "oauth2-envelope",
            "chio.agent-web-proof-envelope.v2",
            "oauth2-envelope.json",
            oauth2_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-openid-connect-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "openid-connect-envelope",
            "chio.agent-web-proof-envelope.v2",
            "openid-connect-envelope.json",
            openid_connect_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-scim-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "scim-envelope",
            "chio.agent-web-proof-envelope.v2",
            "scim-envelope.json",
            scim_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-spiffe-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "spiffe-envelope",
            "chio.agent-web-proof-envelope.v2",
            "spiffe-envelope.json",
            spiffe_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-kubernetes-admission-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "kubernetes-admission-envelope",
            "chio.agent-web-proof-envelope.v2",
            "kubernetes-admission-envelope.json",
            kubernetes_admission_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-oci-ref-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "oci-ref-envelope",
            "chio.agent-web-proof-envelope.v2",
            "oci-ref-envelope.json",
            oci_ref_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-vc-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "vc-envelope",
            "chio.agent-web-proof-envelope.v2",
            "vc-envelope.json",
            vc_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-sd-jwt-vc-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "sd-jwt-vc-envelope",
            "chio.agent-web-proof-envelope.v2",
            "sd-jwt-vc-envelope.json",
            sd_jwt_vc_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-bbs-valid",
        "transaction_passport_ref": builder.passport.id,
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
        AgentWebCase::BbsProjection
            | AgentWebCase::BbsSelfAssertedVerified
            | AgentWebCase::BbsReceiptRefMissing
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "bbs-envelope",
            "chio.agent-web-proof-envelope.v2",
            "bbs-envelope.json",
            bbs_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-sigstore-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "sigstore-envelope",
            "chio.agent-web-proof-envelope.v2",
            "sigstore-envelope.json",
            sigstore_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-in-toto-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "in-toto-envelope",
            "chio.agent-web-proof-envelope.v2",
            "in-toto-envelope.json",
            in_toto_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-dsse-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "dsse-envelope",
            "chio.agent-web-proof-envelope.v2",
            "dsse-envelope.json",
            dsse_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-slsa-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "slsa-envelope",
            "chio.agent-web-proof-envelope.v2",
            "slsa-envelope.json",
            slsa_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-asyncapi-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "asyncapi-envelope",
            "chio.agent-web-proof-envelope.v2",
            "asyncapi-envelope.json",
            asyncapi_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-ap2-valid",
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "ap2-envelope",
            "chio.agent-web-proof-envelope.v2",
            "ap2-envelope.json",
            ap2_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-x402-valid",
        "transaction_passport_ref": builder.passport.id,
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
            | AgentWebCase::X402AssetMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
            | AgentWebCase::X402Refunded
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "agent-web-proof-envelope",
            "x402-envelope",
            "chio.agent-web-proof-envelope.v2",
            "x402-envelope.json",
            x402_envelope,
        );
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
}
