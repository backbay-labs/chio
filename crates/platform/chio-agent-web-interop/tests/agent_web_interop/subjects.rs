use super::support::*;
use chio_test_support::prelude::*;
use serde_json::json;

pub(crate) fn add_external_subject_artifacts(builder: &mut AgentWebBundleBuilder) {
    let case = builder.case;
    let webhook_timestamp = standard_webhooks_timestamp_for_case(case);
    let webhook_signature = standard_webhooks_signature_ref_for_case(case);
    let webhook_delivery = json_bytes(json!({
        "object_kind": "standard_webhooks_delivery",
        "id": "webhook-delivery-agent-web-valid",
        "webhook_id": STANDARD_WEBHOOKS_WEBHOOK_ID,
        "webhook_timestamp": webhook_timestamp,
        "webhook_signature": webhook_signature,
        "event_type": "order.created",
        "tenant_id": "tenant-backbay",
        "endpoint_url_digest": STANDARD_WEBHOOKS_ENDPOINT_URL_DIGEST,
        "method": "POST",
        "body_digest": STANDARD_WEBHOOKS_BODY_DIGEST,
        "signature_ref": "sig-standard-webhooks-valid"
    }));
    push_artifact(
        &mut builder.artifacts,
        &mut builder.graph_nodes,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "external-subject",
        "cloudevents-event",
        "external.cloudevents.event.v1",
        "external/cloudevent.json",
        cloudevent.clone(),
    );

    let graphql_status_code = match case {
        AgentWebCase::GraphqlHttpFailedStatus => 500,
        _ => 200,
    };
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
        "status_code": graphql_status_code
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
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
        "authorization_context_digest": "9090909090909090909090909090909090909090909090909090909090909090",
        "protected_resource_metadata_digest": "9191919191919191919191919191919191919191919191919191919191919191",
        "authorization_server_metadata_digest": "9292929292929292929292929292929292929292929292929292929292929292",
        "dpop_proof_digest": "9393939393939393939393939393939393939393939393939393939393939393",
        "proof_envelope_resource_read_digest": "9494949494949494949494949494949494949494949494949494949494949494"
    }));
    push_artifact(
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "external-subject",
        "mcp-tool-call",
        "external.mcp.tool-call.v1",
        "external/mcp-tool-call.json",
        mcp_tool_call.clone(),
    );

    let a2a_task_state = match case {
        AgentWebCase::A2aFailedTaskState => "failed",
        _ => "completed",
    };
    let a2a_task = json_bytes(json!({
        "object_kind": "a2a_task",
        "id": "a2a-task-agent-web-valid",
        "protocol_version": "0.3.0",
        "task_id": "task-a2a-agent-web-001",
        "message_id": "message-a2a-agent-web-001",
        "agent_card_digest": "1313131313131313131313131313131313131313131313131313131313131313",
        "agent_card_schema_digest": "5858585858585858585858585858585858585858585858585858585858585858",
        "agent_card_url_digest": "5959595959595959595959595959595959595959595959595959595959595959",
        "skill_id_digest": "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a",
        "interface_url_digest": "5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b",
        "context_id_digest": "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c",
        "task_input_digest": "2424242424242424242424242424242424242424242424242424242424242424",
        "task_state": a2a_task_state,
        "task_state_digest": "3535353535353535353535353535353535353535353535353535353535353535",
        "message_parts_digest": "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d",
        "message_send_digest": "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e",
        "result_digest": "4646464646464646464646464646464646464646464646464646464646464646",
        "metadata_chio_skill_selector_digest": "5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f5f",
        "task_artifacts_digest": "6060606060606060606060606060606060606060606060606060606060606060",
        "streaming_lifecycle_digest": "6161616161616161616161616161616161616161616161616161616161616161",
        "cancel_lifecycle_digest": "6262626262626262626262626262626262626262626262626262626262626262",
        "push_notification_config_digest": "6363636363636363636363636363636363636363636363636363636363636363",
        "authorization_context_digest": "5757575757575757575757575757575757575757575757575757575757575757"
    }));
    push_artifact(
        &mut builder.artifacts,
        &mut builder.graph_nodes,
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
    let openapi_status_code = match case {
        AgentWebCase::OpenApiFailedStatus => 500,
        _ => 201,
    };
    let openapi_operation = json_bytes(json!({
        "object_kind": "openapi_operation",
        "id": "openapi-operation-agent-web-valid",
        "spec_digest": "6868686868686868686868686868686868686868686868686868686868686868",
        "openapi_document_id_digest": "a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6",
        "server_url_digest": "a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7",
        "operation_id": "createAgentOrder",
        "method": "POST",
        "path_template": "/orders",
        "path_parameters_digest": "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
        "request_digest": "7979797979797979797979797979797979797979797979797979797979797979",
        "response_digest": "8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a",
        "status_code": openapi_status_code,
        "x_chio_proof_envelope_profile": "chio.agent-web-proof-envelope.v1",
        "x_chio_receipt_binding_digest": "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9",
        "x_chio_evidence_profile_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "egress_contract_digest": "abababababababababababababababababababababababababababababababab",
        "redirect_followed": false,
        "response_size_bytes": 4096,
        "max_response_size_bytes": 1048576,
        "authorization_context_digest": "9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b",
        "chio_operation_receipt_ref": openapi_receipt_ref
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
            "external-subject",
            "openapi-operation",
            "external.openapi.operation.v1",
            "external/openapi-operation.json",
            openapi_operation.clone(),
        );
    }

    let acp_client_permission_decision = match case {
        AgentWebCase::AcpClientDenied => "deny",
        _ => "allow",
    };
    let acp_client_permission = json_bytes(json!({
        "object_kind": "acp_client_permission_request",
        "id": "acp-client-permission-agent-web-valid",
        "protocol_version": "v1",
        "capability_id": "write_file",
        "category": "filesystem",
        "requires_permission": true,
        "permission_decision": acp_client_permission_decision,
        "bridge_fidelity": "lossless",
        "jsonrpc_method": "session/request_permission",
        "jsonrpc_id_digest": "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
        "params_digest": "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
        "permission_request_digest": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
        "file_path_scope_digest": "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3",
        "terminal_command_scope_digest": "a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4",
        "chio_receipt_id": "receipt-agent-web-acp-client-permission-allow",
        "evidence_path_kind": "signed-receipt",
        "receipt_signature_digest": "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
        "source_envelope_digest": "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac",
        "arguments_digest": "bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc",
        "client_session_digest": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "agent_id_digest": "dededededededededededededededededededededededededededededededede",
        "authorization_context_digest": "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"
    }));
    if matches!(
        case,
        AgentWebCase::AcpClientProjection | AgentWebCase::AcpClientDenied
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "quote_sha256": "abababababababababababababababababababababababababababababababab",
        "intent_ref": "intent-commerce-001",
        "provider_admission_ref": "provider-admission-commerce-001",
        "provider_passport_ref": "provider-passport-commerce-001",
        "reputation_snapshot_ref": "reputation-snapshot-commerce-001",
        "federation_trust_bundle_ref": "federation-trust-bundle-commerce-001",
        "settlement_packet_ref": "settlement-packet-commerce-001",
        "reconciliation_ref": "reconciliation-commerce-001",
        "event_log_sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "event_log_path": "commerce/event-log.json",
        "payment_lifecycle_sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "payment_lifecycle_path": "commerce/payment-lifecycle.json",
        "mandate_ledger_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
        "mandate_ledger_path": "commerce/mandate-allowance-ledger.json",
        "provider_passport_sha256": "0303030303030303030303030303030303030303030303030303030303030303",
        "provider_passport_path": "commerce/provider-passport.json",
        "reputation_snapshot_sha256": "0404040404040404040404040404040404040404040404040404040404040404",
        "reputation_snapshot_path": "commerce/reputation-snapshot.json",
        "federation_trust_bundle_sha256": "0505050505050505050505050505050505050505050505050505050505050505",
        "federation_trust_bundle_path": "commerce/federation-trust-bundle.json",
        "settlement_packet_sha256": "0202020202020202020202020202020202020202020202020202020202020202",
        "settlement_packet_path": "commerce/settlement-packet.json",
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
    let acp_commerce_status = match case {
        AgentWebCase::AcpCommerceRefunded => "refunded",
        _ => "authorized",
    };

    let acp_commerce_checkout = json_bytes(json!({
        "object_kind": "acp_commerce_checkout",
        "id": "acp-commerce-checkout-agent-web-valid",
        "transaction_passport_ref": builder.passport.id,
        "order_id": "order-commerce-001",
        "delegated_payment_token_digest": "a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8",
        "checkout_context_digest": "b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9b9",
        "order_context_digest": acp_commerce_order_context_digest,
        "payment_instruction_digest": "dbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdbdb",
        "merchant_identity_digest": "ecececececececececececececececececececececececececececececececec",
        "buyer_identity_digest": "fdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfdfd",
        "amount_units": 1250,
        "currency": "USD",
        "status": acp_commerce_status,
        "chio_checkout_receipt_ref": acp_commerce_receipt_ref
    }));

    let ag_ui_allowed = !matches!(case, AgentWebCase::AgUiDenied);
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
        "allowed": ag_ui_allowed,
        "payload_digest": "4444444444444444444444444444444444444444444444444444444444444444",
        "receipt_digest": "5555555555555555555555555555555555555555555555555555555555555555",
        "authorization_context_digest": "6666666666666666666666666666666666666666666666666666666666666666",
        "event_sequence": [
            {
                "phase": "start",
                "event_id": "evt-agent-web-checkout-001:start",
                "payload_digest": "6767676767676767676767676767676767676767676767676767676767676767",
                "receipt_digest": "6868686868686868686868686868686868686868686868686868686868686868"
            },
            {
                "phase": "content",
                "event_id": "evt-agent-web-checkout-001:content",
                "payload_digest": "6969696969696969696969696969696969696969696969696969696969696969",
                "receipt_digest": "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a"
            },
            {
                "phase": "end",
                "event_id": "evt-agent-web-checkout-001:end",
                "payload_digest": "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b",
                "receipt_digest": "6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c6c"
            }
        ]
    }));
    if matches!(
        case,
        AgentWebCase::AgUiProjection | AgentWebCase::AgUiDenied
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-subject",
            "ag-ui-event",
            "external.ag-ui.event.v1",
            "external/ag-ui-event.json",
            ag_ui_event.clone(),
        );
    }

    let browser_command_receipt_ref = match case {
        AgentWebCase::BrowserAutomationReceiptRefMismatch => {
            "receipt-agent-web-browser-command-other"
        }
        _ => "receipt-agent-web-browser-command-allow",
    };
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
        "chio_command_receipt_ref": browser_command_receipt_ref,
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::BrowserAutomationProjection
            | AgentWebCase::BrowserAutomationReceiptRefMismatch
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-subject",
            "email-message",
            "external.email.connector-action.v1",
            "external/email-message.json",
            email_connector_action.clone(),
        );
    }

    let calendar_time_range_digest = match case {
        AgentWebCase::CalendarTimeRangeMismatch | AgentWebCase::CalendarCreateTimeRangeMismatch => {
            "8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b8a8b"
        }
        _ => "8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c8a8c",
    };
    let calendar_write_method = match case {
        AgentWebCase::CalendarCreateTimeRangeMismatch => "create",
        _ => "update",
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
        "write_method": calendar_write_method,
        "oauth_scope_set_digest": "8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f8b8f",
        "receipt_refs": ["receipt-agent-web-calendar-event-allow"],
        "mediated_by_chio_receipt": true
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "rekor_inclusion_status": "advisory",
        "cache_admission_report_digest": "b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
        "receipt_refs": ["receipt-agent-web-oci-ref-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(
        case,
        AgentWebCase::OciRefProjection | AgentWebCase::OciTagOnly
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-subject",
            "sd-jwt-vc-presentation",
            "external.sd-jwt-vc.presentation.v1",
            "external/sd-jwt-vc-presentation.json",
            sd_jwt_vc_presentation.clone(),
        );
    }

    let bbs_verification_status = if matches!(case, AgentWebCase::BbsSelfAssertedVerified) {
        "verified"
    } else {
        "claimed"
    };
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
        "verification_status": bbs_verification_status,
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
        AgentWebCase::BbsProjection
            | AgentWebCase::BbsSelfAssertedVerified
            | AgentWebCase::BbsReceiptRefMissing
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "verification_status": "advisory",
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "predicate_type": "chio.bilateral-cosign-invocation.v1",
        "dsse_envelope_digest": "a0".repeat(32),
        "payload_digest": "a1".repeat(32),
        "subject_digest": "a2".repeat(32),
        "predicate_digest": "a3".repeat(32),
        "builder_identity_digest": "a4".repeat(32),
        "signer_identity_digest": "a5".repeat(32),
        "verification_material_digest": "a6".repeat(32),
        "authorization_context_digest": "a7".repeat(32),
        "peer_pin_digest": "a8".repeat(32),
        "policy_summary_digest": "a9".repeat(32),
        "capability_lease_ref": "lease-agent-web-in-toto-bilateral",
        "signature_count": 2,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "signature_count": 2,
        "verification_status": "verified",
        "receipt_refs": ["receipt-agent-web-dsse-envelope-allow"],
        "mediated_by_chio_receipt": true
    }));
    if matches!(case, AgentWebCase::DsseProjection) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        "transaction_passport_ref": builder.passport.id,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
    let x402_asset = match case {
        AgentWebCase::X402AssetMismatch => "DAI",
        _ => "USDC",
    };
    let x402_receipt_ref = match case {
        AgentWebCase::X402ReceiptRefMismatch => "receipt-agent-web-x402-other-allow",
        _ => "receipt-agent-web-x402-payment-allow",
    };
    let x402_status = match case {
        AgentWebCase::X402Refunded => "refunded",
        _ => "settled",
    };
    let x402_payment = json_bytes(json!({
        "object_kind": "x402_payment",
        "id": "x402-payment-agent-web-valid",
        "transaction_passport_ref": builder.passport.id,
        "order_id": "order-commerce-001",
        "resource_digest": "abababababababababababababababababababababababababababababababab",
        "payment_requirements_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "payment_proof_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "settlement_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "network": "base-sepolia",
        "asset": x402_asset,
        "amount_units": x402_amount_units,
        "status": x402_status,
        "chio_payment_receipt_ref": x402_receipt_ref
    }));
    if matches!(
        case,
        AgentWebCase::AcpCommerceProjection
            | AgentWebCase::AcpCommerceOrderContextDigestMismatch
            | AgentWebCase::AcpCommerceReceiptRefMismatch
            | AgentWebCase::AcpCommerceRefunded
            | AgentWebCase::Ap2Projection
            | AgentWebCase::Ap2TransactionContextDigestMismatch
            | AgentWebCase::Ap2DetachedOrder
            | AgentWebCase::Ap2ReceiptRefMismatch
            | AgentWebCase::X402Projection
            | AgentWebCase::X402AmountMismatch
            | AgentWebCase::X402AssetMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
            | AgentWebCase::X402Refunded
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            | AgentWebCase::AcpCommerceRefunded
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            | AgentWebCase::X402AssetMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
            | AgentWebCase::X402Refunded
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-subject",
            "x402-payment",
            "external.x402.payment.v1",
            "external/x402-payment.json",
            x402_payment.clone(),
        );
    }

    for (path, bytes) in [
        ("external/webhook-delivery.json", webhook_delivery),
        ("external/cloudevent.json", cloudevent),
        ("external/graphql-operation.json", graphql_operation),
        ("external/mcp-tool-call.json", mcp_tool_call),
        ("external/a2a-task.json", a2a_task),
        ("external/openapi-operation.json", openapi_operation),
        ("external/acp-client-permission.json", acp_client_permission),
        ("external/order-context.json", order_context),
        ("external/acp-commerce-checkout.json", acp_commerce_checkout),
        ("external/ag-ui-event.json", ag_ui_event),
        ("external/browser-command.json", browser_automation_command),
        ("external/rpa-transcript.json", rpa_transcript),
        ("external/email-message.json", email_connector_action),
        ("external/calendar-event.json", calendar_connector_action),
        ("external/slack-message.json", slack_connector_action),
        ("external/oauth2-authorization.json", oauth2_authorization),
        (
            "external/openid-connect-identity.json",
            openid_connect_identity,
        ),
        ("external/scim-lifecycle.json", scim_lifecycle_event),
        (
            "external/spiffe-workload-identity.json",
            spiffe_workload_identity,
        ),
        (
            "external/kubernetes-admission-review.json",
            kubernetes_admission_review,
        ),
        ("external/oci-ref.json", oci_artifact_ref),
        ("external/verifiable-credential.json", verifiable_credential),
        (
            "external/sd-jwt-vc-presentation.json",
            sd_jwt_vc_presentation,
        ),
        (
            "external/bbs-receipt-disclosure.json",
            bbs_receipt_disclosure,
        ),
        ("external/sigstore-bundle.json", sigstore_bundle),
        ("external/in-toto-statement.json", in_toto_statement),
        ("external/dsse-envelope.json", dsse_envelope_subject),
        ("external/slsa-provenance.json", slsa_provenance),
        ("external/asyncapi-message.json", asyncapi_message),
        ("external/ap2-mandate-chain.json", ap2_mandate_chain),
        ("external/x402-payment.json", x402_payment),
    ] {
        builder.raw_artifacts.insert(path.to_string(), bytes);
    }
}
