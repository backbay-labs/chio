use super::support::*;
use serde_json::json;

pub(crate) fn add_core_projection_manifests(builder: &mut AgentWebBundleBuilder) {
    let case = builder.case;
    let webhook_delivery = builder.artifact_bytes("external/webhook-delivery.json");
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
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
        AgentWebCase::MissingRequiredSignature => String::new(),
        _ => standard_webhooks_signature_ref_for_case(case),
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
        "schema": "chio.agent-web-proof-envelope.v2",
        "envelope_id": "agent-web-envelope-standard-webhooks-valid",
        "transaction_passport_ref": builder.passport.id,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "agent-web-proof-envelope",
        "standard-webhooks-envelope",
        "chio.agent-web-proof-envelope.v2",
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "external-projection-manifest",
        "cloudevents-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "cloudevents-manifest.json",
        cloudevents_manifest,
    );

    let graphql_source_version = graphql_source_version(case);
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
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
            "authorization_context_digest",
            "protected_resource_metadata_digest",
            "authorization_server_metadata_digest",
            "dpop_proof_digest",
            "proof_envelope_resource_read_digest"
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
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
            "agent_card_schema_digest",
            "agent_card_url_digest",
            "skill_id_digest",
            "interface_url_digest",
            "context_id_digest",
            "task_input_digest",
            "task_state",
            "task_state_digest",
            "message_parts_digest",
            "message_send_digest",
            "result_digest",
            "metadata_chio_skill_selector_digest",
            "task_artifacts_digest",
            "streaming_lifecycle_digest",
            "cancel_lifecycle_digest",
            "push_notification_config_digest",
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
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "external-projection-manifest",
        "a2a-manifest",
        "chio.agent-web.external-projection-manifest.v1",
        "a2a-manifest.json",
        a2a_manifest,
    );

    let openapi_source_version = openapi_source_version(case);
    let openapi_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-openapi-valid",
        "source_protocol": "openapi",
        "source_version": openapi_source_version,
        "external_fields_used": [
            "spec_digest",
            "openapi_document_id_digest",
            "server_url_digest",
            "operation_id",
            "method",
            "path_template",
            "path_parameters_digest",
            "request_digest",
            "response_digest",
            "status_code",
            "x_chio_proof_envelope_profile",
            "x_chio_receipt_binding_digest",
            "x_chio_evidence_profile_digest",
            "egress_contract_digest",
            "redirect_followed",
            "response_size_bytes",
            "max_response_size_bytes",
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
            | AgentWebCase::OpenApiFailedStatus
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            "jsonrpc_method",
            "jsonrpc_id_digest",
            "params_digest",
            "permission_request_digest",
            "file_path_scope_digest",
            "terminal_command_scope_digest",
            "chio_receipt_id",
            "evidence_path_kind",
            "receipt_signature_digest",
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
    if matches!(
        case,
        AgentWebCase::AcpClientProjection | AgentWebCase::AcpClientDenied
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            | AgentWebCase::AcpCommerceRefunded
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            "authorization_context_digest",
            "event_sequence"
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
    if matches!(
        case,
        AgentWebCase::AgUiProjection | AgentWebCase::AgUiDenied
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            "chio_command_receipt_ref",
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
    if matches!(
        case,
        AgentWebCase::BrowserAutomationProjection
            | AgentWebCase::BrowserAutomationReceiptRefMismatch
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
        AgentWebCase::CalendarProjection
            | AgentWebCase::CalendarTimeRangeMismatch
            | AgentWebCase::CalendarCreateTimeRangeMismatch
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
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
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "slack-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "slack-manifest.json",
            slack_manifest,
        );
    }
}
