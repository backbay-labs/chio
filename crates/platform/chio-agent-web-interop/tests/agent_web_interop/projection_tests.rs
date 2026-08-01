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
fn agent_web_interop_rejects_graphql_http_failed_status() {
    let bundle = agent_web_bundle(AgentWebCase::GraphqlHttpFailedStatus);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("GraphQL failed HTTP status must not verify as success");

    assert!(
        error
            .to_string()
            .contains("GraphQL HTTP status was not successful"),
        "{error}"
    );
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
fn agent_web_interop_rejects_a2a_failed_task_state() {
    let bundle = agent_web_bundle(AgentWebCase::A2aFailedTaskState);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("A2A failed task state must not verify as success");

    assert!(
        error
            .to_string()
            .contains("A2A task state was not successful"),
        "{error}"
    );
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
fn agent_web_interop_accepts_openapi_30_projection() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    replace_agent_web_json_artifact(&mut bundle, "openapi-manifest.json", |manifest| {
        manifest["source_version"] = json!("3.0.3");
    });
    let manifest_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("openapi-manifest.json")
            .test_expect("OpenAPI manifest exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "openapi-envelope.json", |envelope| {
        envelope["source_protocol_version"] = json!("3.0.3");
        envelope["projection_manifest_sha256"] = json!(manifest_digest);
    });
    let subject_digest = bundle
        .artifacts
        .get("external/openapi-operation.json")
        .map(|subject| chio_core_types::sha256_hex(subject))
        .test_expect("OpenAPI subject exists");
    replace_agent_web_receipt_for_subject(
        &mut bundle,
        "receipts/receipt-agent-web-openapi-operation-allow.json",
        "receipt-agent-web-openapi-operation-allow",
        &subject_digest,
    );

    let report =
        verify_agent_web_interop(&bundle).test_expect("OpenAPI 3.0 projection should verify");

    assert!(report
        .projections
        .iter()
        .any(|projection| projection.source_protocol == "openapi"));
}

#[test]
fn agent_web_interop_rejects_openapi_without_proof_envelope_profile() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject
            .as_object_mut()
            .test_expect("OpenAPI subject is an object")
            .remove("x_chio_proof_envelope_profile");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI projection must bind x-chio proof-envelope profile");

    assert!(
        error
            .to_string()
            .contains("missing OpenAPI proof-envelope profile"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_profile_from_another_envelope_version() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject["x_chio_proof_envelope_profile"] = json!("chio.agent-web-proof-envelope.v1");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI profile must match its proof-envelope version");

    assert!(
        error
            .to_string()
            .contains("OpenAPI proof-envelope profile mismatch"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_redirect_followed() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject["redirect_followed"] = json!(true);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OpenAPI projection must reject followed redirects");

    assert!(
        error.to_string().contains("OpenAPI redirect was followed"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_openapi_response_size_exceeded() {
    let mut bundle = agent_web_bundle(AgentWebCase::OpenApiProjection);
    mutate_openapi_subject_and_bound_receipt(&mut bundle, |subject| {
        subject["response_size_bytes"] = json!(2_000_000_u64);
        subject["max_response_size_bytes"] = json!(1_000_000_u64);
    });

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("OpenAPI response size must be bounded");

    assert!(
        error
            .to_string()
            .contains("OpenAPI response exceeded size bound"),
        "{error}"
    );
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
fn agent_web_interop_rejects_openapi_failed_status() {
    let bundle = agent_web_bundle(AgentWebCase::OpenApiFailedStatus);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("OpenAPI failed status must not verify");

    assert!(
        error
            .to_string()
            .contains("OpenAPI response status was not successful"),
        "{error}"
    );
}

fn mutate_openapi_subject_and_bound_receipt(
    bundle: &mut chio_agent_web_interop::AgentWebInteropBundle,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    replace_agent_web_json_artifact(bundle, "external/openapi-operation.json", mutate);
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/openapi-operation.json")
            .test_expect("OpenAPI subject exists"),
    );
    replace_agent_web_envelope_artifact(bundle, "openapi-envelope.json", |envelope| {
        envelope["external_subject_digest"] = json!(subject_digest);
    });
    replace_agent_web_receipt_for_subject(
        bundle,
        "receipts/receipt-agent-web-openapi-operation-allow.json",
        "receipt-agent-web-openapi-operation-allow",
        &subject_digest,
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
fn agent_web_interop_rejects_denied_acp_client_permission() {
    let bundle = agent_web_bundle(AgentWebCase::AcpClientDenied);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("denied ACP-Client permission must fail");

    assert!(error
        .to_string()
        .contains("ACP-Client permission was denied"));
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
fn agent_web_interop_rejects_refunded_acp_commerce_payment() {
    let bundle = agent_web_bundle(AgentWebCase::AcpCommerceRefunded);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("refunded ACP-Commerce payments must not verify");

    assert!(error
        .to_string()
        .contains("ACP-Commerce payment was refunded"));
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
fn agent_web_interop_rejects_denied_ag_ui_event() {
    let bundle = agent_web_bundle(AgentWebCase::AgUiDenied);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("denied AG-UI events must not verify");

    assert!(error.to_string().contains("AG-UI event was not allowed"));
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
fn agent_web_interop_rejects_browser_automation_unbound_command_receipt() {
    let bundle = agent_web_bundle(AgentWebCase::BrowserAutomationReceiptRefMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("browser automation command receipt must be bound to the envelope");

    assert!(
        error
            .to_string()
            .contains("browser command receipt ref is not bound"),
        "{error}"
    );
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
