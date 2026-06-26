use super::support::*;
use chio_test_support::prelude::*;
use serde_json::json;

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
fn agent_web_interop_rejects_tampered_transaction_passport_signature() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    bundle.passport.signature = "00".repeat(64);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web verifier must reject a forged passport root");

    assert!(error
        .to_string()
        .contains("transaction passport signature invalid"));
}

#[test]
fn agent_web_interop_rejects_standard_webhooks_without_configured_secret() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let trust = chio_agent_web_interop::AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys([transaction_passport_keypair().public_key()])
        .with_standard_webhooks_replay_window(
            STANDARD_WEBHOOKS_VERIFIER_NOW,
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
        )
        .with_trusted_envelope_sidecar_keys([agent_web_fixture_sidecar_keypair().public_key()]);

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("Standard Webhooks verification requires verifier-owned secret config");

    assert!(error
        .to_string()
        .contains("missing Standard Webhooks verifier secret"));
}

#[test]
fn agent_web_interop_rejects_receipts_without_trusted_kernel_key() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let trust = chio_agent_web_interop::AgentWebVerifierTrust::new()
        .with_trusted_passport_signer_keys([transaction_passport_keypair().public_key()])
        .with_standard_webhooks_secret_for(
            STANDARD_WEBHOOKS_WEBHOOK_ID,
            STANDARD_WEBHOOKS_VERIFIER_SECRET.to_vec(),
        )
        .with_standard_webhooks_replay_window(
            STANDARD_WEBHOOKS_VERIFIER_NOW,
            STANDARD_WEBHOOKS_MAX_AGE_SECONDS,
        )
        .with_trusted_envelope_sidecar_keys([agent_web_fixture_sidecar_keypair().public_key()]);

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("Agent Web receipt signer must be verifier-trusted");

    assert!(error
        .to_string()
        .contains("Agent Web receipt kernel key untrusted"));
}

#[test]
fn agent_web_interop_rejects_tampered_sidecar_envelope_signature() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "standard-webhooks-envelope.json", |envelope| {
        envelope["signature"] = json!("sig-agent-web-standard-webhooks-envelope-tampered");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web sidecar envelope signature must verify");

    assert!(error
        .to_string()
        .contains("Agent Web envelope signature invalid"));
}

#[test]
fn agent_web_interop_rejects_non_content_addressed_envelope_id() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "standard-webhooks-envelope.json", |envelope| {
        envelope["envelope_id"] = json!("agent-web-envelope-standard-webhooks-valid");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Agent Web envelope id must be content-addressed");

    assert!(error
        .to_string()
        .contains("Agent Web envelope id is not content-addressed"));
}

#[test]
fn agent_web_interop_rejects_projection_manifest_changed_after_sidecar_signature() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "standard-webhooks-manifest.json", |manifest| {
        let mappings = manifest["claim_mapping"]
            .as_array_mut()
            .test_expect("Agent Web manifest has claim mappings");
        let mapping = mappings
            .iter_mut()
            .find(|mapping| mapping["claim_ref"].as_str() == Some(CLAIM_PROJECTION_MANIFEST_BOUND))
            .test_expect("projection manifest claim mapping exists");
        mapping["evidence_class"] = json!("digest-bound-reference");
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("sidecar envelope signature must bind projection manifest digest");

    assert!(error
        .to_string()
        .contains("projection manifest digest mismatch"));
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
fn agent_web_interop_rejects_forged_webhook_signature() {
    let bundle = agent_web_bundle(AgentWebCase::ForgedWebhookSignature);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks signature must verify against the delivery fields");

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
fn agent_web_interop_rejects_stale_webhook_timestamp() {
    let bundle = agent_web_bundle(AgentWebCase::StaleWebhookTimestamp);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Standard Webhooks timestamp must be inside verifier replay window");

    assert!(error
        .to_string()
        .contains("stale Standard Webhooks timestamp"));
}

#[test]
fn agent_web_interop_rejects_replayed_webhook_id() {
    let bundle = agent_web_bundle(AgentWebCase::Valid);
    let trust =
        agent_web_fixture_trust().with_seen_standard_webhooks_id(STANDARD_WEBHOOKS_WEBHOOK_ID);

    let error = chio_agent_web_interop::verify_agent_web_interop_with_trust(&bundle, &trust)
        .test_expect_err("Standard Webhooks ids must be unique inside the replay window");

    assert!(error.to_string().contains("replayed Standard Webhooks id"));
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
