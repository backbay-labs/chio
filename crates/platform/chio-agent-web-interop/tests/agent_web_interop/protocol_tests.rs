use super::support::*;
use chio_test_support::prelude::*;

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
fn agent_web_interop_rejects_calendar_create_time_range_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::CalendarCreateTimeRangeMismatch);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Calendar create must match approved time range");

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
fn agent_web_interop_rejects_ag_ui_without_start_content_end_sequence() {
    let mut bundle = agent_web_bundle(AgentWebCase::AgUiProjection);
    replace_agent_web_json_artifact(&mut bundle, "external/ag-ui-event.json", |subject| {
        subject
            .as_object_mut()
            .test_expect("AG-UI subject is an object")
            .remove("event_sequence");
    });
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/ag-ui-event.json")
            .test_expect("AG-UI subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "ag-ui-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("AG-UI projection must bind a start-content-end event sequence");

    assert!(error.to_string().contains("missing AG-UI event sequence"));
}

#[test]
fn agent_web_interop_rejects_mcp_without_dpop_binding() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "external/mcp-tool-call.json", |subject| {
        subject
            .as_object_mut()
            .test_expect("MCP subject is an object")
            .remove("dpop_proof_digest");
    });
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/mcp-tool-call.json")
            .test_expect("MCP subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "mcp-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("MCP projection must bind DPoP proof");

    assert!(error.to_string().contains("missing MCP DPoP proof digest"));
}

#[test]
fn agent_web_interop_rejects_a2a_without_message_send_binding() {
    let mut bundle = agent_web_bundle(AgentWebCase::Valid);
    replace_agent_web_json_artifact(&mut bundle, "external/a2a-task.json", |subject| {
        subject
            .as_object_mut()
            .test_expect("A2A subject is an object")
            .remove("message_send_digest");
    });
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/a2a-task.json")
            .test_expect("A2A subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "a2a-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("A2A projection must bind message/send");

    assert!(error
        .to_string()
        .contains("missing A2A message/send digest"));
}

#[test]
fn agent_web_interop_rejects_acp_client_without_path_scope() {
    let mut bundle = agent_web_bundle(AgentWebCase::AcpClientProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/acp-client-permission.json",
        |subject| {
            subject
                .as_object_mut()
                .test_expect("ACP-Client subject is an object")
                .remove("file_path_scope_digest");
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/acp-client-permission.json")
            .test_expect("ACP-Client subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "acp-client-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });
    replace_agent_web_receipt_for_subject(
        &mut bundle,
        "receipts/receipt-agent-web-acp-client-permission-allow.json",
        "receipt-agent-web-acp-client-permission-allow",
        &subject_digest,
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("ACP-Client projection must bind file path scope");

    assert!(
        error
            .to_string()
            .contains("missing ACP-Client file path scope digest"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_acp_client_unsigned_audit_path_as_receipt() {
    let mut bundle = agent_web_bundle(AgentWebCase::AcpClientProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/acp-client-permission.json",
        |subject| {
            subject["evidence_path_kind"] = serde_json::json!("unsigned-audit");
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/acp-client-permission.json")
            .test_expect("ACP-Client subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "acp-client-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });
    replace_agent_web_receipt_for_subject(
        &mut bundle,
        "receipts/receipt-agent-web-acp-client-permission-allow.json",
        "receipt-agent-web-acp-client-permission-allow",
        &subject_digest,
    );

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("ACP-Client projection must use a signed receipt path");

    assert!(
        error
            .to_string()
            .contains("ACP-Client unsigned audit path cannot satisfy signed receipt projection"),
        "{error}"
    );
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
fn agent_web_interop_rejects_self_asserted_oci_rekor_verified() {
    let mut bundle = agent_web_bundle(AgentWebCase::OciRefProjection);
    replace_agent_web_json_artifact(&mut bundle, "external/oci-ref.json", |subject| {
        subject["rekor_inclusion_status"] = serde_json::json!("verified");
    });
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/oci-ref.json")
            .test_expect("OCI subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "oci-ref-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("OCI Rekor verification must not be self-asserted");

    assert!(
        error
            .to_string()
            .contains("OCI Rekor inclusion must not be self-asserted as verified"),
        "{error}"
    );
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
fn agent_web_interop_rejects_self_asserted_bbs_verified_status() {
    let bundle = agent_web_bundle(AgentWebCase::BbsSelfAssertedVerified);

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("BBS verification status must not be self-asserted");

    assert!(
        error
            .to_string()
            .contains("BBS verification status must not be self-asserted as verified"),
        "{error}"
    );
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
fn agent_web_interop_rejects_self_asserted_sigstore_verified_status() {
    let mut bundle = agent_web_bundle(AgentWebCase::SigstoreProjection);
    replace_agent_web_json_artifact(&mut bundle, "external/sigstore-bundle.json", |subject| {
        subject["verification_status"] = serde_json::json!("verified");
    });
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/sigstore-bundle.json")
            .test_expect("Sigstore subject exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "sigstore-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("Sigstore verification must not be self-asserted");

    assert!(
        error
            .to_string()
            .contains("Sigstore verification status must not be self-asserted as verified"),
        "{error}"
    );
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
fn agent_web_interop_rejects_in_toto_single_signature_count() {
    let mut bundle = agent_web_bundle(AgentWebCase::InTotoProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/in-toto-statement.json",
        |statement| {
            statement["signature_count"] = serde_json::json!(1);
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/in-toto-statement.json")
            .test_expect("in-toto statement exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "in-toto-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("in-toto statements require bilateral signatures");

    assert!(
        error
            .to_string()
            .contains("in-toto statement requires bilateral DSSE signatures"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_in_toto_non_bilateral_predicate() {
    let mut bundle = agent_web_bundle(AgentWebCase::InTotoProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/in-toto-statement.json",
        |statement| {
            statement["predicate_type"] =
                serde_json::json!("https://chio.dev/predicates/agent-web-invocation/v1");
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/in-toto-statement.json")
            .test_expect("in-toto statement exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "in-toto-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("in-toto statement must use the bilateral invocation predicate");

    assert!(
        error
            .to_string()
            .contains("unsupported in-toto bilateral predicate type"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_in_toto_missing_peer_pin() {
    let mut bundle = agent_web_bundle(AgentWebCase::InTotoProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/in-toto-statement.json",
        |statement| {
            statement
                .as_object_mut()
                .test_expect("in-toto statement is object")
                .remove("peer_pin_digest");
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/in-toto-statement.json")
            .test_expect("in-toto statement exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "in-toto-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("in-toto statement must bind peer pins");

    assert!(
        error
            .to_string()
            .contains("missing in-toto peer pin digest"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_in_toto_missing_policy_summary() {
    let mut bundle = agent_web_bundle(AgentWebCase::InTotoProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/in-toto-statement.json",
        |statement| {
            statement
                .as_object_mut()
                .test_expect("in-toto statement is object")
                .remove("policy_summary_digest");
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/in-toto-statement.json")
            .test_expect("in-toto statement exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "in-toto-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("in-toto statement must bind policy summaries");

    assert!(
        error
            .to_string()
            .contains("missing in-toto policy summary digest"),
        "{error}"
    );
}

#[test]
fn agent_web_interop_rejects_in_toto_missing_capability_lease() {
    let mut bundle = agent_web_bundle(AgentWebCase::InTotoProjection);
    replace_agent_web_json_artifact(
        &mut bundle,
        "external/in-toto-statement.json",
        |statement| {
            statement
                .as_object_mut()
                .test_expect("in-toto statement is object")
                .remove("capability_lease_ref");
        },
    );
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/in-toto-statement.json")
            .test_expect("in-toto statement exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "in-toto-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("in-toto statement must bind a capability lease");

    assert!(
        error
            .to_string()
            .contains("missing in-toto capability lease ref"),
        "{error}"
    );
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
fn agent_web_interop_rejects_dsse_single_signature_count() {
    let mut bundle = agent_web_bundle(AgentWebCase::DsseProjection);
    replace_agent_web_json_artifact(&mut bundle, "external/dsse-envelope.json", |envelope| {
        envelope["signature_count"] = serde_json::json!(1);
    });
    let subject_digest = chio_core_types::sha256_hex(
        bundle
            .artifacts
            .get("external/dsse-envelope.json")
            .test_expect("DSSE envelope exists"),
    );
    replace_agent_web_envelope_artifact(&mut bundle, "dsse-envelope.json", |envelope| {
        envelope["external_subject_digest"] = serde_json::json!(subject_digest);
    });

    let error = verify_agent_web_interop(&bundle)
        .test_expect_err("DSSE envelopes require bilateral signatures");

    assert!(
        error
            .to_string()
            .contains("DSSE envelope requires bilateral signatures"),
        "{error}"
    );
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

#[test]
fn agent_web_interop_rejects_x402_payment_asset_mismatch() {
    let bundle = agent_web_bundle(AgentWebCase::X402AssetMismatch);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("x402 payment asset must match order");

    assert!(error.to_string().contains("x402 payment asset mismatch"));
}

#[test]
fn agent_web_interop_rejects_refunded_x402_payment() {
    let bundle = agent_web_bundle(AgentWebCase::X402Refunded);

    let error =
        verify_agent_web_interop(&bundle).test_expect_err("refunded x402 payments must not verify");

    assert!(error.to_string().contains("x402 payment was refunded"));
}
