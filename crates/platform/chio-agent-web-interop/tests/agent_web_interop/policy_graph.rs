use super::support::*;
use chio_agent_web_interop::AgentWebInteropBundle;
use serde_json::{json, Value};

pub(crate) fn finish_agent_web_bundle(mut builder: AgentWebBundleBuilder) -> AgentWebInteropBundle {
    let case = builder.case;
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
    let claim_set = json_bytes(json!({
        "schema": "chio.transaction.claim-set.v1",
        "id": "claim-set-agent-web-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "claims": [
            {
                "claim_id": CLAIM_EXTERNAL_SUBJECT_DIGEST_BOUND,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio-agent-web-interop"
            },
            {
                "claim_id": CLAIM_PROJECTION_MANIFEST_BOUND,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio-agent-web-interop"
            },
            {
                "claim_id": CLAIM_UNSUPPORTED_CLAIMS_LIMITED,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio-agent-web-interop"
            },
            {
                "claim_id": CLAIM_SIDECAR_NOT_NATIVE_AUTHORITY,
                "status": "verified",
                "required_evidence": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "evidence_refs": [
                    "transaction-passport.json",
                    "evidence-graph.json",
                    "verifier-policy.json"
                ],
                "verifier_module": "chio-agent-web-interop"
            }
        ]
    }));
    let claim_set_sha256 = chio_core_types::sha256_hex(&claim_set);
    push_artifact(
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "claim-set",
        "claim-set",
        "chio.transaction.claim-set.v1",
        "claim-set.json",
        claim_set,
    );
    push_artifact(
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        "verifier-policy",
        "verifier-policy",
        "chio.transaction.verifier-policy.v1",
        "verifier-policy.json",
        verifier_policy.clone(),
    );
    sign_agent_web_receipts(
        case,
        &mut builder.artifacts,
        &mut builder.graph_nodes,
        &verifier_policy_sha256,
    );
    bind_agent_web_envelope_manifest_digests(&mut builder.artifacts, &mut builder.graph_nodes);
    sign_agent_web_envelopes(&mut builder.artifacts, &mut builder.graph_nodes);

    let mut graph_edges = vec![
        json!({
            "from": "claim-set",
            "to": "verifier-policy",
            "predicate": "binds",
            "evidence_class": "digest-bound-reference"
        }),
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
            | AgentWebCase::OpenApiFailedStatus
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
    if matches!(
        case,
        AgentWebCase::AcpClientProjection | AgentWebCase::AcpClientDenied
    ) {
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
            | AgentWebCase::AcpCommerceRefunded
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
    if matches!(
        case,
        AgentWebCase::AgUiProjection | AgentWebCase::AgUiDenied
    ) {
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
    if matches!(
        case,
        AgentWebCase::BrowserAutomationProjection
            | AgentWebCase::BrowserAutomationReceiptRefMismatch
    ) {
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
        AgentWebCase::CalendarProjection
            | AgentWebCase::CalendarTimeRangeMismatch
            | AgentWebCase::CalendarCreateTimeRangeMismatch
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
        AgentWebCase::BbsProjection
            | AgentWebCase::BbsSelfAssertedVerified
            | AgentWebCase::BbsReceiptRefMissing
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
            | AgentWebCase::X402AssetMismatch
            | AgentWebCase::X402DetachedOrder
            | AgentWebCase::X402ReceiptRefMismatch
            | AgentWebCase::X402Refunded
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
    content_address_graph_nodes(&mut builder.graph_nodes, &mut graph_edges);
    let evidence_graph = json_bytes(json!({
        "schema": "chio.transaction.evidence-graph.v1",
        "id": "agent-web-evidence-graph-valid",
        "issued_at": "2026-06-10T00:00:00Z",
        "nodes": builder.graph_nodes,
        "edges": graph_edges
    }));

    builder.passport.evidence_graph_sha256 = chio_core_types::sha256_hex(&evidence_graph);
    builder.passport.claim_set_sha256 = claim_set_sha256;
    builder.passport.verifier_policy_sha256 = verifier_policy_sha256;
    sign_transaction_passport(&mut builder.passport);

    AgentWebInteropBundle {
        passport: builder.passport,
        evidence_graph_bytes: evidence_graph,
        root_evidence_graph_bytes: None,
        verifier_policy_bytes: verifier_policy,
        artifacts: builder.artifacts,
    }
}
