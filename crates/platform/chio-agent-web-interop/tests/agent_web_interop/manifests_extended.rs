use super::support::*;
use serde_json::json;

pub(crate) fn add_extended_projection_manifests(builder: &mut AgentWebBundleBuilder) {
    let case = builder.case;
    let oauth2_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-oauth2-valid",
        "source_protocol": "oauth2",
        "source_version": "rfc6749",
        "external_fields_used": [
            "issuer",
            "resource",
            "grant_type",
            "subject_digest",
            "audience_digest",
            "client_id_digest",
            "scope_set_digest",
            "authorization_details_digest",
            "sender_constraint",
            "sender_constraint_digest",
            "token_verification_report_digest",
            "chio_caller_identity_digest",
            "token_status",
            "authorized_scope_subset",
            "chio_authorization_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["oauth2_token_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_OAUTH2_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OAuth2 authorization evidence is digest-bound bearer admission evidence, not Chio capability authority."
        ]
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
            "external-projection-manifest",
            "oauth2-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "oauth2-manifest.json",
            oauth2_manifest,
        );
    }

    let openid_connect_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-openid-connect-valid",
        "source_protocol": "openid-connect",
        "source_version": "core-1.0",
        "external_fields_used": [
            "issuer",
            "subject_digest",
            "audience_digest",
            "nonce_digest",
            "authentication_time",
            "acr",
            "amr_digest",
            "id_token_verification_report_digest",
            "token_status",
            "chio_identity_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["openid_connect_identity_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_OPENID_CONNECT_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OpenID Connect identity evidence is digest-bound identity evidence, not Chio capability authority."
        ]
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
            "external-projection-manifest",
            "openid-connect-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "openid-connect-manifest.json",
            openid_connect_manifest,
        );
    }

    let scim_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-scim-valid",
        "source_protocol": "scim",
        "source_version": "rfc7644",
        "external_fields_used": [
            "provider_id",
            "resource_type",
            "resource_id_digest",
            "subject_digest",
            "group_digest",
            "operation",
            "active_state",
            "resource_version_digest",
            "deprovisioning_receipt_ref",
            "capability_revocation_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["scim_lifecycle_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_SCIM_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SCIM lifecycle evidence is digest-bound identity lifecycle evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::ScimProjection | AgentWebCase::ScimActiveLifecycleMissingReceiptRef
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "scim-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "scim-manifest.json",
            scim_manifest,
        );
    }

    let spiffe_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-spiffe-valid",
        "source_protocol": "spiffe",
        "source_version": "workload-api-v1",
        "external_fields_used": [
            "trust_domain",
            "spiffe_id",
            "svid_type",
            "bundle_digest",
            "workload_attestation_ref",
            "expiry",
            "chio_workload_identity_mapping_ref",
            "chio_workload_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["spiffe_workload_identity_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_SPIFFE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SPIFFE workload identity evidence is digest-bound workload identity evidence, not Chio capability authority."
        ]
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
            "external-projection-manifest",
            "spiffe-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "spiffe-manifest.json",
            spiffe_manifest,
        );
    }

    let kubernetes_admission_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-kubernetes-admission-valid",
        "source_protocol": "kubernetes-admission",
        "source_version": "admissionreview-v1",
        "external_fields_used": [
            "cluster_id_digest",
            "api_group",
            "api_version",
            "resource",
            "kind",
            "namespace",
            "operation",
            "request_uid",
            "response_uid",
            "user_info_digest",
            "object_digest",
            "admission_webhook_configuration_digest",
            "allowed",
            "patch_digest",
            "warning_digests",
            "chio_capability_token_digest",
            "chio_admission_receipt_ref",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["kubernetes_admission_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_KUBERNETES_ADMISSION_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Kubernetes admission evidence is digest-bound cluster admission evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::KubernetesAdmissionProjection | AgentWebCase::KubernetesAdmissionUidMismatch
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "kubernetes-admission-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "kubernetes-admission-manifest.json",
            kubernetes_admission_manifest,
        );
    }

    let oci_ref_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-oci-ref-valid",
        "source_protocol": "oci",
        "source_version": "image-spec-v1",
        "external_fields_used": [
            "registry",
            "repository",
            "digest",
            "media_type",
            "descriptor_digest",
            "descriptor_size",
            "artifact_type",
            "subject_digest",
            "sigstore_bundle_digest",
            "rekor_inclusion_status",
            "cache_admission_report_digest",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["oci_ref_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_OCI_REF_AUTHORITY_CLAIM],
        "copy_limitations": [
            "OCI artifact evidence is digest-bound supply-chain evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::OciRefProjection | AgentWebCase::OciTagOnly
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "oci-ref-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "oci-ref-manifest.json",
            oci_ref_manifest,
        );
    }

    let vc_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-vc-valid",
        "source_protocol": "vc",
        "source_version": "vc-data-model-2.0",
        "external_fields_used": [
            "media_type",
            "credential_digest",
            "issuer_digest",
            "subject_digest",
            "credential_schema_digest",
            "credential_status_digest",
            "proof_digest",
            "proof_type",
            "proof_purpose",
            "credential_status",
            "verifier_policy_digest",
            "authorization_context_digest",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "credential_signature_as_chio_authority",
            "issuer_as_chio_authority"
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
        "unsupported_claims": [UNSUPPORTED_VC_AUTHORITY_CLAIM],
        "copy_limitations": [
            "VC evidence is digest-bound credential evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::VcProjection | AgentWebCase::VcReceiptRefMissing
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "vc-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "vc-manifest.json",
            vc_manifest,
        );
    }

    let sd_jwt_vc_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-sd-jwt-vc-valid",
        "source_protocol": "sd-jwt-vc",
        "source_version": "v1",
        "external_fields_used": [
            "media_type",
            "credential_digest",
            "disclosed_claims_digest",
            "holder_binding_digest",
            "issuer_key_digest",
            "verifier_policy_digest",
            "presentation_nonce_digest",
            "audience_digest",
            "authorization_context_digest",
            "credential_status",
            "key_binding_alg",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["credential_presentation_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_SD_JWT_VC_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SD-JWT VC presentation evidence is digest-bound credential evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SdJwtVcProjection | AgentWebCase::SdJwtVcReceiptRefMissing
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "sd-jwt-vc-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "sd-jwt-vc-manifest.json",
            sd_jwt_vc_manifest,
        );
    }

    let bbs_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-bbs-valid",
        "source_protocol": "bbs",
        "source_version": "chio-receipt-bbs-v1",
        "external_fields_used": [
            "projection_profile",
            "proof_digest",
            "revealed_messages_digest",
            "hidden_messages_digest",
            "issuer_key_digest",
            "nonce_digest",
            "verifier_policy_digest",
            "receipt_digest",
            "authorization_context_digest",
            "disclosure_count",
            "hidden_count",
            "verification_status",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "bbs_proof_as_chio_authority",
            "vc_di_bbs_interop"
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
        "unsupported_claims": [
            UNSUPPORTED_BBS_AUTHORITY_CLAIM,
            UNSUPPORTED_VC_DI_BBS_INTEROP_CLAIM
        ],
        "copy_limitations": [
            "BBS receipt disclosure evidence is digest-bound Chio receipt evidence, not generic VC Data Integrity BBS interoperability or Chio capability authority."
        ]
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
            "external-projection-manifest",
            "bbs-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "bbs-manifest.json",
            bbs_manifest,
        );
    }

    let sigstore_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-sigstore-valid",
        "source_protocol": "sigstore",
        "source_version": "bundle-v1",
        "external_fields_used": [
            "media_type",
            "bundle_digest",
            "artifact_digest",
            "certificate_identity_digest",
            "certificate_issuer_digest",
            "transparency_log_digest",
            "rekor_entry_digest",
            "signature_digest",
            "verification_material_digest",
            "slsa_provenance_digest",
            "authorization_context_digest",
            "predicate_type",
            "transparency_included",
            "verification_status",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["sigstore_bundle_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_SIGSTORE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "Sigstore bundle evidence is digest-bound supply-chain evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SigstoreProjection | AgentWebCase::SigstoreReceiptRefMissing
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "sigstore-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "sigstore-manifest.json",
            sigstore_manifest,
        );
    }

    let in_toto_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-in-toto-valid",
        "source_protocol": "in-toto",
        "source_version": "statement-v1-dsse",
        "external_fields_used": [
            "statement_type",
            "payload_type",
            "predicate_type",
            "dsse_envelope_digest",
            "payload_digest",
            "subject_digest",
            "predicate_digest",
            "builder_identity_digest",
            "signer_identity_digest",
            "verification_material_digest",
            "authorization_context_digest",
            "signature_count",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": [
            "in_toto_statement_as_chio_authority",
            "dsse_envelope_as_chio_authority"
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
        "unsupported_claims": [
            UNSUPPORTED_IN_TOTO_AUTHORITY_CLAIM,
            UNSUPPORTED_DSSE_AUTHORITY_CLAIM
        ],
        "copy_limitations": [
            "in-toto Statement and DSSE envelope evidence are digest-bound supply-chain evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::InTotoProjection | AgentWebCase::InTotoReceiptRefMissing
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "in-toto-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "in-toto-manifest.json",
            in_toto_manifest,
        );
    }

    let dsse_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-dsse-valid",
        "source_protocol": "dsse",
        "source_version": "v1",
        "external_fields_used": [
            "payload_type",
            "payload_digest",
            "subject_digest",
            "signature_digest",
            "signer_identity_digest",
            "verification_material_digest",
            "authorization_context_digest",
            "signature_count",
            "verification_status"
        ],
        "external_fields_not_used": ["dsse_envelope_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_DSSE_AUTHORITY_CLAIM],
        "copy_limitations": [
            "DSSE envelope evidence is digest-bound supply-chain envelope evidence, not Chio capability authority."
        ]
    }));
    if matches!(case, AgentWebCase::DsseProjection) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "dsse-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "dsse-manifest.json",
            dsse_manifest,
        );
    }

    let slsa_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-slsa-valid",
        "source_protocol": "slsa-provenance",
        "source_version": "v1",
        "external_fields_used": [
            "predicate_type",
            "build_type",
            "builder_id_digest",
            "build_invocation_digest",
            "resolved_dependencies_digest",
            "materials_digest",
            "artifact_digest",
            "provenance_digest",
            "verification_material_digest",
            "authorization_context_digest",
            "build_started_on",
            "build_finished_on",
            "verification_status",
            "receipt_refs",
            "mediated_by_chio_receipt"
        ],
        "external_fields_not_used": ["slsa_provenance_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_SLSA_AUTHORITY_CLAIM],
        "copy_limitations": [
            "SLSA provenance evidence is digest-bound build evidence, not Chio capability authority."
        ]
    }));
    if matches!(
        case,
        AgentWebCase::SlsaProjection | AgentWebCase::SlsaUnverified
    ) {
        push_artifact(
            &mut builder.artifacts,
            &mut builder.graph_nodes,
            "external-projection-manifest",
            "slsa-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "slsa-manifest.json",
            slsa_manifest,
        );
    }

    let asyncapi_source_version = asyncapi_source_version(case);
    let asyncapi_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-asyncapi-valid",
        "source_protocol": "asyncapi",
        "source_version": asyncapi_source_version,
        "external_fields_used": [
            "spec_digest",
            "channel_digest",
            "message_digest",
            "payload_digest",
            "headers_digest",
            "broker_identity_digest",
            "authorization_context_digest",
            "operation_id",
            "channel",
            "direction",
            "protocol",
            "chio_message_receipt_ref"
        ],
        "external_fields_not_used": ["broker_acl_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_ASYNCAPI_AUTHORITY_CLAIM],
        "copy_limitations": [
            "AsyncAPI message evidence is digest-bound event contract evidence, not Chio capability authority."
        ]
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
            "external-projection-manifest",
            "asyncapi-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "asyncapi-manifest.json",
            asyncapi_manifest,
        );
    }

    let ap2_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-ap2-valid",
        "source_protocol": "ap2",
        "source_version": "0.2",
        "external_fields_used": [
            "transaction_passport_ref",
            "order_id",
            "credential_format",
            "checkout_mandate_digest",
            "payment_mandate_digest",
            "payment_instrument_digest",
            "transaction_context_digest",
            "agent_mode",
            "status",
            "chio_mandate_receipt_ref"
        ],
        "external_fields_not_used": ["mandate_signature_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_AP2_AUTHORITY_CLAIM],
        "copy_limitations": [
            "AP2 mandate evidence is digest-bound payment authorization evidence, not Chio capability authority."
        ]
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
            "external-projection-manifest",
            "ap2-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "ap2-manifest.json",
            ap2_manifest,
        );
    }

    let x402_manifest = json_bytes(json!({
        "schema": "chio.agent-web.external-projection-manifest.v1",
        "projection_id": "projection-x402-valid",
        "source_protocol": "x402",
        "source_version": "0.5",
        "external_fields_used": [
            "transaction_passport_ref",
            "order_id",
            "resource_digest",
            "payment_requirements_digest",
            "payment_proof_digest",
            "settlement_digest",
            "network",
            "asset",
            "amount_units",
            "status",
            "chio_payment_receipt_ref"
        ],
        "external_fields_not_used": ["payment_header_as_chio_authority"],
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
        "unsupported_claims": [UNSUPPORTED_X402_AUTHORITY_CLAIM],
        "copy_limitations": [
            "x402 payment evidence is digest-bound payment protocol evidence, not Chio capability authority."
        ]
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
            "external-projection-manifest",
            "x402-manifest",
            "chio.agent-web.external-projection-manifest.v1",
            "x402-manifest.json",
            x402_manifest,
        );
    }
}
