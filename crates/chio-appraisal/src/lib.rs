//! Runtime attestation appraisal artifacts and marketplace pricing for the
//! Chio protocol.
//!
//! This crate is used to appraise runtime attestation evidence and to derive
//! marketplace prices from it. It defines appraisal descriptors and an
//! artifact inventory, the attestation-verifier family taxonomy, and the
//! deterministic marketplace invocation-pricing model
//! (`compute_marketplace_invocation_price`, base prices, reputation tiers, and
//! tier discounts). The underwriting, credit, and market crates build on these
//! types.
//!
//! # Modules
//!
//! - [`marketplace_pricing`] -- per-invocation pricing with reputation-tier
//!   discounts.

#![forbid(unsafe_code)]

pub use chio_core_types::{canonical, capability, crypto, error, receipt, Error};

pub mod marketplace_pricing;

pub use marketplace_pricing::{
    compute_marketplace_invocation_price, MarketplaceBasePrice, MarketplaceInvocationPrice,
    MarketplacePricingContext, MarketplaceReputationTier, TIER_DISCOUNT_PER_HUNDRED,
};

pub use chio_core_types::runtime_attestation::AttestationVerifierFamily;

mod appraisal;
mod artifact_inventory;
mod descriptor;
mod types;
mod validate;

pub use appraisal::*;
pub use artifact_inventory::*;
pub use descriptor::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        AttestationTrustPolicy, AttestationTrustRule, RuntimeAssuranceTier,
        RuntimeAttestationEvidence, WorkloadCredentialKind, WorkloadIdentity,
        WorkloadIdentityScheme,
    };
    use crate::receipt::SignedExportEnvelope;
    use crate::validate::{
        validate_runtime_attestation_reference_value_set,
        validate_runtime_attestation_trust_bundle,
        validate_runtime_attestation_verifier_descriptor,
    };
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    use chio_test_support::prelude::*;

    fn sample_evidence() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: "chio.runtime-attestation.azure-maa.jwt.v1".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "abc123".to_string(),
            runtime_identity: Some("spiffe://contoso.test/runtime/worker".to_string()),
            workload_identity: Some(WorkloadIdentity {
                scheme: WorkloadIdentityScheme::Spiffe,
                credential_kind: WorkloadCredentialKind::Uri,
                uri: "spiffe://contoso.test/runtime/worker".to_string(),
                trust_domain: "contoso.test".to_string(),
                path: "/runtime/worker".to_string(),
            }),
            claims: Some(json!({
                "azureMaa": {
                    "attestationType": "sgx"
                }
            })),
        }
    }

    fn sample_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_string(),
                schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_string()],
                required_assertions: BTreeMap::new(),
            }],
        }
    }

    fn sample_nitro_evidence() -> RuntimeAttestationEvidence {
        RuntimeAttestationEvidence {
            schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://nitro.aws.example/".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "nitro-digest-1".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(json!({
                "awsNitro": {
                    "moduleId": "nitro-enclave-1",
                    "digest": "sha384:nitro-measurement",
                    "pcrs": {"0": "0123"}
                }
            })),
        }
    }

    fn sample_nitro_trust_policy() -> AttestationTrustPolicy {
        AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "aws-nitro-contoso".to_string(),
                schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
                verifier: "https://nitro.aws.example".to_string(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(AttestationVerifierFamily::AwsNitro),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: Vec::new(),
                required_assertions: BTreeMap::from([
                    ("moduleId".to_string(), "nitro-enclave-1".to_string()),
                    ("digest".to_string(), "sha384:nitro-measurement".to_string()),
                ]),
            }],
        }
    }

    fn sample_descriptor_document() -> RuntimeAttestationVerifierDescriptorDocument {
        RuntimeAttestationVerifierDescriptorDocument {
            schema: RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA.to_string(),
            descriptor_id: "azure-prod".to_string(),
            verifier: "https://maa.contoso.test".to_string(),
            verifier_family: AttestationVerifierFamily::AzureMaa,
            adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
            attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
            appraisal_artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
            appraisal_result_schema: RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string(),
            signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
            reference_values_uri: Some("https://maa.contoso.test/reference-values".to_string()),
            issued_at: 100,
            expires_at: 300,
        }
    }

    fn sample_reference_value_set() -> RuntimeAttestationReferenceValueSet {
        RuntimeAttestationReferenceValueSet {
            schema: RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA.to_string(),
            reference_value_id: "azure-rv-1".to_string(),
            descriptor_id: "azure-prod".to_string(),
            verifier_family: AttestationVerifierFamily::AzureMaa,
            attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
            source_uri: Some("https://maa.contoso.test/reference-values/1".to_string()),
            issued_at: 100,
            expires_at: 300,
            state: RuntimeAttestationReferenceValueState::Active,
            superseded_by: None,
            revoked_reason: None,
            measurements: BTreeMap::from([("mrEnclave".to_string(), json!("abc123"))]),
        }
    }

    fn sample_signed_descriptor(
        signer: &crate::crypto::Keypair,
    ) -> SignedRuntimeAttestationVerifierDescriptor {
        SignedExportEnvelope::sign(sample_descriptor_document(), signer)
            .test_expect("sign descriptor")
    }

    fn sample_signed_reference_value_set(
        signer: &crate::crypto::Keypair,
    ) -> SignedRuntimeAttestationReferenceValueSet {
        SignedExportEnvelope::sign(sample_reference_value_set(), signer)
            .test_expect("sign reference values")
    }

    fn sample_trust_bundle_document(
        signer: &crate::crypto::Keypair,
    ) -> RuntimeAttestationTrustBundleDocument {
        RuntimeAttestationTrustBundleDocument {
            schema: RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA.to_string(),
            bundle_id: "bundle-1".to_string(),
            publisher: "https://trust.contoso.test".to_string(),
            version: 1,
            issued_at: 100,
            expires_at: 300,
            descriptors: vec![sample_signed_descriptor(signer)],
            reference_values: vec![sample_signed_reference_value_set(signer)],
        }
    }

    fn empty_import_policy() -> RuntimeAttestationImportedAppraisalPolicy {
        RuntimeAttestationImportedAppraisalPolicy {
            trusted_issuers: Vec::new(),
            trusted_signer_keys: Vec::new(),
            allowed_verifier_families: Vec::new(),
            max_result_age_seconds: None,
            max_evidence_age_seconds: None,
            maximum_effective_tier: None,
            required_claims: BTreeMap::new(),
        }
    }

    fn sample_appraisal_result() -> RuntimeAttestationAppraisalResult {
        let appraisal = derive_runtime_attestation_appraisal(&sample_evidence())
            .test_expect("derive sample appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
            .test_expect("result from sample report")
    }

    #[test]
    fn verified_runtime_attestation_record_requires_local_trust_boundary_for_tier_promotion() {
        let verified =
            verify_runtime_attestation_record(&sample_evidence(), None, 150).test_expect("record");

        assert_eq!(verified.verified_at, 150);
        assert_eq!(
            verified.subject.runtime_identity.as_deref(),
            Some("spiffe://contoso.test/runtime/worker")
        );
        assert_eq!(
            verified
                .workload_identity()
                .test_expect("verified record should carry canonical workload identity")
                .trust_domain,
            "contoso.test"
        );
        assert_eq!(
            verified.appraisal.effective_tier,
            RuntimeAssuranceTier::Attested
        );
        assert!(!verified.policy_outcome.trust_policy_configured);
        assert!(!verified.policy_outcome.accepted);
        assert!(!verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::None);
        assert_eq!(
            verified.provenance.verifier_adapter,
            AZURE_MAA_VERIFIER_ADAPTER
        );
        assert_eq!(
            verified.provenance.canonical_verifier,
            "https://maa.contoso.test"
        );
        assert_eq!(verified.matched_trust_rule(), None);
        assert_eq!(
            verified.policy_outcome.effective_tier,
            RuntimeAssuranceTier::None
        );
        assert_eq!(
            verified.policy_outcome.reason.as_deref(),
            Some("runtime attestation evidence did not cross a local verified trust boundary")
        );
    }

    #[test]
    fn verified_runtime_attestation_record_promotes_tier_only_after_local_policy_verification() {
        let verified = verify_runtime_attestation_record(
            &sample_evidence(),
            Some(&sample_trust_policy()),
            150,
        )
        .test_expect("trusted record");

        assert!(verified.policy_outcome.trust_policy_configured);
        assert!(verified.policy_outcome.accepted);
        assert!(verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
        assert_eq!(
            verified.provenance.verifier_family,
            AttestationVerifierFamily::AzureMaa
        );
        assert_eq!(verified.matched_trust_rule(), Some("azure-contoso"));
        assert_eq!(
            verified.policy_outcome.effective_tier,
            RuntimeAssuranceTier::Verified
        );
        assert_eq!(
            verified.policy_outcome.reason.as_deref(),
            Some("matched attestation trust rule `azure-contoso`")
        );
    }

    #[test]
    fn verified_runtime_attestation_record_accepts_nitro_evidence_across_trust_boundary() {
        let evidence = sample_nitro_evidence();
        let verified =
            verify_runtime_attestation_record(&evidence, Some(&sample_nitro_trust_policy()), 150)
                .test_expect("nitro record should verify across the trust boundary");

        assert!(verified.is_locally_accepted());
        assert_eq!(verified.effective_tier(), RuntimeAssuranceTier::Verified);
        assert_eq!(verified.evidence_schema(), AWS_NITRO_ATTESTATION_SCHEMA);
        assert_eq!(verified.evidence_sha256(), "nitro-digest-1");
        assert_eq!(verified.canonical_verifier(), "https://nitro.aws.example");
        assert_eq!(
            verified.verifier_family(),
            AttestationVerifierFamily::AwsNitro
        );
        assert!(verified.matches_evidence(&evidence));

        let mut modified = evidence.clone();
        modified.evidence_sha256 = "nitro-digest-2".to_string();
        assert!(!verified.matches_evidence(&modified));
    }

    #[test]
    fn verifier_descriptor_validation_and_verification_reject_invalid_variants() {
        let mut descriptor = sample_descriptor_document();
        descriptor.schema = "chio.runtime-attestation.verifier-descriptor.v0".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("invalid descriptor schema")
                .to_string()
                .contains("schema must be")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.descriptor_id = "  ".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("empty descriptor id")
                .to_string()
                .contains("descriptor_id")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.verifier = " ".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("empty verifier")
                .to_string()
                .contains("non-empty verifier")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.adapter = " ".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("empty adapter")
                .to_string()
                .contains("non-empty adapter")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.issued_at = 301;
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("inverted descriptor window")
                .to_string()
                .contains("must not expire before it is issued")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.attestation_schemas.clear();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("missing schemas")
                .to_string()
                .contains("at least one attestation schema")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.attestation_schemas = vec![
            GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
            AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
        ];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("unsorted schemas")
                .to_string()
                .contains("sorted unique order")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.attestation_schemas = vec![String::new()];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("empty schema entry")
                .to_string()
                .contains("cannot contain empty values")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.appraisal_artifact_schema = "chio.runtime-attestation.other.v1".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("wrong artifact schema")
                .to_string()
                .contains("canonical appraisal artifact schema")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.appraisal_result_schema = "chio.runtime-attestation.other-result.v1".to_string();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("wrong result schema")
                .to_string()
                .contains("canonical appraisal result schema")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.signing_key_fingerprints.clear();
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("missing signing keys")
                .to_string()
                .contains("at least one signing-key fingerprint")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.signing_key_fingerprints =
            vec!["sha256:key-b".to_string(), "sha256:key-a".to_string()];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("unsorted signing keys")
                .to_string()
                .contains("sorted unique order")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.signing_key_fingerprints = vec![" ".to_string()];
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("empty signing key")
                .to_string()
                .contains("cannot contain empty values")
        );

        let mut descriptor = sample_descriptor_document();
        descriptor.reference_values_uri = Some(" ".to_string());
        assert!(
            validate_runtime_attestation_verifier_descriptor(&descriptor)
                .test_expect_err("empty reference_values_uri")
                .to_string()
                .contains("reference_values_uri")
        );

        let signer = crate::crypto::Keypair::generate();
        let signed = sample_signed_descriptor(&signer);
        assert!(
            verify_signed_runtime_attestation_verifier_descriptor(&signed, 50)
                .test_expect_err("descriptor not yet valid")
                .to_string()
                .contains("not yet valid")
        );
        assert!(
            verify_signed_runtime_attestation_verifier_descriptor(&signed, 400)
                .test_expect_err("descriptor expired")
                .to_string()
                .contains("has expired")
        );

        let mut tampered = signed.clone();
        tampered.body.verifier = "https://maa.other.example".to_string();
        assert!(
            verify_signed_runtime_attestation_verifier_descriptor(&tampered, 150)
                .test_expect_err("descriptor signature failure")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn reference_value_validation_and_verification_reject_invalid_variants() {
        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.schema = "chio.runtime-attestation.reference-values.v0".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("invalid reference-value schema")
                .to_string()
                .contains("schema must be")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.reference_value_id = " ".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("empty reference_value_id")
                .to_string()
                .contains("reference_value_id")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.descriptor_id = " ".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("empty descriptor_id")
                .to_string()
                .contains("descriptor_id")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.attestation_schema = " ".to_string();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("empty attestation schema")
                .to_string()
                .contains("attestation_schema")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.issued_at = 301;
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("inverted reference-value window")
                .to_string()
                .contains("must not expire before it is issued")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.source_uri = Some(" ".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("empty source uri")
                .to_string()
                .contains("source_uri")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.measurements.clear();
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("missing measurements")
                .to_string()
                .contains("at least one measurement")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.superseded_by = Some("azure-rv-2".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("active state with supersession")
                .to_string()
                .contains("cannot include supersession or revocation fields")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Superseded;
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("superseded without successor")
                .to_string()
                .contains("must include superseded_by")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Superseded;
        reference_value_set.superseded_by = Some("azure-rv-1".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("self supersession")
                .to_string()
                .contains("cannot supersede itself")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Superseded;
        reference_value_set.superseded_by = Some("azure-rv-2".to_string());
        reference_value_set.revoked_reason = Some("compromised".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("superseded with revoked_reason")
                .to_string()
                .contains("cannot include revoked_reason")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Revoked;
        reference_value_set.superseded_by = Some("azure-rv-2".to_string());
        reference_value_set.revoked_reason = Some("compromised".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("revoked with superseded_by")
                .to_string()
                .contains("cannot include superseded_by")
        );

        let mut reference_value_set = sample_reference_value_set();
        reference_value_set.state = RuntimeAttestationReferenceValueState::Revoked;
        reference_value_set.revoked_reason = Some(" ".to_string());
        assert!(
            validate_runtime_attestation_reference_value_set(&reference_value_set)
                .test_expect_err("revoked without reason")
                .to_string()
                .contains("must include revoked_reason")
        );

        let signer = crate::crypto::Keypair::generate();
        let signed = sample_signed_reference_value_set(&signer);
        assert!(
            verify_signed_runtime_attestation_reference_value_set(&signed, 50)
                .test_expect_err("reference values not yet valid")
                .to_string()
                .contains("not yet valid")
        );
        assert!(
            verify_signed_runtime_attestation_reference_value_set(&signed, 400)
                .test_expect_err("reference values expired")
                .to_string()
                .contains("has expired")
        );

        let mut tampered = signed.clone();
        tampered.body.source_uri = Some("https://maa.other.example/reference-values".to_string());
        assert!(
            verify_signed_runtime_attestation_reference_value_set(&tampered, 150)
                .test_expect_err("reference-value signature failure")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn trust_bundle_validation_and_verification_reject_remaining_invalid_states() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = sample_signed_descriptor(&signer);
        let reference_value = sample_signed_reference_value_set(&signer);

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.schema = "chio.runtime-attestation.trust-bundle.v0".to_string();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("invalid bundle schema")
            .to_string()
            .contains("schema must be"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.bundle_id = " ".to_string();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("empty bundle id")
            .to_string()
            .contains("bundle_id"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.publisher = " ".to_string();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("empty bundle publisher")
            .to_string()
            .contains("non-empty publisher"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.version = 0;
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("bundle version zero")
            .to_string()
            .contains("non-zero version"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.issued_at = 301;
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("inverted bundle window")
            .to_string()
            .contains("must not expire before it is issued"));

        let bundle = sample_trust_bundle_document(&signer);
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 50)
            .test_expect_err("bundle not yet valid")
            .to_string()
            .contains("not yet valid"));
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 400)
            .test_expect_err("bundle expired")
            .to_string()
            .contains("has expired"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.descriptors.clear();
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("bundle without descriptors")
            .to_string()
            .contains("at least one verifier descriptor"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.descriptors = vec![descriptor.clone(), descriptor.clone()];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("duplicate descriptor ids")
            .to_string()
            .contains("duplicate verifier descriptor"));

        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values = vec![reference_value.clone(), reference_value.clone()];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("duplicate reference-value ids")
            .to_string()
            .contains("duplicate reference-value set"));

        let mut unknown_reference = sample_reference_value_set();
        unknown_reference.descriptor_id = "azure-other".to_string();
        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values = vec![SignedExportEnvelope::sign(unknown_reference, &signer)
            .test_expect("sign unknown reference")];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("unknown descriptor")
            .to_string()
            .contains("unknown verifier descriptor"));

        let mut schema_mismatch_reference = sample_reference_value_set();
        schema_mismatch_reference.attestation_schema =
            GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string();
        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values =
            vec![
                SignedExportEnvelope::sign(schema_mismatch_reference, &signer)
                    .test_expect("sign schema mismatch reference"),
            ];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("schema outside descriptor")
            .to_string()
            .contains("outside descriptor"));

        let mut superseded_reference = sample_reference_value_set();
        superseded_reference.reference_value_id = "azure-rv-old".to_string();
        superseded_reference.state = RuntimeAttestationReferenceValueState::Superseded;
        superseded_reference.superseded_by = Some("azure-rv-next".to_string());
        let mut bundle = sample_trust_bundle_document(&signer);
        bundle.reference_values = vec![SignedExportEnvelope::sign(superseded_reference, &signer)
            .test_expect("sign superseded reference")];
        assert!(validate_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("missing superseded successor")
            .to_string()
            .contains("unknown successor"));

        let signed_bundle =
            SignedExportEnvelope::sign(sample_trust_bundle_document(&signer), &signer)
                .test_expect("sign trust bundle");
        let mut tampered = signed_bundle.clone();
        tampered.body.publisher = "https://trust.other.example".to_string();
        assert!(
            verify_signed_runtime_attestation_trust_bundle(&tampered, 150)
                .test_expect_err("bundle signature failure")
                .to_string()
                .contains("signature verification failed")
        );
    }

    #[test]
    fn runtime_attestation_import_reasons_cover_remaining_policy_fail_closed_paths() {
        let signed_result = SignedRuntimeAttestationAppraisalResult::sign(
            sample_appraisal_result(),
            &crate::crypto::Keypair::generate(),
        )
        .test_expect("sign result");

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result,
                local_policy: empty_import_policy(),
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::NoLocalPolicy]
        );
        assert_eq!(
            import.local_policy_outcome.reasons[0].description,
            RuntimeAttestationImportReasonCode::NoLocalPolicy.description()
        );
    }

    #[test]
    fn imported_runtime_attestation_rejects_untrusted_exporters_and_claim_policy_failures() {
        let mut result = sample_appraisal_result();
        result.exporter_policy_outcome.accepted = false;
        let signer = crate::crypto::Keypair::generate();
        let signed_result = SignedRuntimeAttestationAppraisalResult::sign(result, &signer)
            .test_expect("sign result");

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:trusted".to_string()],
                    trusted_signer_keys: vec!["sha256:not-the-real-signer".to_string()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::GoogleAttestation],
                    max_result_age_seconds: None,
                    max_evidence_age_seconds: None,
                    maximum_effective_tier: None,
                    required_claims: BTreeMap::from([
                        (
                            RuntimeAttestationNormalizedClaimCode::ModuleId,
                            "module-1".to_string(),
                        ),
                        (
                            RuntimeAttestationNormalizedClaimCode::AttestationType,
                            "sev".to_string(),
                        ),
                    ]),
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        for code in [
            RuntimeAttestationImportReasonCode::ExporterPolicyRejected,
            RuntimeAttestationImportReasonCode::UntrustedIssuer,
            RuntimeAttestationImportReasonCode::UntrustedSigner,
            RuntimeAttestationImportReasonCode::UnsupportedVerifierFamily,
            RuntimeAttestationImportReasonCode::MissingRequiredClaim,
            RuntimeAttestationImportReasonCode::ClaimMismatch,
        ] {
            assert!(import.local_policy_outcome.reason_codes.contains(&code));
            assert!(import
                .local_policy_outcome
                .reasons
                .iter()
                .any(|reason| reason.code == code && reason.description == code.description()));
        }
    }

    #[test]
    fn normalized_claim_values_and_result_guards_cover_remaining_branch_paths() {
        assert_eq!(
            normalized_claim_value_string(&RuntimeAttestationNormalizedClaim::new(
                RuntimeAttestationNormalizedClaimCode::SecureBootState,
                Value::Bool(true),
            )),
            Some("true".to_string())
        );
        assert_eq!(
            normalized_claim_value_string(&RuntimeAttestationNormalizedClaim::new(
                RuntimeAttestationNormalizedClaimCode::ModuleId,
                Value::Number(serde_json::Number::from(7)),
            )),
            Some("7".to_string())
        );
        assert_eq!(
            normalized_claim_value_string(&RuntimeAttestationNormalizedClaim::new(
                RuntimeAttestationNormalizedClaimCode::MeasurementRegisters,
                json!({"0": "abcd"}),
            )),
            Some("{\"0\":\"abcd\"}".to_string())
        );

        let appraisal = derive_runtime_attestation_appraisal(&sample_evidence())
            .test_expect("derive appraisal for result guard test");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };

        assert!(
            RuntimeAttestationAppraisalResult::from_report("  ", &report)
                .test_expect_err("empty issuer")
                .to_string()
                .contains("issuer must not be empty")
        );

        let mut missing_artifact_report = report.clone();
        missing_artifact_report.appraisal.artifact = None;
        assert!(RuntimeAttestationAppraisalResult::from_report(
            "did:chio:test:issuer",
            &missing_artifact_report,
        )
        .test_expect_err("missing artifact")
        .to_string()
        .contains("missing the nested artifact"));

        assert_eq!(
            verifier_family_for_attestation_schema(ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA),
            Some(AttestationVerifierFamily::EnterpriseVerifier)
        );
        assert_eq!(
            verifier_family_for_attestation_schema("urn:chio:unknown"),
            None
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_aws_nitro_and_rejects_unknown_schema() {
        let evidence = RuntimeAttestationEvidence {
            schema: AWS_NITRO_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://nitro.aws.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "aws-digest".to_string(),
            runtime_identity: None,
            workload_identity: None,
            claims: Some(json!({
                "awsNitro": {
                    "moduleId": "nitro-enclave-1",
                    "digest": "sha384:aws-measurement",
                    "pcrs": {"0": "0123"}
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .test_expect("aws nitro evidence should derive");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::AwsNitro
        );
        assert_eq!(
            appraisal.normalized_assertions["moduleId"],
            "nitro-enclave-1"
        );
        assert_eq!(
            appraisal.normalized_assertions["digest"],
            "sha384:aws-measurement"
        );
        assert_eq!(
            appraisal.normalized_assertions["pcrs"],
            json!({"0": "0123"})
        );
        let artifact = appraisal.artifact.test_expect("aws appraisal artifact");
        assert!(artifact.claims.normalized_claims.iter().any(|claim| {
            claim.code == RuntimeAttestationNormalizedClaimCode::MeasurementRegisters
                && claim.value == json!({"0": "0123"})
        }));

        let mut unsupported = sample_evidence();
        unsupported.schema = "chio.runtime-attestation.unknown.v1".to_string();
        let error = derive_runtime_attestation_appraisal(&unsupported)
            .test_expect_err("unsupported schema should fail");
        assert!(matches!(
            error,
            RuntimeAttestationAppraisalError::UnsupportedSchema { schema }
            if schema == "chio.runtime-attestation.unknown.v1"
        ));
    }

    #[test]
    fn runtime_attestation_appraisal_copies_evidence_descriptor_fields() {
        let evidence = sample_evidence();
        let appraisal = RuntimeAttestationAppraisal::accepted(
            "azure_maa",
            AttestationVerifierFamily::AzureMaa,
            &evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::EvidenceVerified],
        );

        assert_eq!(appraisal.schema, RUNTIME_ATTESTATION_APPRAISAL_SCHEMA);
        assert_eq!(appraisal.evidence.schema, evidence.schema);
        assert_eq!(appraisal.evidence.verifier, evidence.verifier);
        assert_eq!(appraisal.evidence.evidence_sha256, evidence.evidence_sha256);
        assert_eq!(
            appraisal.verdict,
            RuntimeAttestationAppraisalVerdict::Accepted
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::Attested);
        let artifact = appraisal
            .artifact
            .test_expect("accepted appraisal should carry artifact");
        assert_eq!(
            artifact.schema,
            RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA
        );
        assert_eq!(artifact.verifier.adapter, "azure_maa");
        assert_eq!(
            artifact.verifier.verifier_family,
            AttestationVerifierFamily::AzureMaa
        );
        assert_eq!(
            artifact.policy.verdict,
            RuntimeAttestationAppraisalVerdict::Accepted
        );
        assert_eq!(
            artifact.policy.effective_tier,
            RuntimeAssuranceTier::Attested
        );
        assert_eq!(
            appraisal.reasons,
            vec![RuntimeAttestationAppraisalReason::from_code(
                RuntimeAttestationAppraisalReasonCode::EvidenceVerified
            )]
        );
    }

    #[test]
    fn rejected_runtime_attestation_appraisal_drops_effective_tier() {
        let evidence = sample_evidence();
        let appraisal = RuntimeAttestationAppraisal::rejected(
            "azure_maa",
            AttestationVerifierFamily::AzureMaa,
            &evidence,
            BTreeMap::new(),
            BTreeMap::new(),
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected],
        );

        assert_eq!(
            appraisal.verdict,
            RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert_eq!(appraisal.effective_tier, RuntimeAssuranceTier::None);
        assert_eq!(
            appraisal.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected]
        );
        let artifact = appraisal
            .artifact
            .test_expect("rejected appraisal should carry artifact");
        assert_eq!(
            artifact.policy.verdict,
            RuntimeAttestationAppraisalVerdict::Rejected
        );
        assert_eq!(artifact.policy.effective_tier, RuntimeAssuranceTier::None);
        assert_eq!(
            artifact.policy.reason_codes,
            vec![RuntimeAttestationAppraisalReasonCode::PolicyRejected]
        );
        assert_eq!(
            artifact.policy.reasons,
            vec![RuntimeAttestationAppraisalReason::from_code(
                RuntimeAttestationAppraisalReasonCode::PolicyRejected
            )]
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_google_confidential_vm() {
        let evidence = RuntimeAttestationEvidence {
            schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://confidentialcomputing.googleapis.com".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "google-digest".to_string(),
            runtime_identity: Some(
                "//compute.googleapis.com/projects/demo/zones/us-central1-a/instances/vm-1"
                    .to_string(),
            ),
            workload_identity: None,
            claims: Some(json!({
                "googleAttestation": {
                    "attestationType": "confidential_vm",
                    "hardwareModel": "GCP_AMD_SEV",
                    "secureBoot": "enabled"
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .test_expect("google evidence should derive a canonical appraisal");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::GoogleAttestation
        );
        assert_eq!(
            appraisal.normalized_assertions["attestationType"],
            "confidential_vm"
        );
        assert_eq!(
            appraisal.normalized_assertions["hardwareModel"],
            "GCP_AMD_SEV"
        );
        assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
        let artifact = appraisal
            .artifact
            .test_expect("derived appraisal should carry artifact");
        assert_eq!(
            artifact.claims.normalized_assertions["secureBoot"],
            "enabled"
        );
        assert!(artifact.claims.normalized_claims.iter().any(|claim| {
            claim.code == RuntimeAttestationNormalizedClaimCode::SecureBootState
                && claim.category == RuntimeAttestationNormalizedClaimCategory::Configuration
                && claim.provenance == RuntimeAttestationClaimProvenance::VendorClaims
                && claim.value == Value::String("enabled".to_string())
        }));
        assert_eq!(
            artifact.verifier.adapter,
            GOOGLE_CONFIDENTIAL_VM_VERIFIER_ADAPTER
        );
    }

    #[test]
    fn derive_runtime_attestation_appraisal_supports_enterprise_verifier() {
        let evidence = RuntimeAttestationEvidence {
            schema: ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA.to_string(),
            verifier: "https://attest.contoso.example".to_string(),
            tier: RuntimeAssuranceTier::Attested,
            issued_at: 100,
            expires_at: 200,
            evidence_sha256: "enterprise-digest".to_string(),
            runtime_identity: Some("spiffe://chio.example/workloads/enterprise".to_string()),
            workload_identity: Some(
                WorkloadIdentity::parse_spiffe_uri("spiffe://chio.example/workloads/enterprise")
                    .test_expect("parse enterprise workload identity"),
            ),
            claims: Some(json!({
                "enterpriseVerifier": {
                    "attestationType": "enterprise_confidential_vm",
                    "hardwareModel": "AMD_SEV_SNP",
                    "secureBoot": "enabled",
                    "digest": "sha384:enterprise-measurement",
                    "pcrs": {
                        "0": "8f7f1be8"
                    }
                }
            })),
        };

        let appraisal = derive_runtime_attestation_appraisal(&evidence)
            .test_expect("enterprise evidence should derive a canonical appraisal");
        assert_eq!(
            appraisal.verifier_family,
            AttestationVerifierFamily::EnterpriseVerifier
        );
        assert_eq!(
            appraisal.normalized_assertions["attestationType"],
            "enterprise_confidential_vm"
        );
        assert_eq!(
            appraisal.normalized_assertions["hardwareModel"],
            "AMD_SEV_SNP"
        );
        assert_eq!(appraisal.normalized_assertions["secureBoot"], "enabled");
        assert_eq!(
            appraisal.normalized_assertions["digest"],
            "sha384:enterprise-measurement"
        );
        let artifact = appraisal
            .artifact
            .test_expect("derived appraisal should carry artifact");
        assert_eq!(artifact.verifier.adapter, ENTERPRISE_VERIFIER_ADAPTER);
        assert!(artifact.claims.normalized_claims.iter().any(|claim| {
            claim.code == RuntimeAttestationNormalizedClaimCode::MeasurementDigest
                && claim.value == Value::String("sha384:enterprise-measurement".to_string())
        }));
    }

    #[test]
    fn runtime_attestation_appraisal_inventory_lists_supported_bridges() {
        let inventory = runtime_attestation_appraisal_artifact_inventory();

        assert_eq!(
            inventory.schema,
            RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_INVENTORY_SCHEMA
        );
        assert_eq!(inventory.entries.len(), 4);
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == AZURE_MAA_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "azureMaa"
            ));
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == AWS_NITRO_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "awsNitro"
            ));
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "googleAttestation"
            ));
        assert!(inventory
            .entries
            .iter()
            .any(
                |entry| entry.attestation_schema == ENTERPRISE_VERIFIER_ATTESTATION_SCHEMA
                    && entry.vendor_claim_namespace == "enterpriseVerifier"
            ));
        assert!(inventory.entries.iter().any(|entry| {
            entry.attestation_schema == AWS_NITRO_ATTESTATION_SCHEMA
                && entry
                    .normalized_claim_codes
                    .contains(&RuntimeAttestationNormalizedClaimCode::MeasurementDigest)
        }));
    }

    #[test]
    fn runtime_attestation_claim_vocabulary_lists_portable_codes() {
        let vocabulary = runtime_attestation_normalized_claim_vocabulary();

        assert_eq!(
            vocabulary.schema,
            RUNTIME_ATTESTATION_NORMALIZED_CLAIM_VOCABULARY_SCHEMA
        );
        assert!(vocabulary.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationNormalizedClaimCode::SecureBootState
                && entry.legacy_assertion_key == "secureBoot"
                && entry.category == RuntimeAttestationNormalizedClaimCategory::Configuration
                && entry
                    .supported_verifier_families
                    .contains(&AttestationVerifierFamily::GoogleAttestation)
        }));
        assert!(vocabulary.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationNormalizedClaimCode::MeasurementDigest
                && entry
                    .supported_verifier_families
                    .contains(&AttestationVerifierFamily::EnterpriseVerifier)
        }));
    }

    #[test]
    fn runtime_attestation_reason_taxonomy_lists_structured_reasons() {
        let taxonomy = runtime_attestation_reason_taxonomy();

        assert_eq!(taxonomy.schema, RUNTIME_ATTESTATION_REASON_TAXONOMY_SCHEMA);
        assert!(taxonomy.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationAppraisalReasonCode::EvidenceVerified
                && entry.group == RuntimeAttestationAppraisalReasonGroup::Verification
                && entry.disposition == RuntimeAttestationAppraisalReasonDisposition::Pass
        }));
        assert!(taxonomy.entries.iter().any(|entry| {
            entry.code == RuntimeAttestationAppraisalReasonCode::UnsupportedClaimMapping
                && entry.group == RuntimeAttestationAppraisalReasonGroup::Compatibility
                && entry.disposition == RuntimeAttestationAppraisalReasonDisposition::Degrade
        }));
    }

    #[test]
    fn runtime_attestation_trust_bundle_verifies_signed_descriptor_and_reference_values() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: Some("https://maa.contoso.test/reference-values".to_string()),
                issued_at: 100,
                expires_at: 300,
            },
        )
        .test_expect("descriptor");
        let reference_values = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "azure-rv-1".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                source_uri: Some("https://maa.contoso.test/reference-values/1".to_string()),
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("mrEnclave".to_string(), json!("abc123"))]),
            },
        )
        .test_expect("reference values");
        let bundle =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-1".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: vec![reference_values],
            })
            .test_expect("bundle");

        let verification =
            verify_signed_runtime_attestation_trust_bundle(&bundle, 150).test_expect("verify");

        assert_eq!(verification.schema, RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA);
        assert_eq!(verification.descriptor_count, 1);
        assert_eq!(verification.reference_value_count, 1);
        assert_eq!(
            verification.verifier_families,
            vec![AttestationVerifierFamily::AzureMaa]
        );
    }

    #[test]
    fn runtime_attestation_trust_bundle_rejects_expired_descriptor() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: None,
                issued_at: 100,
                expires_at: 120,
            },
        )
        .test_expect("descriptor");
        let bundle =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-2".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: Vec::new(),
            })
            .test_expect("bundle");

        let error = verify_signed_runtime_attestation_trust_bundle(&bundle, 150)
            .test_expect_err("expired descriptor");
        assert!(error
            .to_string()
            .contains("verifier descriptor `azure-prod` has expired"));
    }

    #[test]
    fn runtime_attestation_trust_bundle_rejects_ambiguous_active_reference_values() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: None,
                issued_at: 100,
                expires_at: 300,
            },
        )
        .test_expect("descriptor");
        let reference_a = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "azure-rv-1".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                source_uri: None,
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("mrEnclave".to_string(), json!("abc123"))]),
            },
        )
        .test_expect("reference values");
        let reference_b = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "azure-rv-2".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                attestation_schema: AZURE_MAA_ATTESTATION_SCHEMA.to_string(),
                source_uri: None,
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("mrEnclave".to_string(), json!("def456"))]),
            },
        )
        .test_expect("reference values");
        let error =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-3".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: vec![reference_a, reference_b],
            })
            .test_expect_err("ambiguous reference values");
        assert!(error
            .to_string()
            .contains("ambiguous active reference values"));
    }

    #[test]
    fn runtime_attestation_trust_bundle_rejects_reference_values_outside_descriptor_contract() {
        let signer = crate::crypto::Keypair::generate();
        let descriptor = create_signed_runtime_attestation_verifier_descriptor(
            RuntimeAttestationVerifierDescriptorArgs {
                signer: &signer,
                descriptor_id: "azure-prod".to_string(),
                verifier: "https://maa.contoso.test".to_string(),
                verifier_family: AttestationVerifierFamily::AzureMaa,
                adapter: AZURE_MAA_VERIFIER_ADAPTER.to_string(),
                attestation_schemas: vec![AZURE_MAA_ATTESTATION_SCHEMA.to_string()],
                signing_key_fingerprints: vec!["sha256:azure-key-1".to_string()],
                reference_values_uri: None,
                issued_at: 100,
                expires_at: 300,
            },
        )
        .test_expect("descriptor");
        let reference_values = create_signed_runtime_attestation_reference_value_set(
            RuntimeAttestationReferenceValueSetArgs {
                signer: &signer,
                reference_value_id: "google-rv-1".to_string(),
                descriptor_id: "azure-prod".to_string(),
                verifier_family: AttestationVerifierFamily::GoogleAttestation,
                attestation_schema: GOOGLE_CONFIDENTIAL_VM_ATTESTATION_SCHEMA.to_string(),
                source_uri: None,
                issued_at: 100,
                expires_at: 300,
                state: RuntimeAttestationReferenceValueState::Active,
                superseded_by: None,
                revoked_reason: None,
                measurements: BTreeMap::from([("hwModel".to_string(), json!("GCP_AMD_SEV"))]),
            },
        )
        .test_expect("reference values");
        let error =
            create_signed_runtime_attestation_trust_bundle(RuntimeAttestationTrustBundleArgs {
                signer: &signer,
                bundle_id: "bundle-4".to_string(),
                publisher: "https://trust.contoso.test".to_string(),
                version: 1,
                issued_at: 100,
                expires_at: 300,
                descriptors: vec![descriptor],
                reference_values: vec![reference_values],
            })
            .test_expect_err("mismatched reference values");
        assert!(error.to_string().contains("does not match verifier-family"));
    }

    #[test]
    fn runtime_attestation_appraisal_result_ids_are_deterministic() {
        let evidence = sample_evidence();
        let appraisal =
            derive_runtime_attestation_appraisal(&evidence).test_expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: true,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Verified,
                reason: None,
            },
        };

        let first = RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
            .test_unwrap();
        let second =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .test_unwrap();

        assert_eq!(
            first.schema,
            RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string()
        );
        assert_eq!(first.result_id, second.result_id);
        assert!(first.result_id.starts_with("appraisal-result-"));
    }

    #[test]
    fn imported_runtime_attestation_rejects_invalid_signature() {
        let evidence = sample_evidence();
        let appraisal =
            derive_runtime_attestation_appraisal(&evidence).test_expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .test_unwrap();
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).test_unwrap();
        let mut tampered = signed.clone();
        tampered.body.issuer = "did:chio:test:other".to_string();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: tampered,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    max_result_age_seconds: Some(120),
                    ..RuntimeAttestationImportedAppraisalPolicy {
                        trusted_issuers: Vec::new(),
                        trusted_signer_keys: Vec::new(),
                        allowed_verifier_families: Vec::new(),
                        max_result_age_seconds: None,
                        max_evidence_age_seconds: None,
                        maximum_effective_tier: None,
                        required_claims: BTreeMap::new(),
                    }
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::InvalidSignature]
        );
    }

    #[test]
    fn imported_runtime_attestation_can_be_attenuated_locally() {
        let evidence = sample_evidence();
        let appraisal =
            derive_runtime_attestation_appraisal(&evidence).test_expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .test_unwrap();
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).test_unwrap();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: signed,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:issuer".to_string()],
                    trusted_signer_keys: vec![signer.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    max_result_age_seconds: Some(300),
                    max_evidence_age_seconds: Some(300),
                    maximum_effective_tier: Some(RuntimeAssuranceTier::Basic),
                    required_claims: BTreeMap::new(),
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Attenuate
        );
        assert_eq!(
            import.local_policy_outcome.effective_tier,
            RuntimeAssuranceTier::Basic
        );
        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::TierAttenuated]
        );
    }

    #[test]
    fn imported_runtime_attestation_rejects_stale_result_and_evidence() {
        let evidence = sample_evidence();
        let appraisal =
            derive_runtime_attestation_appraisal(&evidence).test_expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .test_unwrap();
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).test_unwrap();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: signed,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:issuer".to_string()],
                    trusted_signer_keys: vec![signer.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::AzureMaa],
                    max_result_age_seconds: Some(20),
                    max_evidence_age_seconds: Some(20),
                    maximum_effective_tier: None,
                    required_claims: BTreeMap::new(),
                },
            },
            200,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert!(import
            .local_policy_outcome
            .reason_codes
            .contains(&RuntimeAttestationImportReasonCode::ResultStale));
        assert!(import
            .local_policy_outcome
            .reason_codes
            .contains(&RuntimeAttestationImportReasonCode::EvidenceStale));
    }

    #[test]
    fn imported_runtime_attestation_rejects_schema_family_mismatch() {
        let evidence = sample_evidence();
        let appraisal =
            derive_runtime_attestation_appraisal(&evidence).test_expect("derive appraisal");
        let report = RuntimeAttestationAppraisalReport {
            schema: RUNTIME_ATTESTATION_APPRAISAL_REPORT_SCHEMA.to_string(),
            generated_at: 150,
            appraisal,
            policy_outcome: RuntimeAttestationPolicyOutcome {
                trust_policy_configured: false,
                accepted: true,
                effective_tier: RuntimeAssuranceTier::Attested,
                reason: None,
            },
        };
        let mut result =
            RuntimeAttestationAppraisalResult::from_report("did:chio:test:issuer", &report)
                .test_unwrap();
        result.appraisal.verifier.verifier_family = AttestationVerifierFamily::GoogleAttestation;
        let signer = crate::crypto::Keypair::generate();
        let signed = SignedRuntimeAttestationAppraisalResult::sign(result, &signer).test_unwrap();

        let import = evaluate_imported_runtime_attestation_appraisal(
            &RuntimeAttestationAppraisalImportRequest {
                signed_result: signed,
                local_policy: RuntimeAttestationImportedAppraisalPolicy {
                    trusted_issuers: vec!["did:chio:test:issuer".to_string()],
                    trusted_signer_keys: vec![signer.public_key().to_hex()],
                    allowed_verifier_families: vec![AttestationVerifierFamily::GoogleAttestation],
                    max_result_age_seconds: Some(300),
                    max_evidence_age_seconds: Some(300),
                    maximum_effective_tier: None,
                    required_claims: BTreeMap::new(),
                },
            },
            160,
        );

        assert_eq!(
            import.local_policy_outcome.disposition,
            RuntimeAttestationImportDisposition::Reject
        );
        assert_eq!(
            import.local_policy_outcome.reason_codes,
            vec![RuntimeAttestationImportReasonCode::UnsupportedAppraisalSchema]
        );
    }
}
