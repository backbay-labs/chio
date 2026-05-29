//! Create and verify signed runtime attestation descriptors, reference-value sets, and trust bundles.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result as ChioResult;
use crate::receipt::SignedExportEnvelope;
use chio_core_types::runtime_attestation::AttestationVerifierFamily;

use crate::types::*;
use crate::validate::{
    validate_runtime_attestation_reference_value_set, validate_runtime_attestation_trust_bundle,
    validate_runtime_attestation_verifier_descriptor,
};

pub struct RuntimeAttestationVerifierDescriptorArgs<'a> {
    pub signer: &'a crate::crypto::Keypair,
    pub descriptor_id: String,
    pub verifier: String,
    pub verifier_family: AttestationVerifierFamily,
    pub adapter: String,
    pub attestation_schemas: Vec<String>,
    pub signing_key_fingerprints: Vec<String>,
    pub reference_values_uri: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

pub fn create_signed_runtime_attestation_verifier_descriptor(
    args: RuntimeAttestationVerifierDescriptorArgs<'_>,
) -> ChioResult<SignedRuntimeAttestationVerifierDescriptor> {
    let descriptor = RuntimeAttestationVerifierDescriptorDocument {
        schema: RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA.to_string(),
        descriptor_id: args.descriptor_id,
        verifier: args.verifier,
        verifier_family: args.verifier_family,
        adapter: args.adapter,
        attestation_schemas: args.attestation_schemas,
        appraisal_artifact_schema: RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA.to_string(),
        appraisal_result_schema: RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA.to_string(),
        signing_key_fingerprints: args.signing_key_fingerprints,
        reference_values_uri: args.reference_values_uri,
        issued_at: args.issued_at,
        expires_at: args.expires_at,
    };
    validate_runtime_attestation_verifier_descriptor(&descriptor)?;
    SignedExportEnvelope::sign(descriptor, args.signer)
}

pub fn verify_signed_runtime_attestation_verifier_descriptor(
    descriptor: &SignedRuntimeAttestationVerifierDescriptor,
    now: u64,
) -> ChioResult<()> {
    validate_runtime_attestation_verifier_descriptor(&descriptor.body)?;
    if now < descriptor.body.issued_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` is not yet valid",
            descriptor.body.descriptor_id
        )));
    }
    if now > descriptor.body.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` has expired",
            descriptor.body.descriptor_id
        )));
    }
    if !descriptor.verify_signature()? {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` signature verification failed",
            descriptor.body.descriptor_id
        )));
    }
    Ok(())
}

pub struct RuntimeAttestationReferenceValueSetArgs<'a> {
    pub signer: &'a crate::crypto::Keypair,
    pub reference_value_id: String,
    pub descriptor_id: String,
    pub verifier_family: AttestationVerifierFamily,
    pub attestation_schema: String,
    pub source_uri: Option<String>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub state: RuntimeAttestationReferenceValueState,
    pub superseded_by: Option<String>,
    pub revoked_reason: Option<String>,
    pub measurements: BTreeMap<String, serde_json::Value>,
}

pub fn create_signed_runtime_attestation_reference_value_set(
    args: RuntimeAttestationReferenceValueSetArgs<'_>,
) -> ChioResult<SignedRuntimeAttestationReferenceValueSet> {
    let reference_value_set = RuntimeAttestationReferenceValueSet {
        schema: RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA.to_string(),
        reference_value_id: args.reference_value_id,
        descriptor_id: args.descriptor_id,
        verifier_family: args.verifier_family,
        attestation_schema: args.attestation_schema,
        source_uri: args.source_uri,
        issued_at: args.issued_at,
        expires_at: args.expires_at,
        state: args.state,
        superseded_by: args.superseded_by,
        revoked_reason: args.revoked_reason,
        measurements: args.measurements,
    };
    validate_runtime_attestation_reference_value_set(&reference_value_set)?;
    SignedExportEnvelope::sign(reference_value_set, args.signer)
}

pub fn verify_signed_runtime_attestation_reference_value_set(
    reference_value_set: &SignedRuntimeAttestationReferenceValueSet,
    now: u64,
) -> ChioResult<()> {
    validate_runtime_attestation_reference_value_set(&reference_value_set.body)?;
    if now < reference_value_set.body.issued_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` is not yet valid",
            reference_value_set.body.reference_value_id
        )));
    }
    if now > reference_value_set.body.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` has expired",
            reference_value_set.body.reference_value_id
        )));
    }
    if !reference_value_set.verify_signature()? {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` signature verification failed",
            reference_value_set.body.reference_value_id
        )));
    }
    Ok(())
}

pub struct RuntimeAttestationTrustBundleArgs<'a> {
    pub signer: &'a crate::crypto::Keypair,
    pub bundle_id: String,
    pub publisher: String,
    pub version: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub descriptors: Vec<SignedRuntimeAttestationVerifierDescriptor>,
    pub reference_values: Vec<SignedRuntimeAttestationReferenceValueSet>,
}

pub fn create_signed_runtime_attestation_trust_bundle(
    args: RuntimeAttestationTrustBundleArgs<'_>,
) -> ChioResult<SignedRuntimeAttestationTrustBundle> {
    let bundle = RuntimeAttestationTrustBundleDocument {
        schema: RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA.to_string(),
        bundle_id: args.bundle_id,
        publisher: args.publisher,
        version: args.version,
        issued_at: args.issued_at,
        expires_at: args.expires_at,
        descriptors: args.descriptors,
        reference_values: args.reference_values,
    };
    validate_runtime_attestation_trust_bundle(&bundle, args.issued_at)?;
    SignedExportEnvelope::sign(bundle, args.signer)
}

pub fn verify_signed_runtime_attestation_trust_bundle(
    bundle: &SignedRuntimeAttestationTrustBundle,
    now: u64,
) -> ChioResult<RuntimeAttestationTrustBundleVerification> {
    validate_runtime_attestation_trust_bundle(&bundle.body, now)?;
    if !bundle.verify_signature()? {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` signature verification failed",
            bundle.body.bundle_id
        )));
    }
    let verifier_families = bundle
        .body
        .descriptors
        .iter()
        .map(|descriptor| descriptor.body.verifier_family)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(RuntimeAttestationTrustBundleVerification {
        schema: RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA.to_string(),
        bundle_id: bundle.body.bundle_id.clone(),
        publisher: bundle.body.publisher.clone(),
        version: bundle.body.version,
        descriptor_count: bundle.body.descriptors.len(),
        reference_value_count: bundle.body.reference_values.len(),
        verifier_families,
        verified_at: now,
    })
}
