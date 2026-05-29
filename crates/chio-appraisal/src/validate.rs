//! Structural validators for runtime attestation descriptors, reference-value sets, and trust bundles.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Result as ChioResult;

use crate::descriptor::{
    verify_signed_runtime_attestation_reference_value_set,
    verify_signed_runtime_attestation_verifier_descriptor,
};
use crate::types::*;

pub(crate) fn validate_runtime_attestation_verifier_descriptor(
    descriptor: &RuntimeAttestationVerifierDescriptorDocument,
) -> ChioResult<()> {
    if descriptor.schema != RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor schema must be {RUNTIME_ATTESTATION_VERIFIER_DESCRIPTOR_SCHEMA}"
        )));
    }
    if descriptor.descriptor_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(
            "runtime attestation verifier descriptor must include a non-empty descriptor_id"
                .to_string(),
        ));
    }
    if descriptor.verifier.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include a non-empty verifier",
            descriptor.descriptor_id
        )));
    }
    if descriptor.adapter.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include a non-empty adapter",
            descriptor.descriptor_id
        )));
    }
    if descriptor.issued_at > descriptor.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must not expire before it is issued",
            descriptor.descriptor_id
        )));
    }
    if descriptor.attestation_schemas.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include at least one attestation schema",
            descriptor.descriptor_id
        )));
    }
    validate_sorted_unique_strings(
        &descriptor.attestation_schemas,
        "attestation_schemas",
        &descriptor.descriptor_id,
    )?;
    if descriptor.appraisal_artifact_schema != RUNTIME_ATTESTATION_APPRAISAL_ARTIFACT_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must reference the canonical appraisal artifact schema",
            descriptor.descriptor_id
        )));
    }
    if descriptor.appraisal_result_schema != RUNTIME_ATTESTATION_APPRAISAL_RESULT_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must reference the canonical appraisal result schema",
            descriptor.descriptor_id
        )));
    }
    if descriptor.signing_key_fingerprints.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation verifier descriptor `{}` must include at least one signing-key fingerprint",
            descriptor.descriptor_id
        )));
    }
    validate_sorted_unique_strings(
        &descriptor.signing_key_fingerprints,
        "signing_key_fingerprints",
        &descriptor.descriptor_id,
    )?;
    if let Some(reference_values_uri) = &descriptor.reference_values_uri {
        if reference_values_uri.trim().is_empty() {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation verifier descriptor `{}` cannot include an empty reference_values_uri",
                descriptor.descriptor_id
            )));
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_attestation_reference_value_set(
    reference_value_set: &RuntimeAttestationReferenceValueSet,
) -> ChioResult<()> {
    if reference_value_set.schema != RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value schema must be {RUNTIME_ATTESTATION_REFERENCE_VALUE_SET_SCHEMA}"
        )));
    }
    if reference_value_set.reference_value_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(
            "runtime attestation reference-value set must include a non-empty reference_value_id"
                .to_string(),
        ));
    }
    if reference_value_set.descriptor_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must include a non-empty descriptor_id",
            reference_value_set.reference_value_id
        )));
    }
    if reference_value_set.attestation_schema.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must include a non-empty attestation_schema",
            reference_value_set.reference_value_id
        )));
    }
    if reference_value_set.issued_at > reference_value_set.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must not expire before it is issued",
            reference_value_set.reference_value_id
        )));
    }
    if let Some(source_uri) = &reference_value_set.source_uri {
        if source_uri.trim().is_empty() {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation reference-value set `{}` cannot include an empty source_uri",
                reference_value_set.reference_value_id
            )));
        }
    }
    if reference_value_set.measurements.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation reference-value set `{}` must include at least one measurement",
            reference_value_set.reference_value_id
        )));
    }
    match reference_value_set.state {
        RuntimeAttestationReferenceValueState::Active => {
            if reference_value_set.superseded_by.is_some()
                || reference_value_set.revoked_reason.is_some()
            {
                return Err(crate::Error::CanonicalJson(format!(
                    "active runtime attestation reference-value set `{}` cannot include supersession or revocation fields",
                    reference_value_set.reference_value_id
                )));
            }
        }
        RuntimeAttestationReferenceValueState::Superseded => {
            let superseded_by = reference_value_set.superseded_by.as_deref().ok_or_else(|| {
                crate::Error::CanonicalJson(format!(
                    "superseded runtime attestation reference-value set `{}` must include superseded_by",
                    reference_value_set.reference_value_id
                ))
            })?;
            if superseded_by == reference_value_set.reference_value_id {
                return Err(crate::Error::CanonicalJson(format!(
                    "runtime attestation reference-value set `{}` cannot supersede itself",
                    reference_value_set.reference_value_id
                )));
            }
            if reference_value_set.revoked_reason.is_some() {
                return Err(crate::Error::CanonicalJson(format!(
                    "superseded runtime attestation reference-value set `{}` cannot include revoked_reason",
                    reference_value_set.reference_value_id
                )));
            }
        }
        RuntimeAttestationReferenceValueState::Revoked => {
            if reference_value_set.superseded_by.is_some() {
                return Err(crate::Error::CanonicalJson(format!(
                    "revoked runtime attestation reference-value set `{}` cannot include superseded_by",
                    reference_value_set.reference_value_id
                )));
            }
            if reference_value_set
                .revoked_reason
                .as_deref()
                .map(str::trim)
                .unwrap_or_default()
                .is_empty()
            {
                return Err(crate::Error::CanonicalJson(format!(
                    "revoked runtime attestation reference-value set `{}` must include revoked_reason",
                    reference_value_set.reference_value_id
                )));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_runtime_attestation_trust_bundle(
    bundle: &RuntimeAttestationTrustBundleDocument,
    now: u64,
) -> ChioResult<()> {
    if bundle.schema != RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust-bundle schema must be {RUNTIME_ATTESTATION_TRUST_BUNDLE_SCHEMA}"
        )));
    }
    if bundle.bundle_id.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(
            "runtime attestation trust bundle must include a non-empty bundle_id".to_string(),
        ));
    }
    if bundle.publisher.trim().is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must include a non-empty publisher",
            bundle.bundle_id
        )));
    }
    if bundle.version == 0 {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must include a non-zero version",
            bundle.bundle_id
        )));
    }
    if bundle.issued_at > bundle.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must not expire before it is issued",
            bundle.bundle_id
        )));
    }
    if now < bundle.issued_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` is not yet valid",
            bundle.bundle_id
        )));
    }
    if now > bundle.expires_at {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` has expired",
            bundle.bundle_id
        )));
    }
    if bundle.descriptors.is_empty() {
        return Err(crate::Error::CanonicalJson(format!(
            "runtime attestation trust bundle `{}` must include at least one verifier descriptor",
            bundle.bundle_id
        )));
    }

    let mut descriptor_ids = BTreeSet::new();
    let mut descriptors = BTreeMap::new();
    for descriptor in &bundle.descriptors {
        verify_signed_runtime_attestation_verifier_descriptor(descriptor, now)?;
        let descriptor_id = descriptor.body.descriptor_id.clone();
        if !descriptor_ids.insert(descriptor_id.clone()) {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation trust bundle `{}` contains duplicate verifier descriptor `{descriptor_id}`",
                bundle.bundle_id
            )));
        }
        descriptors.insert(descriptor_id, &descriptor.body);
    }

    let mut reference_value_ids = BTreeSet::new();
    let mut active_slots = BTreeSet::new();
    let mut reference_value_states = BTreeMap::new();
    for reference_value in &bundle.reference_values {
        verify_signed_runtime_attestation_reference_value_set(reference_value, now)?;
        let reference_value_id = reference_value.body.reference_value_id.clone();
        if !reference_value_ids.insert(reference_value_id.clone()) {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation trust bundle `{}` contains duplicate reference-value set `{reference_value_id}`",
                bundle.bundle_id
            )));
        }
        let descriptor = descriptors
            .get(&reference_value.body.descriptor_id)
            .ok_or_else(|| {
                crate::Error::CanonicalJson(format!(
                "runtime attestation trust bundle `{}` references unknown verifier descriptor `{}`",
                bundle.bundle_id, reference_value.body.descriptor_id
            ))
            })?;
        if descriptor.verifier_family != reference_value.body.verifier_family {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation reference-value set `{}` does not match verifier-family {:?} of descriptor `{}`",
                reference_value_id, descriptor.verifier_family, descriptor.descriptor_id
            )));
        }
        if !descriptor
            .attestation_schemas
            .contains(&reference_value.body.attestation_schema)
        {
            return Err(crate::Error::CanonicalJson(format!(
                "runtime attestation reference-value set `{}` uses attestation schema `{}` outside descriptor `{}`",
                reference_value_id, reference_value.body.attestation_schema, descriptor.descriptor_id
            )));
        }
        if reference_value.body.state == RuntimeAttestationReferenceValueState::Active {
            let slot = (
                reference_value.body.descriptor_id.clone(),
                reference_value.body.attestation_schema.clone(),
            );
            if !active_slots.insert(slot) {
                return Err(crate::Error::CanonicalJson(format!(
                    "runtime attestation trust bundle `{}` contains ambiguous active reference values for descriptor `{}` and schema `{}`",
                    bundle.bundle_id,
                    reference_value.body.descriptor_id,
                    reference_value.body.attestation_schema
                )));
            }
        }
        reference_value_states.insert(
            reference_value_id,
            (
                reference_value.body.state,
                reference_value.body.superseded_by.clone(),
            ),
        );
    }

    for (reference_value_id, (state, superseded_by)) in &reference_value_states {
        if *state == RuntimeAttestationReferenceValueState::Superseded {
            let successor = superseded_by.as_ref().ok_or_else(|| {
                crate::Error::CanonicalJson(format!(
                    "superseded runtime attestation reference-value set `{reference_value_id}` must include superseded_by"
                ))
            })?;
            if !reference_value_states.contains_key(successor) {
                return Err(crate::Error::CanonicalJson(format!(
                    "runtime attestation trust bundle `{}` references unknown successor `{successor}` for superseded set `{reference_value_id}`",
                    bundle.bundle_id
                )));
            }
        }
    }
    Ok(())
}

fn validate_sorted_unique_strings(values: &[String], field: &str, id: &str) -> ChioResult<()> {
    if values.iter().any(|value| value.trim().is_empty()) {
        return Err(crate::Error::CanonicalJson(format!(
            "{field} for `{id}` cannot contain empty values"
        )));
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted != values {
        return Err(crate::Error::CanonicalJson(format!(
            "{field} for `{id}` must be stored in sorted unique order"
        )));
    }
    Ok(())
}
